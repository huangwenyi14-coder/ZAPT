"""Regression tests for victim-side APT scenario regeneration."""

import json

import yaml
from scripts.regenerate_apt_scenarios import (
    LINUX_TARGET_HOST,
    WINDOWS_TARGET_HOST,
    _build_phishing_event,
    _merge_network_context,
    assess_source_quality,
    build_event,
    build_scene_index,
    build_segments,
    build_users_and_systems,
    collect_campaign_network_context,
    convert,
    enrich_storyline_events,
    ensure_c2_server_node,
    extract_network,
    extract_process_image,
    fix_technique_id,
    is_supported_source_step,
    pick_actor_system_end,
    shift_time_window_start,
    synthetic_external_ip,
    visible_prelude_hours,
)

from evidenceforge.models.scenario import Scenario


def _scene_nodes() -> list[dict]:
    """Return source nodes that include external attacker and C2 infrastructure."""
    return [
        {
            "id": 142,
            "name": "linux_attack_server",
            "os": "linux",
            "role": "attacker",
            "hostname": "ATK-LNX-01",
            "ip": "10.10.10.10",
            "os_label": "Ubuntu 22.04 LTS",
            "type": "server",
            "services": ["ssh"],
        },
        {
            "id": 900,
            "name": "c2_server",
            "os": "linux",
            "role": "c2_server",
            "hostname": "C2-SERVER-01",
            "ip": "10.10.99.99",
            "os_label": "Ubuntu 22.04 LTS",
            "type": "server",
            "services": ["https"],
        },
    ]


def test_external_infrastructure_is_not_added_to_victim_environment() -> None:
    """Attacker and C2 source nodes must not receive baseline users or segments."""
    scene_index = build_scene_index(_scene_nodes())
    users, systems = build_users_and_systems(
        {},
        scene_index,
        ["operator.alpha", "victim.user", "victim.lnx"],
    )

    hostnames = {system["hostname"] for system in systems}
    primary_systems = {user["primary_system"] for user in users}
    segment_systems = {
        hostname for segment in build_segments(systems) for hostname in segment["systems"]
    }

    assert hostnames == {
        WINDOWS_TARGET_HOST,
        LINUX_TARGET_HOST,
        "WKS-FIN-014",
        "WKS-HR-009",
        "DC-01",
        "FS-01",
        "WEB-01",
        "DB-01",
    }
    assert primary_systems <= hostnames
    assert {WINDOWS_TARGET_HOST, LINUX_TARGET_HOST, "DC-01"} <= primary_systems
    assert segment_systems == hostnames
    assert "ATK-LNX-01" not in hostnames
    assert "C2-SERVER-01" not in hostnames


def test_c2_steps_stay_on_victim_endpoint_when_source_node_is_attacker() -> None:
    """A report-side attacker source ID must not become the storyline system."""
    scene_index = build_scene_index(_scene_nodes())
    actor, system, c2_host = pick_actor_system_end(
        {
            "src": 142,
            "os": "windows",
            "scene_tag": "c2_beacon",
            "params": {"network": {"host": "sync-gateway.net"}},
        },
        scene_index,
        ["operator.alpha", "victim.user", "victim.lnx"],
        "operator.alpha",
        "victim.user",
        "victim.lnx",
    )

    assert actor == "victim.user"
    assert system == WINDOWS_TARGET_HOST
    assert c2_host == "sync-gateway.net"


def test_deprecated_auto_c2_option_does_not_inject_internal_system() -> None:
    """The compatibility option must leave the collected scene index unchanged."""
    scene_index = build_scene_index(_scene_nodes())
    original = {node_id: dict(node) for node_id, node in scene_index.items()}

    result = ensure_c2_server_node(
        scene_index,
        [{"params": {"network": {"host": "sync-gateway.net"}}}],
    )

    assert result == original


def test_visible_prelude_is_stable_and_moves_window_before_attack() -> None:
    """Visible baseline duration is reproducible, bounded, and preserves the attack anchor."""
    prelude = visible_prelude_hours("example-campaign")

    assert 8 <= prelude <= 72
    assert visible_prelude_hours("example-campaign") == prelude
    assert shift_time_window_start("2024-03-20T10:00:00Z", 12) == "2024-03-19T22:00:00Z"


def test_source_quality_gate_discards_thin_report() -> None:
    """A two-step prose-only report must not be padded into a generated scenario."""
    assessment = assess_source_quality(
        {
            "steps": [
                {
                    "scene_tag": "initial_access",
                    "params": {"attack_mapping": {"technique_id": "T1190"}},
                },
                {
                    "scene_tag": "impact",
                    "params": {"attack_mapping": {"technique_id": "T1485"}},
                },
            ]
        }
    )

    assert assessment["eligible"] is False
    assert any("minimum is 5" in reason for reason in assessment["reasons"])


def test_phishing_event_does_not_invent_missing_message_facts() -> None:
    """Missing sender, recipient, subject, and attachment stay absent."""
    events = _build_phishing_event(
        {"params": {}},
        WINDOWS_TARGET_HOST,
        "T1566.001 - Spearphishing Attachment",
        "The report says only that phishing was used.",
        {},
        "windows",
    )

    rendered = repr(events)
    assert "external-threat-actor" not in rendered
    assert "victim@target-org" not in rendered
    assert "Important document attached" not in rendered
    assert "attachment.bin" not in rendered
    assert events[0]["command_line"].endswith("/c ipm.note")


def test_phishing_event_preserves_only_reported_message_facts() -> None:
    """Reported delivery pivots remain available without fabricated extras."""
    events = _build_phishing_event(
        {
            "params": {
                "email": {
                    "sender": "billing@example.net",
                    "subject": "Updated invoice",
                }
            }
        },
        WINDOWS_TARGET_HOST,
        "T1566.001 - Spearphishing Attachment",
        "",
        {"file_name": "invoice.docm", "sha256": "a" * 64},
        "windows",
    )

    event = events[0]
    assert "billing@example.net" in event["description"]
    assert "Updated invoice" in event["command_line"]
    assert "invoice.docm" in event["command_line"]
    assert "To=<" not in event["description"]


def test_domain_only_network_fact_gets_stable_simulation_ip_without_fake_hostname() -> None:
    """A reported domain may receive a safe IP, but an absent domain stays absent."""
    reported = extract_network(
        {
            "step_id": "s1",
            "params": {"network": {"host": "sync-gateway.example", "port": 443}},
        }
    )
    missing = extract_network({"step_id": "s2", "params": {"network": {"port": 443}}})

    assert reported == {
        "hostname": "sync-gateway.example",
        "dst_ip": synthetic_external_ip("sync-gateway.example"),
        "dst_port": 443,
    }
    assert missing == {"dst_port": 443}


def test_campaign_endpoint_reuses_source_report_fact_for_later_c2_step() -> None:
    """An underspecified later C2 action may reuse an earlier reported endpoint."""
    steps = [
        {
            "scene_tag": "c2_setup",
            "params": {"network": {"host": "sync-gateway.example", "port": 443}},
        },
        {
            "scene_tag": "c2_beacon",
            "params": {"process": {"target_process": "agent.exe"}},
        },
    ]
    campaign_network = collect_campaign_network_context(steps)
    event = build_event(
        steps[1],
        "quality.audit",
        WINDOWS_TARGET_HOST,
        "sync-gateway.example",
        "windows",
        campaign_network,
    )

    assert isinstance(event, dict)
    assert event["type"] == "beacon"
    assert event["hostname"] == "sync-gateway.example"
    assert event["dst_ip"] == synthetic_external_ip("sync-gateway.example")


def test_campaign_network_context_never_leaks_http_behavior_between_steps() -> None:
    """Campaign context may share an endpoint tuple, never another behavior's HTTP facts."""
    campaign = {
        "hostname": "sync-gateway.example",
        "dst_ip": "203.0.113.50",
        "dst_port": 443,
        "service": "ssl",
        "method": "POST",
        "uri": "/submit/first",
    }

    inherited = _merge_network_context({}, campaign)
    overridden = _merge_network_context(
        {
            "hostname": "download.example",
            "dst_ip": "198.51.100.20",
            "method": "GET",
            "uri": "/payload.bin",
        },
        campaign,
    )

    assert inherited == {
        "hostname": "sync-gateway.example",
        "dst_ip": "203.0.113.50",
        "dst_port": 443,
    }
    assert overridden == {
        "hostname": "download.example",
        "dst_ip": "198.51.100.20",
        "method": "GET",
        "uri": "/payload.bin",
    }


def test_missing_process_owner_uses_marked_placeholder_not_previous_process() -> None:
    """A network event with no owner gets a local degradation marker, not stale ownership."""
    events = enrich_storyline_events(
        [
            {
                "type": "connection",
                "dst_ip": "203.0.113.50",
                "dst_port": 443,
            }
        ],
        {"step_id": "network-only", "params": {}},
        sequence=2,
        actor="victim.user",
        system=WINDOWS_TARGET_HOST,
        os_cat="windows",
        latest_process_by_system={WINDOWS_TARGET_HOST: "proc-previous-step"},
        process_owners={},
        referenced_processes=set(),
    )

    placeholder, connection = events
    assert placeholder["type"] == "process"
    assert placeholder["process_ref"] != "proc-previous-step"
    assert "PowerShell" not in placeholder["process_name"]
    assert "LEGACY_CONVERSION_DEGRADED" in placeholder["description"]
    assert connection["source_process_ref"] == placeholder["process_ref"]


def test_missing_process_image_does_not_default_to_shell() -> None:
    """An absent report-side executable must remain absent during extraction."""
    assert extract_process_image({"params": {}}, "windows") == ""
    assert extract_process_image({"params": {}}, "linux") == ""


def test_registry_read_and_write_are_materialized_as_distinct_events() -> None:
    """Registry access semantics come from the same step instead of always becoming a write."""

    def enrich(operation: str, **registry_fields: str) -> list[dict]:
        return enrich_storyline_events(
            [
                {
                    "type": "process",
                    "process_name": r"C:\Windows\System32\reg.exe",
                }
            ],
            {
                "step_id": f"registry-{operation}",
                "scene_tag": f"registry_{operation}",
                "params": {
                    "registry": {
                        "key": r"HKLM\SOFTWARE\Example",
                        "operation": operation,
                        **registry_fields,
                    }
                },
            },
            sequence=3,
            actor="victim.user",
            system=WINDOWS_TARGET_HOST,
            os_cat="windows",
            latest_process_by_system={},
            process_owners={},
            referenced_processes=set(),
        )

    query_events = enrich("query", value_name="SystemBiosVersion")
    set_events = enrich("set", value_name="Updater", value_data="agent.exe")

    assert query_events[-1] == {
        "type": "registry_query",
        "process_ref": query_events[0]["process_ref"],
        "key": r"HKLM\SOFTWARE\Example",
        "value_name": "SystemBiosVersion",
        "description": "Registry read materialized from fields in the source report.",
    }
    assert set_events[-1]["type"] == "registry_set"
    assert set_events[-1]["value_data"] == "agent.exe"


def test_unknown_registry_operation_is_explicitly_degraded() -> None:
    """A registry key without read/write semantics must not silently become a precise write."""
    events = enrich_storyline_events(
        [{"type": "process", "process_name": "sample.exe"}],
        {
            "step_id": "registry-unknown",
            "params": {"registry": {"key": r"HKCU\Software\Example"}},
        },
        sequence=4,
        actor="victim.user",
        system=WINDOWS_TARGET_HOST,
        os_cat="windows",
        latest_process_by_system={},
        process_owners={},
        referenced_processes=set(),
    )

    assert not any(event["type"] in {"registry_query", "registry_set"} for event in events)
    assert "LEGACY_CONVERSION_DEGRADED" in events[0]["description"]


def test_legacy_converter_preserves_behavior_boundaries_end_to_end(tmp_path) -> None:
    """The written scenario remains typed without stale HTTP or process ownership facts."""
    source = tmp_path / "legacy-report.json"
    source.write_text(
        json.dumps(
            {
                "meta": {"report_name": "旧转换器语义边界回归"},
                "steps": [
                    {
                        "step_id": "http-submit",
                        "name": "首次 HTTP 提交",
                        "os": "windows",
                        "scene_tag": "c2_checkin",
                        "params": {
                            "network": {
                                "host": "sync-gateway.example",
                                "port": 443,
                                "method": "POST",
                                "uri": "/submit/first",
                            }
                        },
                    },
                    {
                        "step_id": "beacon-no-owner",
                        "name": "后续信标",
                        "os": "windows",
                        "scene_tag": "c2_beacon",
                        "params": {},
                    },
                    {
                        "step_id": "registry-read",
                        "name": "读取 BIOS 注册表值",
                        "os": "windows",
                        "scene_tag": "registry_query",
                        "params": {
                            "registry": {
                                "key": r"HKLM\HARDWARE\DESCRIPTION\System",
                                "operation": "query",
                                "value_name": "SystemBiosVersion",
                            }
                        },
                    },
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    scenario_dir = convert(source, tmp_path / "scenarios")
    raw_scenario = yaml.safe_load((scenario_dir / "scenario.yaml").read_text(encoding="utf-8"))
    scenario = Scenario.model_validate(raw_scenario)
    entries = {entry.activity.split(" →", 1)[0]: entry for entry in scenario.storyline}

    beacon_events = entries["后续信标"].events
    beacon = next(event for event in beacon_events if event.type == "beacon")
    beacon_owner = next(event for event in beacon_events if event.type == "process")
    assert beacon_owner.process_name == "report-unspecified.exe"
    assert "LEGACY_CONVERSION_DEGRADED" in (beacon_owner.description or "")
    assert beacon.source_process_ref == beacon_owner.process_ref

    first_connection = next(
        event for event in entries["首次 HTTP 提交"].events if event.type == "connection"
    )
    assert first_connection.method == "POST"
    assert first_connection.uri == "/submit/first"
    assert beacon.method is None
    assert beacon.uri is None

    registry_events = entries["读取 BIOS 注册表值"].events
    assert any(event.type == "registry_query" for event in registry_events)
    assert not any(event.type == "registry_set" for event in registry_events)
    rendered = (scenario_dir / "scenario.yaml").read_text(encoding="utf-8")
    assert "WindowsPowerShell" not in rendered


def test_source_quality_gate_discards_five_step_prose_outline() -> None:
    """Five tactic labels without renderable facts are still not a usable report."""
    raw = {
        "steps": [
            {
                "scene_tag": tag,
                "params": {"attack_mapping": {"technique_id": technique}},
            }
            for tag, technique in [
                ("initial_access", "T1566.001"),
                ("execution", "T1059.001"),
                ("discovery", "T1082"),
                ("persistence", "T1053.005"),
                ("cleanup", "T1070.004"),
            ]
        ]
    }

    assessment = assess_source_quality(raw)

    assert assessment["eligible"] is False
    assert assessment["metrics"]["renderable_step_count"] == 0
    assert any("source-backed renderable steps" in reason for reason in assessment["reasons"])


def test_legacy_enterprise_attack_ids_are_normalized_to_v19() -> None:
    """Only retired IDs are remapped; valid bundled Enterprise IDs stay intact."""
    assert fix_technique_id(
        "dll_sideload",
        {"technique_id": "T1574.002", "technique": "DLL Side-Loading"},
    ) == {
        "technique_id": "T1574.001",
        "technique": "Hijack Execution Flow: DLL",
    }
    assert fix_technique_id(
        "disable_security",
        {"technique_id": "T1562.001", "technique": "Disable or Modify Tools"},
    ) == {
        "technique_id": "T1562.001",
        "technique": "Disable or Modify Tools",
    }
    assert fix_technique_id(
        "clear_logs",
        {"technique_id": "T1070.001", "technique": "Clear Windows Event Logs"},
    ) == {
        "technique_id": "T1070.001",
        "technique": "Clear Windows Event Logs",
    }


def test_non_enterprise_attack_id_keeps_name_but_drops_id() -> None:
    """An ICS technique must not masquerade as an Enterprise ATT&CK label."""
    assert fix_technique_id(
        "impact",
        {"technique_id": "T0816", "technique": "Device Restart/Shutdown"},
    ) == {"technique": "Device Restart/Shutdown"}


def test_pure_mobile_report_is_discarded_instead_of_rendered_as_linux() -> None:
    """Unsupported mobile telemetry must not be approximated as a Linux endpoint."""
    mobile_steps = [
        {
            "os": "android",
            "scene_tag": tag,
            "params": {
                "attack_mapping": {"technique_id": technique},
                "command": {"command_line": f"mobile action {index}"},
            },
        }
        for index, (tag, technique) in enumerate(
            [
                ("initial_access", "T1475"),
                ("execution", "T1622"),
                ("persistence", "T1603"),
                ("collection", "T1533"),
                ("exfiltration", "T1041"),
            ],
            start=1,
        )
    ]

    assessment = assess_source_quality({"steps": mobile_steps})

    assert is_supported_source_step(mobile_steps[0]) is False
    assert assessment["eligible"] is False
    assert assessment["metrics"]["step_count"] == 0
    assert assessment["metrics"]["unsupported_platform_step_count"] == 5
    assert any("unsupported endpoint platforms" in reason for reason in assessment["reasons"])
