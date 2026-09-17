from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


def _load_detector():
    detector_path = Path(__file__).parents[2] / "gold" / "source_informed_chain_detector.py"
    spec = importlib.util.spec_from_file_location(
        "gold_source_informed_chain_detector", detector_path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DETECTOR = _load_detector()


def test_process_identities_do_not_expand_parent_or_logon_ids() -> None:
    record = {
        "source_format": "windows_event_sysmon",
        "source_instance": "HOST-A.example.cn",
        "correlation_features": {
            "event_data": {
                "ProcessId": 6848,
                "ParentProcessId": 4816,
                "ProcessGuid": "{process-guid}",
                "ParentProcessGuid": "{parent-guid}",
                "LogonId": "0x106c97e3",
            }
        },
    }

    identities = DETECTOR.process_identities(record)

    assert identities.process_pids == {("host-a", "6848")}
    assert identities.process_stable_ids == {("host-a", "{process-guid}")}


def test_process_identities_normalize_security_hex_pid() -> None:
    record = {
        "source_format": "windows_event_security",
        "source_instance": "HOST-A.example.cn",
        "correlation_features": {
            "event_data": {
                "ProcessId": "0x1ac0",
                "SubjectLogonId": "0x106c97e3",
            }
        },
    }

    identities = DETECTOR.process_identities(record)

    assert identities.process_pids == {("host-a", "6848")}
    assert identities.process_stable_ids == set()


def test_security_4688_keeps_actor_and_new_process_pid_roles_separate() -> None:
    identities = DETECTOR.process_identities(
        {
            "source_format": "windows_event_security",
            "source_instance": "HOST-A.example.cn",
            "correlation_features": {
                "event_id": 4688,
                "event_data": {"ProcessId": "0x100", "NewProcessId": "0x200"},
            },
        }
    )

    assert identities.actor_pids == {("host-a", "256")}
    assert identities.process_pids == {("host-a", "512")}


def test_repo_root_and_baseline_catalogs_load_from_gold_directory() -> None:
    assert (DETECTOR.REPO_ROOT / "src" / "evidenceforge").is_dir()
    assert DETECTOR.BASELINE_DOMAINS
    assert DETECTOR.BASELINE_IPS
    assert DETECTOR.BASELINE_APP_EXES


def test_ip_and_fqdn_host_aliases_do_not_collapse_ipv4() -> None:
    assert DETECTOR.host_aliases("10.12.4.42") == {"10.12.4.42"}
    assert DETECTOR.host_aliases("WS-STU-042.example.cn") == {
        "ws-stu-042",
        "ws-stu-042.example.cn",
    }
    row = {
        "source_instance": "10.12.4.42",
        "correlation_features": {},
    }
    assert DETECTOR.record_matches_host(row, {"10.12.4.42"})
    assert not DETECTOR.record_matches_host(row, {"10.99.1.7"})


def test_pid_identity_is_scoped_by_host() -> None:
    def identities(host: str):
        return DETECTOR.process_identities(
            {
                "source_format": "windows_event_sysmon",
                "source_instance": host,
                "correlation_features": {
                    "event_data": {"ProcessId": 6848, "ProcessGuid": "{same-text}"}
                },
            }
        )

    host_a = identities("HOST-A.example.cn")
    host_b = identities("HOST-B.example.cn")

    assert host_a.process_pids.isdisjoint(host_b.process_pids)
    assert host_a.process_stable_ids.isdisjoint(host_b.process_stable_ids)


def test_ecar_actor_and_object_roles_are_not_conflated() -> None:
    process_create = DETECTOR.process_identities(
        {
            "source_format": "ecar",
            "source_instance": "HOST-A.example.cn",
            "correlation_features": {
                "action": "CREATE",
                "object": "PROCESS",
                "actorID": "parent-process",
                "objectID": "new-process",
                "pid": 7000,
            },
        }
    )
    file_create = DETECTOR.process_identities(
        {
            "source_format": "ecar",
            "source_instance": "HOST-A.example.cn",
            "correlation_features": {
                "action": "CREATE",
                "object": "FILE",
                "actorID": "new-process",
                "objectID": "created-file",
                "pid": 7000,
            },
        }
    )

    assert process_create.process_stable_ids == {("host-a", "new-process")}
    assert process_create.actor_stable_ids == {("host-a", "parent-process")}
    assert ("host-a", "parent-process") not in process_create.process_stable_ids
    assert file_create.process_stable_ids == {("host-a", "new-process")}
    assert file_create.object_ids == {("host-a", "created-file")}


def test_load_record_index_rejects_private_labels(tmp_path: Path) -> None:
    index_path = tmp_path / "RECORD_INDEX.jsonl"
    index_path.write_text(
        json.dumps({"physical_record_id": "pr-test", "label": "malicious"}) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="private keys"):
        DETECTOR.load_record_index(index_path)


def test_load_record_index_rejects_detectability_metadata(tmp_path: Path) -> None:
    index_path = tmp_path / "RECORD_INDEX.jsonl"
    index_path.write_text(
        json.dumps(
            {
                "physical_record_id": "pr-000000000000000000000000",
                "detectability_class": "direct",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="private keys"):
        DETECTOR.load_record_index(index_path)


def test_load_record_index_rejects_nested_private_labels(tmp_path: Path) -> None:
    index_path = tmp_path / "RECORD_INDEX.jsonl"
    index_path.write_text(
        json.dumps(
            {
                "physical_record_id": "pr-000000000000000000000000",
                "correlation_features": {"nested": {"storyline_id": "evt-secret"}},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"correlation_features\.nested\.storyline_id"):
        DETECTOR.load_record_index(index_path)


def test_load_record_index_verifies_hash_and_locator(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    payload = b'{"record":1}\n'
    (data_dir / "events.json").write_bytes(payload)
    row = {
        "byte_length": len(payload),
        "byte_offset": 0,
        "correlation_features": {},
        "native_record_id": {},
        "observed_time": "2026-01-01T00:00:00Z",
        "physical_record_id": "pr-000000000000000000000000",
        "record_index": 0,
        "record_sha256": hashlib.sha256(payload).hexdigest(),
        "relative_path": "events.json",
        "source_format": "test",
        "source_instance": "HOST-A",
    }
    index_path = tmp_path / "RECORD_INDEX.jsonl"
    index_path.write_text(json.dumps(row) + "\n", encoding="utf-8")

    assert DETECTOR.load_record_index(index_path, data_dir=data_dir) == [row]

    row["record_sha256"] = "0" * 64
    index_path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        DETECTOR.load_record_index(index_path, data_dir=data_dir)


def test_load_record_index_rejects_duplicate_physical_ids(tmp_path: Path) -> None:
    base = {
        "byte_length": 1,
        "byte_offset": 0,
        "correlation_features": {},
        "observed_time": "2026-01-01T00:00:00Z",
        "physical_record_id": "pr-000000000000000000000000",
        "record_index": 0,
        "record_sha256": "0" * 64,
        "relative_path": "one.log",
        "source_format": "test",
        "source_instance": "HOST-A",
    }
    duplicate = {**base, "record_index": 1, "relative_path": "two.log"}
    index_path = tmp_path / "RECORD_INDEX.jsonl"
    index_path.write_text(json.dumps(base) + "\n" + json.dumps(duplicate) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate physical_record_id"):
        DETECTOR.load_record_index(index_path)


def test_record_expansion_supports_no_beacon_direct_finding(tmp_path: Path) -> None:
    host_dir = tmp_path / "HOST-A.example.cn"
    host_dir.mkdir()
    log_record = {
        "timestamp_ms": 1767225600000,
        "hostname": "HOST-A",
        "object": "PROCESS",
        "action": "CREATE",
        "pid": 7000,
        "objectID": "process-7000",
        "properties": {"image_path": "C:\\Temp\\sample.exe"},
    }
    (host_dir / "ecar.json").write_text(json.dumps(log_record) + "\n", encoding="utf-8")
    record_index = [
        {
            "physical_record_id": "pr-000000000000000000000000",
            "relative_path": "HOST-A.example.cn/ecar.json",
            "record_index": 0,
            "observed_time": "2026-01-01T00:00:00Z",
            "source_format": "ecar",
            "source_instance": "HOST-A.example.cn",
            "correlation_features": {
                "hostname": "HOST-A",
                "object": "PROCESS",
                "action": "CREATE",
                "pid": 7000,
                "objectID": "process-7000",
            },
            "native_record_id": {},
        }
    ]
    findings = [
        {
            "host": "HOST-A",
            "timestamp": "2026-01-01T00:00:00Z",
            "evidence": [{"file": "HOST-A.example.cn/ecar.json", "line": 1, "detail": "direct"}],
        }
    ]

    output = DETECTOR.record_level_predictions(
        data_dir=tmp_path,
        record_index=record_index,
        findings=findings,
    )

    assert [row["physical_record_id"] for row in output["predictions"]] == [
        "pr-000000000000000000000000"
    ]


def test_record_expansion_returns_empty_predictions_when_no_findings(tmp_path: Path) -> None:
    output = DETECTOR.record_level_predictions(
        data_dir=tmp_path,
        record_index=[],
        findings=[],
    )

    assert output == {
        "analysis_summary": (
            "source-informed detector produced no findings and expanded 0 physical records"
        ),
        "predictions": [],
    }


def test_xml_finding_line_maps_to_physical_record_index(tmp_path: Path) -> None:
    xml_dir = tmp_path / "HOST-A.example.cn"
    xml_dir.mkdir()
    xml_text = """<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><EventID>1</EventID></System>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><EventID>4698</EventID></System>
</Event>
</Events>
"""
    (xml_dir / "windows_event_security.xml").write_text(xml_text, encoding="utf-8")
    findings = [
        {
            "evidence": [
                {
                    "file": "HOST-A.example.cn/windows_event_security.xml",
                    "line": 5,
                }
            ]
        }
    ]

    assert DETECTOR.evidence_locator_keys(findings, tmp_path) == {
        ("HOST-A.example.cn/windows_event_security.xml", 1)
    }


def test_process_chain_family_is_explicit() -> None:
    assert DETECTOR.is_process_chain_record(
        {
            "source_format": "windows_event_security",
            "correlation_features": {"event_id": 4689},
        }
    )
    assert not DETECTOR.is_process_chain_record(
        {
            "source_format": "windows_event_security",
            "correlation_features": {"event_id": 5156},
        }
    )
