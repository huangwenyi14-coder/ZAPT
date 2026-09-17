from __future__ import annotations

from datetime import datetime, timedelta, timezone

from gold import record_graph_detector as detector

UTC = timezone.utc  # noqa: UP017 - mirror the detector's Python 3.10 runtime


def row(
    physical_id: str,
    source_format: str,
    timestamp: datetime,
    features: dict,
    *,
    source_instance: str = "HOST-A.example.test",
    record_index: int = 0,
) -> dict:
    return {
        "physical_record_id": physical_id,
        "relative_path": f"{source_instance}/{source_format}.json",
        "record_index": record_index,
        "observed_time": timestamp.isoformat().replace("+00:00", "Z"),
        "source_format": source_format,
        "source_instance": source_instance,
        "correlation_features": features,
    }


def ecar_process(
    physical_id: str,
    timestamp: datetime,
    *,
    action: str,
    object_id: str,
    pid: int,
    image: str,
    command: str = "",
    actor_id: str = "parent",
    ppid: int = 400,
) -> dict:
    return row(
        physical_id,
        "ecar",
        timestamp,
        {
            "action": action,
            "actorID": actor_id,
            "hostname": "HOST-A",
            "object": "PROCESS",
            "objectID": object_id,
            "pid": pid,
            "ppid": ppid,
            "properties": {"image_path": image, "command_line": command},
        },
    )


def ecar_file(
    physical_id: str,
    timestamp: datetime,
    *,
    path: str,
    actor_id: str,
    pid: int,
    image: str,
    action: str = "CREATE",
    source_instance: str = "HOST-A.example.test",
) -> dict:
    return row(
        physical_id,
        "ecar",
        timestamp,
        {
            "action": action,
            "actorID": actor_id,
            "hostname": source_instance.split(".", 1)[0],
            "object": "FILE",
            "objectID": f"file-{physical_id}",
            "pid": pid,
            "properties": {"file_path": path, "image_path": image},
        },
        source_instance=source_instance,
    )


def test_record_index_view_discards_unknown_and_nested_private_fields() -> None:
    public = detector.allowlisted_features(
        {
            "source_format": "ecar",
            "correlation_features": {
                "action": "CREATE",
                "storyline_id": "must-not-be-seen",
                "future_unreviewed_key": "must-not-be-seen",
                "properties": {
                    "image_path": "C:\\Temp\\tool.exe",
                    "logical_event_id": "must-not-be-seen",
                },
            },
        }
    )

    assert public == {
        "action": "CREATE",
        "properties": {"image_path": "C:\\Temp\\tool.exe"},
    }


def test_adaptive_period_finds_short_and_multi_hour_series_with_outliers() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = []
    elapsed = 0.0
    for index in range(12):
        if index:
            elapsed += 32 + (-1.5 if index % 2 else 1.5)
        rows.append(
            row(
                f"short-{index}",
                "zeek_conn",
                start + timedelta(seconds=elapsed),
                {
                    "id.orig_h": "10.1.1.5",
                    "id.orig_p": 40000 + index,
                    "id.resp_h": "198.51.100.10",
                    "id.resp_p": 443,
                    "proto": "tcp",
                    "uid": f"C{index}",
                },
                source_instance="ZEEK",
                record_index=index,
            )
        )
    # A suspended-host gap must not destroy the coherent 32-second fit.
    rows.append(
        row(
            "short-after-gap",
            "zeek_conn",
            start + timedelta(seconds=elapsed + 1600),
            {
                "id.orig_h": "10.1.1.5",
                "id.orig_p": 50000,
                "id.resp_h": "198.51.100.10",
                "id.resp_p": 443,
                "proto": "tcp",
                "uid": "Cgap",
            },
            source_instance="ZEEK",
            record_index=20,
        )
    )
    for index, seconds in enumerate((0, 7200, 14460, 21630, 28820)):
        rows.append(
            row(
                f"long-{index}",
                "zeek_conn",
                start + timedelta(seconds=seconds),
                {
                    "id.orig_h": "10.2.2.8",
                    "id.orig_p": 51000 + index,
                    "id.resp_h": "203.0.113.77",
                    "id.resp_p": 8443,
                    "proto": "tcp",
                    "uid": f"L{index}",
                },
                source_instance="ZEEK",
                record_index=30 + index,
            )
        )

    anchors = detector.discover_periodic(
        detector.normalize_records(rows),
        baseline_domains=set(),
        baseline_ips=set(),
        benign_tokens=(),
    )
    ids = {item[0].physical_id for item in anchors}

    assert {"short-0", "short-11", "long-0", "long-2"}.issubset(ids)


def test_adaptive_period_rejects_cherry_picked_subsequence() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    timestamps = (0, 3100, 4000, 7105, 14305, 17415, 17815, 20920)
    rows = [
        row(
            f"irregular-{index}",
            "zeek_conn",
            start + timedelta(seconds=seconds),
            {
                "id.orig_h": "10.1.1.5",
                "id.orig_p": 50000 + index,
                "id.resp_h": "198.51.100.10",
                "id.resp_p": 443,
                "proto": "tcp",
                "uid": f"I{index}",
            },
            source_instance="ZEEK",
            record_index=index,
        )
        for index, seconds in enumerate(timestamps)
    ]

    anchors = detector.discover_periodic(
        detector.normalize_records(rows),
        baseline_domains=set(),
        baseline_ips=set(),
        benign_tokens=(),
    )

    assert anchors == []


def test_discovery_engines_are_independent_and_web_rule_is_direct() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        ecar_process(
            "terminal",
            start,
            action="CREATE",
            object_id="proc-terminal",
            pid=7000,
            image="C:\\Windows\\System32\\reg.exe",
            command="reg save HKLM\\SAM C:\\Temp\\sam.hiv",
        ),
        ecar_process(
            "ioc",
            start + timedelta(seconds=1),
            action="CREATE",
            object_id="proc-ioc",
            pid=7001,
            image="C:\\Temp\\caddywiper.exe",
            command="C:\\Temp\\caddywiper.exe",
        ),
        row(
            "web",
            "web_access",
            start + timedelta(seconds=2),
            {
                "method": "GET",
                "target": "/geoserver/wfs?valueReference=exec(java.lang.Runtime.getRuntime(),'cmd%20/c%20whoami')",
            },
        ),
    ]

    output, _findings = detector.detect_record_graph(case_id="case", rows=rows)
    counts = output["diagnostics"]["discovery_anchor_counts"]

    assert counts["terminal"] == 1
    assert counts["ioc"] == 1
    assert counts["web_exploit"] == 1


def test_exact_lifecycle_termination_is_selected_but_pid_reuse_is_not() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        ecar_process(
            "create",
            start,
            action="CREATE",
            object_id="exact-instance",
            pid=8120,
            image="C:\\Temp\\caddywiper.exe",
            command="C:\\Temp\\caddywiper.exe",
        ),
        ecar_process(
            "terminate",
            start + timedelta(seconds=20),
            action="TERMINATE",
            object_id="exact-instance",
            pid=8120,
            image="C:\\Temp\\caddywiper.exe",
        ),
        ecar_process(
            "pid-reuse",
            start + timedelta(seconds=25),
            action="CREATE",
            object_id="different-instance",
            pid=8120,
            image="C:\\Windows\\System32\\notepad.exe",
            command="notepad.exe",
        ),
    ]

    output, _findings = detector.detect_record_graph(case_id="case", rows=rows)
    selected = {item["physical_record_id"]: item for item in output["predictions"]}

    assert selected["terminate"]["association_strength"] == "process_create_to_exact_terminate"
    assert "pid-reuse" not in selected


def test_parent_child_expansion_stops_after_one_hop() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        ecar_process(
            "parent",
            start,
            action="CREATE",
            object_id="parent-id",
            pid=9000,
            image="C:\\Temp\\caddywiper.exe",
            command="C:\\Temp\\caddywiper.exe",
        ),
        ecar_process(
            "child",
            start + timedelta(seconds=1),
            action="CREATE",
            object_id="child-id",
            pid=9001,
            image="C:\\Temp\\child.exe",
            actor_id="parent-id",
            ppid=9000,
        ),
        ecar_process(
            "grandchild",
            start + timedelta(seconds=2),
            action="CREATE",
            object_id="grandchild-id",
            pid=9002,
            image="C:\\Temp\\grandchild.exe",
            actor_id="child-id",
            ppid=9001,
        ),
        ecar_process(
            "child-terminate",
            start + timedelta(seconds=3),
            action="TERMINATE",
            object_id="child-id",
            pid=9001,
            image="C:\\Temp\\child.exe",
            actor_id="child-id",
            ppid=9000,
        ),
    ]

    output, _findings = detector.detect_record_graph(case_id="case", rows=rows)
    selected = {item["physical_record_id"] for item in output["predictions"]}

    assert "child" in selected
    assert "child-terminate" in selected
    assert "grandchild" not in selected


def test_process_flow_expands_through_five_tuple_uid_and_fuid() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        ecar_process(
            "process",
            start,
            action="CREATE",
            object_id="malware-process",
            pid=9200,
            image="C:\\Temp\\caddywiper.exe",
            command="C:\\Temp\\caddywiper.exe",
        ),
        row(
            "flow",
            "ecar",
            start + timedelta(seconds=2),
            {
                "action": "CONNECT",
                "actorID": "malware-process",
                "hostname": "HOST-A",
                "object": "FLOW",
                "pid": 9200,
                "properties": {
                    "src_ip": "10.5.5.5",
                    "src_port": 53000,
                    "dst_ip": "198.51.100.55",
                    "dst_port": 443,
                    "protocol": "tcp",
                    "image_path": "C:\\Temp\\caddywiper.exe",
                },
            },
            record_index=1,
        ),
        row(
            "conn",
            "zeek_conn",
            start + timedelta(seconds=2, milliseconds=200),
            {
                "id.orig_h": "10.5.5.5",
                "id.orig_p": 53000,
                "id.resp_h": "198.51.100.55",
                "id.resp_p": 443,
                "proto": "tcp",
                "uid": "C-exact",
            },
            source_instance="ZEEK",
        ),
        row(
            "http",
            "zeek_http",
            start + timedelta(seconds=2, milliseconds=300),
            {
                "id.orig_h": "10.5.5.5",
                "id.orig_p": 53000,
                "id.resp_h": "198.51.100.55",
                "id.resp_p": 443,
                "uid": "C-exact",
                "resp_fuids": ["F-payload"],
                "uri": "/payload",
            },
            source_instance="ZEEK",
        ),
        row(
            "file",
            "zeek_files",
            start + timedelta(seconds=2, milliseconds=400),
            {"conn_uids": ["C-exact"], "fuid": "F-payload", "filename": "payload.exe"},
            source_instance="ZEEK",
        ),
        row(
            "pe",
            "zeek_pe",
            start + timedelta(seconds=2, milliseconds=500),
            {"id": "F-payload", "machine": "AMD64"},
            source_instance="ZEEK",
        ),
    ]

    output, _findings = detector.detect_record_graph(case_id="case", rows=rows)
    selected = {item["physical_record_id"] for item in output["predictions"]}

    assert {"process", "flow", "conn", "http", "file", "pe"}.issubset(selected)


def test_dns_added_after_connection_reopens_uid_closure() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        row(
            "external",
            "zeek_conn",
            start + timedelta(seconds=10),
            {
                "id.orig_h": "10.0.0.5",
                "id.orig_p": 51000,
                "id.resp_h": "203.0.113.8",
                "id.resp_p": 443,
                "proto": "tcp",
                "uid": "C-external",
            },
            source_instance="ZEEK",
        ),
        row(
            "dns",
            "zeek_dns",
            start + timedelta(seconds=5),
            {
                "id.orig_h": "10.0.0.5",
                "id.orig_p": 53000,
                "id.resp_h": "10.0.0.53",
                "id.resp_p": 53,
                "proto": "udp",
                "uid": "C-dns",
                "query": "payload.example",
                "answers": ["203.0.113.8"],
            },
            source_instance="ZEEK",
        ),
        row(
            "dns-conn",
            "zeek_conn",
            start + timedelta(seconds=5, milliseconds=100),
            {
                "id.orig_h": "10.0.0.5",
                "id.orig_p": 53000,
                "id.resp_h": "10.0.0.53",
                "id.resp_p": 53,
                "proto": "udp",
                "uid": "C-dns",
            },
            source_instance="ZEEK",
        ),
    ]
    records = detector.normalize_records(rows)
    graph = detector.BoundedGraph(records)
    graph.add(records[0], "test external anchor", 0.99, "test", "test")

    graph.expand_network()

    assert {"external", "dns", "dns-conn"}.issubset(graph.selected)


def test_dns_reverse_edge_does_not_expand_internal_system_connections() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        row(
            "selected-dns-transport",
            "zeek_conn",
            start + timedelta(seconds=10),
            {
                "id.orig_h": "10.0.0.5",
                "id.orig_p": 53000,
                "id.resp_h": "10.0.0.53",
                "id.resp_p": 53,
                "proto": "udp",
                "uid": "C-selected",
            },
            source_instance="ZEEK",
        ),
        row(
            "unrelated-internal-answer",
            "zeek_dns",
            start + timedelta(seconds=5),
            {
                "id.orig_h": "10.0.0.5",
                "id.orig_p": 54000,
                "id.resp_h": "10.0.0.53",
                "id.resp_p": 53,
                "proto": "udp",
                "uid": "C-unrelated",
                "query": "dc.example.test",
                "answers": ["10.0.0.53"],
            },
            source_instance="ZEEK",
        ),
    ]
    records = detector.normalize_records(rows)
    graph = detector.BoundedGraph(records)
    graph.add(records[0], "test internal anchor", 0.99, "test", "test")

    graph.expand_network()

    assert "unrelated-internal-answer" not in graph.selected


def test_selected_proxy_request_bridges_internal_and_origin_network_records() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        row(
            "proxy",
            "proxy_access",
            start,
            {
                "client_ip": "10.61.30.20",
                "method": "CONNECT",
                "target": "ns2.example.test:443",
                "timestamp": "01/Jan/2026:00:00:00 +0000",
            },
            source_instance="PROXY-01.example.test",
        ),
        row(
            "internal-http",
            "zeek_http",
            start + timedelta(milliseconds=200),
            {
                "id.orig_h": "10.61.30.20",
                "id.orig_p": 62000,
                "id.resp_h": "10.61.20.40",
                "id.resp_p": 8080,
                "uid": "C-internal",
                "host": "ns2.example.test",
                "method": "CONNECT",
                "uri": "ns2.example.test:443",
            },
            source_instance="ZEEK",
        ),
        row(
            "internal-conn",
            "zeek_conn",
            start + timedelta(milliseconds=100),
            {
                "id.orig_h": "10.61.30.20",
                "id.orig_p": 62000,
                "id.resp_h": "10.61.20.40",
                "id.resp_p": 8080,
                "proto": "tcp",
                "uid": "C-internal",
            },
            source_instance="ZEEK",
        ),
        row(
            "internal-flow",
            "ecar",
            start + timedelta(milliseconds=300),
            {
                "hostname": "HOST-A",
                "object": "FLOW",
                "action": "CONNECT",
                "properties": {
                    "src_ip": "10.61.30.20",
                    "src_port": 62000,
                    "dst_ip": "10.61.20.40",
                    "dst_port": 8080,
                    "protocol": "tcp",
                },
            },
        ),
        row(
            "proxy-dns",
            "zeek_dns",
            start + timedelta(seconds=5),
            {
                "id.orig_h": "10.61.20.40",
                "id.orig_p": 53000,
                "id.resp_h": "10.61.20.10",
                "id.resp_p": 53,
                "proto": "udp",
                "uid": "C-dns",
                "query": "ns2.example.test",
                "answers": ["198.51.100.41"],
            },
            source_instance="ZEEK",
        ),
        row(
            "proxy-dns-conn",
            "zeek_conn",
            start + timedelta(seconds=5, milliseconds=100),
            {
                "id.orig_h": "10.61.20.40",
                "id.orig_p": 53000,
                "id.resp_h": "10.61.20.10",
                "id.resp_p": 53,
                "proto": "udp",
                "uid": "C-dns",
            },
            source_instance="ZEEK",
        ),
        row(
            "origin-conn",
            "zeek_conn",
            start + timedelta(seconds=6),
            {
                "id.orig_h": "10.61.20.40",
                "id.orig_p": 54000,
                "id.resp_h": "198.51.100.41",
                "id.resp_p": 443,
                "proto": "tcp",
                "uid": "C-origin",
            },
            source_instance="ZEEK",
        ),
        row(
            "origin-ssl",
            "zeek_ssl",
            start + timedelta(seconds=6, milliseconds=100),
            {
                "id.orig_h": "10.61.20.40",
                "id.orig_p": 54000,
                "id.resp_h": "198.51.100.41",
                "id.resp_p": 443,
                "uid": "C-origin",
                "server_name": "ns2.example.test",
            },
            source_instance="ZEEK",
        ),
    ]
    records = detector.normalize_records(rows)
    graph = detector.BoundedGraph(records)
    graph.add(records[0], "test proxy anchor", 0.99, "test", "test")

    graph.expand_network()

    assert {
        "proxy",
        "internal-http",
        "internal-conn",
        "internal-flow",
        "proxy-dns",
        "proxy-dns-conn",
        "origin-conn",
        "origin-ssl",
    }.issubset(graph.selected)


def test_exact_termination_cluster_accepts_bounded_emitter_skew() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        ecar_process(
            "create",
            start,
            action="CREATE",
            object_id="exact-instance",
            pid=8120,
            image="C:\\Temp\\caddywiper.exe",
            command="C:\\Temp\\caddywiper.exe",
        ),
        ecar_process(
            "terminate-first",
            start + timedelta(seconds=20),
            action="TERMINATE",
            object_id="exact-instance",
            pid=8120,
            image="C:\\Temp\\caddywiper.exe",
        ),
        ecar_process(
            "terminate-late-emitter",
            start + timedelta(seconds=23, milliseconds=600),
            action="TERMINATE",
            object_id="exact-instance",
            pid=8120,
            image="C:\\Temp\\caddywiper.exe",
        ),
        ecar_process(
            "terminate-outside-skew",
            start + timedelta(seconds=27),
            action="TERMINATE",
            object_id="exact-instance",
            pid=8120,
            image="C:\\Temp\\caddywiper.exe",
        ),
    ]

    output, _findings = detector.detect_record_graph(case_id="case", rows=rows)
    selected = {item["physical_record_id"]: item for item in output["predictions"]}

    assert selected["terminate-late-emitter"]["association_strength"] == (
        "process_create_to_exact_terminate"
    )
    assert "terminate-outside-skew" not in selected


def test_schtasks_create_and_terminal_sequences_are_discovered() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        ecar_process(
            "schtasks",
            start,
            action="CREATE",
            object_id="schtasks-proc",
            pid=7000,
            image="C:\\Windows\\System32\\schtasks.exe",
            command=("schtasks.exe /Create /SC ONLOGON /TN Update /TR C:\\ProgramData\\update.exe"),
        ),
        ecar_process(
            "whoami",
            start + timedelta(seconds=30),
            action="CREATE",
            object_id="whoami-proc",
            pid=7001,
            image="C:\\Windows\\System32\\whoami.exe",
            command="whoami.exe /all",
        ),
        ecar_process(
            "net-group",
            start + timedelta(seconds=60),
            action="CREATE",
            object_id="net-proc",
            pid=7002,
            image="C:\\Windows\\System32\\net.exe",
            command='net.exe group "Domain Admins" /domain',
        ),
        ecar_process(
            "wmic",
            start + timedelta(seconds=90),
            action="CREATE",
            object_id="wmic-proc",
            pid=7003,
            image="C:\\Windows\\System32\\wbem\\WMIC.exe",
            command="wmic.exe computersystem get domain",
        ),
        ecar_process(
            "benign-hidden-archive",
            start + timedelta(seconds=120),
            action="CREATE",
            object_id="archive-proc",
            pid=7004,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command=(
                'powershell.exe -WindowStyle Hidden -Command "Compress-Archive '
                '-Path C:\\Temp\\Logs\\*.log -DestinationPath C:\\Backups\\audit.zip"'
            ),
        ),
    ]

    anchors = detector.discover_terminal(detector.normalize_records(rows))
    by_id = {record.physical_id: edge for record, _reason, _confidence, edge in anchors}

    assert by_id["schtasks"] == "terminal_anchor"
    assert by_id["whoami"] == "terminal_sequence_anchor"
    assert by_id["net-group"] == "terminal_sequence_anchor"
    assert by_id["wmic"] == "terminal_sequence_anchor"
    assert "benign-hidden-archive" not in by_id


def test_v13_security_event_mapping_keeps_native_roles_separate() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        row(
            "security-4688",
            "windows_event_security",
            start,
            {
                "computer": "HOST-A",
                "event_id": 4688,
                "event_data": {
                    "NewProcessId": "0x200",
                    "ProcessId": "0x100",
                    "NewProcessName": "C:\\Windows\\System32\\rundll32.exe",
                    "ParentProcessName": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                    "CommandLine": ("rundll32.exe C:\\Users\\alice\\AppData\\Local\\Temp\\x.dll,X"),
                },
            },
        ),
        row(
            "security-4698",
            "windows_event_security",
            start + timedelta(seconds=1),
            {
                "computer": "HOST-A",
                "event_id": 4698,
                "event_data": {
                    "TaskName": "\\Updater",
                    "TaskContent": (
                        "<Task><Actions><Exec><Command>"
                        "C:\\Users\\alice\\AppData\\Local\\x.exe"
                        "</Command></Exec></Actions></Task>"
                    ),
                },
            },
        ),
        row(
            "security-5156",
            "windows_event_security",
            start + timedelta(seconds=2),
            {
                "computer": "HOST-A",
                "event_id": 5156,
                "event_data": {
                    "ProcessID": "0x200",
                    "Application": "C:\\Users\\alice\\AppData\\Local\\x.exe",
                    "Direction": "%%14593",
                    "SourceAddress": "10.0.0.5",
                    "SourcePort": 55000,
                    "DestAddress": "198.51.100.8",
                    "DestPort": 443,
                    "Protocol": 6,
                },
            },
        ),
    ]

    by_id = {record.physical_id: record for record in detector.normalize_records(rows)}

    assert by_id["security-4688"].pid == "512"
    assert by_id["security-4688"].parent_pid == "256"
    assert by_id["security-4688"].parent_image.endswith("WINWORD.EXE")
    assert by_id["security-4698"].task_name == "\\Updater"
    assert "AppData\\Local\\x.exe" in by_id["security-4698"].task_content
    assert by_id["security-5156"].pid == "512"
    assert by_id["security-5156"].network == ("10.0.0.5", 55000, "198.51.100.8", 443, "6")


def test_v13_office_lolbin_writable_and_double_extension_rules() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        ecar_process(
            "office-lolbin",
            start,
            action="CREATE",
            object_id="office-lolbin-proc",
            pid=8000,
            image="C:\\Windows\\System32\\rundll32.exe",
            command="rundll32.exe C:\\Users\\alice\\AppData\\Local\\Temp\\x.dll,X",
        ),
        ecar_process(
            "double-extension",
            start + timedelta(seconds=1),
            action="CREATE",
            object_id="double-proc",
            pid=8001,
            image="C:\\Users\\alice\\Downloads\\resume.pdf.exe",
            command="C:\\Users\\alice\\Downloads\\resume.pdf.exe",
        ),
        ecar_process(
            "system-lookalike",
            start + timedelta(seconds=2),
            action="CREATE",
            object_id="lookalike-proc",
            pid=8002,
            image="C:\\Users\\alice\\AppData\\Local\\sihost.exe",
            command="C:\\Users\\alice\\AppData\\Local\\sihost.exe",
        ),
        ecar_process(
            "download-lure",
            start + timedelta(seconds=3),
            action="CREATE",
            object_id="download-lure-proc",
            pid=8003,
            image="C:\\Users\\alice\\Downloads\\Read-Me New VPN Configuration Settings.exe",
            command="C:\\Users\\alice\\Downloads\\Read-Me New VPN Configuration Settings.exe",
        ),
        ecar_process(
            "ordinary-installer",
            start + timedelta(seconds=4),
            action="CREATE",
            object_id="installer-proc",
            pid=8004,
            image="C:\\Users\\alice\\Downloads\\VendorSetup.exe",
            command="VendorSetup.exe --silent",
        ),
    ]
    rows[0]["correlation_features"]["properties"]["parent_image_path"] = (
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
    )
    rows[1]["correlation_features"]["properties"]["parent_image_path"] = "C:\\Windows\\explorer.exe"
    rows[2]["correlation_features"]["properties"]["parent_image_path"] = (
        "C:\\Users\\alice\\Downloads\\loader.exe"
    )
    rows[3]["correlation_features"]["properties"]["parent_image_path"] = "C:\\Windows\\explorer.exe"
    rows[4]["correlation_features"]["properties"]["parent_image_path"] = "C:\\Windows\\explorer.exe"

    anchors = detector.discover_process_anomaly(detector.normalize_records(rows))
    by_id = {record.physical_id: edge for record, _reason, _confidence, edge in anchors}

    assert by_id == {
        "office-lolbin": "office_lolbin_process_anchor",
        "double-extension": "double_extension_process_anchor",
        "system-lookalike": "writable_system_lookalike_anchor",
        "download-lure": "download_lure_process_anchor",
    }


def test_v13_security_4698_and_process_owned_one_shot_flow_are_discovered() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    process = ecar_process(
        "suspicious-process",
        start,
        action="CREATE",
        object_id="suspicious-instance",
        pid=8100,
        image="C:\\Users\\alice\\Downloads\\invoice.pdf.exe",
        command="C:\\Users\\alice\\Downloads\\invoice.pdf.exe",
    )
    process["correlation_features"]["properties"]["parent_image_path"] = "C:\\Windows\\explorer.exe"
    rows = [
        process,
        row(
            "suspicious-flow",
            "ecar",
            start + timedelta(seconds=5),
            {
                "action": "OPEN",
                "actorID": "suspicious-instance",
                "hostname": "HOST-A",
                "object": "FLOW",
                "objectID": "flow-1",
                "pid": 8100,
                "properties": {
                    "src_ip": "10.0.0.5",
                    "src_port": 55000,
                    "dst_ip": "10.10.99.99",
                    "dst_port": 443,
                    "protocol": "tcp",
                },
            },
        ),
        row(
            "suspicious-task",
            "windows_event_security",
            start + timedelta(seconds=10),
            {
                "computer": "HOST-A",
                "event_id": 4698,
                "event_data": {
                    "TaskName": "\\Updater",
                    "TaskContent": (
                        "<Task><Actions><Exec><Command>"
                        "C:\\Users\\alice\\AppData\\Roaming\\update.exe"
                        "</Command></Exec></Actions></Task>"
                    ),
                },
            },
        ),
        row(
            "benign-task",
            "windows_event_security",
            start + timedelta(seconds=11),
            {
                "computer": "HOST-A",
                "event_id": 4698,
                "event_data": {
                    "TaskName": "\\VendorMaintenance",
                    "TaskContent": (
                        "<Task><Actions><Exec><Command>"
                        "C:\\Program Files\\Vendor\\maintenance.exe"
                        "</Command></Exec></Actions></Task>"
                    ),
                },
            },
        ),
    ]
    records = detector.normalize_records(rows)

    task_ids = {record.physical_id for record, *_rest in detector.discover_scheduled_task(records)}
    network_ids = {
        record.physical_id for record, *_rest in detector.discover_one_shot_network(records)
    }

    assert task_ids == {"suspicious-task"}
    assert "suspicious-flow" in network_ids
    assert "benign-task" not in task_ids


def test_v14_storyline_tactic_predictions_are_optional_and_evidence_scoped() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    process = ecar_process(
        "double-extension",
        start,
        action="CREATE",
        object_id="suspicious-instance",
        pid=8100,
        image="C:\\Users\\alice\\Downloads\\invoice.pdf.exe",
        command="C:\\Users\\alice\\Downloads\\invoice.pdf.exe",
    )
    process["correlation_features"]["properties"]["parent_image_path"] = "C:\\Windows\\explorer.exe"
    rows = [
        process,
        row(
            "suspicious-task",
            "windows_event_security",
            start + timedelta(seconds=10),
            {
                "computer": "HOST-A",
                "event_id": 4698,
                "event_data": {
                    "TaskName": "\\Updater",
                    "TaskContent": (
                        "<Task><Actions><Exec><Command>"
                        "C:\\Users\\alice\\AppData\\Roaming\\update.exe"
                        "</Command></Exec></Actions></Task>"
                    ),
                },
            },
        ),
    ]

    default_output, _ = detector.detect_record_graph(case_id="case", rows=rows)
    tactic_output, _ = detector.detect_record_graph(
        case_id="case",
        rows=rows,
        predict_storyline_tactics=True,
    )

    assert "storyline_tactic_predictions" not in default_output
    assert "storyline_tactic_prediction_enabled" not in default_output["diagnostics"]
    claims = {
        claim["evidence_physical_record_id"]: claim
        for claim in tactic_output["storyline_tactic_predictions"]
    }
    assert claims["double-extension"]["tactic"] == "Execution"
    assert claims["suspicious-task"]["tactic"] == "Persistence"
    assert set(claims).issubset(
        {item["physical_record_id"] for item in tactic_output["predictions"]}
    )
    assert tactic_output["diagnostics"]["storyline_tactic_prediction_counts"] == {
        "Execution": 1,
        "Persistence": 1,
    }


def test_v15_active_content_lures_require_legacy_handler_or_corroborated_drop() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    flash = ecar_process(
        "flash",
        start,
        action="CREATE",
        object_id="flash-instance",
        pid=8200,
        image="C:\\Windows\\SysWOW64\\Macromed\\Flash\\FlashPlayerPlugin_20_0_0_267.exe",
        command=(
            '"C:\\Windows\\SysWOW64\\Macromed\\Flash\\FlashPlayerPlugin_20_0_0_267.exe" '
            '"C:\\Users\\alice\\Downloads\\briefing.swf"'
        ),
    )
    flash["correlation_features"]["properties"]["parent_image_path"] = "C:\\Windows\\explorer.exe"
    rtf = ecar_process(
        "rtf",
        start + timedelta(minutes=1),
        action="CREATE",
        object_id="word-instance",
        pid=8201,
        image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        command=(
            '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" '
            '"C:\\Users\\alice\\Downloads\\agenda.rtf"'
        ),
    )
    rtf["correlation_features"]["properties"]["parent_image_path"] = "C:\\Windows\\explorer.exe"
    benign_rtf = ecar_process(
        "benign-rtf",
        start + timedelta(minutes=2),
        action="CREATE",
        object_id="benign-word-instance",
        pid=8202,
        image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        command=(
            '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" '
            '"C:\\Users\\alice\\Downloads\\ordinary.rtf"'
        ),
    )
    benign_rtf["correlation_features"]["properties"]["parent_image_path"] = (
        "C:\\Windows\\explorer.exe"
    )
    rows = [
        flash,
        ecar_file(
            "flash-drop",
            start + timedelta(seconds=20),
            path="C:\\Users\\alice\\AppData\\Local\\Temp\\update.exe",
            actor_id="flash-instance",
            pid=8200,
            image=flash["correlation_features"]["properties"]["image_path"],
        ),
        ecar_process(
            "flash-stop",
            start + timedelta(minutes=5),
            action="TERMINATE",
            object_id="flash-instance",
            pid=8200,
            image=flash["correlation_features"]["properties"]["image_path"],
        ),
        rtf,
        ecar_file(
            "rtf-drop",
            start + timedelta(minutes=1, seconds=20),
            path="C:\\Users\\alice\\AppData\\Local\\Temp\\payload.dll",
            actor_id="word-instance",
            pid=8201,
            image=rtf["correlation_features"]["properties"]["image_path"],
        ),
        benign_rtf,
    ]

    records = detector.normalize_records(rows)
    anchors = detector.discover_process_anomaly(records)
    by_id = {record.physical_id: edge for record, _reason, _confidence, edge in anchors}
    output, _findings = detector.detect_record_graph(case_id="case", rows=rows)
    selected = {item["physical_record_id"] for item in output["predictions"]}

    assert by_id["flash"] == "active_content_swf_lure_anchor"
    assert by_id["rtf"] == "active_content_rtf_exploit_anchor"
    assert "benign-rtf" not in by_id
    assert {"flash", "flash-drop", "flash-stop", "rtf", "rtf-drop"}.issubset(selected)
    assert "benign-rtf" not in selected


def test_v15_tactic_context_uses_process_and_transaction_semantics() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    plugin = ecar_process(
        "plugin",
        start,
        action="CREATE",
        object_id="plugin-instance",
        pid=8300,
        image="C:\\ProgramData\\Vendor\\plugin.exe",
        command="C:\\ProgramData\\Vendor\\plugin.exe",
    )
    uploader = ecar_process(
        "uploader",
        start + timedelta(minutes=1),
        action="CREATE",
        object_id="uploader-instance",
        pid=8301,
        image="C:\\Windows\\System32\\rundll32.exe",
        command="rundll32.exe C:\\ProgramData\\Vendor\\upload.dll,Run",
    )
    rows = [
        plugin,
        ecar_file(
            "plugin-image-emission",
            start + timedelta(milliseconds=100),
            path="C:\\ProgramData\\Vendor\\plugin.exe",
            actor_id="plugin-instance",
            pid=8300,
            image="C:\\ProgramData\\Vendor\\plugin.exe",
        ),
        ecar_file(
            "stage",
            start + timedelta(seconds=10),
            path="C:\\ProgramData\\stage.bin",
            actor_id="plugin-instance",
            pid=8300,
            image="C:\\ProgramData\\Vendor\\plugin.exe",
        ),
        ecar_file(
            "credential-read",
            start + timedelta(seconds=20),
            path="C:\\Users\\alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            actor_id="plugin-instance",
            pid=8300,
            image="C:\\ProgramData\\Vendor\\plugin.exe",
            action="READ",
        ),
        uploader,
        ecar_file(
            "staged-read",
            start + timedelta(minutes=1, seconds=10),
            path="C:\\ProgramData\\stage.bin",
            actor_id="uploader-instance",
            pid=8301,
            image="C:\\Windows\\System32\\rundll32.exe",
            action="READ",
        ),
        row(
            "upload-flow",
            "ecar",
            start + timedelta(minutes=1, seconds=11),
            {
                "action": "CONNECT",
                "actorID": "uploader-instance",
                "hostname": "HOST-A",
                "object": "FLOW",
                "pid": 8301,
                "properties": {
                    "image_path": "C:\\Windows\\System32\\rundll32.exe",
                    "src_ip": "10.0.0.5",
                    "src_port": 55000,
                    "dst_ip": "198.51.100.25",
                    "dst_port": 443,
                    "protocol": "tcp",
                },
            },
        ),
        row(
            "probe-flow",
            "ecar",
            start + timedelta(minutes=2),
            {
                "action": "CONNECT",
                "actorID": "uploader-instance",
                "hostname": "HOST-A",
                "object": "FLOW",
                "pid": 8301,
                "properties": {
                    "image_path": "C:\\Windows\\System32\\rundll32.exe",
                    "src_ip": "10.0.0.5",
                    "src_port": 55001,
                    "dst_ip": "198.51.100.26",
                    "dst_port": 443,
                    "protocol": "tcp",
                },
            },
        ),
        row(
            "probe-ssl",
            "zeek_ssl",
            start + timedelta(minutes=2, milliseconds=200),
            {
                "id.orig_h": "10.0.0.5",
                "id.orig_p": 55001,
                "id.resp_h": "198.51.100.26",
                "id.resp_p": 443,
                "server_name": "en.wikipedia.org",
                "uid": "C-probe",
            },
            source_instance="ZEEK",
        ),
    ]
    records = detector.normalize_records(rows)
    selections = {
        record.physical_id: detector.Selection("test selection", 0.99, "test", "test")
        for record in records
    }
    context = detector.TacticEvidenceContext(records, selections)
    by_id = {record.physical_id: record for record in records}

    assert (
        detector.infer_storyline_tactic(by_id["plugin"], selections["plugin"], context)[0]
        == "Credential Access"
    )
    assert (
        detector.infer_storyline_tactic(
            by_id["plugin-image-emission"], selections["plugin-image-emission"], context
        )
        is None
    )
    assert (
        detector.infer_storyline_tactic(by_id["stage"], selections["stage"], context)[0]
        == "Collection"
    )
    assert (
        detector.infer_storyline_tactic(
            by_id["credential-read"], selections["credential-read"], context
        )[0]
        == "Credential Access"
    )
    assert (
        detector.infer_storyline_tactic(by_id["staged-read"], selections["staged-read"], context)[0]
        == "Exfiltration"
    )
    assert (
        detector.infer_storyline_tactic(by_id["upload-flow"], selections["upload-flow"], context)[0]
        == "Exfiltration"
    )
    assert (
        detector.infer_storyline_tactic(by_id["probe-flow"], selections["probe-flow"], context)[0]
        == "Discovery"
    )


def test_v15_exact_materialization_expands_to_module_and_preserves_event_tactic() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        ecar_file(
            "materialized-module",
            start,
            path="C:\\ProgramData\\Vendor\\payload.dll",
            actor_id="core-instance",
            pid=8400,
            image="C:\\Windows\\System32\\rundll32.exe",
        ),
        row(
            "loaded-module",
            "ecar",
            start + timedelta(seconds=10),
            {
                "action": "LOAD",
                "actorID": "core-instance",
                "hostname": "HOST-A",
                "object": "MODULE",
                "objectID": "module-id",
                "pid": 8400,
                "properties": {
                    "image_path": "C:\\Windows\\System32\\rundll32.exe",
                    "file_path": "C:\\ProgramData\\Vendor\\payload.dll",
                },
            },
        ),
    ]
    records = detector.normalize_records(rows)
    graph = detector.BoundedGraph(records)
    graph.add(records[0], "selected file", 0.99, "test", "test")

    derived = graph.expand_artifacts()
    module = next(record for record in records if record.physical_id == "loaded-module")
    selection = graph.selected["loaded-module"]

    assert {record.physical_id for record in derived} == {"loaded-module"}
    assert selection.edge == "file_path_to_module_load"
    assert detector.infer_storyline_tactic(module, selection)[0] == "Execution"
    assert (
        detector.infer_storyline_tactic(
            records[0],
            detector.Selection(
                "same bounded process instance",
                0.985,
                "host_process_guid",
                "process_graph",
            ),
        )
        is None
    )


def test_v15_tactic_context_uses_exact_archive_proxy_and_registry_evidence() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        ecar_file(
            "archive",
            start,
            path="C:\\Users\\alice\\AppData\\Local\\payload.zip",
            actor_id="dropper-instance",
            pid=8500,
            image="C:\\Users\\alice\\Downloads\\dropper.exe",
        ),
        ecar_file(
            "extracted",
            start + timedelta(seconds=30),
            path="C:\\Users\\alice\\AppData\\Local\\sihost.exe",
            actor_id="dropper-instance",
            pid=8500,
            image="C:\\Users\\alice\\Downloads\\dropper.exe",
        ),
        ecar_file(
            "proxy-payload",
            start + timedelta(minutes=1),
            path="C:\\ProgramData\\Vendor\\update.bin",
            actor_id="dropper-instance",
            pid=8500,
            image="C:\\Users\\alice\\Downloads\\dropper.exe",
        ),
        ecar_process(
            "proxy-exec",
            start + timedelta(minutes=2),
            action="CREATE",
            object_id="proxy-instance",
            pid=8501,
            image="C:\\Windows\\System32\\rundll32.exe",
            command="rundll32.exe C:\\ProgramData\\Vendor\\update.bin,Start",
        ),
        row(
            "loaded-proxy-payload",
            "ecar",
            start + timedelta(minutes=2, seconds=1),
            {
                "action": "LOAD",
                "actorID": "proxy-instance",
                "hostname": "HOST-A",
                "object": "MODULE",
                "objectID": "proxy-module",
                "pid": 8501,
                "properties": {
                    "image_path": "C:\\Windows\\System32\\rundll32.exe",
                    "file_path": "C:\\ProgramData\\Vendor\\update.bin",
                },
            },
        ),
        row(
            "run-key",
            "windows_event_sysmon",
            start + timedelta(minutes=3),
            {
                "computer": "HOST-A",
                "event_id": 13,
                "event_data": {
                    "ProcessGuid": "{proxy-instance}",
                    "ProcessId": 8501,
                    "Image": "C:\\Windows\\System32\\rundll32.exe",
                    "TargetObject": (
                        "HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
                    ),
                    "Details": "rundll32.exe C:\\ProgramData\\Vendor\\update.bin,Start",
                },
            },
        ),
        row(
            "routine-module",
            "windows_event_sysmon",
            start + timedelta(minutes=3, seconds=1),
            {
                "computer": "HOST-A",
                "event_id": 7,
                "event_data": {
                    "ProcessGuid": "{proxy-instance}",
                    "ProcessId": 8501,
                    "Image": "C:\\Windows\\System32\\rundll32.exe",
                    "ImageLoaded": "C:\\Windows\\System32\\ntdll.dll",
                    "Signed": "true",
                    "SignatureStatus": "Valid",
                },
            },
        ),
    ]
    records = detector.normalize_records(rows)
    selections = {
        record.physical_id: detector.Selection(
            "same bounded process instance",
            0.985,
            "host_process_guid",
            "process_graph",
        )
        for record in records
    }
    context = detector.TacticEvidenceContext(records, selections)
    by_id = {record.physical_id: record for record in records}

    assert (
        detector.infer_storyline_tactic(by_id["extracted"], selections["extracted"], context)[0]
        == "Defense Evasion"
    )
    assert (
        detector.infer_storyline_tactic(
            by_id["proxy-payload"], selections["proxy-payload"], context
        )[0]
        == "Defense Evasion"
    )
    assert (
        detector.infer_storyline_tactic(by_id["run-key"], selections["run-key"], context)[0]
        == "Persistence"
    )
    assert (
        detector.infer_storyline_tactic(
            by_id["loaded-proxy-payload"], selections["loaded-proxy-payload"], context
        )[0]
        == "Execution"
    )
    assert (
        detector.infer_storyline_tactic(
            by_id["routine-module"], selections["routine-module"], context
        )
        is None
    )


def test_v12_allowlist_exposes_module_and_auth_fields_but_not_private_labels() -> None:
    public = detector.allowlisted_features(
        {
            "source_format": "windows_event_sysmon",
            "correlation_features": {
                "event_data": {
                    "Image": "C:\\Temp\\host.exe",
                    "ImageLoaded": "C:\\Temp\\payload.dll",
                    "Signed": "false",
                    "SignatureStatus": "Unavailable",
                    "OriginalFileName": "host.exe",
                    "TargetObject": "HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                    "Details": "rundll32.exe C:\\ProgramData\\update.bin,Start",
                    "storyline_id": "must-not-be-seen",
                },
                "ground_truth": "must-not-be-seen",
            },
        }
    )

    assert public == {
        "event_data": {
            "Image": "C:\\Temp\\host.exe",
            "ImageLoaded": "C:\\Temp\\payload.dll",
            "OriginalFileName": "host.exe",
            "SignatureStatus": "Unavailable",
            "Signed": "false",
            "TargetObject": "HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            "Details": "rundll32.exe C:\\ProgramData\\update.bin,Start",
        }
    }


def test_v12_high_confidence_endpoint_and_one_shot_engines_reject_weak_variants() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        ecar_process(
            "db-export",
            start,
            action="CREATE",
            object_id="db-export-proc",
            pid=7000,
            image="C:\\ProgramData\\sqluldr.exe",
            command=(
                "sqluldr.exe rows=50000000 text=csv "
                'query="select * from SHIPMENT" file=C:\\ProgramData\\staging\\out.csv'
            ),
        ),
        ecar_process(
            "password-archive",
            start + timedelta(seconds=1),
            action="CREATE",
            object_id="password-proc",
            pid=7001,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command=(
                "powershell.exe -Paths C:\\Users\\alice\\PasswordVault,"
                "C:\\Users\\alice\\KeePass -Archive C:\\ProgramData\\vault.zip"
            ),
        ),
        ecar_process(
            "removable-batch",
            start + timedelta(seconds=2),
            action="CREATE",
            object_id="batch-proc",
            pid=7002,
            image="C:\\Windows\\System32\\cmd.exe",
            command='cmd.exe /c "D:\\pack\\n.bat"',
        ),
        ecar_process(
            "weak-delete",
            start + timedelta(seconds=3),
            action="CREATE",
            object_id="delete-proc",
            pid=7003,
            image="C:\\Windows\\System32\\cmd.exe",
            command="cmd.exe /c del C:\\Temp\\report.csv",
        ),
        row(
            "webshell-post",
            "web_access",
            start + timedelta(seconds=4),
            {"method": "POST", "target": "/manager/bluebeam.aspx"},
        ),
        row(
            "ordinary-post",
            "web_access",
            start + timedelta(seconds=5),
            {"method": "POST", "target": "/api/v1/orders"},
        ),
    ]
    records = detector.normalize_records(rows)
    endpoint_ids = {
        record.physical_id
        for record, _reason, _confidence, _edge in detector.discover_endpoint_behavior(records)
    }
    network_ids = {
        record.physical_id
        for record, _reason, _confidence, _edge in detector.discover_one_shot_network(records)
    }

    assert endpoint_ids == {"db-export", "password-archive", "removable-batch"}
    assert network_ids == {"webshell-post"}


def test_v12_process_anomaly_requires_all_composite_signals() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        ecar_process(
            "anomalous",
            start,
            action="CREATE",
            object_id="anomalous-proc",
            pid=7100,
            image="C:\\Windows\\Temp\\Systemsetting.exe",
            command="C:\\Windows\\Temp\\Systemsetting.exe",
            actor_id="services-proc",
        ),
        ecar_process(
            "installer-with-args",
            start + timedelta(seconds=1),
            action="CREATE",
            object_id="installer-proc",
            pid=7101,
            image="C:\\Users\\alice\\Downloads\\VendorSetup.exe",
            command="VendorSetup.exe --silent",
            actor_id="explorer-proc",
        ),
        ecar_process(
            "system-service",
            start + timedelta(seconds=2),
            action="CREATE",
            object_id="system-service-proc",
            pid=7102,
            image="C:\\Windows\\System32\\svchost.exe",
            command="svchost.exe -k netsvcs",
            actor_id="services-proc",
        ),
    ]
    rows[0]["correlation_features"]["properties"]["parent_image_path"] = (
        "C:\\Windows\\System32\\services.exe"
    )
    rows[1]["correlation_features"]["properties"]["parent_image_path"] = "C:\\Windows\\explorer.exe"
    rows[2]["correlation_features"]["properties"]["parent_image_path"] = (
        "C:\\Windows\\System32\\services.exe"
    )

    anchors = detector.discover_process_anomaly(detector.normalize_records(rows))

    assert {record.physical_id for record, *_rest in anchors} == {"anomalous"}


def test_v12_artifact_graph_requires_exact_host_path_and_forward_time() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        ecar_file(
            "materialized",
            start,
            path="C:\\Program Files\\Vendor\\agent.exe",
            actor_id="downloader-proc",
            pid=7200,
            image="C:\\Windows\\System32\\curl.exe",
        ),
        ecar_process(
            "executed",
            start + timedelta(minutes=10),
            action="CREATE",
            object_id="agent-proc",
            pid=7201,
            image="C:\\Program Files\\Vendor\\agent.exe",
            command="C:\\Program Files\\Vendor\\agent.exe --service",
        ),
        ecar_process(
            "other-host",
            start + timedelta(minutes=10),
            action="CREATE",
            object_id="other-agent-proc",
            pid=7202,
            image="C:\\Program Files\\Vendor\\agent.exe",
            command="C:\\Program Files\\Vendor\\agent.exe --service",
        ),
    ]
    rows[2]["source_instance"] = "HOST-B.example.test"
    rows[2]["relative_path"] = "HOST-B.example.test/ecar.json"
    rows[2]["correlation_features"]["hostname"] = "HOST-B"
    records = detector.normalize_records(rows)
    graph = detector.BoundedGraph(records)
    graph.add(records[0], "test selected materialization", 0.99, "test", "test")

    derived = graph.expand_artifacts()

    assert {record.physical_id for record in derived} == {"executed"}
    assert "other-host" not in graph.selected


def test_v12_module_engine_requires_side_load_or_invalid_signature() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        row(
            "suspicious-module",
            "windows_event_sysmon",
            start,
            {
                "computer": "HOST-A",
                "event_id": 7,
                "event_data": {
                    "Image": "C:\\Windows\\Temp\\host.exe",
                    "ImageLoaded": "C:\\Windows\\Temp\\payload.dll",
                    "ProcessGuid": "{bad-proc}",
                    "ProcessId": 7300,
                    "Signed": "false",
                    "SignatureStatus": "Unavailable",
                },
            },
        ),
        row(
            "ordinary-module",
            "windows_event_sysmon",
            start + timedelta(seconds=1),
            {
                "computer": "HOST-A",
                "event_id": 7,
                "event_data": {
                    "Image": "C:\\Windows\\System32\\svchost.exe",
                    "ImageLoaded": "C:\\Windows\\System32\\ntdll.dll",
                    "ProcessGuid": "{good-proc}",
                    "ProcessId": 7301,
                    "Signed": "true",
                    "SignatureStatus": "Valid",
                },
            },
        ),
        row(
            "zoom-module",
            "ecar",
            start + timedelta(seconds=2),
            {
                "action": "LOAD",
                "actorID": "zoom-proc",
                "hostname": "HOST-A",
                "object": "MODULE",
                "objectID": "zoom-module-id",
                "pid": 7302,
                "properties": {
                    "image_path": "C:\\Users\\alice\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe",
                    "file_path": ("C:\\Users\\alice\\AppData\\Roaming\\Zoom\\bin\\zVideoApp.dll"),
                },
            },
        ),
    ]

    anchors = detector.discover_module_behavior(detector.normalize_records(rows))

    assert {record.physical_id for record, *_rest in anchors} == {"suspicious-module"}
    record, reason, confidence, edge = anchors[0]
    tactic = detector.infer_storyline_tactic(
        record,
        detector.Selection(reason, confidence, edge, "module_behavior"),
    )
    assert tactic is not None
    assert tactic[0] == "Execution"


def test_v12_external_rdp_expands_only_exact_login_identity() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        row(
            "rdp-flow",
            "ecar",
            start,
            {
                "action": "CONNECT",
                "hostname": "JUMP-A",
                "object": "FLOW",
                "objectID": "rdp-flow-id",
                "properties": {
                    "src_ip": "198.51.100.25",
                    "src_port": 55000,
                    "dst_ip": "10.0.0.10",
                    "dst_port": 3389,
                    "protocol": "tcp",
                },
            },
            source_instance="JUMP-A.example.test",
        ),
        row(
            "rdp-login",
            "ecar",
            start + timedelta(milliseconds=300),
            {
                "action": "LOGIN",
                "hostname": "JUMP-A",
                "object": "USER_SESSION",
                "objectID": "session-id",
                "principal": "alice",
                "properties": {
                    "logon_id": "0x4242",
                    "src_ip": "198.51.100.25",
                    "src_port": 55000,
                },
            },
            source_instance="JUMP-A.example.test",
        ),
        row(
            "security-logon",
            "windows_event_security",
            start + timedelta(milliseconds=500),
            {
                "computer": "JUMP-A",
                "event_id": 4624,
                "event_data": {
                    "TargetLogonId": "0x4242",
                    "TargetUserName": "alice",
                    "SubjectLogonId": "0x3e7",
                },
            },
            source_instance="JUMP-A.example.test",
        ),
        row(
            "unrelated-system-logon",
            "windows_event_security",
            start + timedelta(milliseconds=600),
            {
                "computer": "JUMP-A",
                "event_id": 4624,
                "event_data": {
                    "TargetLogonId": "0x9999",
                    "TargetUserName": "bob",
                    "SubjectLogonId": "0x3e7",
                },
            },
            source_instance="JUMP-A.example.test",
        ),
    ]

    output, _findings = detector.detect_record_graph(case_id="case", rows=rows)
    selected = {item["physical_record_id"] for item in output["predictions"]}

    assert {"rdp-flow", "rdp-login", "security-logon"}.issubset(selected)
    assert "unrelated-system-logon" not in selected
    assert output["detector_version"] == "1.5"
    assert "auth_anomaly" in output["diagnostics"]["discovery_anchor_counts"]


def test_v12_routine_late_module_does_not_inherit_malicious_process_label() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        ecar_process(
            "malicious-process",
            start,
            action="CREATE",
            object_id="malicious-instance",
            pid=7400,
            image="C:\\Windows\\Temp\\host.exe",
            command="C:\\Windows\\Temp\\host.exe",
            actor_id="services-instance",
        ),
        row(
            "initial-module",
            "ecar",
            start + timedelta(seconds=1),
            {
                "action": "LOAD",
                "actorID": "malicious-instance",
                "hostname": "HOST-A",
                "object": "MODULE",
                "objectID": "initial-module-id",
                "pid": 7400,
                "properties": {
                    "file_path": "C:\\Windows\\System32\\ntdll.dll",
                    "image_path": "C:\\Windows\\Temp\\host.exe",
                },
            },
        ),
        row(
            "late-module",
            "ecar",
            start + timedelta(hours=1),
            {
                "action": "LOAD",
                "actorID": "malicious-instance",
                "hostname": "HOST-A",
                "object": "MODULE",
                "objectID": "late-module-id",
                "pid": 7400,
                "properties": {
                    "file_path": "C:\\Windows\\System32\\rpcrt4.dll",
                    "image_path": "C:\\Windows\\Temp\\host.exe",
                },
            },
        ),
    ]
    rows[0]["correlation_features"]["properties"]["parent_image_path"] = (
        "C:\\Windows\\System32\\services.exe"
    )

    output, _findings = detector.detect_record_graph(case_id="case", rows=rows)
    selected = {item["physical_record_id"] for item in output["predictions"]}

    assert "initial-module" in selected
    assert "late-module" not in selected
