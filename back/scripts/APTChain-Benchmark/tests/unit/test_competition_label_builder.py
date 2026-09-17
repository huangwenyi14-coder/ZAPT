# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Regression tests for competition-label evidence joins."""

import json

from scripts.build_competition_labels import event_matches_ecar_record, scan_json_file


def test_connection_dns_transport_requires_storyline_host() -> None:
    """Coincident DNS flows on another endpoint must not become attack evidence."""
    event = {
        "record_id": "evt-download#0",
        "kind": "connection",
        "time": "2018-09-20T10:17:56Z",
        "system": "WS-VICTIM-01",
        "attributes": {
            "dst_ip": "45.83.221.30",
            "dst_port": 80,
            "pid": 9204,
        },
    }
    record = {
        "timestamp_ms": 1_537_438_672_781,
        "hostname": "ATK-LNX-01",
        "object": "FLOW",
        "action": "CONNECT",
        "pid": 32_203,
        "properties": {
            "src_ip": "10.10.10.10",
            "src_port": "41258",
            "dst_ip": "10.0.0.1",
            "dst_port": "53",
            "protocol": "udp",
        },
    }

    assert event_matches_ecar_record(event, record) is None

    record["hostname"] = "WS-VICTIM-01.example.local"
    assert event_matches_ecar_record(event, record) == "dns_transport"


def test_json_scanner_ignores_non_record_metadata(tmp_path) -> None:
    """Pretty-printed metadata JSON must not be treated as NDJSON log records."""
    scenario_dir = tmp_path / "scenario"
    data_dir = scenario_dir / "data"
    data_dir.mkdir(parents=True)
    path = data_dir / "COLLECTION_PROFILE.json"
    path.write_text(json.dumps({"profile": "complete"}, indent=2), encoding="utf-8")

    assert scan_json_file(path, scenario_dir, []) == {}
