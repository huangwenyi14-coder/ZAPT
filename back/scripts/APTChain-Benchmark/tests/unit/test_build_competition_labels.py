# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for exact competition-label derivation."""

import json
from pathlib import Path

import yaml
from scripts.build_competition_labels import (
    build_extracted_attack_logs,
    build_scenario_labels,
)


def test_record_ground_truth_drives_exact_competition_labels(tmp_path: Path) -> None:
    scenario_name = "exact-label-case"
    output_dir = tmp_path / "output" / scenario_name
    data_file = output_dir / "data" / "WS-01.example.local" / "ecar.json"
    data_file.parent.mkdir(parents=True)
    records = [
        {"id": "benign-row", "object": "PROCESS", "action": "CREATE"},
        {"id": "malicious-row", "object": "PROCESS", "action": "CREATE"},
    ]
    encoded_records = [
        (json.dumps(record, separators=(",", ":")) + "\n").encode() for record in records
    ]
    data_file.write_bytes(b"".join(encoded_records))

    ground_truth = {
        "scenario_name": scenario_name,
        "events": [
            {
                "record_id": "step-1#0",
                "kind": "process",
                "storyline_id": "step-1",
                "time": "2026-01-01T00:00:00Z",
                "actor": "analyst",
                "system": "WS-01",
                "activity": "Execute the payload",
                "attributes": {
                    "process_name": r"C:\Temp\payload.exe",
                    "command_line": r"C:\Temp\payload.exe",
                },
            }
        ],
        "storyline_steps": [
            {
                "index": 0,
                "storyline_id": "step-1",
                "event_types": ["process"],
                "actor": "analyst",
                "system": "WS-01",
                "activity": "Execute the payload",
            }
        ],
        "source_evidence_status": {"step-1": {"ecar": {"visible": 1}}},
    }
    (output_dir / "GROUND_TRUTH.json").write_text(
        json.dumps(ground_truth),
        encoding="utf-8",
    )
    malicious_bytes = encoded_records[1]
    record_ground_truth = {
        "physical_record_id": "pr-0123456789abcdef01234567",
        "logical_event_id": "le-0123456789abcdef01234567",
        "storyline_id": "step-1",
        "contributing_storyline_ids": ["step-1"],
        "source_format": "ecar",
        "relative_path": "WS-01.example.local/ecar.json",
        "record_index": 1,
        "byte_offset": len(encoded_records[0]),
        "byte_length": len(malicious_bytes),
        "observed_time": "2026-01-01T00:00:01Z",
        "label": "malicious",
    }
    (output_dir / "RECORD_GROUND_TRUTH.jsonl").write_text(
        json.dumps(record_ground_truth) + "\n",
        encoding="utf-8",
    )

    scenarios_root = tmp_path / "scenarios"
    scenario_source_dir = scenarios_root / scenario_name
    scenario_source_dir.mkdir(parents=True)
    (scenario_source_dir / "scenario.yaml").write_text(
        yaml.safe_dump(
            {
                "storyline": [
                    {
                        "id": "step-1",
                        "events": [
                            {
                                "type": "process",
                                "technique": "T1204.002 - Malicious File",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    labels, summary = build_scenario_labels(output_dir, scenarios_root)

    assert summary["record_ground_truth_used"] is True
    assert summary["coverage_gaps"] == {}
    assert summary["steps_without_evidence"] == []
    assert labels["attack_log_labels"] == [
        {
            "log_id": "pr-0123456789abcdef01234567",
            "physical_record_id": "pr-0123456789abcdef01234567",
            "storyline_id": "step-1",
            "storyline_ids": ["step-1"],
            "record_id": "le-0123456789abcdef01234567",
            "source_type": "ecar",
            "source_file": "data/WS-01.example.local/ecar.json",
            "relative_path": "WS-01.example.local/ecar.json",
            "record_index": 1,
            "record_ref": "record_index:1",
            "byte_offset": len(encoded_records[0]),
            "byte_length": len(malicious_bytes),
            "match_reason": "generation_provenance",
            "label": "attack_evidence",
            "timestamp": "2026-01-01T00:00:01Z",
        }
    ]
    assert (
        labels["predicted_storyline"][0]["evidence_refs"][0]["physical_record_id"]
        == "pr-0123456789abcdef01234567"
    )

    extracted = build_extracted_attack_logs(output_dir, labels)
    assert extracted["attack_logs"][0]["record"] == records[1]
