# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Regression tests for bit-perfect generation repeatability."""

import json
from pathlib import Path

from evidenceforge.evaluation.parsers import discover_log_files, get_parser
from evidenceforge.events.record_ground_truth import RECORD_GROUND_TRUTH_FILENAME
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml


def _snapshot_generated_files(root: Path) -> dict[str, bytes]:
    """Return generated file bytes keyed by stable relative path."""
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "generation.log"
    }


def test_minimal_generation_is_bit_perfect_for_identical_inputs(tmp_path: Path) -> None:
    """Identical scenario input should produce byte-identical generated artifacts."""
    scenario_path = Path(__file__).parent.parent / "fixtures" / "scenarios" / "minimal.yaml"
    scenario_data = load_yaml(scenario_path)

    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"

    first_scenario = Scenario(**scenario_data)
    second_scenario = Scenario(**scenario_data)
    GenerationEngine(first_scenario, first_dir).generate()
    GenerationEngine(second_scenario, second_dir).generate()

    assert _snapshot_generated_files(first_dir) == _snapshot_generated_files(second_dir)

    labels = [
        json.loads(line)
        for line in (first_dir / RECORD_GROUND_TRUTH_FILENAME)
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    parsed_count = 0
    for format_name, paths in discover_log_files(first_dir).items():
        parser = get_parser(format_name)
        parser.scenario = first_scenario
        for path in paths:
            parsed_count += sum(1 for _record in parser.parse_file(path))

    assert labels
    assert len(labels) == parsed_count
    assert len({label["physical_record_id"] for label in labels}) == len(labels)
    assert all(label["label"] == "benign" for label in labels)
    assert all(label["detectability_class"] == "not_applicable" for label in labels)


def test_storyline_generation_links_one_logical_event_to_physical_records(tmp_path: Path) -> None:
    """Storyline provenance should survive source fan-out without entering source logs."""
    scenario_path = Path(__file__).parent.parent / "fixtures" / "scenarios" / "minimal.yaml"
    scenario_data = load_yaml(scenario_path)
    scenario_data["storyline"] = [
        {
            "id": "step-record-gt",
            "time": "2024-01-15T10:30:00Z",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Execute a suspicious PowerShell command",
            "events": [
                {
                    "type": "process",
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -NoProfile -Command whoami",
                }
            ],
        }
    ]
    output_dir = tmp_path / "storyline"

    GenerationEngine(Scenario(**scenario_data), output_dir).generate()

    labels = [
        json.loads(line)
        for line in (output_dir / RECORD_GROUND_TRUTH_FILENAME)
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    malicious = [label for label in labels if label["storyline_id"] == "step-record-gt"]
    assert malicious
    assert all(label["label"] == "malicious" for label in malicious)
    assert {label["source_format"] for label in malicious} >= {
        "windows_event_security",
        "windows_event_sysmon",
    }
    assert len({label["physical_record_id"] for label in malicious}) == len(malicious)
    assert len({label["logical_event_id"] for label in malicious}) < len(malicious)
    assert all(label["schema_version"] == 3 for label in malicious)
    assert {label["detectability_class"] for label in malicious} <= {
        "direct",
        "association_required",
        "provenance_only",
    }

    for relative_path in {label["relative_path"] for label in labels}:
        content = (output_dir / relative_path).read_text(encoding="utf-8", errors="ignore")
        for leaked_field in (
            "storyline_id",
            "logical_event_id",
            "physical_record_id",
            "ground_truth_label",
            "ground_truth_detectability_class",
            "detectability_class",
            "detectability_reason",
            "required_anchor_types",
            "provenance_kind",
            "_evidenceforge_record_provenance",
        ):
            assert leaked_field not in content
