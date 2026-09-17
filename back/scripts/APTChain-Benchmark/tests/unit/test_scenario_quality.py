"""Tests for fail-closed report-derived scenario quality gates."""

import json
from pathlib import Path

import yaml

from evidenceforge.validation.scenario_quality import (
    audit_generated_command_corpus,
    audit_scenario_corpus,
    audit_scenario_definition,
)


def _scenario(
    *,
    name: str = "neutral-scenario",
    hostname: str = "WKS-ENG-021",
    process_name: str = r"C:\Windows\System32\cmd.exe",
    command_line: str = r"C:\Windows\System32\cmd.exe /c whoami",
) -> dict:
    return {
        "version": "1.0",
        "name": name,
        "environment": {
            "systems": [
                {
                    "hostname": hostname,
                    "ip": "10.20.20.21",
                    "os": "Windows 11",
                    "type": "workstation",
                }
            ],
            "network": {"sensors": []},
        },
        "output": {"logs": [{"format": "windows"}, {"format": "zeek"}]},
        "storyline": [
            {
                "id": "execute-command",
                "time": "+10m",
                "actor": "analyst",
                "system": hostname,
                "activity": "Run a local identity-discovery command.",
                "events": [
                    {
                        "type": "process",
                        "process_name": process_name,
                        "command_line": command_line,
                        "process_ref": "discovery",
                        "description": "cmd.exe starts whoami on the modeled workstation.",
                    }
                ],
            }
        ],
    }


def _write_scenario(tmp_path: Path, payload: dict, name: str = "scenario") -> Path:
    scenario_dir = tmp_path / name
    scenario_dir.mkdir()
    path = scenario_dir / "scenario.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def test_quality_gate_accepts_neutral_semantically_aligned_scenario(tmp_path: Path) -> None:
    """Manual review reminders do not block an otherwise clean scenario."""
    path = _write_scenario(tmp_path, _scenario())

    result = audit_scenario_definition(path)

    assert result.accepted
    assert {issue.rule_id for issue in result.issues} == {
        f"EFQ-M{index:02d}" for index in range(1, 11)
    }


def test_quality_gate_rejects_role_leak_optional_ids_and_command_mismatch(
    tmp_path: Path,
) -> None:
    """Known leakage and process semantic anti-patterns are hard failures."""
    payload = _scenario(
        hostname="WS-VICTIM-01",
        process_name=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="etool.exe -scan",
    )
    payload["environment"]["network"]["sensors"] = [
        {"name": "ids", "type": "ids", "log_formats": ["snort_alert"]}
    ]
    payload["output"]["logs"].append({"format": "cisco_asa"})
    path = _write_scenario(tmp_path, payload)

    result = audit_scenario_definition(path)
    rule_ids = {issue.rule_id for issue in result.issues}

    assert not result.accepted
    assert {"EFQ001", "EFQ003", "EFQ007"}.issubset(rule_ids)


def test_quality_gate_rejects_outlook_compose_as_email_delivery(tmp_path: Path) -> None:
    """Outlook compose switches cannot stand in for received-message evidence."""
    payload = _scenario(
        process_name=r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
        command_line=(
            r'"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE" '
            r'/c ipm.note /a "lure.doc"'
        ),
    )
    path = _write_scenario(tmp_path, payload)

    result = audit_scenario_definition(path)

    assert not result.accepted
    assert any(issue.rule_id == "EFQ008" for issue in result.issues)


def test_quality_gate_rejects_bare_argument_required_interpreter(tmp_path: Path) -> None:
    """A process image repeated as its whole command line does not prove an action."""
    image = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    path = _write_scenario(
        tmp_path,
        _scenario(process_name=image, command_line=image),
    )

    result = audit_scenario_definition(path)

    assert not result.accepted
    assert any(issue.rule_id == "EFQ029" for issue in result.issues)


def test_corpus_gate_rejects_compiler_timing_and_beacon_templates(tmp_path: Path) -> None:
    """Corpus-wide fixed cadence and beacon profiles fail before generation."""
    paths: list[Path] = []
    for scenario_index in range(5):
        payload = _scenario(name=f"scenario-{scenario_index}")
        payload["storyline"] = []
        for step_index in range(5):
            payload["storyline"].append(
                {
                    "id": f"beacon-{step_index}",
                    "time": f"+{step_index * 6}m",
                    "actor": "analyst",
                    "system": "WKS-ENG-021",
                    "activity": "The implant sends a periodic C2 check-in.",
                    "events": [
                        {
                            "type": "beacon",
                            "dst_ip": "203.0.113.20",
                            "dst_port": 443,
                            "interval": "5m",
                            "duration": "1h",
                            "jitter": 0.2,
                            "description": "The modeled implant sends one C2 check-in.",
                        }
                    ],
                }
            )
        paths.append(_write_scenario(tmp_path, payload, name=f"scenario-{scenario_index}"))

    report = audit_scenario_corpus(paths)
    rule_ids = {issue.rule_id for result in report.scenarios for issue in result.issues} | {
        issue.rule_id for issue in report.corpus_issues
    }

    assert not report.accepted
    assert {"EFQ012", "EFQ016"}.issubset(rule_ids)


def test_generated_command_gate_rejects_bare_and_cross_scenario_template(
    tmp_path: Path,
) -> None:
    """Final eCAR rows are audited, not only their source scenario YAML."""
    output_dirs: list[Path] = []
    repeated_command = (
        r"powershell.exe -NoProfile -ExecutionPolicy Bypass "
        r"-File C:\Scripts\service-health.ps1"
    )
    image = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    for scenario_index in range(3):
        output_dir = tmp_path / f"scenario-{scenario_index}"
        data_dir = output_dir / "data" / "WKS-01.example"
        data_dir.mkdir(parents=True)
        rows = []
        for event_index in range(20):
            command = image if scenario_index == 0 and event_index == 0 else repeated_command
            rows.append(
                {
                    "object": "PROCESS",
                    "action": "CREATE",
                    "properties": {
                        "image_path": image,
                        "command_line": command,
                    },
                }
            )
        (data_dir / "ecar.json").write_text(
            "".join(json.dumps(row) + "\n" for row in rows),
            encoding="utf-8",
        )
        output_dirs.append(output_dir)

    report = audit_generated_command_corpus(output_dirs)

    assert not report.accepted
    assert {issue.rule_id for issue in report.issues} == {"EFQ029", "EFQ030"}
