"""Tests for resumable quality-corpus generation safety checks."""

import json

from scripts.generate_quality_corpus import (
    COMPLETION_MARKER,
    QUALITY_STANDARD_VERSION,
    _is_complete,
    _scenario_digest,
    audit_generated_data,
)


def test_generated_data_audit_accepts_neutral_victim_side_logs(tmp_path) -> None:
    """Neutral internal asset names do not reveal attacker or victim roles."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "events.jsonl").write_text(
        '{"host":"WKS-ENG-021","dst":"203.0.113.10"}\n',
        encoding="utf-8",
    )

    assert audit_generated_data(data_dir) == []


def test_generated_data_audit_rejects_answer_hosts_and_private_labels(tmp_path) -> None:
    """Legacy role-bearing hosts and evaluator artifacts fail the public-data gate."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "events.jsonl").write_text(
        '{"host":"ATK-LNX-01"}\n',
        encoding="utf-8",
    )
    (data_dir / "campaign.labels.json").write_text("{}\n", encoding="utf-8")

    issues = audit_generated_data(data_dir)

    assert any("ATK-LNX-01" in issue for issue in issues)
    assert any("private label" in issue for issue in issues)


def test_generated_data_audit_rejects_placeholder_and_optional_sensor_sources(tmp_path) -> None:
    """Role-labeled placeholders plus default-disabled ASA/Snort sources fail."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "events.jsonl").write_text(
        '{"attachment":"attachment.bin"}\n',
        encoding="utf-8",
    )
    (data_dir / "cisco_asa.log").write_text("permit\n", encoding="utf-8")
    (data_dir / "snort_alert.log").write_text("alert\n", encoding="utf-8")

    issues = audit_generated_data(data_dir)

    assert any("attachment.bin" in issue for issue in issues)
    assert sum("excluded optional firewall/IDS" in issue for issue in issues) == 2


def test_completion_marker_is_invalidated_when_scenario_source_changes(tmp_path) -> None:
    """Resume never reuses logs produced from a different scenario revision."""
    scenario_dir = tmp_path / "scenario"
    scenario_dir.mkdir()
    scenario_path = scenario_dir / "scenario.yaml"
    scenario_path.write_text("version: '1.0'\n", encoding="utf-8")
    output_dir = tmp_path / "output"
    (output_dir / "data").mkdir(parents=True)

    (output_dir / COMPLETION_MARKER).write_text(
        json.dumps(
            {
                "status": "complete",
                "scenario": scenario_dir.name,
                "quality_standard_version": QUALITY_STANDARD_VERSION,
                "scenario_sha256": _scenario_digest(scenario_path),
            }
        ),
        encoding="utf-8",
    )

    assert _is_complete(output_dir, scenario_path)

    scenario_path.write_text("version: '1.1'\n", encoding="utf-8")

    assert not _is_complete(output_dir, scenario_path)
