# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the compact GOLD_Label.json sidecar."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from evidenceforge.events.gold_labels import (
    build_gold_label_document,
    build_storyline_tactic_map,
    load_enterprise_attack_mapping,
    validate_gold_label_document,
)
from evidenceforge.events.ground_truth import GroundTruthStep
from evidenceforge.models.scenario import ProcessEventSpec, StorylineEvent


def _step(storyline_id: str, index: int) -> GroundTruthStep:
    return GroundTruthStep(
        storyline_id=storyline_id,
        index=index,
        actor="analyst",
        system="WS-01",
        activity=f"attack step {index + 1}",
        ground_truth_section="storyline",
        event_types=["process"],
    )


def _record(
    physical_id: str,
    *,
    storyline_id: str | None,
    index: int,
    label: str = "malicious",
    contributing: list[str] | None = None,
) -> dict:
    return {
        "physical_record_id": physical_id,
        "relative_path": "host/process.json",
        "record_index": index,
        "label": label,
        "storyline_id": storyline_id,
        "contributing_storyline_ids": contributing or ([storyline_id] if storyline_id else []),
    }


def test_attack_v18_1_mapping_uses_official_tactic_numbers():
    mapping = load_enterprise_attack_mapping()

    assert mapping["attack_version"] == "18.1"
    assert mapping["tactics"]["TA0002"] == "Execution"
    assert mapping["tactics"]["TA0005"] == "Defense Evasion"
    assert "TA0112" not in mapping["tactics"]
    assert mapping["technique_to_tactics"]["T1203"] == ["TA0002"]


def test_public_tactic_catalog_matches_bundled_mapping_and_contains_no_answers():
    project_root = Path(__file__).resolve().parents[2]
    catalog = json.loads(
        (project_root / "docs/reference/ATTACK_TACTICS_v18.1.json").read_text(encoding="utf-8")
    )
    mapping = load_enterprise_attack_mapping()
    rows = catalog["tactics"]
    tactic_ids = [row["id"] for row in rows]

    assert catalog["attack_version"] == "18.1"
    assert catalog["domain"] == "enterprise-attack"
    assert catalog["publication_scope"] == "competition-public-reference"
    assert catalog["tactic_count"] == len(rows) == 14
    assert tactic_ids == sorted(tactic_ids)
    assert len(tactic_ids) == len(set(tactic_ids))
    assert all(re.fullmatch(r"TA\d{4}", tactic_id) for tactic_id in tactic_ids)
    assert {row["id"]: row["name"] for row in rows} == mapping["tactics"]
    assert all(row["url"].endswith(row["id"]) for row in rows)

    def collect_keys(value):
        if isinstance(value, dict):
            return set(value).union(*(collect_keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(collect_keys(item) for item in value))
        return set()

    catalog_keys = {key.lower() for key in collect_keys(catalog)}
    for forbidden_key in (
        "physical_record_id",
        "storyline_id",
        "logical_event_id",
        "record_index",
        "relative_path",
        "score",
        "label",
        "technique_to_tactics",
    ):
        assert forbidden_key not in catalog_keys


def test_build_storyline_tactic_map_extracts_ids_from_technique_text():
    storyline = [
        StorylineEvent(
            id="story-1",
            time="+1h",
            actor="analyst",
            system="WS-01",
            activity="execute attachment",
            events=[
                ProcessEventSpec(
                    process_name="payload.exe",
                    technique="T1204.002 - Malicious File",
                )
            ],
        )
    ]

    assert build_storyline_tactic_map(storyline) == {"story-1": ("TA0002",)}


def test_build_gold_label_document_has_three_sections_and_no_locators():
    records = [
        _record("pr-b", storyline_id="story-2", index=1),
        _record("pr-a", storyline_id="story-1", index=0),
        _record(
            "pr-c",
            storyline_id="story-1",
            index=2,
            contributing=["story-1", "story-2"],
        ),
        _record("pr-benign", storyline_id=None, index=3, label="benign"),
    ]

    document = build_gold_label_document(
        records=records,
        storyline_steps=[_step("story-1", 0), _step("story-2", 1)],
        storyline_tactics={"story-1": ["TA0002"], "story-2": ["TA0011"]},
    )

    assert list(document) == [
        "ta_physical_ids",
        "physical_id_set",
        "storyline_attack_steps",
    ]
    assert document["physical_id_set"] == ["pr-a", "pr-b", "pr-c"]
    assert document["ta_physical_ids"] == {
        "TA0002": ["pr-a", "pr-c"],
        "TA0011": ["pr-b", "pr-c"],
    }
    assert document["storyline_attack_steps"] == {
        "S1": ["pr-a", "pr-c"],
        "S2": ["pr-b", "pr-c"],
    }
    assert "relative_path" not in repr(document)
    assert "record_index" not in repr(document)
    assert "byte_offset" not in repr(document)


def test_validation_rejects_reference_outside_physical_id_set():
    document = {
        "ta_physical_ids": {"TA0002": ["pr-unknown"]},
        "physical_id_set": ["pr-a"],
        "storyline_attack_steps": {"S1": ["pr-a"]},
    }

    with pytest.raises(ValueError, match="outside physical_id_set"):
        validate_gold_label_document(
            document,
            record_index_records=[_record("pr-a", storyline_id="story-1", index=0)],
        )


def test_validation_rejects_duplicate_record_index_source_id():
    document = {
        "ta_physical_ids": {"TA0002": ["pr-a"]},
        "physical_id_set": ["pr-a"],
        "storyline_attack_steps": {"S1": ["pr-a"]},
    }

    with pytest.raises(ValueError, match="record-index source contains duplicate"):
        validate_gold_label_document(
            document,
            record_index_records=[
                _record("pr-a", storyline_id="story-1", index=0),
                _record("pr-a", storyline_id="story-1", index=1),
            ],
        )


def test_validation_rejects_non_contiguous_storyline_steps():
    document = {
        "ta_physical_ids": {"TA0002": ["pr-a"]},
        "physical_id_set": ["pr-a"],
        "storyline_attack_steps": {
            "S1": ["pr-a"],
            "S3": [],
        },
    }

    with pytest.raises(ValueError, match="contiguous and ordered"):
        validate_gold_label_document(
            document,
            record_index_records=[_record("pr-a", storyline_id="story-1", index=0)],
        )
