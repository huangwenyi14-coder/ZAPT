# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the standalone v2 participant-submission scorer."""

from __future__ import annotations

import json

import pytest
from blind_test.score_predictions_v2 import (
    ScoringInputError,
    main,
    parse_gold_labels,
    parse_prediction,
    parse_ratio,
    score_submission,
)


def _gold_labels() -> dict[str, object]:
    return {
        "ta_physical_ids": {
            "TA0002": ["pr-a", "pr-b"],
            "TA0011": ["pr-c"],
        },
        "physical_id_set": ["pr-a", "pr-b", "pr-c", "pr-d"],
        "storyline_attack_steps": {
            "S1": ["pr-a", "pr-b"],
            "S2": ["pr-c"],
            "S3": ["pr-d"],
        },
    }


def test_score_submission_perfect_prediction_returns_full_score() -> None:
    prediction = {
        "ta_physical_ids": {"TA0002": "pr-b", "TA0011": "pr-c"},
        "physical_id_set": ["pr-a", "pr-b", "pr-c", "pr-d"],
    }

    report = score_submission(_gold_labels(), prediction)

    assert report["ta_stage"]["f1"] == 1.0
    assert report["physical_id_set"]["f1"] == 1.0
    assert report["storyline_attack_steps"]["recall"] == 1.0
    assert report["storyline_attack_steps"]["score"] == 1.0
    assert report["overall_score"] == 1.0
    assert report["overall_score_100"] == 100.0


def test_score_submission_mixed_prediction_uses_documented_formula() -> None:
    prediction = {
        "ta_physical_ids": {
            "TA0002": "pr-a",
            "TA0011": "pr-wrong",
            "TA9999": "pr-a",
        },
        "physical_id_set": ["pr-a", "pr-c", "pr-wrong"],
    }

    report = score_submission(_gold_labels(), prediction)

    assert report["ta_stage"] == {
        "gold_stages": 2,
        "submitted_stages": 3,
        "correct_stages": 1,
        "wrong_stages": 2,
        "missed_stages": 1,
        "precision": pytest.approx(1 / 3),
        "recall": 0.5,
        "f1": pytest.approx(0.4),
        "score": pytest.approx(0.4),
    }
    assert report["physical_id_set"]["true_positives"] == 2
    assert report["physical_id_set"]["false_positives"] == 1
    assert report["physical_id_set"]["false_negatives"] == 2
    assert report["physical_id_set"]["precision"] == pytest.approx(2 / 3)
    assert report["physical_id_set"]["recall"] == 0.5
    assert report["physical_id_set"]["f1"] == pytest.approx(4 / 7)
    assert report["storyline_attack_steps"]["hit_steps"] == 2
    assert report["storyline_attack_steps"]["recall"] == pytest.approx(2 / 3)
    assert report["storyline_attack_steps"]["physical_id_precision"] == pytest.approx(2 / 3)
    assert report["storyline_attack_steps"]["score"] == pytest.approx(2 / 3)
    assert report["overall_score"] == pytest.approx(0.3 * 0.4 + 0.2 * (4 / 7) + 0.5 * (2 / 3))


def test_score_submission_removes_wrong_ids_before_step_hits() -> None:
    gold = {
        "ta_physical_ids": {"TA0002": ["pr-a"]},
        "physical_id_set": ["pr-a"],
        "storyline_attack_steps": {"S1": ["pr-a"]},
    }
    prediction = {
        "ta_physical_ids": {},
        "physical_id_set": ["S1", "pr-not-gold"],
    }

    report = score_submission(gold, prediction)

    assert report["physical_id_set"]["true_positives"] == 0
    assert report["physical_id_set"]["false_positives"] == 2
    assert report["storyline_attack_steps"]["hit_steps"] == 0
    assert report["storyline_attack_steps"]["recall"] == 0.0
    assert report["storyline_attack_steps"]["physical_id_precision"] == 0.0
    assert report["storyline_attack_steps"]["score"] == 0.0


def test_score_submission_empty_prediction_gets_no_credit_when_gold_has_attack() -> None:
    prediction = {"ta_physical_ids": {}, "physical_id_set": []}

    report = score_submission(_gold_labels(), prediction)

    assert report["ta_stage"]["precision"] == 0.0
    assert report["ta_stage"]["f1"] == 0.0
    assert report["physical_id_set"]["precision"] == 0.0
    assert report["physical_id_set"]["f1"] == 0.0
    assert report["storyline_attack_steps"]["score"] == 0.0
    assert report["overall_score"] == 0.0


def test_parse_prediction_accepts_ta_array_and_only_uses_first_id() -> None:
    prediction = parse_prediction(
        {
            "ta_physical_ids": {"TA0002": ["pr-first", "pr-ignored", "pr-also-ignored"]},
            "physical_id_set": ["pr-first", "pr-first"],
        }
    )

    assert prediction.ta_physical_ids == {"TA0002": "pr-first"}
    assert prediction.ta_extra_evidence_ignored == 2
    assert prediction.physical_ids == frozenset({"pr-first"})
    assert prediction.duplicate_physical_ids_ignored == 1


def test_parse_gold_labels_rejects_non_contiguous_steps() -> None:
    gold = _gold_labels()
    gold["storyline_attack_steps"] = {"S1": ["pr-a"], "S3": ["pr-c"]}

    with pytest.raises(ScoringInputError, match="ordered and contiguous from S1"):
        parse_gold_labels(gold)


def test_parse_prediction_rejects_extra_top_level_section() -> None:
    with pytest.raises(ScoringInputError, match="unexpected keys: notes"):
        parse_prediction(
            {
                "ta_physical_ids": {},
                "physical_id_set": [],
                "notes": "not part of the contract",
            }
        )


def test_parse_ratio_normalizes_arbitrary_equivalent_ratios() -> None:
    assert parse_ratio("3:2:5", expected_parts=3, name="--weights") == pytest.approx(
        (0.3, 0.2, 0.5)
    )


@pytest.mark.parametrize("value", ["nan:1:1", "inf:1:1", "-1:1:1", "0:0:0"])
def test_parse_ratio_rejects_invalid_values(value: str) -> None:
    with pytest.raises(ScoringInputError):
        parse_ratio(value, expected_parts=3, name="--weights")


def test_score_submission_normalizes_direct_weight_sequences() -> None:
    prediction = {
        "ta_physical_ids": {"TA0002": "pr-a"},
        "physical_id_set": ["pr-a"],
    }

    report = score_submission(_gold_labels(), prediction, weights=(3, 2, 5), step_weights=(1, 3))

    assert report["weights"] == {
        "ta_stage": 0.3,
        "physical_id_f1": 0.2,
        "attack_step": 0.5,
        "attack_step_components": {"recall": 0.25, "precision": 0.75},
    }


def test_main_writes_report_and_prints_same_json(tmp_path, capsys) -> None:
    gold_path = tmp_path / "GOLD_Label.json"
    prediction_path = tmp_path / "predict.json"
    output_path = tmp_path / "score_v2.json"
    gold_path.write_text(json.dumps(_gold_labels()), encoding="utf-8")
    prediction_path.write_text(
        json.dumps(
            {
                "ta_physical_ids": {"TA0002": "pr-a", "TA0011": "pr-c"},
                "physical_id_set": ["pr-a", "pr-b", "pr-c", "pr-d"],
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "--gold",
            str(gold_path),
            "--prediction",
            str(prediction_path),
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    stdout_document = json.loads(capsys.readouterr().out)
    assert json.loads(output_path.read_text(encoding="utf-8")) == stdout_document
    assert stdout_document["overall_score_100"] == 100.0
