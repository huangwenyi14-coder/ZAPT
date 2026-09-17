# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Score a two-section participant submission against a compact GOLD label file."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_GOLD_KEYS = {"ta_physical_ids", "physical_id_set", "storyline_attack_steps"}
_PREDICTION_KEYS = {"ta_physical_ids", "physical_id_set"}
_TACTIC_ID_RE = re.compile(r"^TA\d{4}$")


class ScoringInputError(ValueError):
    """Raised when a GOLD label or participant submission is malformed."""


@dataclass(frozen=True)
class GoldLabels:
    """Validated private labels used by the v2 scorer."""

    ta_physical_ids: dict[str, frozenset[str]]
    physical_ids: frozenset[str]
    storyline_attack_steps: tuple[tuple[str, frozenset[str]], ...]


@dataclass(frozen=True)
class Prediction:
    """Validated and normalized participant submission."""

    ta_physical_ids: dict[str, str]
    physical_ids: frozenset[str]
    duplicate_physical_ids_ignored: int
    ta_extra_evidence_ignored: int


def _require_object(value: Any, *, location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ScoringInputError(f"{location} must be a JSON object")
    if not all(isinstance(key, str) for key in value):
        raise ScoringInputError(f"{location} keys must be strings")
    return value


def _require_exact_keys(document: Mapping[str, Any], *, expected: set[str], location: str) -> None:
    actual = set(document)
    missing = sorted(expected.difference(actual))
    extra = sorted(actual.difference(expected))
    messages: list[str] = []
    if missing:
        messages.append(f"missing keys: {', '.join(missing)}")
    if extra:
        messages.append(f"unexpected keys: {', '.join(extra)}")
    if messages:
        raise ScoringInputError(
            f"{location} has invalid top-level sections ({'; '.join(messages)})"
        )


def _require_string(value: Any, *, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScoringInputError(f"{location} must be a non-empty string")
    return value


def _require_string_list(value: Any, *, location: str, allow_empty: bool) -> list[str]:
    if not isinstance(value, list):
        raise ScoringInputError(f"{location} must be a JSON array")
    if not value and not allow_empty:
        raise ScoringInputError(f"{location} must contain at least one physical ID")
    values = [
        _require_string(item, location=f"{location}[{index}]") for index, item in enumerate(value)
    ]
    return values


def parse_gold_labels(document: Any) -> GoldLabels:
    """Validate and normalize one generated ``GOLD_Label.json`` document."""
    root = _require_object(document, location="GOLD_Label.json")
    _require_exact_keys(root, expected=_GOLD_KEYS, location="GOLD_Label.json")

    physical_values = _require_string_list(
        root["physical_id_set"],
        location="GOLD_Label.json.physical_id_set",
        allow_empty=True,
    )
    physical_ids = frozenset(physical_values)
    if len(physical_values) != len(physical_ids):
        raise ScoringInputError("GOLD_Label.json.physical_id_set contains duplicate IDs")

    ta_document = _require_object(
        root["ta_physical_ids"], location="GOLD_Label.json.ta_physical_ids"
    )
    ta_physical_ids: dict[str, frozenset[str]] = {}
    for tactic_id, raw_ids in ta_document.items():
        if not _TACTIC_ID_RE.fullmatch(tactic_id):
            raise ScoringInputError(
                f"GOLD_Label.json.ta_physical_ids has invalid ATT&CK tactic ID {tactic_id!r}"
            )
        values = _require_string_list(
            raw_ids,
            location=f"GOLD_Label.json.ta_physical_ids.{tactic_id}",
            allow_empty=False,
        )
        ids = frozenset(values)
        if len(values) != len(ids):
            raise ScoringInputError(
                f"GOLD_Label.json.ta_physical_ids.{tactic_id} contains duplicate IDs"
            )
        outside_ids = ids.difference(physical_ids)
        if outside_ids:
            raise ScoringInputError(
                f"GOLD_Label.json.ta_physical_ids.{tactic_id} references IDs outside "
                f"physical_id_set: {', '.join(sorted(outside_ids))}"
            )
        ta_physical_ids[tactic_id] = ids

    steps_document = _require_object(
        root["storyline_attack_steps"],
        location="GOLD_Label.json.storyline_attack_steps",
    )
    expected_step_names = [f"S{index}" for index in range(1, len(steps_document) + 1)]
    actual_step_names = list(steps_document)
    if actual_step_names != expected_step_names:
        raise ScoringInputError(
            "GOLD_Label.json.storyline_attack_steps must be ordered and contiguous from S1; "
            f"expected {expected_step_names}, got {actual_step_names}"
        )

    storyline_attack_steps: list[tuple[str, frozenset[str]]] = []
    for step_name, raw_ids in steps_document.items():
        values = _require_string_list(
            raw_ids,
            location=f"GOLD_Label.json.storyline_attack_steps.{step_name}",
            allow_empty=False,
        )
        ids = frozenset(values)
        if len(values) != len(ids):
            raise ScoringInputError(
                f"GOLD_Label.json.storyline_attack_steps.{step_name} contains duplicate IDs"
            )
        outside_ids = ids.difference(physical_ids)
        if outside_ids:
            raise ScoringInputError(
                f"GOLD_Label.json.storyline_attack_steps.{step_name} references IDs outside "
                f"physical_id_set: {', '.join(sorted(outside_ids))}"
            )
        storyline_attack_steps.append((step_name, ids))

    return GoldLabels(
        ta_physical_ids=ta_physical_ids,
        physical_ids=physical_ids,
        storyline_attack_steps=tuple(storyline_attack_steps),
    )


def parse_prediction(document: Any) -> Prediction:
    """Validate and normalize a participant ``predict.json`` document."""
    root = _require_object(document, location="predict.json")
    _require_exact_keys(root, expected=_PREDICTION_KEYS, location="predict.json")

    ta_document = _require_object(root["ta_physical_ids"], location="predict.json.ta_physical_ids")
    ta_physical_ids: dict[str, str] = {}
    ta_extra_evidence_ignored = 0
    for tactic_id, raw_value in ta_document.items():
        if not _TACTIC_ID_RE.fullmatch(tactic_id):
            raise ScoringInputError(
                f"predict.json.ta_physical_ids has invalid ATT&CK tactic ID {tactic_id!r}"
            )
        if isinstance(raw_value, list):
            values = _require_string_list(
                raw_value,
                location=f"predict.json.ta_physical_ids.{tactic_id}",
                allow_empty=False,
            )
            physical_id = values[0]
            ta_extra_evidence_ignored += len(values) - 1
        else:
            physical_id = _require_string(
                raw_value, location=f"predict.json.ta_physical_ids.{tactic_id}"
            )
        ta_physical_ids[tactic_id] = physical_id

    physical_values = _require_string_list(
        root["physical_id_set"],
        location="predict.json.physical_id_set",
        allow_empty=True,
    )
    physical_ids = frozenset(physical_values)
    return Prediction(
        ta_physical_ids=ta_physical_ids,
        physical_ids=physical_ids,
        duplicate_physical_ids_ignored=len(physical_values) - len(physical_ids),
        ta_extra_evidence_ignored=ta_extra_evidence_ignored,
    )


def parse_ratio(value: str, *, expected_parts: int, name: str) -> tuple[float, ...]:
    """Parse and normalize a colon-separated, non-negative scoring ratio."""
    raw_parts = value.split(":")
    if len(raw_parts) != expected_parts:
        raise ScoringInputError(
            f"{name} must contain {expected_parts} colon-separated numbers, got {value!r}"
        )
    try:
        parts = tuple(float(part) for part in raw_parts)
    except ValueError as error:
        raise ScoringInputError(f"{name} contains a non-numeric value: {value!r}") from error
    if any(not math.isfinite(part) or part < 0 for part in parts):
        raise ScoringInputError(f"{name} must contain finite, non-negative values: {value!r}")
    total = sum(parts)
    if total <= 0:
        raise ScoringInputError(f"{name} must have a positive total: {value!r}")
    return tuple(part / total for part in parts)


def _precision_recall_f1(
    *, true_positives: int, false_positives: int, false_negatives: int
) -> tuple[float, float, float]:
    predicted_count = true_positives + false_positives
    gold_count = true_positives + false_negatives
    if predicted_count:
        precision = true_positives / predicted_count
    else:
        precision = 1.0 if gold_count == 0 else 0.0
    recall = true_positives / gold_count if gold_count else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


def score_submission(
    gold_document: Any,
    prediction_document: Any,
    *,
    weights: Sequence[float] = (0.3, 0.2, 0.5),
    step_weights: Sequence[float] = (0.5, 0.5),
) -> dict[str, Any]:
    """Score a participant prediction and return a JSON-serializable report.

    ``weights`` applies to TA F1, physical-record F1, and attack-step score.
    ``step_weights`` applies to step-hit recall and submitted physical-ID precision.
    Both sequences are normalized so callers may pass either ratios or fractions.
    """
    gold = parse_gold_labels(gold_document)
    prediction = parse_prediction(prediction_document)
    normalized_weights = _normalize_numeric_weights(weights, expected_parts=3, name="weights")
    normalized_step_weights = _normalize_numeric_weights(
        step_weights, expected_parts=2, name="step_weights"
    )

    correct_tactics = {
        tactic_id
        for tactic_id, physical_id in prediction.ta_physical_ids.items()
        if physical_id in gold.ta_physical_ids.get(tactic_id, frozenset())
    }
    ta_true_positives = len(correct_tactics)
    ta_false_positives = len(prediction.ta_physical_ids) - ta_true_positives
    ta_false_negatives = len(gold.ta_physical_ids) - ta_true_positives
    ta_precision, ta_recall, ta_f1 = _precision_recall_f1(
        true_positives=ta_true_positives,
        false_positives=ta_false_positives,
        false_negatives=ta_false_negatives,
    )

    correct_physical_ids = prediction.physical_ids.intersection(gold.physical_ids)
    physical_true_positives = len(correct_physical_ids)
    physical_false_positives = len(prediction.physical_ids.difference(gold.physical_ids))
    physical_false_negatives = len(gold.physical_ids.difference(prediction.physical_ids))
    physical_precision, physical_recall, physical_f1 = _precision_recall_f1(
        true_positives=physical_true_positives,
        false_positives=physical_false_positives,
        false_negatives=physical_false_negatives,
    )

    hit_steps = sum(
        bool(step_physical_ids.intersection(correct_physical_ids))
        for _, step_physical_ids in gold.storyline_attack_steps
    )
    total_steps = len(gold.storyline_attack_steps)
    step_recall = hit_steps / total_steps if total_steps else 1.0
    step_score = (
        normalized_step_weights[0] * step_recall + normalized_step_weights[1] * physical_precision
    )

    weighted_contributions = {
        "ta_stage": normalized_weights[0] * ta_f1,
        "physical_id_f1": normalized_weights[1] * physical_f1,
        "attack_step": normalized_weights[2] * step_score,
    }
    overall_score = sum(weighted_contributions.values())

    return {
        "schema_version": 2,
        "weights": {
            "ta_stage": normalized_weights[0],
            "physical_id_f1": normalized_weights[1],
            "attack_step": normalized_weights[2],
            "attack_step_components": {
                "recall": normalized_step_weights[0],
                "precision": normalized_step_weights[1],
            },
        },
        "ta_stage": {
            "gold_stages": len(gold.ta_physical_ids),
            "submitted_stages": len(prediction.ta_physical_ids),
            "correct_stages": ta_true_positives,
            "wrong_stages": ta_false_positives,
            "missed_stages": ta_false_negatives,
            "precision": ta_precision,
            "recall": ta_recall,
            "f1": ta_f1,
            "score": ta_f1,
        },
        "physical_id_set": {
            "gold_ids": len(gold.physical_ids),
            "submitted_ids": len(prediction.physical_ids),
            "true_positives": physical_true_positives,
            "false_positives": physical_false_positives,
            "false_negatives": physical_false_negatives,
            "precision": physical_precision,
            "recall": physical_recall,
            "f1": physical_f1,
            "score": physical_f1,
        },
        "storyline_attack_steps": {
            "total_steps": total_steps,
            "hit_steps": hit_steps,
            "missed_steps": total_steps - hit_steps,
            "recall": step_recall,
            "physical_id_precision": physical_precision,
            "recall_weight": normalized_step_weights[0],
            "precision_weight": normalized_step_weights[1],
            "score": step_score,
        },
        "weighted_contributions": weighted_contributions,
        "overall_score": overall_score,
        "overall_score_100": overall_score * 100,
        "submission_normalization": {
            "duplicate_physical_ids_ignored": prediction.duplicate_physical_ids_ignored,
            "ta_extra_evidence_ignored": prediction.ta_extra_evidence_ignored,
        },
    }


def _normalize_numeric_weights(
    values: Sequence[float], *, expected_parts: int, name: str
) -> tuple[float, ...]:
    if len(values) != expected_parts:
        raise ScoringInputError(f"{name} must contain exactly {expected_parts} values")
    normalized_values = tuple(float(value) for value in values)
    if any(not math.isfinite(value) or value < 0 for value in normalized_values):
        raise ScoringInputError(f"{name} must contain finite, non-negative values")
    total = sum(normalized_values)
    if total <= 0:
        raise ScoringInputError(f"{name} must have a positive total")
    return tuple(value / total for value in normalized_values)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ScoringInputError(f"Cannot read {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ScoringInputError(
            f"Invalid JSON in {path} at line {error.lineno}, column {error.colno}: {error.msg}"
        ) from error


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as error:
        raise ScoringInputError(f"Cannot write {path}: {error}") from error


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the standalone v2 scorer command-line parser."""
    parser = argparse.ArgumentParser(
        description="Score predict.json against a private GOLD_Label.json using scoring v2."
    )
    parser.add_argument("--gold", type=Path, required=True, help="Path to GOLD_Label.json")
    parser.add_argument(
        "--prediction",
        type=Path,
        default=Path("predict.json"),
        help="Path to participant predict.json (default: ./predict.json)",
    )
    parser.add_argument("--output", type=Path, help="Optional score report path")
    parser.add_argument(
        "--weights",
        default="0.3:0.2:0.5",
        help="TA:physical-F1:attack-step ratio (default: 0.3:0.2:0.5)",
    )
    parser.add_argument(
        "--step-weights",
        default="0.5:0.5",
        help="step-recall:physical-ID-precision ratio (default: 0.5:0.5)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the v2 scorer CLI."""
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    try:
        weights = parse_ratio(args.weights, expected_parts=3, name="--weights")
        step_weights = parse_ratio(args.step_weights, expected_parts=2, name="--step-weights")
        report = score_submission(
            _load_json(args.gold),
            _load_json(args.prediction),
            weights=weights,
            step_weights=step_weights,
        )
        rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            _write_report(args.output, report)
        sys.stdout.write(rendered)
    except ScoringInputError as error:
        parser.exit(2, f"error: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
