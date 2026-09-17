# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Compact attack labels derived from record provenance and ATT&CK v18.1."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING, Any

from evidenceforge.utils.paths import safe_write_text

if TYPE_CHECKING:
    from evidenceforge.events.ground_truth import GroundTruthStep
    from evidenceforge.models.scenario import StorylineEvent


GOLD_LABEL_FILENAME = "GOLD_Label.json"
ENTERPRISE_ATTACK_VERSION = "18.1"
_ATTACK_MAPPING_FILENAME = "enterprise_attack_v18_1.json"
_TECHNIQUE_ID_RE = re.compile(r"(?<![A-Z0-9])T\d{4}(?:\.\d{3})?(?![A-Z0-9])", re.IGNORECASE)
_TACTIC_ID_RE = re.compile(r"^TA\d{4}$")


@lru_cache(maxsize=1)
def load_enterprise_attack_mapping() -> dict[str, Any]:
    """Load the bundled Enterprise ATT&CK v18.1 technique-to-tactic mapping."""
    resource = files("evidenceforge._data").joinpath(_ATTACK_MAPPING_FILENAME)
    document = json.loads(resource.read_text(encoding="utf-8"))
    if document.get("attack_version") != ENTERPRISE_ATTACK_VERSION:
        raise ValueError(
            "Bundled ATT&CK mapping version mismatch: "
            f"expected {ENTERPRISE_ATTACK_VERSION}, got {document.get('attack_version')!r}"
        )
    tactics = document.get("tactics")
    technique_to_tactics = document.get("technique_to_tactics")
    if not isinstance(tactics, dict) or not isinstance(technique_to_tactics, dict):
        raise ValueError("Bundled ATT&CK mapping is missing tactics or technique_to_tactics")
    return document


def build_storyline_tactic_map(
    storyline: Sequence[StorylineEvent],
) -> dict[str, tuple[str, ...]]:
    """Resolve each storyline step's technique declarations to ATT&CK tactic IDs."""
    mapping = load_enterprise_attack_mapping()
    technique_to_tactics: Mapping[str, Sequence[str]] = mapping["technique_to_tactics"]
    result: dict[str, tuple[str, ...]] = {}
    for step in storyline:
        tactic_ids: set[str] = set()
        for event in step.events:
            technique_text = event.technique or ""
            for match in _TECHNIQUE_ID_RE.finditer(technique_text):
                technique_id = match.group(0).upper()
                resolved = technique_to_tactics.get(technique_id)
                if resolved is None:
                    raise ValueError(
                        f"Storyline {step.id!r} references ATT&CK technique {technique_id!r} "
                        f"which is absent from Enterprise ATT&CK v{ENTERPRISE_ATTACK_VERSION}"
                    )
                tactic_ids.update(str(tactic_id) for tactic_id in resolved)
        result[step.id] = tuple(sorted(tactic_ids))
    return result


def build_gold_label_document(
    *,
    records: Sequence[Mapping[str, Any]],
    storyline_steps: Sequence[GroundTruthStep],
    storyline_tactics: Mapping[str, Sequence[str]],
) -> dict[str, Any]:
    """Build the three-section GOLD label document in deterministic order."""
    ordered_records = sorted(
        records,
        key=lambda item: (str(item.get("relative_path") or ""), int(item.get("record_index", -1))),
    )
    malicious_records = [record for record in ordered_records if record.get("label") == "malicious"]
    physical_id_set = [str(record["physical_record_id"]) for record in malicious_records]
    physical_rank = {physical_id: index for index, physical_id in enumerate(physical_id_set)}

    ordered_steps = sorted(storyline_steps, key=lambda step: step.index)
    step_ids: dict[str, set[str]] = {step.storyline_id: set() for step in ordered_steps}
    tactic_ids: dict[str, set[str]] = defaultdict(set)

    for record in malicious_records:
        physical_id = str(record["physical_record_id"])
        for storyline_id in _record_storyline_ids(record):
            if storyline_id in step_ids:
                step_ids[storyline_id].add(physical_id)
            for tactic_id in storyline_tactics.get(storyline_id, ()):
                tactic_ids[str(tactic_id)].add(physical_id)

    def ordered_physical_ids(values: set[str]) -> list[str]:
        return sorted(values, key=lambda physical_id: physical_rank[physical_id])

    document = {
        "ta_physical_ids": {
            tactic_id: ordered_physical_ids(tactic_ids[tactic_id])
            for tactic_id in sorted(tactic_ids)
            if tactic_ids[tactic_id]
        },
        "physical_id_set": physical_id_set,
        "storyline_attack_steps": {
            f"S{position}": ordered_physical_ids(step_ids[step.storyline_id])
            for position, step in enumerate(ordered_steps, start=1)
        },
    }
    validate_gold_label_document(document, record_index_records=ordered_records)
    return document


def validate_gold_label_document(
    document: Mapping[str, Any],
    *,
    record_index_records: Sequence[Mapping[str, Any]],
) -> None:
    """Run the three required GOLD label consistency checks."""
    errors: list[str] = []
    physical_ids = [str(value) for value in document.get("physical_id_set", [])]
    physical_set = set(physical_ids)
    if len(physical_ids) != len(physical_set):
        errors.append("physical_id_set contains duplicate IDs")

    referenced_ids: list[str] = []
    ta_physical_ids = document.get("ta_physical_ids", {})
    if not isinstance(ta_physical_ids, Mapping):
        errors.append("ta_physical_ids must be an object")
    else:
        for tactic_id, values in ta_physical_ids.items():
            if not _TACTIC_ID_RE.fullmatch(str(tactic_id)):
                errors.append(f"invalid ATT&CK tactic ID {tactic_id!r}")
            section_ids = [str(value) for value in values]
            if len(section_ids) != len(set(section_ids)):
                errors.append(f"ta_physical_ids[{tactic_id!r}] contains duplicate IDs")
            referenced_ids.extend(section_ids)

    steps = document.get("storyline_attack_steps", {})
    if not isinstance(steps, Mapping):
        errors.append("storyline_attack_steps must be an object")
        steps = {}
    actual_step_names = [str(step_name) for step_name in steps]
    for step_name, values in steps.items():
        if not isinstance(values, list):
            errors.append(f"storyline step {step_name!r} must contain an array of physical IDs")
            continue
        section_ids = [str(value) for value in values]
        if len(section_ids) != len(set(section_ids)):
            errors.append(f"storyline step {step_name!r} contains duplicate IDs")
        referenced_ids.extend(section_ids)

    # Check 1: IDs used by the TA and storyline sections must belong to the attack-ID set.
    outside_physical_set = sorted(set(referenced_ids).difference(physical_set))
    if outside_physical_set:
        errors.append(
            "TA/storyline sections reference IDs outside physical_id_set: "
            + ", ".join(outside_physical_set[:10])
        )

    # Check 2: every GOLD ID must resolve exactly once in the source used to build RECORD_INDEX.
    record_id_counts = Counter(
        str(record.get("physical_record_id") or "") for record in record_index_records
    )
    duplicate_record_ids = sorted(
        physical_id for physical_id, count in record_id_counts.items() if physical_id and count > 1
    )
    if duplicate_record_ids:
        errors.append(
            "record-index source contains duplicate physical_record_id values: "
            + ", ".join(duplicate_record_ids[:10])
        )
    unresolved_ids = sorted(
        physical_id for physical_id in physical_set if record_id_counts.get(physical_id, 0) != 1
    )
    if unresolved_ids:
        errors.append(
            "physical IDs do not resolve exactly once in the record-index source: "
            + ", ".join(unresolved_ids[:10])
        )

    # Check 3: storyline steps must be ordered, unique, and contiguous from S1.
    expected_step_names = [f"S{index}" for index in range(1, len(actual_step_names) + 1)]
    if actual_step_names != expected_step_names:
        errors.append(
            "storyline steps must be contiguous and ordered from S1: "
            f"expected {expected_step_names}, got {actual_step_names}"
        )

    if errors:
        raise ValueError("GOLD label consistency validation failed: " + "; ".join(errors))


def write_gold_label_document(output_path: Path, document: Mapping[str, Any]) -> None:
    """Write a validated GOLD label document without locator duplication."""
    safe_write_text(
        output_path,
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _record_storyline_ids(record: Mapping[str, Any]) -> tuple[str, ...]:
    values = [str(value) for value in record.get("contributing_storyline_ids", []) if value]
    primary = record.get("storyline_id")
    if primary:
        values.append(str(primary))
    return tuple(dict.fromkeys(values))
