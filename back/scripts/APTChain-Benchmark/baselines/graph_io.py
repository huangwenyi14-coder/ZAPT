"""Dependency-free reads and temporal splits for neutral provenance graphs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read one JSON-lines artifact."""
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def split_edges(
    edges: list[dict[str, Any]], labels_by_edge: dict[str, dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], int]:
    """Create the frozen clean-prefix 80/20 train/validation and attack-onward test split."""
    ordered = sorted(edges, key=lambda edge: (edge["timestamp_ns"], edge["sequence"]))
    malicious_times = [
        edge["timestamp_ns"]
        for edge in ordered
        if labels_by_edge[edge["id"]]["label"] == "malicious"
    ]
    if not malicious_times:
        raise ValueError("dataset has no malicious detector-visible eCAR edges")
    attack_start = min(malicious_times)
    clean_prefix = [edge for edge in ordered if edge["timestamp_ns"] < attack_start]
    if len(clean_prefix) < 10:
        raise ValueError("dataset does not have a sufficient clean prefix")
    train_end = max(1, int(len(clean_prefix) * 0.8))
    train = clean_prefix[:train_end]
    validation = clean_prefix[train_end:]
    test = [edge for edge in ordered if edge["timestamp_ns"] >= attack_start]
    if not validation or not test:
        raise ValueError("dataset split produced an empty validation or test set")
    return train, validation, test, attack_start
