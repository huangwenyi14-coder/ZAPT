"""Leakage-free event and storyline evaluation for provenance detectors."""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _roc_auc(labels: list[int], scores: list[float]) -> float | None:
    positives = sum(labels)
    negatives = len(labels) - positives
    if not positives or not negatives:
        return None

    ordered = sorted(enumerate(scores), key=lambda item: item[1])
    ranks = [0.0] * len(scores)
    cursor = 0
    while cursor < len(ordered):
        end = cursor + 1
        while end < len(ordered) and ordered[end][1] == ordered[cursor][1]:
            end += 1
        average_rank = (cursor + 1 + end) / 2
        for offset in range(cursor, end):
            ranks[ordered[offset][0]] = average_rank
        cursor = end
    positive_rank_sum = sum(rank for rank, label in zip(ranks, labels, strict=True) if label)
    return _safe_div(
        positive_rank_sum - positives * (positives + 1) / 2,
        positives * negatives,
    )


def _average_precision(labels: list[int], scores: list[float]) -> float | None:
    positives = sum(labels)
    if not positives:
        return None
    ranked = sorted(zip(scores, labels, strict=True), key=lambda item: item[0], reverse=True)
    true_positives = 0
    precision_sum = 0.0
    for rank, (_, label) in enumerate(ranked, start=1):
        if label:
            true_positives += 1
            precision_sum += true_positives / rank
    return precision_sum / positives


def binary_metrics(
    labels: list[int], predictions: list[int], scores: list[float] | None = None
) -> dict[str, int | float | None]:
    """Compute imbalance-aware binary classification metrics without extra dependencies."""
    if len(labels) != len(predictions):
        raise ValueError("labels and predictions must have the same length")
    if scores is not None and len(scores) != len(labels):
        raise ValueError("labels and scores must have the same length")

    paired = list(zip(labels, predictions, strict=True))
    tp = sum(label == 1 and prediction == 1 for label, prediction in paired)
    fp = sum(label == 0 and prediction == 1 for label, prediction in paired)
    tn = sum(label == 0 and prediction == 0 for label, prediction in paired)
    fn = sum(label == 1 and prediction == 0 for label, prediction in paired)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    specificity = _safe_div(tn, tn + fp)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = _safe_div(tp * tn - fp * fn, denominator)
    result: dict[str, int | float | None] = {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": _safe_div(tp + tn, len(labels)),
        "balanced_accuracy": (recall + specificity) / 2,
        "mcc": mcc,
        "false_positives_per_million_benign": _safe_div(fp * 1_000_000, fp + tn),
    }
    if scores is not None:
        result["auroc"] = _roc_auc(labels, scores)
        result["average_precision"] = _average_precision(labels, scores)
    return result


class _UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


def _action_ids(label: dict[str, Any]) -> set[str]:
    action_ids = set(label.get("contributing_storyline_ids") or [])
    if label.get("storyline_id"):
        action_ids.add(str(label["storyline_id"]))
    return action_ids


def alert_components(
    alerted_edges: list[dict[str, Any]], gap_ns: int = 5 * 60 * 1_000_000_000
) -> list[list[dict[str, Any]]]:
    """Collapse edge alerts by host, shared endpoint, and a transitive time gap."""
    edges = sorted(alerted_edges, key=lambda edge: (edge["timestamp_ns"], edge["sequence"]))
    union_find = _UnionFind(len(edges))
    last_by_endpoint: dict[tuple[str, str], tuple[int, int]] = {}
    for index, edge in enumerate(edges):
        endpoints = {str(edge["subject_id"])}
        if edge.get("object_id"):
            endpoints.add(str(edge["object_id"]))
        for endpoint in endpoints:
            key = (str(edge["host"]), endpoint)
            previous = last_by_endpoint.get(key)
            if previous and edge["timestamp_ns"] - previous[0] <= gap_ns:
                union_find.union(index, previous[1])
            last_by_endpoint[key] = (edge["timestamp_ns"], index)

    components: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for index, edge in enumerate(edges):
        components[union_find.find(index)].append(edge)
    return sorted(components.values(), key=lambda group: group[0]["timestamp_ns"])


def action_metrics(
    test_edges: list[dict[str, Any]],
    labels_by_edge: dict[str, dict[str, Any]],
    predictions_by_edge: dict[str, int],
) -> dict[str, Any]:
    """Match predicted alert components one-to-one with visible storyline actions."""
    ground_start: dict[str, int] = {}
    for edge in test_edges:
        label = labels_by_edge[edge["id"]]
        if label["label"] != "malicious":
            continue
        for action_id in _action_ids(label):
            ground_start[action_id] = min(
                ground_start.get(action_id, edge["timestamp_ns"]), edge["timestamp_ns"]
            )

    alerted = [edge for edge in test_edges if predictions_by_edge.get(edge["id"], 0)]
    components = alert_components(alerted)
    matched_actions: set[str] = set()
    matched_components = 0
    time_to_detect_seconds: list[float] = []
    component_rows: list[dict[str, Any]] = []
    for component in components:
        overlapping: set[str] = set()
        first_alert_by_action: dict[str, int] = {}
        for edge in component:
            label = labels_by_edge[edge["id"]]
            if label["label"] != "malicious":
                continue
            for action_id in _action_ids(label):
                overlapping.add(action_id)
                first_alert_by_action[action_id] = min(
                    first_alert_by_action.get(action_id, edge["timestamp_ns"]),
                    edge["timestamp_ns"],
                )
        candidates = sorted(
            overlapping - matched_actions,
            key=lambda action_id: (ground_start.get(action_id, 0), action_id),
        )
        matched_action = candidates[0] if candidates else None
        if matched_action is not None:
            matched_actions.add(matched_action)
            matched_components += 1
            time_to_detect_seconds.append(
                (first_alert_by_action[matched_action] - ground_start[matched_action])
                / 1_000_000_000
            )
        component_rows.append(
            {
                "first_timestamp_ns": component[0]["timestamp_ns"],
                "last_timestamp_ns": component[-1]["timestamp_ns"],
                "edge_count": len(component),
                "matched_action": matched_action,
                "overlapping_actions": sorted(overlapping),
            }
        )

    tp = matched_components
    fp = len(components) - matched_components
    fn = len(ground_start) - len(matched_actions)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": _safe_div(2 * precision * recall, precision + recall),
        "visible_action_count": len(ground_start),
        "alert_component_count": len(components),
        "matched_action_ids": sorted(matched_actions),
        "mean_time_to_detect_seconds": (
            sum(time_to_detect_seconds) / len(time_to_detect_seconds)
            if time_to_detect_seconds
            else None
        ),
        "median_time_to_detect_seconds": (
            sorted(time_to_detect_seconds)[len(time_to_detect_seconds) // 2]
            if time_to_detect_seconds
            else None
        ),
        "components": component_rows,
    }
