"""Unit tests for detector-independent benchmark metrics."""

import math

from baselines.evaluation import action_metrics, alert_components, binary_metrics


def test_binary_metrics_include_imbalance_metrics() -> None:
    metrics = binary_metrics([1, 1, 0, 0], [1, 0, 1, 0], [0.9, 0.4, 0.8, 0.1])

    assert metrics["tp"] == 1
    assert metrics["fp"] == 1
    assert metrics["tn"] == 1
    assert metrics["fn"] == 1
    assert metrics["f1"] == 0.5
    assert metrics["auroc"] == 0.75
    assert math.isclose(metrics["average_precision"], 5 / 6)


def test_alert_components_join_shared_recent_endpoints() -> None:
    edges = [
        {
            "id": "a",
            "timestamp_ns": 1,
            "sequence": 1,
            "host": "h",
            "subject_id": "p",
            "object_id": "f1",
        },
        {
            "id": "b",
            "timestamp_ns": 2,
            "sequence": 2,
            "host": "h",
            "subject_id": "p",
            "object_id": "f2",
        },
        {
            "id": "c",
            "timestamp_ns": 3,
            "sequence": 3,
            "host": "other",
            "subject_id": "p",
            "object_id": "f3",
        },
    ]

    components = alert_components(edges, gap_ns=10)

    assert [[edge["id"] for edge in component] for component in components] == [["a", "b"], ["c"]]


def test_action_metrics_match_components_one_to_one() -> None:
    edges = [
        {
            "id": "a",
            "timestamp_ns": 10,
            "sequence": 1,
            "host": "h",
            "subject_id": "p1",
            "object_id": "f1",
        },
        {
            "id": "b",
            "timestamp_ns": 20,
            "sequence": 2,
            "host": "h",
            "subject_id": "p2",
            "object_id": "f2",
        },
        {
            "id": "c",
            "timestamp_ns": 30,
            "sequence": 3,
            "host": "h",
            "subject_id": "benign",
            "object_id": "noise",
        },
    ]
    labels = {
        "a": {"label": "malicious", "storyline_id": "s1", "contributing_storyline_ids": []},
        "b": {"label": "malicious", "storyline_id": "s2", "contributing_storyline_ids": []},
        "c": {"label": "benign", "storyline_id": None, "contributing_storyline_ids": []},
    }

    result = action_metrics(edges, labels, {"a": 1, "b": 0, "c": 1})

    assert result["tp"] == 1
    assert result["fp"] == 1
    assert result["fn"] == 1
    assert result["f1"] == 0.5
