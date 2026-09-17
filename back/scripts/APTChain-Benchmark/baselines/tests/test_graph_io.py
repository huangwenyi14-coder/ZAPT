"""Unit tests for neutral graph input and frozen temporal splitting."""

import pytest

from baselines.graph_io import split_edges


def _edge(index: int) -> dict[str, int | str]:
    return {"id": f"e{index}", "timestamp_ns": index, "sequence": index}


def test_split_edges_uses_clean_prefix_and_attack_onward_test() -> None:
    edges = [_edge(index) for index in range(1, 16)]
    labels = {
        str(edge["id"]): {"label": "malicious" if edge["id"] == "e13" else "benign"}
        for edge in edges
    }

    train, validation, test, attack_start = split_edges(edges, labels)

    assert [edge["id"] for edge in train] == [f"e{index}" for index in range(1, 10)]
    assert [edge["id"] for edge in validation] == ["e10", "e11", "e12"]
    assert [edge["id"] for edge in test] == ["e13", "e14", "e15"]
    assert attack_start == 13


def test_split_edges_rejects_dataset_without_malicious_event() -> None:
    edges = [_edge(index) for index in range(1, 12)]
    labels = {str(edge["id"]): {"label": "benign"} for edge in edges}

    with pytest.raises(ValueError, match="no malicious"):
        split_edges(edges, labels)
