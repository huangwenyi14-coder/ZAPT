"""Modern PyG API port of ThreaTrace for neutral EvidenceForge graphs."""

from __future__ import annotations

import argparse
import json
import random
import statistics
import time
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as functional
from torch_geometric.nn import SAGEConv

from baselines.evaluation import action_metrics, binary_metrics
from baselines.graph_io import read_jsonl, split_edges

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINES_ROOT = Path(__file__).resolve().parent
DEFAULT_GRAPHS_ROOT = REPO_ROOT / "provenance_graph" / "graphs"
DEFAULT_RESULTS_ROOT = BASELINES_ROOT / "results"


class ThreaTraceSAGE(nn.Module):
    """Two-layer GraphSAGE architecture from the locked ThreaTrace source."""

    def __init__(self, input_dim: int, output_dim: int) -> None:
        super().__init__()
        self.first = SAGEConv(input_dim, 32, normalize=False)
        self.second = SAGEConv(32, output_dim, normalize=False)

    def forward(self, features: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        hidden = functional.relu(self.first(features, edge_index))
        hidden = functional.dropout(hidden, p=0.5, training=self.training)
        return functional.log_softmax(self.second(hidden, edge_index), dim=1)


def make_graph(
    edges: list[dict[str, Any]],
    nodes_by_id: dict[str, dict[str, Any]],
    node_type_index: dict[str, int],
    edge_type_index: dict[str, int],
) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, dict[str, int]]:
    """Apply ThreaTrace's incoming/outgoing edge-type count featurization."""
    node_ids = sorted(
        {
            str(endpoint)
            for edge in edges
            for endpoint in (edge["subject_id"], edge.get("object_id") or edge["subject_id"])
        }
    )
    node_index = {node_id: index for index, node_id in enumerate(node_ids)}
    edge_type_count = len(edge_type_index)
    features = torch.zeros((len(node_ids), edge_type_count * 2), dtype=torch.float32)
    source_indices: list[int] = []
    destination_indices: list[int] = []
    for edge in edges:
        source = node_index[str(edge["subject_id"])]
        destination = node_index[str(edge.get("object_id") or edge["subject_id"])]
        edge_type = edge_type_index[str(edge["type"])]
        source_indices.append(source)
        destination_indices.append(destination)
        features[source, edge_type] += 1
        features[destination, edge_type + edge_type_count] += 1
    labels = torch.tensor(
        [node_type_index[str(nodes_by_id[node_id]["type"])] for node_id in node_ids],
        dtype=torch.long,
    )
    edge_index = torch.tensor([source_indices, destination_indices], dtype=torch.long)
    return features, labels, edge_index, node_index


def train_model(
    features: torch.Tensor,
    labels: torch.Tensor,
    edge_index: torch.Tensor,
    output_dim: int,
    seed: int,
    epochs: int,
) -> tuple[ThreaTraceSAGE, list[float]]:
    """Train using ThreaTrace's optimizer, dropout, and node-type objective."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    model = ThreaTraceSAGE(features.shape[1], output_dim)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=5e-4)
    losses: list[float] = []
    for _ in range(epochs):
        model.train()
        optimizer.zero_grad()
        loss = functional.nll_loss(model(features, edge_index), labels)
        loss.backward()
        optimizer.step()
        losses.append(float(loss.item()))
    return model, losses


def node_scores(
    model: ThreaTraceSAGE,
    features: torch.Tensor,
    labels: torch.Tensor,
    edge_index: torch.Tensor,
) -> list[float]:
    """Score nodes by their source objective's true-type negative log likelihood."""
    model.eval()
    with torch.no_grad():
        return functional.nll_loss(model(features, edge_index), labels, reduction="none").tolist()


def project_edge_scores(
    edges: list[dict[str, Any]], node_index: dict[str, int], scores: list[float]
) -> list[float]:
    """Project anomalous node-type scores to their incident events."""
    return [
        max(
            scores[node_index[str(edge["subject_id"])]],
            scores[node_index[str(edge.get("object_id") or edge["subject_id"])]],
        )
        for edge in edges
    ]


def run_dataset(
    dataset_dir: Path,
    raw_output_dir: Path,
    seed: int,
    epochs: int,
) -> dict[str, Any]:
    """Train and evaluate one ThreaTrace API-port run."""
    started = time.perf_counter()
    nodes = read_jsonl(dataset_dir / "nodes.jsonl")
    edges = read_jsonl(dataset_dir / "edges.jsonl")
    labels = read_jsonl(dataset_dir / "labels.jsonl")
    nodes_by_id = {str(node["id"]): node for node in nodes}
    labels_by_edge = {str(label["edge_id"]): label for label in labels}
    train_edges, validation_edges, test_edges, attack_start = split_edges(edges, labels_by_edge)
    node_type_index = {
        value: index for index, value in enumerate(sorted({str(node["type"]) for node in nodes}))
    }
    edge_type_index = {
        value: index for index, value in enumerate(sorted({str(edge["type"]) for edge in edges}))
    }
    train_features, train_labels, train_index, _ = make_graph(
        train_edges, nodes_by_id, node_type_index, edge_type_index
    )
    validation_features, validation_labels, validation_edge_index, validation_index = make_graph(
        validation_edges, nodes_by_id, node_type_index, edge_type_index
    )
    test_features, test_labels, test_edge_index, test_index = make_graph(
        test_edges, nodes_by_id, node_type_index, edge_type_index
    )
    model, losses = train_model(
        train_features,
        train_labels,
        train_index,
        len(node_type_index),
        seed,
        epochs,
    )
    validation_scores = project_edge_scores(
        validation_edges,
        validation_index,
        node_scores(model, validation_features, validation_labels, validation_edge_index),
    )
    threshold = max(validation_scores)
    test_scores = project_edge_scores(
        test_edges,
        test_index,
        node_scores(model, test_features, test_labels, test_edge_index),
    )
    predictions = [int(score > threshold) for score in test_scores]
    truth = [int(labels_by_edge[edge["id"]]["label"] == "malicious") for edge in test_edges]
    predictions_by_edge = {
        str(edge["id"]): prediction
        for edge, prediction in zip(test_edges, predictions, strict=True)
    }

    raw_output_dir.mkdir(parents=True, exist_ok=True)
    with (raw_output_dir / f"seed-{seed}.jsonl").open("w", encoding="utf-8") as handle:
        for edge, score, prediction in zip(test_edges, test_scores, predictions, strict=True):
            handle.write(
                json.dumps(
                    {
                        "edge_id": edge["id"],
                        "timestamp_ns": edge["timestamp_ns"],
                        "score": score,
                        "threshold": threshold,
                        "alert": bool(prediction),
                    },
                    separators=(",", ":"),
                )
                + "\n"
            )
    return {
        "dataset": dataset_dir.name,
        "seed": seed,
        "adapter_class": "algorithm_api_port",
        "source_reference": "baselines/third_party/threatrace/scripts/train_darpatc.py",
        "port_reason": "published PyG 1.4 NeighborSampler/data-flow API is unavailable",
        "threshold_policy": "maximum clean-validation node-type loss",
        "attack_start_ns": attack_start,
        "train_edge_count": len(train_edges),
        "validation_edge_count": len(validation_edges),
        "test_edge_count": len(test_edges),
        "threshold": threshold,
        "final_train_loss": losses[-1],
        "event_metrics": binary_metrics(truth, predictions, test_scores),
        "action_metrics": action_metrics(test_edges, labels_by_edge, predictions_by_edge),
        "runtime_seconds": time.perf_counter() - started,
    }


def aggregate_metrics(rows: list[dict[str, Any]], key: str) -> dict[str, float]:
    """Average core metrics across scenario/seed runs."""
    return {
        field: statistics.mean(float(row[key][field]) for row in rows)
        for field in ("precision", "recall", "f1")
    }


def write_summary(rows: list[dict[str, Any]], output_dir: Path) -> None:
    """Write machine-readable and Markdown ThreaTrace results."""
    output = {
        "schema_version": "1.0",
        "method": "ThreaTrace",
        "reproduction_scope": "modern PyG API port of locked source architecture/objective",
        "runs": rows,
        "macro_mean_event": aggregate_metrics(rows, "event_metrics"),
        "macro_mean_action": aggregate_metrics(rows, "action_metrics"),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# ThreaTrace API-port results",
        "",
        "This is a modern PyG port of the locked two-layer GraphSAGE and node-type "
        "prediction objective, not an unmodified-source run.",
        "",
        "| Dataset | Seed | Event P / R / F1 | Action P / R / F1 |",
        "|---|---:|---:|---:|",
    ]
    for row in rows:
        event = row["event_metrics"]
        action = row["action_metrics"]
        lines.append(
            f"| {row['dataset']} | {row['seed']} | "
            f"{event['precision']:.4f} / {event['recall']:.4f} / {event['f1']:.4f} | "
            f"{action['precision']:.4f} / {action['recall']:.4f} / {action['f1']:.4f} |"
        )
    event_mean = output["macro_mean_event"]
    action_mean = output["macro_mean_action"]
    lines.extend(
        [
            "",
            f"Macro mean event P/R/F1: **{event_mean['precision']:.4f} / "
            f"{event_mean['recall']:.4f} / {event_mean['f1']:.4f}**.",
            f"Macro mean action P/R/F1: **{action_mean['precision']:.4f} / "
            f"{action_mean['recall']:.4f} / {action_mean['f1']:.4f}**.",
            "",
        ]
    )
    (output_dir / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    """Run ThreaTrace over all converted scenarios."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--graphs-root", type=Path, default=DEFAULT_GRAPHS_ROOT)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--dataset", action="append", dest="datasets")
    parser.add_argument("--seeds", default="0,1,2,3,4")
    parser.add_argument("--epochs", type=int, default=30)
    args = parser.parse_args()
    selected = set(args.datasets or [])
    dataset_dirs = sorted(
        directory
        for directory in args.graphs_root.iterdir()
        if directory.is_dir()
        and (directory / "manifest.json").exists()
        and (not selected or directory.name in selected)
    )
    if not dataset_dirs:
        parser.error("no converted datasets selected")
    seeds = [int(value) for value in args.seeds.split(",") if value.strip()]
    rows: list[dict[str, Any]] = []
    for dataset_dir in dataset_dirs:
        for seed in seeds:
            print(f"ThreaTrace {dataset_dir.name} seed={seed}", flush=True)
            rows.append(
                run_dataset(
                    dataset_dir,
                    args.results_root / "raw" / "threatrace" / dataset_dir.name,
                    seed,
                    args.epochs,
                )
            )
    write_summary(rows, args.results_root / "threatrace")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
