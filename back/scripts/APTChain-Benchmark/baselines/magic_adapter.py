"""Run MAGIC's official masked graph model on neutral EvidenceForge graphs."""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import dgl
import numpy as np
import torch
import torch.nn.functional as functional
from sklearn.neighbors import NearestNeighbors

from baselines.evaluation import action_metrics, binary_metrics
from baselines.graph_io import read_jsonl, split_edges

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINES_ROOT = Path(__file__).resolve().parent
DEFAULT_GRAPHS_ROOT = REPO_ROOT / "provenance_graph" / "graphs"
DEFAULT_RESULTS_ROOT = BASELINES_ROOT / "results"
MAGIC_SOURCE = BASELINES_ROOT / "third_party" / "magic"


def load_build_model() -> Any:
    """Import the model builder from the locked MAGIC source checkout."""
    source = str(MAGIC_SOURCE)
    if source not in sys.path:
        sys.path.insert(0, source)
    from model.autoencoder import build_model

    return build_model


def make_graph(
    edges: list[dict[str, Any]],
    nodes_by_id: dict[str, dict[str, Any]],
    node_type_index: dict[str, int],
    edge_type_index: dict[str, int],
) -> tuple[dgl.DGLGraph, dict[str, int]]:
    """Create MAGIC's one-hot typed DGL graph for one temporal split."""
    node_ids = sorted(
        {
            str(endpoint)
            for edge in edges
            for endpoint in (edge["subject_id"], edge.get("object_id") or edge["subject_id"])
        }
    )
    node_index = {node_id: index for index, node_id in enumerate(node_ids)}
    sources = [node_index[str(edge["subject_id"])] for edge in edges]
    destinations = [node_index[str(edge.get("object_id") or edge["subject_id"])] for edge in edges]
    graph = dgl.graph((sources, destinations), num_nodes=len(node_ids))
    node_types = torch.tensor(
        [node_type_index[str(nodes_by_id[node_id]["type"])] for node_id in node_ids],
        dtype=torch.long,
    )
    edge_types = torch.tensor(
        [edge_type_index[str(edge["type"])] for edge in edges], dtype=torch.long
    )
    graph.ndata["attr"] = functional.one_hot(node_types, num_classes=len(node_type_index)).float()
    graph.edata["attr"] = functional.one_hot(edge_types, num_classes=len(edge_type_index)).float()
    return graph, node_index


def train_model(
    graph: dgl.DGLGraph,
    node_dim: int,
    edge_dim: int,
    seed: int,
    epochs: int,
) -> tuple[torch.nn.Module, list[float]]:
    """Train MAGIC's official entity-level graph masked autoencoder."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    arguments = SimpleNamespace(
        num_hidden=64,
        num_layers=3,
        negative_slope=0.2,
        mask_rate=0.5,
        alpha_l=3,
        n_dim=node_dim,
        e_dim=edge_dim,
    )
    model = load_build_model()(arguments)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001, weight_decay=5e-4)
    losses: list[float] = []
    model.train()
    for _ in range(epochs):
        loss = model(graph)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        losses.append(float(loss.item()))
    return model, losses


def embeddings(model: torch.nn.Module, graph: dgl.DGLGraph) -> np.ndarray[Any, Any]:
    """Extract official MAGIC node embeddings."""
    model.eval()
    with torch.no_grad():
        return model.embed(graph).cpu().numpy()


def fit_knn(train_embeddings: np.ndarray[Any, Any]) -> tuple[NearestNeighbors, Any, Any, float]:
    """Fit MAGIC's standardized nearest-neighbor entity detector."""
    mean = train_embeddings.mean(axis=0)
    standard_deviation = train_embeddings.std(axis=0)
    normalized = (train_embeddings - mean) / (standard_deviation + 1e-6)
    neighbors = min(max(2, int(len(normalized) * 0.02)), 10, len(normalized))
    model = NearestNeighbors(n_neighbors=neighbors, n_jobs=-1)
    model.fit(normalized)
    distances, _ = model.kneighbors(normalized, n_neighbors=neighbors)
    baseline = float(distances.mean())
    return model, mean, standard_deviation, baseline


def node_scores(
    model: NearestNeighbors,
    values: np.ndarray[Any, Any],
    mean: np.ndarray[Any, Any],
    standard_deviation: np.ndarray[Any, Any],
    baseline: float,
) -> list[float]:
    """Return normalized MAGIC KNN distances for nodes."""
    normalized = (values - mean) / (standard_deviation + 1e-6)
    distances, _ = model.kneighbors(normalized)
    return (distances.mean(axis=1) / (baseline + 1e-12)).tolist()


def project_edge_scores(
    edges: list[dict[str, Any]], node_index: dict[str, int], scores: list[float]
) -> list[float]:
    """Project entity scores to events by the more anomalous endpoint."""
    projected: list[float] = []
    for edge in edges:
        source = scores[node_index[str(edge["subject_id"])]]
        destination = scores[node_index[str(edge.get("object_id") or edge["subject_id"])]]
        projected.append(max(source, destination))
    return projected


def run_dataset(
    dataset_dir: Path,
    raw_output_dir: Path,
    seed: int,
    epochs: int,
) -> dict[str, Any]:
    """Train and evaluate one adapted-source MAGIC run."""
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

    train_graph, _ = make_graph(train_edges, nodes_by_id, node_type_index, edge_type_index)
    validation_graph, validation_index = make_graph(
        validation_edges, nodes_by_id, node_type_index, edge_type_index
    )
    test_graph, test_index = make_graph(test_edges, nodes_by_id, node_type_index, edge_type_index)
    model, losses = train_model(
        train_graph, len(node_type_index), len(edge_type_index), seed, epochs
    )
    detector, mean, standard_deviation, baseline = fit_knn(embeddings(model, train_graph))
    validation_node_scores = node_scores(
        detector,
        embeddings(model, validation_graph),
        mean,
        standard_deviation,
        baseline,
    )
    validation_scores = project_edge_scores(
        validation_edges, validation_index, validation_node_scores
    )
    threshold = max(validation_scores)
    test_node_scores = node_scores(
        detector,
        embeddings(model, test_graph),
        mean,
        standard_deviation,
        baseline,
    )
    test_scores = project_edge_scores(test_edges, test_index, test_node_scores)
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
        "adapter_class": "source_model_input_adapter",
        "source_model": "baselines/third_party/magic/model/autoencoder.py",
        "compatibility_patch": "baselines/patches/magic-small-graph-sampling.patch",
        "threshold_policy": "maximum clean-validation projected entity score",
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
    """Write machine-readable and Markdown MAGIC results."""
    output = {
        "schema_version": "1.0",
        "method": "MAGIC",
        "reproduction_scope": "official GMAE model with neutral DGL input adapter",
        "runs": rows,
        "macro_mean_event": aggregate_metrics(rows, "event_metrics"),
        "macro_mean_action": aggregate_metrics(rows, "action_metrics"),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# MAGIC adapted-source results",
        "",
        "The locked upstream masked graph autoencoder and KNN entity detector are executed "
        "directly. Entity scores are projected to events using the maximum endpoint score.",
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
    """Run MAGIC over all converted scenarios."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--graphs-root", type=Path, default=DEFAULT_GRAPHS_ROOT)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--dataset", action="append", dest="datasets")
    parser.add_argument("--seeds", default="0,1,2,3,4")
    parser.add_argument("--epochs", type=int, default=50)
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
            print(f"MAGIC {dataset_dir.name} seed={seed}", flush=True)
            rows.append(
                run_dataset(
                    dataset_dir,
                    args.results_root / "raw" / "magic" / dataset_dir.name,
                    seed,
                    args.epochs,
                )
            )
    write_summary(rows, args.results_root / "magic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
