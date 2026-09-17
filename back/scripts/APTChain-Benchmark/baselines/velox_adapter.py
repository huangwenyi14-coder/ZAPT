"""Run a PIDSMaker VELOX-compatible edge detector on neutral EvidenceForge graphs.

The adapter preserves VELOX's published Word2Vec featurization, linear node
encoder, edge MLP, edge-type prediction objective, and maximum-validation-loss
threshold. It replaces only PIDSMaker's PostgreSQL/DARPA parser and PyG batching
with direct reads of ``provenance_graph/graphs``.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import statistics
import time
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as functional
from gensim.models import Word2Vec
from nltk.tokenize import word_tokenize

from baselines.evaluation import action_metrics, binary_metrics

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GRAPHS_ROOT = REPO_ROOT / "provenance_graph" / "graphs"
DEFAULT_RESULTS_ROOT = Path(__file__).resolve().parent / "results"


class VeloxEdgeModel(nn.Module):
    """VELOX linear encoder and edge-type MLP from PIDSMaker's locked config."""

    def __init__(self, feature_dim: int, hidden_dim: int, edge_type_count: int) -> None:
        super().__init__()
        self.node_encoder = nn.Linear(feature_dim, hidden_dim)
        self.source_projection = nn.Linear(hidden_dim, hidden_dim * 2)
        self.destination_projection = nn.Linear(hidden_dim, hidden_dim * 2)
        self.edge_decoder = nn.Sequential(
            nn.Linear(hidden_dim * 4, hidden_dim * 2),
            nn.ReLU(),
            nn.Linear(hidden_dim * 2, edge_type_count),
        )

    def forward(self, source: torch.Tensor, destination: torch.Tensor) -> torch.Tensor:
        source_hidden = self.node_encoder(source)
        destination_hidden = self.node_encoder(destination)
        pair = torch.cat(
            [
                self.source_projection(source_hidden),
                self.destination_projection(destination_hidden),
            ],
            dim=-1,
        )
        return self.edge_decoder(pair)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read one JSON-lines artifact."""
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def node_label(node: dict[str, Any]) -> tuple[str, str]:
    """Build the same kind of type-aware text label expected by PIDSMaker."""
    node_type = str(node["type"])
    properties = node.get("properties") or {}
    if node_type == "SUBJECT":
        category = "subject"
        parts = [
            "subject",
            properties.get("image_path") or properties.get("path") or "",
            properties.get("command_line") or properties.get("cmd_line") or "",
        ]
    elif node_type == "NET_FLOW_OBJECT":
        category = "netflow"
        parts = [
            "netflow",
            properties.get("local_ip") or properties.get("source_ip") or "",
            str(properties.get("local_port") or properties.get("source_port") or ""),
            properties.get("remote_ip") or properties.get("destination_ip") or "",
            str(properties.get("remote_port") or properties.get("destination_port") or ""),
        ]
    else:
        category = "file"
        parts = [
            node_type.lower(),
            properties.get("path")
            or properties.get("key")
            or properties.get("name")
            or properties.get("principal")
            or node.get("natural_key")
            or "",
        ]
    return category, " ".join(str(part) for part in parts if part not in (None, ""))


def tokenize(label: str, category: str) -> list[str]:
    """Tokenize labels with PIDSMaker-compatible path and netflow separators."""
    normalized = re.sub(r"\\+", "/", label)
    if category in {"subject", "file"}:
        normalized = normalized.replace("/", " / ")
    else:
        normalized = normalized.replace(":", " : ").replace(".", " . ")
    tokens = word_tokenize(normalized, preserve_line=True)
    return tokens or [""]


def _declining_weights(length: int, decline_percentage: float = 30.0) -> list[float]:
    delta = -1 / length * decline_percentage / 100
    first = 1 / length - 0.5 * (length - 1) * delta
    return [first + index * delta for index in range(length)]


def train_word2vec(
    nodes_by_id: dict[str, dict[str, Any]],
    training_node_ids: set[str],
    seed: int,
    feature_dim: int,
    epochs: int = 50,
) -> Word2Vec:
    """Train VELOX Word2Vec only on unique node labels in the clean train split."""
    seen_labels: set[str] = set()
    corpus: list[list[str]] = []
    for node_id in sorted(training_node_ids):
        category, label = node_label(nodes_by_id[node_id])
        if label in seen_labels:
            continue
        seen_labels.add(label)
        corpus.append(tokenize(label, category))
    if not corpus:
        raise ValueError("clean training split produced an empty node-label corpus")
    model = Word2Vec(
        corpus,
        alpha=0.025,
        vector_size=feature_dim,
        window=5,
        min_count=1,
        sg=1,
        workers=1,
        epochs=1,
        compute_loss=True,
        negative=5,
        seed=seed,
    )
    for _ in range(epochs - 1):
        model.train(corpus, epochs=1, total_examples=len(corpus), compute_loss=True)
    return model


def embed_nodes(
    nodes: list[dict[str, Any]], model: Word2Vec, feature_dim: int
) -> tuple[torch.Tensor, dict[str, int], float]:
    """Apply PIDSMaker's declining token weights and L2 normalization."""
    vectors: list[np.ndarray[Any, np.dtype[np.float32]]] = []
    node_index: dict[str, int] = {}
    zero_nodes = 0
    for index, node in enumerate(nodes):
        category, label = node_label(node)
        tokens = tokenize(label, category)
        weights = _declining_weights(len(tokens))
        weighted = [
            weight * (model.wv[token] if token in model.wv else np.zeros(feature_dim))
            for weight, token in zip(weights, tokens, strict=True)
        ]
        vector = np.mean(weighted, axis=0).astype(np.float32)
        norm = float(np.linalg.norm(vector))
        if norm == 0:
            zero_nodes += 1
        vector = vector / (norm + 1e-12)
        vectors.append(vector)
        node_index[str(node["id"])] = index
    return torch.from_numpy(np.stack(vectors)), node_index, zero_nodes / len(nodes)


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


def endpoint_tensor(
    edges: list[dict[str, Any]], features: torch.Tensor, node_index: dict[str, int]
) -> tuple[torch.Tensor, torch.Tensor]:
    """Gather source/destination features, using a self-edge for unary events."""
    source_indices = [node_index[str(edge["subject_id"])] for edge in edges]
    destination_indices = [
        node_index[str(edge.get("object_id") or edge["subject_id"])] for edge in edges
    ]
    return features[source_indices], features[destination_indices]


def edge_targets(edges: list[dict[str, Any]], edge_type_index: dict[str, int]) -> torch.Tensor:
    """Map canonical event types to decoder class indices."""
    return torch.tensor([edge_type_index[str(edge["type"])] for edge in edges], dtype=torch.long)


def score_edges(
    model: VeloxEdgeModel,
    edges: list[dict[str, Any]],
    features: torch.Tensor,
    node_index: dict[str, int],
    edge_type_index: dict[str, int],
    batch_size: int,
) -> list[float]:
    """Return per-edge cross-entropy anomaly scores."""
    model.eval()
    scores: list[float] = []
    with torch.no_grad():
        for start in range(0, len(edges), batch_size):
            batch = edges[start : start + batch_size]
            source, destination = endpoint_tensor(batch, features, node_index)
            targets = edge_targets(batch, edge_type_index)
            logits = model(source, destination)
            scores.extend(functional.cross_entropy(logits, targets, reduction="none").tolist())
    return scores


def train_model(
    model: VeloxEdgeModel,
    train_edges: list[dict[str, Any]],
    features: torch.Tensor,
    node_index: dict[str, int],
    edge_type_index: dict[str, int],
    seed: int,
    epochs: int,
    batch_size: int,
) -> list[float]:
    """Train the VELOX self-supervised edge-type objective."""
    generator = torch.Generator().manual_seed(seed)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.0001, weight_decay=0.00001)
    epoch_losses: list[float] = []
    for _ in range(epochs):
        model.train()
        permutation = torch.randperm(len(train_edges), generator=generator).tolist()
        total_loss = 0.0
        for start in range(0, len(permutation), batch_size):
            indices = permutation[start : start + batch_size]
            batch = [train_edges[index] for index in indices]
            source, destination = endpoint_tensor(batch, features, node_index)
            targets = edge_targets(batch, edge_type_index)
            optimizer.zero_grad()
            loss = functional.cross_entropy(model(source, destination), targets)
            loss.backward()
            optimizer.step()
            total_loss += float(loss.item()) * len(batch)
        epoch_losses.append(total_loss / len(train_edges))
    return epoch_losses


def run_dataset(
    dataset_dir: Path,
    raw_output_dir: Path,
    seed: int,
    epochs: int,
    batch_size: int,
    feature_dim: int,
) -> dict[str, Any]:
    """Train and evaluate one VELOX run on one scenario."""
    started = time.perf_counter()
    nodes = read_jsonl(dataset_dir / "nodes.jsonl")
    edges = read_jsonl(dataset_dir / "edges.jsonl")
    labels = read_jsonl(dataset_dir / "labels.jsonl")
    labels_by_edge = {str(label["edge_id"]): label for label in labels}
    nodes_by_id = {str(node["id"]): node for node in nodes}
    train_edges, validation_edges, test_edges, attack_start = split_edges(edges, labels_by_edge)

    training_node_ids = {
        str(endpoint)
        for edge in train_edges
        for endpoint in (edge["subject_id"], edge.get("object_id"))
        if endpoint
    }
    embedding_model = train_word2vec(
        nodes_by_id,
        training_node_ids,
        seed=seed,
        feature_dim=feature_dim,
    )
    features, node_index, zero_feature_fraction = embed_nodes(nodes, embedding_model, feature_dim)
    edge_types = sorted({str(edge["type"]) for edge in edges})
    edge_type_index = {edge_type: index for index, edge_type in enumerate(edge_types)}

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    model = VeloxEdgeModel(feature_dim, 128, len(edge_types))
    epoch_losses = train_model(
        model,
        train_edges,
        features,
        node_index,
        edge_type_index,
        seed,
        epochs,
        batch_size,
    )
    validation_scores = score_edges(
        model,
        validation_edges,
        features,
        node_index,
        edge_type_index,
        batch_size,
    )
    threshold = max(validation_scores)
    test_scores = score_edges(
        model,
        test_edges,
        features,
        node_index,
        edge_type_index,
        batch_size,
    )
    predictions = [int(score > threshold) for score in test_scores]
    truth = [int(labels_by_edge[edge["id"]]["label"] == "malicious") for edge in test_edges]
    predictions_by_edge = {
        str(edge["id"]): prediction
        for edge, prediction in zip(test_edges, predictions, strict=True)
    }

    raw_output_dir.mkdir(parents=True, exist_ok=True)
    alert_path = raw_output_dir / f"seed-{seed}.jsonl"
    with alert_path.open("w", encoding="utf-8") as handle:
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

    action_result = action_metrics(test_edges, labels_by_edge, predictions_by_edge)
    action_result.pop("components")
    return {
        "dataset": dataset_dir.name,
        "seed": seed,
        "split": {
            "attack_start_ns": attack_start,
            "train_edges": len(train_edges),
            "validation_edges": len(validation_edges),
            "test_edges": len(test_edges),
            "test_malicious_edges": sum(truth),
        },
        "model": {
            "feature_dim": feature_dim,
            "hidden_dim": 128,
            "edge_type_count": len(edge_types),
            "edge_types": edge_types,
            "epochs": epochs,
            "batch_size": batch_size,
            "final_train_loss": epoch_losses[-1],
            "validation_threshold": threshold,
            "zero_feature_node_fraction": zero_feature_fraction,
        },
        "event": binary_metrics(truth, predictions, test_scores),
        "action": action_result,
        "runtime_seconds": time.perf_counter() - started,
        "raw_alerts": str(alert_path.resolve().relative_to(REPO_ROOT)),
    }


def _mean(values: list[float | int | None]) -> float | None:
    concrete = [float(value) for value in values if value is not None]
    return sum(concrete) / len(concrete) if concrete else None


def aggregate_runs(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate counts across datasets for each seed and macro-average scalar metrics."""
    by_seed: dict[int, list[dict[str, Any]]] = {}
    for run in runs:
        by_seed.setdefault(int(run["seed"]), []).append(run)
    aggregates: list[dict[str, Any]] = []
    for seed, seed_runs in sorted(by_seed.items()):
        event_counts = {
            key: sum(int(run["event"][key]) for run in seed_runs)
            for key in ("tp", "fp", "tn", "fn")
        }
        event_truth = [1] * event_counts["tp"] + [0] * event_counts["fp"]
        event_predictions = [1] * (event_counts["tp"] + event_counts["fp"])
        event_truth += [0] * event_counts["tn"] + [1] * event_counts["fn"]
        event_predictions += [0] * (event_counts["tn"] + event_counts["fn"])
        event_micro = binary_metrics(event_truth, event_predictions)

        action_tp = sum(int(run["action"]["tp"]) for run in seed_runs)
        action_fp = sum(int(run["action"]["fp"]) for run in seed_runs)
        action_fn = sum(int(run["action"]["fn"]) for run in seed_runs)
        action_precision = action_tp / (action_tp + action_fp) if action_tp + action_fp else 0.0
        action_recall = action_tp / (action_tp + action_fn) if action_tp + action_fn else 0.0
        aggregates.append(
            {
                "seed": seed,
                "event_micro": event_micro,
                "event_macro": {
                    key: _mean([run["event"].get(key) for run in seed_runs])
                    for key in (
                        "precision",
                        "recall",
                        "f1",
                        "accuracy",
                        "balanced_accuracy",
                        "mcc",
                        "auroc",
                        "average_precision",
                        "false_positives_per_million_benign",
                    )
                },
                "action_micro": {
                    "tp": action_tp,
                    "fp": action_fp,
                    "fn": action_fn,
                    "precision": action_precision,
                    "recall": action_recall,
                    "f1": (
                        2 * action_precision * action_recall / (action_precision + action_recall)
                        if action_precision + action_recall
                        else 0.0
                    ),
                },
                "runtime_seconds": sum(float(run["runtime_seconds"]) for run in seed_runs),
            }
        )
    across_seeds: dict[str, dict[str, dict[str, float]]] = {}
    for view in ("event_micro", "action_micro"):
        across_seeds[view] = {}
        for metric in ("precision", "recall", "f1"):
            values = [float(aggregate[view][metric]) for aggregate in aggregates]
            across_seeds[view][metric] = {
                "mean": statistics.mean(values),
                "population_stddev": statistics.pstdev(values),
            }
    return {"by_seed": aggregates, "across_seeds": across_seeds}


def write_markdown(summary: dict[str, Any], path: Path) -> None:
    """Write a concise, human-readable benchmark table."""
    lines = [
        "# VELOX Adapted Reproduction Results",
        "",
        "The threshold is the maximum clean validation loss, matching the locked PIDSMaker VELOX configuration.",
        "",
        "| Dataset | Seed | Event P | Event R | Event F1 | AUPRC | FP / 1M benign | Action P | Action R | Action F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for run in summary["runs"]:
        event = run["event"]
        action = run["action"]
        lines.append(
            f"| {run['dataset']} | {run['seed']} | {event['precision']:.4f} | "
            f"{event['recall']:.4f} | {event['f1']:.4f} | "
            f"{(event['average_precision'] or 0):.4f} | "
            f"{event['false_positives_per_million_benign']:.1f} | "
            f"{action['precision']:.4f} | {action['recall']:.4f} | {action['f1']:.4f} |"
        )
    lines.extend(["", "## Micro aggregate", ""])
    for aggregate in summary["aggregate"]["by_seed"]:
        event = aggregate["event_micro"]
        action = aggregate["action_micro"]
        lines.append(
            f"- Seed {aggregate['seed']}: event P/R/F1 = {event['precision']:.4f}/"
            f"{event['recall']:.4f}/{event['f1']:.4f}; action P/R/F1 = "
            f"{action['precision']:.4f}/{action['recall']:.4f}/{action['f1']:.4f}."
        )
    across = summary["aggregate"]["across_seeds"]
    lines.extend(["", "## Across-seed stability", ""])
    for view in ("event_micro", "action_micro"):
        metrics = across[view]
        lines.append(
            f"- {view}: P/R/F1 mean = {metrics['precision']['mean']:.4f}/"
            f"{metrics['recall']['mean']:.4f}/{metrics['f1']['mean']:.4f}; "
            f"population standard deviation = {metrics['precision']['population_stddev']:.4f}/"
            f"{metrics['recall']['population_stddev']:.4f}/"
            f"{metrics['f1']['population_stddev']:.4f}."
        )
    lines.extend(
        [
            "",
            "These are EvidenceForge results under `baselines/EVALUATION_PROTOCOL.md`, not the paper's DARPA numbers.",
            "The adapter changes only ingestion/batching and runs the published objective on CPU with modern PyTorch.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    """Run VELOX over all or selected converted scenarios."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--graphs-root", type=Path, default=DEFAULT_GRAPHS_ROOT)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--dataset", action="append")
    parser.add_argument("--seeds", default="0", help="Comma-separated integer seeds.")
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--batch-size", type=int, default=1024)
    parser.add_argument("--feature-dim", type=int, default=128)
    args = parser.parse_args()

    selected = set(args.dataset or [])
    dataset_dirs = sorted(path for path in args.graphs_root.iterdir() if path.is_dir())
    if selected:
        dataset_dirs = [path for path in dataset_dirs if path.name in selected]
    if not dataset_dirs:
        raise ValueError("no converted dataset directories selected")
    seeds = [int(seed.strip()) for seed in args.seeds.split(",") if seed.strip()]

    runs: list[dict[str, Any]] = []
    for dataset_dir in dataset_dirs:
        for seed in seeds:
            print(f"[velox] dataset={dataset_dir.name} seed={seed}", flush=True)
            result = run_dataset(
                dataset_dir,
                args.results_root / "raw" / "velox" / dataset_dir.name,
                seed=seed,
                epochs=args.epochs,
                batch_size=args.batch_size,
                feature_dim=args.feature_dim,
            )
            runs.append(result)
            print(
                f"[velox] event_f1={result['event']['f1']:.4f} "
                f"action_f1={result['action']['f1']:.4f} "
                f"runtime={result['runtime_seconds']:.1f}s",
                flush=True,
            )

    summary = {
        "schema_version": "1.0",
        "method": "velox",
        "implementation": {
            "upstream": "ubc-provenance/PIDSMaker",
            "upstream_commit": "32602734bc9f896be5fc0f03f0a185c967cd6624",
            "adapter": "baselines.velox_adapter",
            "device": "cpu",
            "seeds": seeds,
        },
        "protocol": "baselines/EVALUATION_PROTOCOL.md",
        "runs": runs,
        "aggregate": aggregate_runs(runs),
    }
    output_dir = args.results_root / "velox"
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    write_markdown(summary, output_dir / "SUMMARY.md")
    print(f"[velox] wrote {summary_path}", flush=True)


if __name__ == "__main__":
    main()
