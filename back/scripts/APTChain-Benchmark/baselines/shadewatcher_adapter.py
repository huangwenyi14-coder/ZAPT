"""Modern PyTorch port of ShadeWatcher's recommendation objective."""

from __future__ import annotations

import argparse
import json
import random
import statistics
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as functional

from baselines.evaluation import action_metrics, binary_metrics
from baselines.graph_io import read_jsonl, split_edges

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINES_ROOT = Path(__file__).resolve().parent
DEFAULT_GRAPHS_ROOT = REPO_ROOT / "provenance_graph" / "graphs"
DEFAULT_RESULTS_ROOT = BASELINES_ROOT / "results"
SHADEWATCHER_SOURCE = BASELINES_ROOT / "third_party" / "shadewatcher" / "recommend"
EMBEDDING_DIM = 32
LAYER_DIMS = (32, 16)


class ShadeWatcherModel(nn.Module):
    """TransR plus high-order GraphSAGE architecture from ShadeWatcher."""

    def __init__(self, node_count: int, relation_count: int) -> None:
        super().__init__()
        self.entity_embedding = nn.Embedding(node_count, EMBEDDING_DIM)
        self.relation_embedding = nn.Embedding(relation_count, EMBEDDING_DIM)
        self.transformation = nn.Parameter(
            torch.empty(relation_count, EMBEDDING_DIM, EMBEDDING_DIM)
        )
        self.sage_layers = nn.ModuleList(
            [
                nn.Linear(EMBEDDING_DIM * 2, LAYER_DIMS[0]),
                nn.Linear(LAYER_DIMS[0] * 2, LAYER_DIMS[1]),
            ]
        )
        nn.init.xavier_uniform_(self.entity_embedding.weight)
        nn.init.xavier_uniform_(self.relation_embedding.weight)
        nn.init.xavier_uniform_(self.transformation)
        for layer in self.sage_layers:
            nn.init.xavier_uniform_(layer.weight)
            nn.init.zeros_(layer.bias)

    def node_embeddings(self, adjacency: torch.Tensor) -> torch.Tensor:
        """Run the source's two normalized GraphSAGE aggregation layers."""
        previous = self.entity_embedding.weight
        embeddings = [previous]
        for layer in self.sage_layers:
            neighbor = torch.sparse.mm(adjacency, previous)
            previous = functional.leaky_relu(layer(torch.cat([previous, neighbor], dim=1)))
            previous = functional.dropout(previous, p=0.2, training=self.training)
            previous = functional.normalize(previous, p=2, dim=1)
            embeddings.append(previous)
        return torch.cat(embeddings, dim=1)

    def transr_distance(
        self, heads: torch.Tensor, relations: torch.Tensor, tails: torch.Tensor
    ) -> torch.Tensor:
        """Return the source TransR squared-distance score."""
        transforms = self.transformation[relations]
        head_vectors = self.entity_embedding(heads).unsqueeze(1)
        tail_vectors = self.entity_embedding(tails).unsqueeze(1)
        projected_heads = torch.bmm(head_vectors, transforms).squeeze(1)
        projected_tails = torch.bmm(tail_vectors, transforms).squeeze(1)
        relation_vectors = self.relation_embedding(relations)
        return ((projected_heads + relation_vectors - projected_tails) ** 2).sum(dim=1)

    def attention_score(
        self, heads: torch.Tensor, relations: torch.Tensor, tails: torch.Tensor
    ) -> torch.Tensor:
        """Compute the source's TransR knowledge-attention coefficient."""
        transforms = self.transformation[relations]
        head_vectors = torch.bmm(self.entity_embedding(heads).unsqueeze(1), transforms).squeeze(1)
        tail_vectors = torch.bmm(self.entity_embedding(tails).unsqueeze(1), transforms).squeeze(1)
        relation_vectors = self.relation_embedding(relations)
        return (tail_vectors * torch.tanh(head_vectors + relation_vectors)).sum(dim=1)


def edge_endpoints(
    edges: list[dict[str, Any]], node_index: dict[str, int]
) -> tuple[torch.Tensor, torch.Tensor]:
    """Map neutral event roles to ShadeWatcher interaction endpoints."""
    heads = torch.tensor([node_index[str(edge["subject_id"])] for edge in edges], dtype=torch.long)
    tails = torch.tensor(
        [node_index[str(edge.get("object_id") or edge["subject_id"])] for edge in edges],
        dtype=torch.long,
    )
    return heads, tails


def build_attention_adjacency(
    model: ShadeWatcherModel,
    edges: list[dict[str, Any]],
    node_index: dict[str, int],
    edge_type_index: dict[str, int],
) -> torch.Tensor:
    """Build the fixed knowledge-aware adjacency used by the source GNN."""
    heads, tails = edge_endpoints(edges, node_index)
    event_relations = torch.tensor(
        [edge_type_index[str(edge["type"])] + 1 for edge in edges], dtype=torch.long
    )
    # ShadeWatcher includes both a generic interaction matrix (relation 0) and
    # one matrix per typed knowledge-graph relation.
    all_heads = torch.cat([heads, heads])
    all_tails = torch.cat([tails, tails])
    all_relations = torch.cat([torch.zeros_like(event_relations), event_relations])
    model.eval()
    with torch.no_grad():
        raw_scores = model.attention_score(all_heads, all_relations, all_tails)

    positions_by_head: dict[int, list[int]] = defaultdict(list)
    for position, head in enumerate(all_heads.tolist()):
        positions_by_head[head].append(position)
    weights = torch.empty_like(raw_scores)
    for positions in positions_by_head.values():
        index = torch.tensor(positions, dtype=torch.long)
        weights[index] = functional.softmax(raw_scores[index], dim=0)
    adjacency = torch.sparse_coo_tensor(
        torch.stack([all_heads, all_tails]),
        weights,
        size=(len(node_index), len(node_index)),
    )
    return adjacency.coalesce()


def neighbor_sets(edges: list[dict[str, Any]], node_index: dict[str, int]) -> dict[int, set[int]]:
    """Return observed interaction tails keyed by head entity."""
    heads, tails = edge_endpoints(edges, node_index)
    result: dict[int, set[int]] = defaultdict(set)
    for head, tail in zip(heads.tolist(), tails.tolist(), strict=True):
        result[head].add(tail)
    return result


def random_non_neighbors(
    heads: torch.Tensor,
    observed: dict[int, set[int]],
    node_count: int,
    rate: int,
    generator: torch.Generator,
) -> torch.Tensor:
    """Sample the source's synthetic anomalous (unobserved) interactions."""
    samples: list[int] = []
    for head in heads.tolist():
        selected: set[int] = set()
        while len(selected) < rate:
            candidate = int(torch.randint(node_count, (1,), generator=generator).item())
            if candidate not in observed.get(head, set()) and candidate not in selected:
                selected.add(candidate)
        samples.extend(sorted(selected))
    return torch.tensor(samples, dtype=torch.long)


def train_model(
    train_edges: list[dict[str, Any]],
    node_index: dict[str, int],
    edge_type_index: dict[str, int],
    seed: int,
    epochs: int,
    batch_size: int,
) -> tuple[ShadeWatcherModel, torch.Tensor, list[float]]:
    """Train the high-order interaction and first-order TransR objectives."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    generator = torch.Generator().manual_seed(seed)
    model = ShadeWatcherModel(len(node_index), len(edge_type_index) + 1)
    adjacency = build_attention_adjacency(model, train_edges, node_index, edge_type_index)
    observed = neighbor_sets(train_edges, node_index)
    all_heads, all_tails = edge_endpoints(train_edges, node_index)
    all_relations = torch.tensor(
        [edge_type_index[str(edge["type"])] + 1 for edge in train_edges], dtype=torch.long
    )
    interaction_optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    knowledge_optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    sample_size = min(batch_size, len(train_edges))
    losses: list[float] = []
    for _ in range(epochs):
        positions = torch.randint(
            len(train_edges), (sample_size,), generator=generator, dtype=torch.long
        )
        heads = all_heads[positions]
        tails = all_tails[positions]
        random_tails = random_non_neighbors(
            heads,
            observed,
            len(node_index),
            rate=2,
            generator=generator,
        )

        interaction_optimizer.zero_grad()
        model.train()
        embeddings = model.node_embeddings(adjacency)
        observed_scores = (embeddings[heads] * embeddings[tails]).sum(dim=1)
        repeated_heads = heads.repeat_interleave(2)
        anomalous_scores = (embeddings[repeated_heads] * embeddings[random_tails]).sum(dim=1)
        anomalous_scores = anomalous_scores.reshape(-1, 2).sum(dim=1)
        interaction_loss = functional.softplus(observed_scores - anomalous_scores).mean()
        interaction_regularizer = 1e-5 * (
            embeddings[heads].square().mean()
            + embeddings[tails].square().mean()
            + embeddings[random_tails].square().mean()
        )
        (interaction_loss + interaction_regularizer).backward()
        interaction_optimizer.step()

        knowledge_optimizer.zero_grad()
        model.train()
        relations = all_relations[positions]
        random_kg_tails = random_non_neighbors(
            heads,
            observed,
            len(node_index),
            rate=2,
            generator=generator,
        )
        observed_distance = model.transr_distance(heads, relations, tails)
        random_distance = model.transr_distance(
            heads.repeat_interleave(2), relations.repeat_interleave(2), random_kg_tails
        )
        random_distance = random_distance.reshape(-1, 2).sum(dim=1)
        knowledge_loss = functional.softplus(observed_distance - random_distance).mean()
        knowledge_regularizer = 1e-5 * (
            model.entity_embedding(heads).square().mean()
            + model.entity_embedding(tails).square().mean()
            + model.entity_embedding(random_kg_tails).square().mean()
            + model.relation_embedding(relations).square().mean()
        )
        (knowledge_loss + knowledge_regularizer).backward()
        knowledge_optimizer.step()
        losses.append(float((interaction_loss + knowledge_loss).item()))
    return model, adjacency, losses


def score_edges(
    model: ShadeWatcherModel,
    adjacency: torch.Tensor,
    edges: list[dict[str, Any]],
    node_index: dict[str, int],
) -> list[float]:
    """Return the source interaction-recommendation score for each event."""
    heads, tails = edge_endpoints(edges, node_index)
    model.eval()
    with torch.no_grad():
        embeddings = model.node_embeddings(adjacency)
        return (embeddings[heads] * embeddings[tails]).sum(dim=1).tolist()


def run_dataset(
    dataset_dir: Path,
    raw_output_dir: Path,
    seed: int,
    epochs: int,
    batch_size: int,
) -> dict[str, Any]:
    """Train and evaluate one ShadeWatcher objective-port run."""
    started = time.perf_counter()
    nodes = read_jsonl(dataset_dir / "nodes.jsonl")
    edges = read_jsonl(dataset_dir / "edges.jsonl")
    labels = read_jsonl(dataset_dir / "labels.jsonl")
    labels_by_edge = {str(label["edge_id"]): label for label in labels}
    train_edges, validation_edges, test_edges, attack_start = split_edges(edges, labels_by_edge)
    node_index = {
        str(node["id"]): index
        for index, node in enumerate(sorted(nodes, key=lambda item: str(item["id"])))
    }
    edge_type_index = {
        value: index for index, value in enumerate(sorted({str(edge["type"]) for edge in edges}))
    }
    model, adjacency, losses = train_model(
        train_edges,
        node_index,
        edge_type_index,
        seed,
        epochs,
        batch_size,
    )
    validation_scores = score_edges(model, adjacency, validation_edges, node_index)
    threshold = max(validation_scores)
    test_scores = score_edges(model, adjacency, test_edges, node_index)
    predictions = [int(score > threshold) for score in test_scores]
    truth = [int(labels_by_edge[str(edge["id"])]["label"] == "malicious") for edge in test_edges]
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
        "source_reference": "baselines/third_party/shadewatcher/recommend",
        "port_reason": "official TensorFlow 1.14/Python 3.6 stack is unavailable on arm64",
        "threshold_policy": "maximum clean-validation interaction score",
        "epochs": epochs,
        "official_default_epochs": 1000,
        "configured_batch_size": batch_size,
        "effective_batch_size": min(batch_size, len(train_edges)),
        "architecture": {
            "entity_embedding_dim": EMBEDDING_DIM,
            "graphsage_layer_dims": list(LAYER_DIMS),
            "interaction_corruptions_per_edge": 2,
            "knowledge_corruptions_per_triple": 2,
        },
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
    """Write ShadeWatcher JSON and Markdown result artifacts."""
    output = {
        "schema_version": "1.0",
        "method": "ShadeWatcher",
        "reproduction_scope": "modern PyTorch port of locked recommendation objectives",
        "protocol_changes": [
            "neutral graph ingestion",
            "maximum clean-validation threshold instead of fixed 1.5",
            "40 benchmark epochs by default instead of upstream's 1000",
        ],
        "runs": rows,
        "macro_mean_event": aggregate_metrics(rows, "event_metrics"),
        "macro_mean_action": aggregate_metrics(rows, "action_metrics"),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# ShadeWatcher objective-port results",
        "",
        "This is a modern PyTorch port of the locked TransR, knowledge-attention, "
        "GraphSAGE, and interaction-ranking objectives. The official Python 3.6 / "
        "TensorFlow 1.14 runtime is unavailable on this arm64 host, and upstream's "
        "included evaluator contains benign samples only.",
        "The benchmark uses 40 epochs by default rather than upstream's 1000 and "
        "calibrates the threshold on the clean validation prefix rather than using "
        "the source's fixed 1.5 threshold.",
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
    """Run ShadeWatcher over all converted scenarios."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--graphs-root", type=Path, default=DEFAULT_GRAPHS_ROOT)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--dataset", action="append", dest="datasets")
    parser.add_argument("--seeds", default="0,1,2,3,4")
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--batch-size", type=int, default=1024)
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
            print(f"ShadeWatcher {dataset_dir.name} seed={seed}", flush=True)
            rows.append(
                run_dataset(
                    dataset_dir,
                    args.results_root / "raw" / "shadewatcher" / dataset_dir.name,
                    seed,
                    args.epochs,
                    args.batch_size,
                )
            )
    write_summary(rows, args.results_root / "shadewatcher")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
