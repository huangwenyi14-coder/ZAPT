"""Run KAIROS's official TGN model on neutral EvidenceForge temporal graphs."""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn.functional as functional
from sklearn.feature_extraction import FeatureHasher
from torch_geometric.data import TemporalData
from torch_geometric.loader import TemporalDataLoader
from torch_geometric.nn import TGNMemory
from torch_geometric.nn.models.tgn import IdentityMessage, LastAggregator, LastNeighborLoader

from baselines.evaluation import action_metrics, binary_metrics
from baselines.graph_io import read_jsonl, split_edges

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINES_ROOT = Path(__file__).resolve().parent
DEFAULT_GRAPHS_ROOT = REPO_ROOT / "provenance_graph" / "graphs"
DEFAULT_RESULTS_ROOT = BASELINES_ROOT / "results"
KAIROS_SOURCE = BASELINES_ROOT / "third_party" / "kairos" / "DARPA" / "CADETS_E3"
NODE_EMBEDDING_DIM = 16
NODE_STATE_DIM = 100
EDGE_DIM = 100
TIME_DIM = 100
NEIGHBOR_SIZE = 20


def load_source_models() -> tuple[Any, Any]:
    """Import GraphAttentionEmbedding and LinkPredictor from locked KAIROS source."""
    source = str(KAIROS_SOURCE)
    if source not in sys.path:
        sys.path.insert(0, source)
    from model import GraphAttentionEmbedding, LinkPredictor

    return GraphAttentionEmbedding, LinkPredictor


def node_text(node: dict[str, Any]) -> str:
    """Build KAIROS's hierarchical subject/file/netflow label input."""
    properties = node.get("properties") or {}
    value = (
        properties.get("image_path")
        or properties.get("path")
        or properties.get("remote_ip")
        or properties.get("destination_ip")
        or properties.get("name")
        or node.get("natural_key")
        or node["id"]
    )
    return f"{str(node['type']).lower()}:{value}"


def embed_nodes(nodes: list[dict[str, Any]]) -> tuple[torch.Tensor, dict[str, int]]:
    """Apply KAIROS's 16-dimensional FeatureHasher node representation."""
    ordered = sorted(nodes, key=lambda node: str(node["id"]))
    node_index = {str(node["id"]): index for index, node in enumerate(ordered)}
    hasher = FeatureHasher(n_features=NODE_EMBEDDING_DIM, input_type="string")
    values = hasher.transform([[node_text(node)] for node in ordered]).toarray()
    return torch.from_numpy(values.astype(np.float32)), node_index


def make_temporal_data(
    edges: list[dict[str, Any]],
    node_features: torch.Tensor,
    node_index: dict[str, int],
    edge_type_index: dict[str, int],
) -> TemporalData:
    """Create the temporal src/dst/time/message representation consumed by KAIROS."""
    source = torch.tensor([node_index[str(edge["subject_id"])] for edge in edges], dtype=torch.long)
    destination = torch.tensor(
        [node_index[str(edge.get("object_id") or edge["subject_id"])] for edge in edges],
        dtype=torch.long,
    )
    times = torch.tensor([int(edge["timestamp_ns"]) for edge in edges], dtype=torch.long)
    edge_types = torch.tensor(
        [edge_type_index[str(edge["type"])] for edge in edges], dtype=torch.long
    )
    relation = functional.one_hot(edge_types, num_classes=len(edge_type_index)).float()
    messages = torch.cat([node_features[source], relation, node_features[destination]], dim=1)
    data = TemporalData(src=source, dst=destination, t=times, msg=messages)
    data.edge_type = edge_types
    return data


def build_models(
    node_count: int, message_dim: int, edge_type_count: int
) -> tuple[TGNMemory, torch.nn.Module, torch.nn.Module, LastNeighborLoader, torch.Tensor]:
    """Instantiate KAIROS's memory, GNN, link predictor, and neighbor state."""
    graph_attention_embedding, link_predictor = load_source_models()
    memory = TGNMemory(
        node_count,
        message_dim,
        NODE_STATE_DIM,
        TIME_DIM,
        message_module=IdentityMessage(message_dim, NODE_STATE_DIM, TIME_DIM),
        aggregator_module=LastAggregator(),
    )
    gnn = graph_attention_embedding(
        in_channels=NODE_STATE_DIM,
        out_channels=EDGE_DIM,
        msg_dim=message_dim,
        time_enc=memory.time_enc,
    )
    predictor = link_predictor(in_channels=EDGE_DIM, out_channels=edge_type_count)
    neighbor_loader = LastNeighborLoader(node_count, size=NEIGHBOR_SIZE, device="cpu")
    association = torch.empty(node_count, dtype=torch.long)
    return memory, gnn, predictor, neighbor_loader, association


def train_model(
    data: TemporalData,
    node_count: int,
    edge_type_count: int,
    seed: int,
    epochs: int,
    batch_size: int,
) -> tuple[tuple[Any, ...], list[float]]:
    """Train KAIROS's edge-type prediction objective on the clean prefix."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    memory, gnn, predictor, neighbor_loader, association = build_models(
        node_count, data.msg.shape[1], edge_type_count
    )
    optimizer = torch.optim.Adam(
        set(memory.parameters()) | set(gnn.parameters()) | set(predictor.parameters()),
        lr=0.00005,
        eps=1e-8,
        weight_decay=0.01,
    )
    epoch_losses: list[float] = []
    for _ in range(epochs):
        memory.train()
        gnn.train()
        predictor.train()
        memory.reset_state()
        neighbor_loader.reset_state()
        total_loss = 0.0
        for batch in TemporalDataLoader(data, batch_size=batch_size):
            optimizer.zero_grad()
            nodes = torch.cat([batch.src, batch.dst]).unique()
            nodes, local_edges, edge_ids = neighbor_loader(nodes)
            association[nodes] = torch.arange(nodes.size(0))
            embeddings, last_update = memory(nodes)
            embeddings = gnn(
                embeddings,
                last_update,
                local_edges,
                data.t[edge_ids],
                data.msg[edge_ids],
            )
            logits = predictor(
                embeddings[association[batch.src]], embeddings[association[batch.dst]]
            )
            loss = functional.cross_entropy(logits, batch.edge_type)
            memory.update_state(batch.src, batch.dst, batch.t, batch.msg)
            neighbor_loader.insert(batch.src, batch.dst)
            loss.backward()
            optimizer.step()
            memory.detach()
            total_loss += float(loss.item()) * batch.num_events
        epoch_losses.append(total_loss / data.num_events)
    return (memory, gnn, predictor, neighbor_loader, association), epoch_losses


def score_edges(models: tuple[Any, ...], data: TemporalData, batch_size: int) -> list[float]:
    """Return KAIROS per-edge cross-entropy reconstruction losses."""
    memory, gnn, predictor, neighbor_loader, association = models
    memory.eval()
    gnn.eval()
    predictor.eval()
    memory.reset_state()
    neighbor_loader.reset_state()
    scores: list[float] = []
    with torch.no_grad():
        for batch in TemporalDataLoader(data, batch_size=batch_size):
            nodes = torch.cat([batch.src, batch.dst]).unique()
            nodes, local_edges, edge_ids = neighbor_loader(nodes)
            association[nodes] = torch.arange(nodes.size(0))
            embeddings, last_update = memory(nodes)
            embeddings = gnn(
                embeddings,
                last_update,
                local_edges,
                data.t[edge_ids],
                data.msg[edge_ids],
            )
            logits = predictor(
                embeddings[association[batch.src]], embeddings[association[batch.dst]]
            )
            scores.extend(
                functional.cross_entropy(logits, batch.edge_type, reduction="none").tolist()
            )
            memory.update_state(batch.src, batch.dst, batch.t, batch.msg)
            neighbor_loader.insert(batch.src, batch.dst)
    return scores


def run_dataset(
    dataset_dir: Path,
    raw_output_dir: Path,
    seed: int,
    epochs: int,
    batch_size: int,
) -> dict[str, Any]:
    """Train and evaluate one KAIROS adapted-source run."""
    started = time.perf_counter()
    nodes = read_jsonl(dataset_dir / "nodes.jsonl")
    edges = read_jsonl(dataset_dir / "edges.jsonl")
    labels = read_jsonl(dataset_dir / "labels.jsonl")
    labels_by_edge = {str(label["edge_id"]): label for label in labels}
    train_edges, validation_edges, test_edges, attack_start = split_edges(edges, labels_by_edge)
    node_features, node_index = embed_nodes(nodes)
    edge_type_index = {
        value: index for index, value in enumerate(sorted({str(edge["type"]) for edge in edges}))
    }
    train_data = make_temporal_data(train_edges, node_features, node_index, edge_type_index)
    validation_data = make_temporal_data(
        validation_edges, node_features, node_index, edge_type_index
    )
    test_data = make_temporal_data(test_edges, node_features, node_index, edge_type_index)
    models, losses = train_model(
        train_data,
        len(nodes),
        len(edge_type_index),
        seed,
        epochs,
        batch_size,
    )
    validation_scores = score_edges(models, validation_data, batch_size)
    threshold = max(validation_scores)
    test_scores = score_edges(models, test_data, batch_size)
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
        "source_model": "baselines/third_party/kairos/DARPA/CADETS_E3/model.py",
        "threshold_policy": "maximum clean-validation edge reconstruction loss",
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
    """Write KAIROS JSON and Markdown result artifacts."""
    output = {
        "schema_version": "1.0",
        "method": "KAIROS",
        "reproduction_scope": "official TGN model with neutral temporal-data adapter",
        "runs": rows,
        "macro_mean_event": aggregate_metrics(rows, "event_metrics"),
        "macro_mean_action": aggregate_metrics(rows, "action_metrics"),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# KAIROS adapted-source results",
        "",
        "The locked upstream TGN, temporal attention, and edge-type predictor are executed "
        "directly; PostgreSQL/DARPA ingestion is replaced with neutral TemporalData.",
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
    """Run KAIROS over all converted scenarios."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--graphs-root", type=Path, default=DEFAULT_GRAPHS_ROOT)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--dataset", action="append", dest="datasets")
    parser.add_argument("--seeds", default="0,1,2,3,4")
    parser.add_argument("--epochs", type=int, default=50)
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
            print(f"KAIROS {dataset_dir.name} seed={seed}", flush=True)
            rows.append(
                run_dataset(
                    dataset_dir,
                    args.results_root / "raw" / "kairos" / dataset_dir.name,
                    seed,
                    args.epochs,
                    args.batch_size,
                )
            )
    write_summary(rows, args.results_root / "kairos")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
