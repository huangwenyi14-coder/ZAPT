"""Run ORTHRUS's official model stack on neutral EvidenceForge graphs."""

from __future__ import annotations

import argparse
import copy
import json
import random
import statistics
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import numpy as np
import torch
import torch.nn.functional as functional
from gensim.models import Word2Vec
from torch_geometric.data import Data, TemporalData

from baselines.evaluation import action_metrics, binary_metrics
from baselines.graph_io import read_jsonl, split_edges

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINES_ROOT = Path(__file__).resolve().parent
DEFAULT_GRAPHS_ROOT = REPO_ROOT / "provenance_graph" / "graphs"
DEFAULT_RESULTS_ROOT = BASELINES_ROOT / "results"
ORTHRUS_SOURCE = BASELINES_ROOT / "third_party" / "orthrus" / "src"
WORD_DIM = 128
NODE_TYPE_DIM = 3


def load_source_stack() -> tuple[Any, Any, Any, Any, Any, Any]:
    """Import the model factory and tokenizers from the locked ORTHRUS checkout."""
    source = str(ORTHRUS_SOURCE)
    if source not in sys.path:
        sys.path.insert(0, source)
    from factory import batch_loader_factory, build_model, optimizer_factory
    from provnet_utils import tokenize_file, tokenize_netflow, tokenize_subject

    return (
        build_model,
        optimizer_factory,
        batch_loader_factory,
        tokenize_subject,
        tokenize_file,
        tokenize_netflow,
    )


def node_message(node: dict[str, Any]) -> tuple[str, str]:
    """Map a neutral node to ORTHRUS's subject/file/netflow message families."""
    node_type = str(node["type"])
    properties = node.get("properties") or {}
    if node_type == "SUBJECT":
        category = "subject"
        value = " ".join(
            str(part)
            for part in (
                properties.get("image_path") or properties.get("path") or "",
                properties.get("command_line") or properties.get("cmd_line") or "",
            )
            if part
        )
    elif node_type == "NET_FLOW_OBJECT":
        category = "netflow"
        value = str(
            properties.get("remote_ip")
            or properties.get("destination_ip")
            or properties.get("local_ip")
            or properties.get("source_ip")
            or node.get("natural_key")
            or node["id"]
        )
    else:
        category = "file"
        value = str(
            properties.get("path")
            or properties.get("key")
            or properties.get("name")
            or properties.get("principal")
            or node.get("natural_key")
            or node["id"]
        )
    return category, value


def tokenize_nodes(
    nodes: list[dict[str, Any]], tokenizers: tuple[Any, Any, Any]
) -> tuple[list[list[str]], dict[str, list[str]], dict[str, int]]:
    """Tokenize every entity using the official ORTHRUS tokenizer functions."""
    tokenize_subject, tokenize_file, tokenize_netflow = tokenizers
    tokenizer_by_category = {
        "subject": tokenize_subject,
        "file": tokenize_file,
        "netflow": tokenize_netflow,
    }
    type_index = {"subject": 0, "file": 1, "netflow": 2}
    corpus_by_value: dict[str, list[str]] = {}
    tokens_by_id: dict[str, list[str]] = {}
    node_type_by_id: dict[str, int] = {}
    for node in sorted(nodes, key=lambda item: str(item["id"])):
        category, value = node_message(node)
        tokens = tokenizer_by_category[category](value) or [""]
        corpus_by_value.setdefault(value, tokens)
        tokens_by_id[str(node["id"])] = tokens
        node_type_by_id[str(node["id"])] = type_index[category]
    return list(corpus_by_value.values()), tokens_by_id, node_type_by_id


def train_word2vec(corpus: list[list[str]], seed: int) -> Word2Vec:
    """Train ORTHRUS's configured 128-dimensional skip-gram representation."""
    model = Word2Vec(
        corpus,
        vector_size=WORD_DIM,
        window=5,
        min_count=1,
        sg=1,
        workers=1,
        epochs=1,
        compute_loss=True,
        negative=5,
        seed=seed,
    )
    for _ in range(49):
        model.train(corpus, epochs=1, total_examples=len(corpus), compute_loss=True)
    return model


def declining_weights(length: int, percentage: float = 30.0) -> list[float]:
    """Return the position weights used by ORTHRUS's feature_word2vec adapter."""
    delta = -1 / length * percentage / 100
    first = 1 / length - 0.5 * (length - 1) * delta
    return [first + index * delta for index in range(length)]


def embed_nodes(
    nodes: list[dict[str, Any]],
    tokens_by_id: dict[str, list[str]],
    node_type_by_id: dict[str, int],
    word2vec: Word2Vec,
) -> tuple[torch.Tensor, dict[str, int]]:
    """Build ORTHRUS Word2Vec plus node-type feature vectors."""
    ordered = sorted(nodes, key=lambda node: str(node["id"]))
    node_index = {str(node["id"]): index for index, node in enumerate(ordered)}
    vectors: list[np.ndarray[Any, Any]] = []
    for node in ordered:
        node_id = str(node["id"])
        tokens = tokens_by_id[node_id]
        weights = declining_weights(len(tokens))
        weighted = [
            weight * word2vec.wv[token] for weight, token in zip(weights, tokens, strict=True)
        ]
        vector = np.mean(weighted, axis=0).astype(np.float32)
        vector = vector / (float(np.linalg.norm(vector)) + 1e-12)
        node_type = np.zeros(NODE_TYPE_DIM, dtype=np.float32)
        node_type[node_type_by_id[node_id]] = 1.0
        vectors.append(np.concatenate([vector, node_type]))
    return torch.from_numpy(np.stack(vectors)), node_index


def make_temporal_data(
    edges: list[dict[str, Any]],
    node_features: torch.Tensor,
    node_index: dict[str, int],
    edge_type_index: dict[str, int],
) -> TemporalData:
    """Create the per-event tensors expected by the official ORTHRUS model."""
    source = torch.tensor([node_index[str(edge["subject_id"])] for edge in edges])
    destination = torch.tensor(
        [node_index[str(edge.get("object_id") or edge["subject_id"])] for edge in edges]
    )
    edge_classes = torch.tensor(
        [edge_type_index[str(edge["type"])] for edge in edges], dtype=torch.long
    )
    edge_types = functional.one_hot(edge_classes, num_classes=len(edge_type_index)).float()
    x_source = node_features[source]
    x_destination = node_features[destination]
    data = TemporalData(
        src=source.long(),
        dst=destination.long(),
        t=torch.tensor([int(edge["timestamp_ns"]) for edge in edges], dtype=torch.long),
        msg=torch.cat([x_source, x_destination], dim=1),
    )
    data.x_src = x_source
    data.x_dst = x_destination
    data.edge_type = edge_types
    data.edge_feats = edge_types
    data.edge_index = torch.stack([data.src, data.dst])
    return data


def source_config(edge_type_count: int, batch_size: int) -> SimpleNamespace:
    """Build the subset of the locked ORTHRUS YAML consumed by its model factory."""
    graph_attention = SimpleNamespace(dropout=0.5, activation="relu", num_heads=8)
    encoder = SimpleNamespace(
        temporal_dim=100,
        edge_features="edge_type",
        neighbor_size=20,
        use_node_feats_in_gnn=True,
        batch_size=batch_size,
        graph_attention=graph_attention,
    )
    decoder_custom = SimpleNamespace(dropout=0.0, num_layers=2, activation="relu")
    predict_edge_type = SimpleNamespace(custom=decoder_custom)
    decoder = SimpleNamespace(used_methods="predict_edge_type", predict_edge_type=predict_edge_type)
    training = SimpleNamespace(
        node_hid_dim=128,
        node_out_dim=64,
        encoder=encoder,
        decoder=decoder,
        lr=0.00001,
        weight_decay=0.00001,
    )
    return SimpleNamespace(
        dataset=SimpleNamespace(num_edge_types=edge_type_count),
        detection=SimpleNamespace(gnn_training=training),
    )


def train_model(
    train_data: TemporalData,
    full_data: Data,
    node_count: int,
    edge_type_count: int,
    source_functions: tuple[Any, Any, Any],
    seed: int,
    epochs: int,
    batch_size: int,
) -> tuple[torch.nn.Module, list[float]]:
    """Train through ORTHRUS's official factory, model, loader, and optimizer."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    build_model, optimizer_factory, batch_loader_factory = source_functions
    config = source_config(edge_type_count, batch_size)
    model = build_model(train_data, torch.device("cpu"), config, node_count)
    optimizer = optimizer_factory(config, parameters=set(model.parameters()))
    epoch_losses: list[float] = []
    for _ in range(epochs):
        model.train()
        model.encoder.reset_state()
        losses: list[float] = []
        for batch in batch_loader_factory(config, train_data, model.graph_reindexer):
            optimizer.zero_grad()
            loss = model(batch, full_data)
            loss.backward()
            optimizer.step()
            losses.append(float(loss.item()))
        epoch_losses.append(statistics.mean(losses))

    # Upstream evaluation rebuilds the model, restores its weights and saved
    # neighbor state, and starts with a fresh GraphReindexer feature cache.
    neighbor_state = copy.deepcopy(model.encoder.neighbor_loader)
    evaluation_model = build_model(train_data, torch.device("cpu"), config, node_count)
    evaluation_model.load_state_dict(model.state_dict())
    evaluation_model.encoder.neighbor_loader = neighbor_state
    return evaluation_model, epoch_losses


def score_edges(
    model: torch.nn.Module,
    data: TemporalData,
    full_data: Data,
    edge_type_count: int,
    batch_size: int,
) -> list[float]:
    """Score events sequentially with ORTHRUS's official inference path."""
    config = source_config(edge_type_count, batch_size)
    _, _, batch_loader_factory, *_ = load_source_stack()
    model.eval()
    scores: list[float] = []
    with torch.no_grad():
        for batch in batch_loader_factory(config, data, model.graph_reindexer):
            scores.extend(model(batch, full_data, inference=True).tolist())
    return scores


def run_dataset(
    dataset_dir: Path,
    raw_output_dir: Path,
    seed: int,
    epochs: int,
    batch_size: int,
) -> dict[str, Any]:
    """Train and evaluate one ORTHRUS adapted-source run."""
    started = time.perf_counter()
    nodes = read_jsonl(dataset_dir / "nodes.jsonl")
    edges = read_jsonl(dataset_dir / "edges.jsonl")
    labels = read_jsonl(dataset_dir / "labels.jsonl")
    labels_by_edge = {str(label["edge_id"]): label for label in labels}
    train_edges, validation_edges, test_edges, attack_start = split_edges(edges, labels_by_edge)
    source_stack = load_source_stack()
    corpus, tokens_by_id, node_type_by_id = tokenize_nodes(nodes, source_stack[3:])
    word2vec = train_word2vec(corpus, seed)
    node_features, node_index = embed_nodes(nodes, tokens_by_id, node_type_by_id, word2vec)
    edge_type_index = {
        value: index for index, value in enumerate(sorted({str(edge["type"]) for edge in edges}))
    }
    train_data = make_temporal_data(train_edges, node_features, node_index, edge_type_index)
    validation_data = make_temporal_data(
        validation_edges, node_features, node_index, edge_type_index
    )
    test_data = make_temporal_data(test_edges, node_features, node_index, edge_type_index)
    full_data = Data(
        msg=torch.cat([train_data.msg, validation_data.msg, test_data.msg]),
        t=torch.cat([train_data.t, validation_data.t, test_data.t]),
        edge_type=torch.cat([train_data.edge_type, validation_data.edge_type, test_data.edge_type]),
    )
    model, losses = train_model(
        train_data,
        full_data,
        len(nodes),
        len(edge_type_index),
        source_stack[:3],
        seed,
        epochs,
        batch_size,
    )
    validation_scores = score_edges(
        model, validation_data, full_data, len(edge_type_index), batch_size
    )
    threshold = max(validation_scores)
    test_scores = score_edges(model, test_data, full_data, len(edge_type_index), batch_size)
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
        "source_model": "baselines/third_party/orthrus/src",
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
    """Write ORTHRUS JSON and Markdown result artifacts."""
    output = {
        "schema_version": "1.0",
        "method": "ORTHRUS",
        "reproduction_scope": "official model stack with neutral temporal-data adapter",
        "runs": rows,
        "macro_mean_event": aggregate_metrics(rows, "event_metrics"),
        "macro_mean_action": aggregate_metrics(rows, "action_metrics"),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# ORTHRUS adapted-source results",
        "",
        "The locked upstream factory, GraphTransformer, OrthrusEncoder, EdgeTypeDecoder, "
        "neighbor state, optimizer, and inference path execute directly. PostgreSQL/DARPA "
        "ingestion is replaced with the neutral graph adapter.",
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
    """Run ORTHRUS over all converted scenarios."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--graphs-root", type=Path, default=DEFAULT_GRAPHS_ROOT)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--dataset", action="append", dest="datasets")
    parser.add_argument("--seeds", default="0,1,2,3,4")
    parser.add_argument("--epochs", type=int, default=6)
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
            print(f"ORTHRUS {dataset_dir.name} seed={seed}", flush=True)
            rows.append(
                run_dataset(
                    dataset_dir,
                    args.results_root / "raw" / "orthrus" / dataset_dir.name,
                    seed,
                    args.epochs,
                    args.batch_size,
                )
            )
    write_summary(rows, args.results_root / "orthrus")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
