"""Adapt NODLINK's official process VAE to the neutral EvidenceForge graphs.

The locked upstream VAE class is imported directly. This adapter replaces the
ETW/Sysdig parsers with neutral-graph process-behavior documents and preserves
the published 256->128->64->32 variational autoencoder, reconstruction score,
Adam settings, and 90th-percentile anomaly threshold.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import random
import statistics
import time
from collections import defaultdict
from pathlib import Path
from types import ModuleType
from typing import Any

import numpy as np
import torch
import torch.nn as nn
from gensim.models import FastText

from baselines.evaluation import action_metrics, binary_metrics
from baselines.velox_adapter import node_label, read_jsonl, split_edges, tokenize

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GRAPHS_ROOT = REPO_ROOT / "provenance_graph" / "graphs"
DEFAULT_RESULTS_ROOT = Path(__file__).resolve().parent / "results"
NODLINK_MODEL = (
    Path(__file__).resolve().parent
    / "third_party"
    / "nodlink"
    / "src"
    / "ETW"
    / "real-time"
    / "VAE.py"
)


def load_official_vae_module() -> ModuleType:
    """Load the CPU-capable VAE shipped in the locked NODLINK source tree."""
    specification = importlib.util.spec_from_file_location("nodlink_official_vae", NODLINK_MODEL)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"could not load NODLINK model from {NODLINK_MODEL}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def process_documents(
    edges: list[dict[str, Any]], nodes_by_id: dict[str, dict[str, Any]]
) -> dict[str, list[str]]:
    """Build one process-behavior token document per subject process."""
    documents: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        subject_id = str(edge["subject_id"])
        subject = nodes_by_id[subject_id]
        if not documents[subject_id]:
            category, label = node_label(subject)
            documents[subject_id].extend(tokenize(label, category))
        documents[subject_id].append(str(edge["type"]).lower())
        object_id = edge.get("object_id")
        if object_id and str(object_id) in nodes_by_id:
            category, label = node_label(nodes_by_id[str(object_id)])
            documents[subject_id].extend(tokenize(label, category))
    return dict(documents)


def train_fasttext(documents: dict[str, list[str]], seed: int, epochs: int) -> FastText:
    """Train NODLINK-style subword embeddings only on clean process behavior."""
    corpus = [documents[key] for key in sorted(documents) if documents[key]]
    if not corpus:
        raise ValueError("clean training split produced no process behavior")
    return FastText(
        sentences=corpus,
        vector_size=256,
        window=5,
        min_count=1,
        sg=1,
        workers=1,
        epochs=epochs,
        seed=seed,
    )


def embed_documents(
    documents: dict[str, list[str]], embedding: FastText
) -> tuple[list[str], torch.Tensor]:
    """Mean-pool FastText tokens into the 256-dimensional NODLINK VAE input."""
    process_ids = sorted(documents)
    vectors: list[np.ndarray[Any, np.dtype[np.float32]]] = []
    for process_id in process_ids:
        tokens = documents[process_id]
        token_vectors = [embedding.wv.get_vector(token) for token in tokens]
        vectors.append(np.mean(token_vectors, axis=0).astype(np.float32))
    return process_ids, torch.from_numpy(np.stack(vectors))


def train_vae(
    features: torch.Tensor,
    seed: int,
    epochs: int,
    batch_size: int,
) -> tuple[nn.Module, list[float]]:
    """Train the official NODLINK VAE with its published objective and optimizer."""
    module = load_official_vae_module()
    model = module.VariationalAutoencoder(32)
    criterion = nn.MSELoss(reduction="sum")
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-5)
    generator = torch.Generator().manual_seed(seed)
    dataset = torch.utils.data.TensorDataset(features)
    loader = torch.utils.data.DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=True,
        generator=generator,
    )
    minimum = float("inf")
    best_state = copy.deepcopy(model.state_dict())
    epoch_losses: list[float] = []
    model.train()
    for _ in range(epochs):
        running_loss = 0.0
        for (batch,) in loader:
            reconstruction = model(batch)
            loss = criterion(batch, reconstruction) + model.encoder.kl
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            running_loss += float(loss.item())
        epoch_loss = running_loss / len(features)
        epoch_losses.append(epoch_loss)
        if epoch_loss < minimum:
            minimum = epoch_loss
            best_state = copy.deepcopy(model.state_dict())
    model.load_state_dict(best_state)
    return model, epoch_losses


def reconstruction_scores(model: nn.Module, features: torch.Tensor) -> list[float]:
    """Return the official sum-of-squared-error process anomaly score."""
    model.eval()
    scores: list[float] = []
    with torch.no_grad():
        for feature in features:
            reconstruction = model(feature)
            scores.append(float(torch.sum((feature - reconstruction) ** 2).item()))
    return scores


def edge_scores(edges: list[dict[str, Any]], scores_by_process: dict[str, float]) -> list[float]:
    """Project NODLINK process scores back to their constituent graph events."""
    return [scores_by_process[str(edge["subject_id"])] for edge in edges]


def run_dataset(
    dataset_dir: Path,
    raw_output_dir: Path,
    seed: int,
    epochs: int,
    embedding_epochs: int,
    batch_size: int,
) -> dict[str, Any]:
    """Train and evaluate one NODLINK run on one scenario."""
    started = time.perf_counter()
    nodes = read_jsonl(dataset_dir / "nodes.jsonl")
    edges = read_jsonl(dataset_dir / "edges.jsonl")
    labels = read_jsonl(dataset_dir / "labels.jsonl")
    nodes_by_id = {str(node["id"]): node for node in nodes}
    labels_by_edge = {str(label["edge_id"]): label for label in labels}
    train_edges, validation_edges, test_edges, attack_start = split_edges(edges, labels_by_edge)

    training_documents = process_documents(train_edges, nodes_by_id)
    validation_documents = process_documents(validation_edges, nodes_by_id)
    test_documents = process_documents(test_edges, nodes_by_id)
    embedding = train_fasttext(training_documents, seed=seed, epochs=embedding_epochs)
    _, training_features = embed_documents(training_documents, embedding)
    validation_ids, validation_features = embed_documents(validation_documents, embedding)
    test_ids, test_features = embed_documents(test_documents, embedding)

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    model, epoch_losses = train_vae(training_features, seed, epochs, batch_size)
    validation_process_scores = reconstruction_scores(model, validation_features)
    threshold = float(np.percentile(validation_process_scores, 90))
    test_process_scores = reconstruction_scores(model, test_features)
    test_scores_by_process = dict(zip(test_ids, test_process_scores, strict=True))
    test_scores = edge_scores(test_edges, test_scores_by_process)
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
                        "subject_id": edge["subject_id"],
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
        "source_model": str(NODLINK_MODEL.relative_to(REPO_ROOT)),
        "attack_start_ns": attack_start,
        "train_edge_count": len(train_edges),
        "validation_edge_count": len(validation_edges),
        "test_edge_count": len(test_edges),
        "train_process_count": len(training_documents),
        "validation_process_count": len(validation_ids),
        "test_process_count": len(test_ids),
        "threshold": threshold,
        "final_train_loss": epoch_losses[-1],
        "event_metrics": binary_metrics(truth, predictions, test_scores),
        "action_metrics": action_metrics(test_edges, labels_by_edge, predictions_by_edge),
        "runtime_seconds": time.perf_counter() - started,
    }


def aggregate_metrics(rows: list[dict[str, Any]], key: str) -> dict[str, float]:
    """Average core metrics across scenario/seed runs."""
    fields = ["precision", "recall", "f1"]
    return {field: statistics.mean(float(row[key][field]) for row in rows) for field in fields}


def write_summary(rows: list[dict[str, Any]], output_dir: Path) -> None:
    """Write machine-readable and concise Markdown benchmark summaries."""
    output = {
        "schema_version": "1.0",
        "method": "NODLINK",
        "reproduction_scope": "official VAE with EvidenceForge process-behavior input adapter",
        "runs": rows,
        "macro_mean_event": aggregate_metrics(rows, "event_metrics"),
        "macro_mean_action": aggregate_metrics(rows, "action_metrics"),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    lines = [
        "# NODLINK adapted-source results",
        "",
        "The locked upstream 256-dimensional process VAE is executed directly. Only the "
        "ETW/Sysdig input parser is replaced. Scores are process-level and projected to events.",
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
    """Run NODLINK over all converted scenarios."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--graphs-root", type=Path, default=DEFAULT_GRAPHS_ROOT)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--dataset", action="append", dest="datasets")
    parser.add_argument("--seeds", default="0,1,2,3,4")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--embedding-epochs", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=128)
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
            print(f"NODLINK {dataset_dir.name} seed={seed}", flush=True)
            rows.append(
                run_dataset(
                    dataset_dir,
                    args.results_root / "raw" / "nodlink" / dataset_dir.name,
                    seed,
                    args.epochs,
                    args.embedding_epochs,
                    args.batch_size,
                )
            )
    write_summary(rows, args.results_root / "nodlink")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
