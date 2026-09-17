"""Run TAPAS's official LSTM and GraphSAGE with cross-scenario evaluation."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import random
import statistics
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import numpy as np
import torch
import torch.nn.functional as functional
from torch_geometric.data import Data
from torch_geometric.loader import DataLoader

from baselines.evaluation import action_metrics, binary_metrics
from baselines.graph_io import read_jsonl

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINES_ROOT = Path(__file__).resolve().parent
DEFAULT_GRAPHS_ROOT = REPO_ROOT / "provenance_graph" / "graphs"
DEFAULT_RESULTS_ROOT = BASELINES_ROOT / "results"
DEFAULT_ARTIFACT_ROOT = BASELINES_ROOT / "artifacts" / "tapas-inspection"
DEFAULT_SOURCE = DEFAULT_ARTIFACT_ROOT / "TAPAS-artifact" / "darpa.py"
DEFAULT_CHECKPOINT = DEFAULT_ARTIFACT_ROOT / "TAPAS-artifact" / "model" / "stackedlstm_tc.pt"

EVENT_CODE = {
    "EVENT_CONNECT": 2,
    "EVENT_READ": 5,
    "EVENT_LOADLIBRARY": 5,
    "EVENT_WRITE": 10,
    "EVENT_REGISTRY_MODIFY": 10,
    "EVENT_CREATE_OBJECT": 11,
    "EVENT_UNLINK": 11,
}
FILE_TYPES = {"FILE_OBJECT", "REGISTRY_KEY_OBJECT"}
NETWORK_TYPES = {"NET_FLOW_OBJECT"}


@dataclass(frozen=True)
class TaskGraph:
    """One process-tree task and its detector/evaluation projection metadata."""

    task_id: str
    process_ids: frozenset[str]
    edge_ids: frozenset[str]
    graph: Data
    label: int


@dataclass(frozen=True)
class ScenarioGraphs:
    """TAPAS task graphs plus the neutral events needed for offline evaluation."""

    name: str
    tasks: tuple[TaskGraph, ...]
    edges: tuple[dict[str, Any], ...]
    labels_by_edge: dict[str, dict[str, Any]]
    task_by_process: dict[str, int]
    feature_seconds: float


class _UnionFind:
    """Small deterministic union-find used for process-task segmentation."""

    def __init__(self, values: list[str]) -> None:
        self.parent = {value: value for value in values}

    def find(self, value: str) -> str:
        parent = self.parent[value]
        if parent != value:
            self.parent[value] = self.find(parent)
        return self.parent[value]

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        if left_root < right_root:
            self.parent[right_root] = left_root
        else:
            self.parent[left_root] = right_root


def load_official_source(source_path: Path) -> ModuleType:
    """Load the official TAPAS artifact module without modifying its source."""
    if not source_path.exists():
        raise FileNotFoundError(
            f"TAPAS source is missing at {source_path}. Extract TAPAS-artifact/darpa.py "
            "from the official Zenodo RAR first."
        )
    specification = importlib.util.spec_from_file_location("tapas_official_darpa", source_path)
    if specification is None or specification.loader is None:
        raise ImportError(f"cannot construct an import specification for {source_path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    module.device = torch.device("cpu")
    return module


def _stable_code(value: str, modulus: int) -> int:
    digest = hashlib.sha256(value.lower().encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % modulus


def _path_code(path: str) -> int:
    normalized = path.replace("\\", "/").lower()
    prefixes = (
        ("c:/windows/system32/", 1),
        ("c:/windows/", 2),
        ("c:/program files/", 3),
        ("c:/users/", 4),
        ("c:/temp/", 5),
        ("/usr/bin/", 11),
        ("/bin/", 12),
        ("/usr/lib/", 13),
        ("/lib/", 14),
        ("/etc/", 15),
        ("/var/", 16),
        ("/tmp/", 17),
        ("/home/", 18),
        ("/opt/", 19),
    )
    for prefix, code in prefixes:
        if normalized.startswith(prefix):
            return code
    return 90


def _file_type_code(path: str) -> int:
    filename = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    suffix = filename.rsplit(".", 1)[-1] if "." in filename else ""
    known = {
        "dll": 1,
        "exe": 2,
        "sys": 3,
        "so": 4,
        "py": 5,
        "sh": 6,
        "txt": 7,
        "conf": 8,
        "json": 9,
        "yaml": 10,
        "yml": 10,
        "log": 11,
        "ps1": 12,
        "bat": 13,
    }
    return known.get(suffix, 0 if not suffix else 14 + _stable_code(suffix, 16))


def _port_code(value: Any) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        port = 1024
    if port < 1024:
        return 0
    if port < 49152:
        return 1
    return 2


def _address_code(source: str, destination: str) -> int:
    if source == destination:
        return 4
    if not source or not destination:
        return 5
    source_parts = source.split(".")
    destination_parts = destination.split(".")
    if len(source_parts) != 4 or len(destination_parts) != 4:
        return 7
    for index, (source_part, destination_part) in enumerate(
        zip(source_parts, destination_parts, strict=True), start=1
    ):
        if source_part != destination_part:
            return index
    return 4


def _object_vector(node: dict[str, Any], edge: dict[str, Any]) -> list[float] | None:
    node_type = str(node["type"])
    node_properties = node.get("properties") or {}
    edge_properties = edge.get("properties") or {}
    if node_type in FILE_TYPES:
        path = str(
            node_properties.get("path")
            or node_properties.get("registry_key")
            or node.get("natural_key")
            or ""
        )
        return [2.0, float(_path_code(path)), float(_file_type_code(path)), 0.0]
    if node_type in NETWORK_TYPES:
        source = str(edge_properties.get("src_ip") or node_properties.get("src_ip") or "")
        destination = str(edge_properties.get("dst_ip") or node_properties.get("dst_ip") or "")
        source_port = edge_properties.get("src_port") or node_properties.get("src_port")
        destination_port = edge_properties.get("dst_port") or node_properties.get("dst_port")
        return [
            3.0,
            float(_address_code(source, destination)),
            float(_port_code(source_port)),
            float(_port_code(destination_port)),
        ]
    return None


def process_histories(
    edges: list[dict[str, Any]], nodes_by_id: dict[str, dict[str, Any]]
) -> dict[str, list[list[float]]]:
    """Build TAPAS-compatible six-value action histories without reading labels."""
    grouped: dict[str, dict[tuple[int, str], tuple[int, list[float]]]] = defaultdict(dict)
    ordered = sorted(edges, key=lambda edge: (edge["timestamp_ns"], edge["sequence"]))
    for edge in ordered:
        event_code = EVENT_CODE.get(str(edge["type"]))
        object_id = str(edge.get("object_id") or "")
        subject_id = str(edge["subject_id"])
        node = nodes_by_id.get(object_id)
        if (
            event_code is None
            or node is None
            or nodes_by_id.get(subject_id, {}).get("type") != "SUBJECT"
        ):
            continue
        object_vector = _object_vector(node, edge)
        if object_vector is None:
            continue
        key = (event_code, object_id)
        previous = grouped[subject_id].get(key)
        if previous is None:
            grouped[subject_id][key] = (
                1,
                [float(event_code), 1.0, *object_vector],
            )
        else:
            count, vector = previous
            vector = list(vector)
            vector[1] = float(count + 1)
            grouped[subject_id][key] = (count + 1, vector)
    return {
        subject_id: [vector for _, vector in action_groups.values()]
        for subject_id, action_groups in grouped.items()
    }


def embed_processes(
    subject_ids: list[str],
    histories: dict[str, list[list[float]]],
    source_module: ModuleType,
    checkpoint_path: Path,
) -> dict[str, list[float]]:
    """Execute TAPAS's official 42-dimensional LSTM/GRU process encoder."""
    if not checkpoint_path.exists():
        raise FileNotFoundError(
            f"TAPAS checkpoint is missing at {checkpoint_path}. Extract "
            "TAPAS-artifact/model/stackedlstm_tc.pt from the official Zenodo RAR first."
        )
    model = source_module.LSTM(6, 256, 6)
    state = torch.load(checkpoint_path, weights_only=True, map_location="cpu")
    model.load_state_dict(state)
    model.to(torch.device("cpu"))
    model.eval()
    vectors: dict[str, list[float]] = {}
    with torch.no_grad():
        for subject_id in subject_ids:
            history = histories.get(subject_id)
            if not history:
                vectors[subject_id] = [0.0] * 42
                continue
            tensor = torch.tensor([history], dtype=torch.float32)
            vectors[subject_id] = model(tensor).detach().cpu().tolist()
    return vectors


def _process_components(
    subject_ids: list[str], edges: list[dict[str, Any]]
) -> tuple[list[list[str]], list[tuple[str, str]]]:
    union_find = _UnionFind(subject_ids)
    subject_set = set(subject_ids)
    task_edges: list[tuple[str, str]] = []
    for edge in edges:
        parent = str(edge["subject_id"])
        child = str(edge.get("object_id") or "")
        if edge["type"] != "EVENT_EXECUTE" or parent not in subject_set or child not in subject_set:
            continue
        union_find.union(parent, child)
        task_edges.append((child, parent))
    components: dict[str, list[str]] = defaultdict(list)
    for subject_id in subject_ids:
        components[union_find.find(subject_id)].append(subject_id)
    tasks = [sorted(values) for values in components.values() if len(values) >= 2]
    tasks.sort(key=lambda values: values[0])
    return tasks, task_edges


def build_scenario(
    dataset_dir: Path,
    source_module: ModuleType,
    checkpoint_path: Path,
) -> ScenarioGraphs:
    """Convert one neutral graph into TAPAS process-tree tasks."""
    started = time.perf_counter()
    nodes = read_jsonl(dataset_dir / "nodes.jsonl")
    edges = sorted(
        read_jsonl(dataset_dir / "edges.jsonl"),
        key=lambda edge: (edge["timestamp_ns"], edge["sequence"]),
    )
    labels = read_jsonl(dataset_dir / "labels.jsonl")
    nodes_by_id = {str(node["id"]): node for node in nodes}
    labels_by_edge = {str(label["edge_id"]): label for label in labels}
    subject_ids = sorted(str(node["id"]) for node in nodes if str(node["type"]) == "SUBJECT")
    task_processes, parent_edges = _process_components(subject_ids, edges)
    task_subjects = sorted({subject_id for values in task_processes for subject_id in values})
    histories = process_histories(edges, nodes_by_id)
    process_vectors = embed_processes(
        task_subjects,
        histories,
        source_module,
        checkpoint_path,
    )

    task_by_process: dict[str, int] = {}
    tasks: list[TaskGraph] = []
    for task_index, process_ids in enumerate(task_processes):
        process_set = frozenset(process_ids)
        local_index = {process_id: index for index, process_id in enumerate(process_ids)}
        internal_edges = [
            (child, parent)
            for child, parent in parent_edges
            if child in process_set and parent in process_set
        ]
        edge_index = torch.tensor(
            [
                [local_index[child] for child, _ in internal_edges],
                [local_index[parent] for _, parent in internal_edges],
            ],
            dtype=torch.long,
        )
        incident_edge_ids = frozenset(
            str(edge["id"])
            for edge in edges
            if str(edge["subject_id"]) in process_set
            or str(edge.get("object_id") or "") in process_set
        )
        label = int(
            any(labels_by_edge[edge_id]["label"] == "malicious" for edge_id in incident_edge_ids)
        )
        features = torch.tensor(
            [process_vectors[process_id] for process_id in process_ids], dtype=torch.float32
        )
        graph = Data(x=features, edge_index=edge_index, y=torch.tensor(label, dtype=torch.long))
        task_id = f"{dataset_dir.name}:{process_ids[0]}"
        tasks.append(
            TaskGraph(
                task_id=task_id,
                process_ids=process_set,
                edge_ids=incident_edge_ids,
                graph=graph,
                label=label,
            )
        )
        for process_id in process_ids:
            task_by_process[process_id] = task_index

    return ScenarioGraphs(
        name=dataset_dir.name,
        tasks=tuple(tasks),
        edges=tuple(edges),
        labels_by_edge=labels_by_edge,
        task_by_process=task_by_process,
        feature_seconds=time.perf_counter() - started,
    )


def train_model(
    source_module: ModuleType,
    train_tasks: list[TaskGraph],
    seed: int,
    epochs: int,
    batch_size: int,
) -> tuple[torch.nn.Module, list[float]]:
    """Train TAPAS's official two-layer GraphSAGE task classifier."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    model = source_module.GraphSAGE(input_dim=42, hidden_dim=64, output_dim=2)
    model.to(torch.device("cpu"))
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001, weight_decay=5e-4)
    criterion = torch.nn.CrossEntropyLoss()
    loader = DataLoader(
        [task.graph for task in train_tasks],
        batch_size=batch_size,
        shuffle=True,
    )
    losses: list[float] = []
    for _ in range(epochs):
        optimizer.zero_grad()
        model.train()
        total_loss: torch.Tensor | None = None
        for batch in loader:
            _, output = model(batch.x, batch.edge_index, batch.batch)
            loss = criterion(output, batch.y)
            total_loss = loss if total_loss is None else total_loss + loss
        if total_loss is None:
            raise ValueError("TAPAS training fold contains no task graphs")
        total_loss.backward()
        optimizer.step()
        losses.append(float(total_loss.item()))
    return model, losses


def score_tasks(
    model: torch.nn.Module, tasks: tuple[TaskGraph, ...], batch_size: int
) -> tuple[list[float], list[int]]:
    """Return TAPAS attack probabilities and argmax predictions for task graphs."""
    loader = DataLoader([task.graph for task in tasks], batch_size=batch_size, shuffle=False)
    scores: list[float] = []
    predictions: list[int] = []
    model.eval()
    with torch.no_grad():
        for batch in loader:
            _, output = model(batch.x, batch.edge_index, batch.batch)
            probabilities = functional.softmax(output, dim=1)[:, 1]
            scores.extend(probabilities.cpu().tolist())
            predictions.extend(output.argmax(dim=1).cpu().tolist())
    return scores, predictions


def project_events(
    scenario: ScenarioGraphs,
    task_scores: list[float],
    task_predictions: list[int],
) -> tuple[list[float], list[int], dict[str, int]]:
    """Project native task predictions to all incident provenance events."""
    scores: list[float] = []
    predictions: list[int] = []
    predictions_by_edge: dict[str, int] = {}
    for edge in scenario.edges:
        subject_task = scenario.task_by_process.get(str(edge["subject_id"]))
        object_task = scenario.task_by_process.get(str(edge.get("object_id") or ""))
        task_index = subject_task if subject_task is not None else object_task
        score = task_scores[task_index] if task_index is not None else 0.0
        prediction = task_predictions[task_index] if task_index is not None else 0
        scores.append(score)
        predictions.append(prediction)
        predictions_by_edge[str(edge["id"])] = prediction
    return scores, predictions, predictions_by_edge


def run_fold(
    scenarios: list[ScenarioGraphs],
    held_out: ScenarioGraphs,
    source_module: ModuleType,
    raw_output_dir: Path,
    seed: int,
    epochs: int,
    batch_size: int,
) -> dict[str, Any]:
    """Train on six complete scenarios and evaluate the untouched seventh scenario."""
    started = time.perf_counter()
    train_tasks = [
        task for scenario in scenarios if scenario.name != held_out.name for task in scenario.tasks
    ]
    model, losses = train_model(
        source_module,
        train_tasks,
        seed,
        epochs,
        batch_size,
    )
    task_scores, task_predictions = score_tasks(model, held_out.tasks, batch_size)
    task_truth = [task.label for task in held_out.tasks]
    event_scores, event_predictions, predictions_by_edge = project_events(
        held_out,
        task_scores,
        task_predictions,
    )
    event_truth = [
        int(held_out.labels_by_edge[str(edge["id"])]["label"] == "malicious")
        for edge in held_out.edges
    ]
    malicious_times = [
        int(edge["timestamp_ns"])
        for edge, label in zip(held_out.edges, event_truth, strict=True)
        if label
    ]
    if not malicious_times:
        raise ValueError(f"{held_out.name} contains no malicious detector-visible event")
    attack_start = min(malicious_times)
    attack_indices = [
        index
        for index, edge in enumerate(held_out.edges)
        if int(edge["timestamp_ns"]) >= attack_start
    ]
    attack_edges = [held_out.edges[index] for index in attack_indices]
    attack_truth = [event_truth[index] for index in attack_indices]
    attack_predictions = [event_predictions[index] for index in attack_indices]
    attack_scores = [event_scores[index] for index in attack_indices]

    raw_output_dir.mkdir(parents=True, exist_ok=True)
    with (raw_output_dir / f"seed-{seed}.jsonl").open("w", encoding="utf-8") as handle:
        for task, score, prediction in zip(
            held_out.tasks, task_scores, task_predictions, strict=True
        ):
            handle.write(
                json.dumps(
                    {
                        "task_id": task.task_id,
                        "process_count": len(task.process_ids),
                        "incident_edge_count": len(task.edge_ids),
                        "score": score,
                        "alert": bool(prediction),
                    },
                    separators=(",", ":"),
                )
                + "\n"
            )

    return {
        "dataset": held_out.name,
        "seed": seed,
        "adapter_class": "official_models_cross_scenario_input_adapter",
        "source_model": str(DEFAULT_SOURCE.relative_to(REPO_ROOT)),
        "evaluation_protocol": "leave-one-scenario-out supervised task classification",
        "prediction_policy": "official two-class argmax",
        "train_scenarios": sorted(
            scenario.name for scenario in scenarios if scenario.name != held_out.name
        ),
        "train_task_count": len(train_tasks),
        "train_positive_task_count": sum(task.label for task in train_tasks),
        "test_task_count": len(held_out.tasks),
        "test_positive_task_count": sum(task_truth),
        "attack_start_ns": attack_start,
        "final_train_loss": losses[-1],
        "task_metrics": binary_metrics(task_truth, task_predictions, task_scores),
        "event_metrics_full_capture": binary_metrics(event_truth, event_predictions, event_scores),
        "event_metrics_attack_onward": binary_metrics(
            attack_truth, attack_predictions, attack_scores
        ),
        "action_metrics_attack_onward": action_metrics(
            attack_edges,
            held_out.labels_by_edge,
            predictions_by_edge,
        ),
        "runtime_seconds": time.perf_counter() - started,
    }


def aggregate_metrics(rows: list[dict[str, Any]], key: str) -> dict[str, float]:
    """Average classification metrics across scenario/seed folds."""
    return {
        field: statistics.mean(float(row[key][field]) for row in rows)
        for field in ("accuracy", "precision", "recall", "f1")
        if field in rows[0][key]
    }


def write_summary(rows: list[dict[str, Any]], output_dir: Path) -> None:
    """Write separate supervised TAPAS JSON and Markdown reports."""
    output = {
        "schema_version": "1.0",
        "method": "TAPAS",
        "reproduction_scope": (
            "official TAPAS LSTM checkpoint and GraphSAGE classes with a neutral graph adapter"
        ),
        "comparison_class": "cross-scenario supervised; not clean-prefix anomaly detection",
        "runs": rows,
        "macro_mean_task": aggregate_metrics(rows, "task_metrics"),
        "macro_mean_event_full_capture": aggregate_metrics(rows, "event_metrics_full_capture"),
        "macro_mean_event_attack_onward": aggregate_metrics(rows, "event_metrics_attack_onward"),
        "macro_mean_action_attack_onward": aggregate_metrics(rows, "action_metrics_attack_onward"),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# TAPAS cross-scenario supervised results",
        "",
        "This run imports the official `LSTM` and `GraphSAGE` classes and loads the official "
        "`stackedlstm_tc.pt` checkpoint. The original random 80/20 split is replaced with "
        "leave-one-scenario-out folds so no held-out scenario label is available during "
        "training. These scores are reported separately from clean-prefix anomaly detectors.",
        "",
        "| Held-out dataset | Seed | Task Acc / P / R / F1 | "
        "Attack-onward event Acc / P / R / F1 | Action P / R / F1 |",
        "|---|---:|---:|---:|---:|",
    ]
    for row in rows:
        task = row["task_metrics"]
        event = row["event_metrics_attack_onward"]
        action = row["action_metrics_attack_onward"]
        lines.append(
            f"| {row['dataset']} | {row['seed']} | "
            f"{task['accuracy']:.4f} / {task['precision']:.4f} / "
            f"{task['recall']:.4f} / {task['f1']:.4f} | "
            f"{event['accuracy']:.4f} / {event['precision']:.4f} / "
            f"{event['recall']:.4f} / {event['f1']:.4f} | "
            f"{action['precision']:.4f} / {action['recall']:.4f} / "
            f"{action['f1']:.4f} |"
        )
    task_mean = output["macro_mean_task"]
    full_mean = output["macro_mean_event_full_capture"]
    event_mean = output["macro_mean_event_attack_onward"]
    action_mean = output["macro_mean_action_attack_onward"]
    lines.extend(
        [
            "",
            f"Macro mean native task accuracy/P/R/F1: **{task_mean['accuracy']:.4f} / "
            f"{task_mean['precision']:.4f} / {task_mean['recall']:.4f} / "
            f"{task_mean['f1']:.4f}**.",
            f"Macro mean full-capture event accuracy/P/R/F1: **{full_mean['accuracy']:.4f} / "
            f"{full_mean['precision']:.4f} / {full_mean['recall']:.4f} / "
            f"{full_mean['f1']:.4f}**.",
            f"Macro mean attack-onward event accuracy/P/R/F1: **{event_mean['accuracy']:.4f} / "
            f"{event_mean['precision']:.4f} / {event_mean['recall']:.4f} / "
            f"{event_mean['f1']:.4f}**.",
            f"Macro mean attack-onward action P/R/F1: **{action_mean['precision']:.4f} / "
            f"{action_mean['recall']:.4f} / {action_mean['f1']:.4f}**.",
            "",
        ]
    )
    (output_dir / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    """Run leave-one-scenario-out TAPAS folds over the selected seeds."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--graphs-root", type=Path, default=DEFAULT_GRAPHS_ROOT)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--dataset", action="append", dest="datasets")
    parser.add_argument("--seeds", default="0,1,2,3,4")
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--batch-size", type=int, default=500)
    args = parser.parse_args()

    selected = set(args.datasets or [])
    dataset_dirs = sorted(
        directory
        for directory in args.graphs_root.iterdir()
        if directory.is_dir()
        and (directory / "manifest.json").exists()
        and (not selected or directory.name in selected)
    )
    if len(dataset_dirs) < 2:
        parser.error("TAPAS leave-one-scenario-out evaluation requires at least two datasets")
    seeds = [int(value) for value in args.seeds.split(",") if value.strip()]
    source_module = load_official_source(args.source)
    scenarios: list[ScenarioGraphs] = []
    for dataset_dir in dataset_dirs:
        print(f"TAPAS featurize {dataset_dir.name}", flush=True)
        scenario = build_scenario(dataset_dir, source_module, args.checkpoint)
        print(
            f"  tasks={len(scenario.tasks)} positive={sum(task.label for task in scenario.tasks)} "
            f"seconds={scenario.feature_seconds:.2f}",
            flush=True,
        )
        scenarios.append(scenario)

    rows: list[dict[str, Any]] = []
    for held_out in scenarios:
        for seed in seeds:
            print(f"TAPAS held-out={held_out.name} seed={seed}", flush=True)
            rows.append(
                run_fold(
                    scenarios,
                    held_out,
                    source_module,
                    args.results_root / "raw" / "tapas" / held_out.name,
                    seed,
                    args.epochs,
                    args.batch_size,
                )
            )
    write_summary(rows, args.results_root / "tapas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
