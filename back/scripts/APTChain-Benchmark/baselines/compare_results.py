"""Build one comparable table from completed provenance detector runs."""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

from baselines.evaluation import binary_metrics

ROOT = Path(__file__).resolve().parent
RESULTS_ROOT = ROOT / "results"
METHODS = {
    "velox": "VELOX (PIDSMaker)",
    "nodlink": "NODLINK",
    "magic": "MAGIC",
    "threatrace": "ThreaTrace",
    "shadewatcher": "ShadeWatcher",
    "kairos": "KAIROS",
    "orthrus": "ORTHRUS",
}
SCOPES = {
    "velox": "adapted specification",
    "nodlink": "official VAE + input adapter",
    "magic": "official GMAE + two compatibility patches + input adapter",
    "threatrace": "modern PyG API port",
    "shadewatcher": "modern PyTorch objective port",
    "kairos": "official TGN + input adapter",
    "orthrus": "official model stack + input adapter",
}


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def action_from_counts(tp: int, fp: int, fn: int) -> dict[str, float | int]:
    """Compute action precision/recall/F1 from summed counts."""
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": _safe_div(2 * precision * recall, precision + recall),
    }


def aggregate_seed(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Micro-aggregate all scenarios for one seed."""
    event = {
        key: sum(int(row["event_metrics"][key]) for row in rows) for key in ("tp", "fp", "tn", "fn")
    }
    labels = [1] * (event["tp"] + event["fn"]) + [0] * (event["tn"] + event["fp"])
    predictions = [1] * event["tp"] + [0] * event["fn"] + [0] * event["tn"] + [1] * event["fp"]
    action = {
        key: sum(int(row["action_metrics"][key]) for row in rows) for key in ("tp", "fp", "fn")
    }
    return {
        "seed": int(rows[0]["seed"]),
        "event": binary_metrics(labels, predictions),
        "action": action_from_counts(**action),
    }


def mean_metrics(seed_rows: list[dict[str, Any]], view: str) -> dict[str, float]:
    """Average micro metrics across seeds."""
    return {
        metric: statistics.mean(float(row[view][metric]) for row in seed_rows)
        for metric in ("precision", "recall", "f1")
    }


def summarize_method(method_id: str) -> dict[str, Any]:
    """Load one method summary and create seed-micro and scenario-macro views."""
    source = RESULTS_ROOT / method_id / "summary.json"
    raw = json.loads(source.read_text(encoding="utf-8"))
    rows = raw["runs"]
    if method_id == "velox":
        rows = [
            {**row, "event_metrics": row["event"], "action_metrics": row["action"]} for row in rows
        ]
    by_seed: dict[int, list[dict[str, Any]]] = defaultdict(list)
    by_dataset: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_seed[int(row["seed"])].append(row)
        by_dataset[str(row["dataset"])].append(row)
    seed_rows = [aggregate_seed(by_seed[seed]) for seed in sorted(by_seed)]
    scenarios = [
        {
            "dataset": dataset,
            "event_f1": statistics.mean(float(row["event_metrics"]["f1"]) for row in dataset_rows),
            "action_f1": statistics.mean(
                float(row["action_metrics"]["f1"]) for row in dataset_rows
            ),
        }
        for dataset, dataset_rows in sorted(by_dataset.items())
    ]
    return {
        "id": method_id,
        "name": METHODS[method_id],
        "scope": SCOPES[method_id],
        "run_count": len(rows),
        "seed_micro": seed_rows,
        "mean_seed_micro_event": mean_metrics(seed_rows, "event"),
        "mean_seed_micro_action": mean_metrics(seed_rows, "action"),
        "scenario_means": scenarios,
    }


def summarize_tapas() -> dict[str, Any] | None:
    """Load TAPAS without mixing its supervised LOSO scores into the anomaly table."""
    source = RESULTS_ROOT / "tapas" / "summary.json"
    if not source.exists():
        return None
    raw = json.loads(source.read_text(encoding="utf-8"))
    by_dataset: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in raw["runs"]:
        by_dataset[str(row["dataset"])].append(row)
    return {
        "id": "tapas",
        "name": "TAPAS",
        "scope": raw["reproduction_scope"],
        "comparison_class": raw["comparison_class"],
        "run_count": len(raw["runs"]),
        "macro_mean_task": raw["macro_mean_task"],
        "macro_mean_event_full_capture": raw["macro_mean_event_full_capture"],
        "macro_mean_event_attack_onward": raw["macro_mean_event_attack_onward"],
        "macro_mean_action_attack_onward": raw["macro_mean_action_attack_onward"],
        "scenario_means": [
            {
                "dataset": dataset,
                "event_f1": statistics.mean(
                    float(row["event_metrics_attack_onward"]["f1"]) for row in dataset_rows
                ),
                "action_f1": statistics.mean(
                    float(row["action_metrics_attack_onward"]["f1"]) for row in dataset_rows
                ),
            }
            for dataset, dataset_rows in sorted(by_dataset.items())
        ],
    }


def _classification_cell(metrics: dict[str, float]) -> str:
    return (
        f"{metrics['accuracy']:.4f} / {metrics['precision']:.4f} / "
        f"{metrics['recall']:.4f} / {metrics['f1']:.4f}"
    )


def write_markdown(
    methods: list[dict[str, Any]], tapas: dict[str, Any] | None, output: Path
) -> None:
    """Write the main benchmark and source-status tables."""
    dataset_count = len(methods[0]["scenario_means"])
    lines = [
        "# Provenance detector comparison",
        "",
        f"All numeric rows use the same {dataset_count} graphs, temporal clean-prefix split, "
        "five seeds, "
        "event matching, and action-component matching. Reproduction scope still matters: the "
        "table does not present API ports as byte-identical paper reproductions.",
        "",
        "| Method | Reproduction scope | Event P / R / F1 | Action P / R / F1 |",
        "|---|---|---:|---:|",
    ]
    for method in methods:
        event = method["mean_seed_micro_event"]
        action = method["mean_seed_micro_action"]
        lines.append(
            f"| {method['name']} | {method['scope']} | "
            f"{event['precision']:.4f} / {event['recall']:.4f} / {event['f1']:.4f} | "
            f"{action['precision']:.4f} / {action['recall']:.4f} / {action['f1']:.4f} |"
        )
    lines.extend(
        [
            "",
            "## Per-scenario mean F1",
            "",
            "| Dataset | " + " | ".join(method["name"] for method in methods) + " |",
            "|---|" + "---:|" * len(methods),
        ]
    )
    datasets = [row["dataset"] for row in methods[0]["scenario_means"]]
    for dataset in datasets:
        values: list[str] = []
        for method in methods:
            row = next(item for item in method["scenario_means"] if item["dataset"] == dataset)
            values.append(f"{row['event_f1']:.4f} / {row['action_f1']:.4f}")
        lines.append(f"| {dataset} | " + " | ".join(values) + " |")
    lines.extend(
        [
            "",
            "Each cell is `event F1 / action F1`, averaged over five seeds.",
        ]
    )
    if tapas is not None:
        fold_count = len(tapas["scenario_means"])
        task = tapas["macro_mean_task"]
        full_event = tapas["macro_mean_event_full_capture"]
        attack_event = tapas["macro_mean_event_attack_onward"]
        action = tapas["macro_mean_action_attack_onward"]
        lines.extend(
            [
                "",
                "## TAPAS supervised cross-scenario result",
                "",
                "TAPAS uses attack labels to train a task classifier. It therefore runs in "
                f"leave-one-scenario-out folds ({fold_count} total) and is not inserted into the "
                "clean-prefix anomaly "
                "table above. The official LSTM checkpoint and GraphSAGE classes execute directly; "
                "only CDM ingestion and the unsafe within-dataset random split are replaced.",
                "",
                "| View | Accuracy / P / R / F1 |",
                "|---|---:|",
                f"| Native process task | {_classification_cell(task)} |",
                f"| Full-capture log/event | {_classification_cell(full_event)} |",
                f"| Attack-onward log/event | {_classification_cell(attack_event)} |",
                f"| Attack-onward action | — / {action['precision']:.4f} / "
                f"{action['recall']:.4f} / {action['f1']:.4f} |",
                "",
                "| Held-out dataset | Event F1 / action F1 |",
                "|---|---:|",
            ]
        )
        for row in tapas["scenario_means"]:
            lines.append(f"| {row['dataset']} | {row['event_f1']:.4f} / {row['action_f1']:.4f} |")
    lines.extend(
        [
            "",
            "## Remaining source status",
            "",
            "| Method/artifact | Current evidence | Why no score yet |",
            "|---|---|---|",
            "| ProvFusion | Current public entry point loads | Full release is pending; processed input is absent and the main path calls a missing function |",
            "| RapSheet | Paper located | No author source located; consumes upstream EDR alerts rather than raw provenance |",
            "| PROGRAPHER | Paper located | No author source located |",
            "| Slot | Paper located | No author source located |",
            "",
        ]
    )
    output.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    """Build JSON and Markdown comparison artifacts."""
    global RESULTS_ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--results-root",
        type=Path,
        default=RESULTS_ROOT,
        help="Directory containing one summary directory per baseline.",
    )
    args = parser.parse_args(argv)
    RESULTS_ROOT = args.results_root.resolve()
    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)

    methods = [summarize_method(method_id) for method_id in METHODS]
    tapas = summarize_tapas()
    output = {
        "schema_version": "1.0",
        "clean_prefix_methods": methods,
        "supervised_cross_scenario_methods": [tapas] if tapas is not None else [],
    }
    (RESULTS_ROOT / "comparison.json").write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    write_markdown(methods, tapas, RESULTS_ROOT / "COMPARISON.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
