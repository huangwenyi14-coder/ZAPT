"""Round-trip converted graphs through the pinned SPADE JSON reporter."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parent
SPADE_ROOT = ROOT / "third_party" / "spade"
GRAPHS_ROOT = ROOT / "graphs"
RESULTS_ROOT = ROOT / "results"
JAVA_PROBE = ROOT / "java" / "SpadeImportProbe.java"


def run(
    command: list[str], cwd: Path, timeout_seconds: int = 300
) -> subprocess.CompletedProcess[str]:
    """Run a checked command and retain its text output."""
    return subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=True,
    )


def load_lock() -> dict[str, Any]:
    """Load the single pinned SPADE tool record."""
    lock = json.loads((ROOT / "tool_lock.json").read_text(encoding="utf-8"))
    return next(tool for tool in lock["tools"] if tool["id"] == "spade")


def prepare_spade(expected_revision: str) -> str:
    """Verify the source revision and build only the JSON import path."""
    if not (SPADE_ROOT / ".git").is_dir():
        raise FileNotFoundError(
            "pinned SPADE source is missing; run `uv run python -m "
            "provenance_graph.fetch_tools` first"
        )
    revision = run(["git", "rev-parse", "HEAD"], SPADE_ROOT).stdout.strip()
    if revision != expected_revision:
        raise ValueError(f"SPADE revision mismatch: expected {expected_revision}, got {revision}")
    if not (SPADE_ROOT / "Makefile").exists():
        run(["./configure"], SPADE_ROOT)
    run(
        ["make", "prepare-dirs", "build/spade/reporter/JSON.class"],
        SPADE_ROOT,
        timeout_seconds=600,
    )
    classpath = run(["./bin/classpath.sh"], SPADE_ROOT).stdout.strip()
    run(
        ["javac", "-cp", classpath, "-d", str(SPADE_ROOT / "build"), str(JAVA_PROBE)],
        SPADE_ROOT,
    )
    return classpath


def probe_dataset(dataset_dir: Path, classpath: str) -> dict[str, Any]:
    """Import one graph with SPADE and compare all event counts to its manifest."""
    started = time.perf_counter()
    manifest = json.loads((dataset_dir / "manifest.json").read_text(encoding="utf-8"))
    process = run(
        [
            "java",
            "-cp",
            classpath,
            "SpadeImportProbe",
            str((dataset_dir / "spade.jsonl").resolve()),
        ],
        SPADE_ROOT,
        timeout_seconds=600,
    )
    imported = json.loads(process.stdout.strip().splitlines()[-1])
    expected_counts = manifest["counts"]
    node_count_matches = imported["nodes"] == expected_counts["nodes"]
    edge_count_matches = imported["edges"] == expected_counts["edges"]
    edge_types_match = imported["edges_by_type"] == expected_counts["edges_by_type"]
    checked_direction_types = {
        event_type
        for event_type in (
            "EVENT_EXECUTE",
            "EVENT_READ",
            "EVENT_LOADLIBRARY",
            "EVENT_WRITE",
            "EVENT_CREATE_OBJECT",
            "EVENT_REGISTRY_MODIFY",
            "EVENT_CONNECT",
        )
        if event_type in expected_counts["edges_by_type"]
    }
    directions_match = all(
        imported["valid_direction_by_type"].get(event_type, 0)
        == expected_counts["edges_by_type"][event_type]
        for event_type in checked_direction_types
    )
    return {
        "dataset": dataset_dir.name,
        "expected_nodes": expected_counts["nodes"],
        "imported_nodes": imported["nodes"],
        "expected_edges": expected_counts["edges"],
        "imported_edges": imported["edges"],
        "edges_by_type": imported["edges_by_type"],
        "node_count_matches": node_count_matches,
        "edge_count_matches": edge_count_matches,
        "edge_types_match": edge_types_match,
        "checked_direction_types": sorted(checked_direction_types),
        "causal_directions_match": directions_match,
        "passed": (
            node_count_matches and edge_count_matches and edge_types_match and directions_match
        ),
        "runtime_seconds": time.perf_counter() - started,
    }


def write_results(rows: list[dict[str, Any]], revision: str) -> None:
    """Write machine-readable and human-readable SPADE round-trip evidence."""
    output = {
        "schema_version": "1.0",
        "tool": "SPADE",
        "revision": revision,
        "scope": "official JSON reporter in-memory import and causal-direction checks",
        "all_passed": all(row["passed"] for row in rows),
        "datasets": rows,
    }
    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
    (RESULTS_ROOT / "spade_roundtrip.json").write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# SPADE JSON round-trip",
        "",
        f"Pinned SPADE revision: `{revision}`.",
        "",
        "The official SPADE JSON reporter imported every generated vertex and edge in memory. "
        "Counts were compared with each converter manifest, and execution, file I/O, registry, "
        "and network causal directions were checked after import.",
        "",
        "| Dataset | Nodes | Edges | Type counts | Causal directions | Result |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['dataset']} | {row['imported_nodes']:,} | {row['imported_edges']:,} | "
            f"{'pass' if row['edge_types_match'] else 'fail'} | "
            f"{'pass' if row['causal_directions_match'] else 'fail'} | "
            f"**{'pass' if row['passed'] else 'fail'}** |"
        )
    lines.extend(["", f"Overall: **{'pass' if output['all_passed'] else 'fail'}**.", ""])
    (RESULTS_ROOT / "SPADE_ROUNDTRIP.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    """Build pinned SPADE and round-trip selected converted datasets."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", action="append", dest="datasets")
    args = parser.parse_args()
    selected = set(args.datasets or [])
    dataset_dirs = sorted(
        directory
        for directory in GRAPHS_ROOT.iterdir()
        if directory.is_dir()
        and (directory / "manifest.json").exists()
        and (not selected or directory.name in selected)
    )
    if not dataset_dirs:
        parser.error("no converted datasets selected")
    tool = load_lock()
    revision = str(tool["ref"])
    classpath = prepare_spade(revision)
    rows: list[dict[str, Any]] = []
    for dataset_dir in dataset_dirs:
        print(f"SPADE import {dataset_dir.name}", flush=True)
        row = probe_dataset(dataset_dir, classpath)
        rows.append(row)
        print(
            f"  nodes={row['imported_nodes']} edges={row['imported_edges']} passed={row['passed']}",
            flush=True,
        )
    write_results(rows, revision)
    return int(not all(row["passed"] for row in rows))


if __name__ == "__main__":
    raise SystemExit(main())
