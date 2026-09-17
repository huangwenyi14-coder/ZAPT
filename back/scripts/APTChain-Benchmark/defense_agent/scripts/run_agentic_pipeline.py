"""Run the stage-2 through stage-5 event-level incident pipeline.

Stages:
2. Single-event alerting via rule detections.
3. Candidate chain construction from alerts and cross-event correlation.
4. Chain-level judging/filtering without ground truth.
5. Final incident/storyline scoring with ground truth.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from defense_agent.detectors import detect_scenario  # noqa: E402
from defense_agent.detectors.agent.chain_judge import judge_candidates  # noqa: E402
from defense_agent.evaluation import (  # noqa: E402
    build_candidates_from_detections,
    compute_storyline_candidate_pr,
    compute_storyline_candidate_pr_from_candidates,
)
from defense_agent.parsers import load_scenario  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Run agentic incident pipeline")
    parser.add_argument("--out", default="defense_agent/reports_agentic", help="Output root")
    parser.add_argument("--only", nargs="*", default=None, help="Optional scenario names")
    parser.add_argument("--min-score", type=float, default=0.62, help="Stage-4 keep threshold")
    parser.add_argument(
        "--max-incidents", type=int, default=12, help="Max final incidents per scenario"
    )
    args = parser.parse_args()

    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)

    scenario_dirs = sorted([path for path in (ROOT / "output").iterdir() if path.is_dir()])
    if args.only:
        scenario_dirs = [path for path in scenario_dirs if path.name in args.only]

    rows: list[dict[str, Any]] = []
    print(f"Running stage 2-5 pipeline on {len(scenario_dirs)} scenarios...\n")
    started = time.time()
    for scenario_dir in scenario_dirs:
        try:
            row = run_scenario(
                scenario_dir,
                out_root,
                min_score=args.min_score,
                max_incidents=args.max_incidents,
            )
        except Exception as exc:
            print(f"[{scenario_dir.name}] ERROR: {exc}")
            continue
        rows.append(row)
        print(
            f"[{row['scenario']:35s}] "
            f"events={row['stage1_events']:6d} "
            f"alerts={row['stage2_alerts']:5d} "
            f"candidates={row['stage3_candidates']:5d} "
            f"incidents={row['stage4_incidents']:3d} "
            f"P/R/F1={row['final_precision']:.3f}/{row['final_recall']:.3f}/"
            f"{row['final_f1']:.3f} score={row['final_score'] * 100:5.2f}"
        )

    write_global(out_root / "global", rows, elapsed=time.time() - started)
    print(f"\nGlobal report: {out_root / 'global' / 'agentic_report.md'}")
    return 0


def run_scenario(
    scenario_dir: Path,
    out_root: Path,
    *,
    min_score: float,
    max_incidents: int,
) -> dict[str, Any]:
    name, events = load_scenario(scenario_dir)

    # Stage 2: single-event alerts.
    detection_result = detect_scenario(events)
    detections = detection_result["detections"]
    alerts = [item for item in detections if item.get("verdict") in ("suspicious", "malicious")]

    # Stage 3: expand and correlate into candidate chains.
    candidates = build_candidates_from_detections(detections, detection_result["cross_summary"])
    before_pr = _load_gt_and_score(
        name, scenario_dir, detections, detection_result["cross_summary"]
    )

    # Stage 4: chain-level judging. This does not read GT.
    judged = judge_candidates(
        candidates,
        detections,
        min_score=min_score,
        max_candidates=max_incidents,
    )
    incidents = judged["incidents"]

    # Stage 5: final event/storyline scoring.
    with (scenario_dir / "GROUND_TRUTH.json").open(encoding="utf-8") as handle:
        gt = json.load(handle)
    after_pr = compute_storyline_candidate_pr_from_candidates(name, incidents, gt).to_dict()
    final_score = _final_score(after_pr)

    out_dir = out_root / name
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(out_dir / "stage2_detections.jsonl", detections)
    _write_json(out_dir / "stage3_candidates.json", {"candidates": candidates, "score": before_pr})
    _write_json(out_dir / "stage4_incidents.json", judged)
    _write_json(out_dir / "stage5_score.json", {"score": final_score, "candidate_pr": after_pr})
    _write_scenario_md(out_dir / "summary.md", name, judged, before_pr, after_pr, final_score)

    return {
        "scenario": name,
        "stage1_events": len(events),
        "stage2_alerts": len(alerts),
        "stage3_candidates": len(candidates),
        "stage4_incidents": len(incidents),
        "pre_precision": before_pr["precision"],
        "pre_recall": before_pr["recall"],
        "pre_f1": before_pr["f1"],
        "final_precision": after_pr["precision"],
        "final_recall": after_pr["recall"],
        "final_f1": after_pr["f1"],
        "final_score": final_score,
        "gt_total": after_pr["gt_total"],
        "gt_matched": after_pr["gt_matched"],
        "matched_incidents": after_pr["matched"],
        "unmatched_incidents": after_pr["unmatched"],
    }


def _load_gt_and_score(
    name: str,
    scenario_dir: Path,
    detections: list[dict[str, Any]],
    cross_summary: dict[str, Any],
) -> dict[str, Any]:
    with (scenario_dir / "GROUND_TRUTH.json").open(encoding="utf-8") as handle:
        gt = json.load(handle)
    return compute_storyline_candidate_pr(name, detections, gt, cross_summary).to_dict()


def _final_score(candidate_pr: dict[str, Any]) -> float:
    """Final event-level score for this experiment.

    This intentionally scores only the final incident submission. No seed-alert
    score is included.
    """
    precision = candidate_pr["precision"]
    recall = candidate_pr["recall"]
    f1 = candidate_pr["f1"]
    return (0.60 * f1) + (0.25 * recall) + (0.15 * precision)


def _write_json(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _write_scenario_md(
    path: Path,
    scenario: str,
    judged: dict[str, Any],
    before_pr: dict[str, Any],
    after_pr: dict[str, Any],
    final_score: float,
) -> None:
    lines = [
        f"# Agentic Incident Pipeline: {scenario}",
        "",
        "## Stage Counts",
        "",
        f"- Stage 3 candidates: {judged['stats']['input_candidates']}",
        f"- Stage 4 final incidents: {judged['stats']['kept_incidents']}",
        f"- Stage 4 rejected candidates: {judged['stats']['rejected_candidates']}",
        "",
        "## Candidate PR Before Stage 4",
        "",
        _format_pr(before_pr),
        "",
        "## Final Incident PR After Stage 4",
        "",
        _format_pr(after_pr),
        "",
        f"Final score: **{final_score * 100:.2f}/100**",
        "",
        "## Final Incidents",
        "",
    ]
    for incident in judged["incidents"][:20]:
        lines.append(
            f"- {incident['candidate_id']} source={incident.get('source')} "
            f"score={incident.get('judge_score')} host={incident.get('host')} "
            f"time={incident.get('first')}..{incident.get('last')} "
            f"reasons={'; '.join(incident.get('judge_reasons', [])[:4])}"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _format_pr(pr: dict[str, Any]) -> str:
    return (
        f"Candidates={pr['candidates']} matched={pr['matched']} unmatched={pr['unmatched']} "
        f"GT={pr['gt_matched']}/{pr['gt_total']} "
        f"P/R/F1={pr['precision']:.4f}/{pr['recall']:.4f}/{pr['f1']:.4f}"
    )


def write_global(global_dir: Path, rows: list[dict[str, Any]], *, elapsed: float) -> None:
    global_dir.mkdir(parents=True, exist_ok=True)
    _write_json(global_dir / "agentic_all_scenarios.json", rows)

    csv_path = global_dir / "agentic_all_scenarios.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else [])
        writer.writeheader()
        writer.writerows(rows)

    macro = _macro(rows)
    micro = _micro(rows)
    lines = [
        "# Agentic Pipeline Report",
        "",
        f"Elapsed: {elapsed:.1f}s",
        "",
        "## Aggregate",
        "",
        f"- Macro P/R/F1: {macro['precision']:.4f}/{macro['recall']:.4f}/{macro['f1']:.4f}",
        f"- Macro final score: {macro['score'] * 100:.2f}/100",
        f"- Micro P/R/F1: {micro['precision']:.4f}/{micro['recall']:.4f}/{micro['f1']:.4f}",
        "",
        "## Scenarios",
        "",
        "| Scenario | Events | Alerts | Candidates | Incidents | P | R | F1 | Score |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['scenario']} | {row['stage1_events']} | {row['stage2_alerts']} | "
            f"{row['stage3_candidates']} | {row['stage4_incidents']} | "
            f"{row['final_precision']:.3f} | {row['final_recall']:.3f} | "
            f"{row['final_f1']:.3f} | {row['final_score'] * 100:.2f} |"
        )
    (global_dir / "agentic_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _macro(rows: list[dict[str, Any]]) -> dict[str, float]:
    if not rows:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "score": 0.0}
    return {
        "precision": sum(row["final_precision"] for row in rows) / len(rows),
        "recall": sum(row["final_recall"] for row in rows) / len(rows),
        "f1": sum(row["final_f1"] for row in rows) / len(rows),
        "score": sum(row["final_score"] for row in rows) / len(rows),
    }


def _micro(rows: list[dict[str, Any]]) -> dict[str, float]:
    candidates = sum(row["stage4_incidents"] for row in rows)
    matched = sum(row["matched_incidents"] for row in rows)
    gt_total = sum(row["gt_total"] for row in rows)
    gt_matched = sum(row["gt_matched"] for row in rows)
    precision = matched / candidates if candidates else 0.0
    recall = gt_matched / gt_total if gt_total else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


if __name__ == "__main__":
    sys.exit(main())
