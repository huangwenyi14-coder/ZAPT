"""Run detection + evaluation for a single scenario."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from defense_agent.detectors import detect_scenario  # noqa: E402
from defense_agent.evaluation import (  # noqa: E402
    compute_log_level,
    compute_pr_curve,
    compute_storyline,
    compute_storyline_candidate_pr,
)
from defense_agent.evaluation.report import write_scenario_report  # noqa: E402
from defense_agent.parsers import load_scenario  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Run defense_agent on a single scenario")
    parser.add_argument("scenario", help="Scenario directory under output/ (or absolute path)")
    parser.add_argument("--out", default="defense_agent/reports", help="Output root directory")
    parser.add_argument("--threshold", type=float, default=0.2, help="Score threshold for 'malicious' (default 0.2)")
    args = parser.parse_args()

    sd = Path(args.scenario)
    if not sd.exists():
        # Try relative to output/
        sd = ROOT / "output" / args.scenario
    if not sd.exists():
        print(f"ERROR: scenario not found: {args.scenario}", file=sys.stderr)
        return 1

    t0 = time.time()
    name, events = load_scenario(sd)
    t1 = time.time()
    result = detect_scenario(events)
    t2 = time.time()

    with (sd / "GROUND_TRUTH.json").open() as f:
        gt = json.load(f)

    log_metrics = compute_log_level(name, result["detections"], gt, malicious_threshold=args.threshold)
    pr_curve = compute_pr_curve(name, result["detections"], gt)
    storyline_metrics = compute_storyline(name, result["detections"], gt)
    candidate_pr = compute_storyline_candidate_pr(name, result["detections"], gt, result["cross_summary"])
    t3 = time.time()

    out_dir = Path(args.out) / name
    write_scenario_report(out_dir, name, result, log_metrics.to_dict(), pr_curve, storyline_metrics.to_dict(), candidate_pr.to_dict())

    print(f"=== {name} ===")
    print(f"parse {t1 - t0:.1f}s, detect {t2 - t1:.1f}s, eval {t3 - t2:.1f}s")
    log_dict = log_metrics.to_dict()
    print(f"  log-level (t={args.threshold}): TP={log_dict['tp']} FP={log_dict['fp']} FN={log_dict['fn']}  P={log_dict['precision']:.4f} R={log_dict['recall']:.4f} F1={log_dict['f1']:.4f}")
    sd_m = storyline_metrics.to_dict()
    cpr = candidate_pr.to_dict()
    print(f"  storyline (GT-side): {sd_m['storyline_detected']}/{sd_m['storyline_total']} coverage={sd_m['avg_step_coverage']:.2f} order={sd_m['order_score']:.2f}")
    print(f"  storyline (cand-side): candidates={cpr['candidates']} matched={cpr['matched']} unmatched={cpr['unmatched']}  P={cpr['precision']:.4f} R={cpr['recall']:.4f} F1={cpr['f1']:.4f}")
    print(f"  report: {out_dir}/summary.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())