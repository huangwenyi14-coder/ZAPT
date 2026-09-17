"""Run detection + evaluation for all scenarios under output/."""

from __future__ import annotations

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
from defense_agent.evaluation.report import (  # noqa: E402
    write_global_report,
    write_scenario_report,
)
from defense_agent.parsers import load_scenario  # noqa: E402


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="defense_agent/reports", help="Output root directory")
    parser.add_argument("--threshold", type=float, default=0.2)
    parser.add_argument("--only", nargs="*", default=None, help="Optional list of scenario names to limit to")
    args = parser.parse_args()

    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)

    scenario_dirs = sorted([p for p in (ROOT / "output").iterdir() if p.is_dir()])
    if args.only:
        scenario_dirs = [p for p in scenario_dirs if p.name in args.only]

    per_scenario = []
    print(f"Running on {len(scenario_dirs)} scenarios...\n")
    grand_t0 = time.time()
    for sd in scenario_dirs:
        t0 = time.time()
        try:
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

            out_dir = out_root / name
            write_scenario_report(out_dir, name, result, log_metrics.to_dict(), pr_curve, storyline_metrics.to_dict(), candidate_pr.to_dict())

            log_dict = log_metrics.to_dict()
            sd_m = storyline_metrics.to_dict()
            cand_dict = candidate_pr.to_dict()
            print(f"[{name:35s}] parse {t1 - t0:5.1f}s detect {t2 - t1:5.1f}s eval {t3 - t2:5.1f}s  | log P/R/F1={log_dict['precision']:.3f}/{log_dict['recall']:.3f}/{log_dict['f1']:.3f} ({log_dict['tp']}/{log_dict['fp']}/{log_dict['fn']})  | cand-storyline P/R/F1={cand_dict['precision']:.3f}/{cand_dict['recall']:.3f}/{cand_dict['f1']:.3f} ({cand_dict['matched']}/{cand_dict['candidates']} matched; {cand_dict['gt_matched']}/{cand_dict['gt_total']} GT)")

            per_scenario.append({
                "scenario": name,
                "log_dict": log_dict,
                "pr_curve": pr_curve,
                "storyline_dict": sd_m,
                "candidate_pr_dict": cand_dict,
                "cross_counts": {
                    "beacons": len(result["cross_summary"]["beacons"]),
                    "lateral": len(result["cross_summary"]["lateral_movement"]),
                    "cred_dumping": len(result["cross_summary"]["credential_dumping"]),
                },
            })
        except Exception as exc:
            print(f"[{sd.name}] ERROR: {exc}")

    grand_t1 = time.time()
    print(f"\nTotal elapsed: {grand_t1 - grand_t0:.1f}s")

    write_global_report(out_root / "global", per_scenario)
    print(f"\nGlobal report: {out_root / 'global' / 'report.md'}")
    print(f"Per-scenario reports: {out_root}/<scenario>/summary.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())