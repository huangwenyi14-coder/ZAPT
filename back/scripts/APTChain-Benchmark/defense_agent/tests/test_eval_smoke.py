"""Smoke test for evaluation pipeline — runs detection + eval on a scenario."""

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
)
from defense_agent.parsers import load_scenario  # noqa: E402


def main(scenario: str = "2018-09-20-apt-c-01") -> None:
    sd = ROOT / "output" / scenario
    t0 = time.time()
    name, events = load_scenario(sd)
    t1 = time.time()
    result = detect_scenario(events)
    t2 = time.time()

    with (sd / "GROUND_TRUTH.json").open() as f:
        gt = json.load(f)

    log_metrics = compute_log_level(name, result["detections"], gt)
    pr_curve = compute_pr_curve(name, result["detections"], gt)
    storyline_metrics = compute_storyline(name, result["detections"], gt)
    t3 = time.time()
    print(f"=== {name} ===")
    print(f"parse {t1 - t0:.1f}s, detect {t2 - t1:.1f}s, eval {t3 - t2:.1f}s")
    print(f"detect stats: {result['stats']}")
    print("log_level (default t=0.2):")
    d = log_metrics.to_dict()
    print(f"  TP={d['tp']} FP={d['fp']} FN={d['fn']}  P={d['precision']} R={d['recall']} F1={d['f1']}")
    print("PR curve:")
    for row in pr_curve:
        print(f"  t={row['threshold']:.1f}  P={row['precision']:.3f} R={row['recall']:.3f} F1={row['f1']:.3f}  TP={row['tp']} FP={row['fp']} FN={row['fn']}")
    print("storyline:")
    sd_m = storyline_metrics.to_dict()
    print(f"  detected {sd_m['storyline_detected']}/{sd_m['storyline_total']}  coverage={sd_m['avg_step_coverage']:.2f}  order={sd_m['order_score']:.2f}")
    print(f"  per_storyline (top missed):")
    missed = [(k, v) for k, v in sd_m['per_storyline'].items() if not v['detected']]
    for k, v in missed[:5]:
        print(f"    miss {k} coverage={v['coverage']}")


if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "2018-09-20-apt-c-01"
    main(scenario)