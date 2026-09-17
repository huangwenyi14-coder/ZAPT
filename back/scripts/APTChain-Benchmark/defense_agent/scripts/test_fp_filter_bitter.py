"""Test the chain FP scorer on bitter: before/after comparison."""

from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from defense_agent.detectors import detect_scenario  # noqa: E402
from defense_agent.evaluation.storyline_candidates import (  # noqa: E402
    build_candidates_from_detections,
)
from defense_agent.parsers import load_scenario  # noqa: E402
from defense_agent.scripts.chain_fp_scorer import (  # noqa: E402
    filter_chains,
    score_chain_fp,
)
from defense_agent.scripts.count_pipeline_stages import (  # noqa: E402
    _chain_to_candidate_format,
    _union_find_chains,
)


def _parse_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _gt_win(gt_events, sid):
    evs = [e for e in gt_events if e.get("storyline_id") == sid]
    ts = [_parse_ts(e.get("time")) for e in evs]
    ts = [t for t in ts if t]
    if not ts:
        return None, None
    return min(ts), max(ts)


def align_to_gt(all_cands, gt_steps, gt_events):
    cand_to_gt = {}
    for c in all_cands:
        cf, cl = _parse_ts(c.get("first")), _parse_ts(c.get("last"))
        chost = c.get("host", "")
        best_sid, best_score = None, -1
        for st in gt_steps:
            gf, gl = _gt_win(gt_events, st["storyline_id"])
            if not (cf and cl and gf and gl):
                continue
            if not (cf <= gl and gf <= cl):
                continue
            gsys = st.get("system", "")
            host_ok = chost and (chost == gsys or chost.endswith(gsys) or gsys.endswith(chost))
            if not host_ok and c.get("user"):
                host_ok = True
            if not host_ok and c.get("source") in ("rule_cluster", "id_union"):
                host_ok = True
            if not host_ok:
                continue
            dur = (gl - gf).total_seconds()
            score = (min(cl, gl) - max(cf, gf)).total_seconds() / dur if dur > 0 else 0
            if score > best_score:
                best_score, best_sid = score, st["storyline_id"]
        if best_sid:
            cand_to_gt[c["candidate_id"]] = best_sid
    return cand_to_gt


def run_scenario(sd: Path, threshold: float = 0.50):
    name, events = load_scenario(sd)
    result = detect_scenario(events)
    detections = result["detections"]
    cross = result["cross_summary"]

    with (sd / "GROUND_TRUTH.json").open() as f:
        gt = json.load(f)
    gt_steps = gt.get("storyline_steps", [])
    gt_events = gt.get("events", [])

    susp = [d for d in detections if d.get("verdict") in ("suspicious", "malicious")]
    chains = _union_find_chains(susp, time_window_sec=1800)
    chain_cands = [_chain_to_candidate_format(c, susp) for c in chains]
    cross_cands = build_candidates_from_detections(detections, cross)
    seen = {c["candidate_id"] for c in chain_cands}
    all_cands_pre = list(chain_cands) + [c for c in cross_cands if c["candidate_id"] not in seen]

    # Build members map for chain_cands
    chain_id_to_members = {}
    for c, indices in zip(chain_cands, chains):
        chain_id_to_members[c["candidate_id"]] = [susp[i] for i in indices]

    # Filter
    chain_kept, chain_dropped, chain_dropped_reasons = filter_chains(
        chain_cands, chain_id_to_members, threshold=threshold
    )
    # cross_summary candidates: not filtered (they're already beacon/lateral/cred)
    all_cands_post = list(chain_kept) + [c for c in cross_cands if c["candidate_id"] not in {x["candidate_id"] for x in chain_kept}]

    # Align
    pre_to_gt = align_to_gt(all_cands_pre, gt_steps, gt_events)
    post_to_gt = align_to_gt(all_cands_post, gt_steps, gt_events)

    pre_tp = len(set(pre_to_gt.values()))
    pre_fp = len(all_cands_pre) - len(pre_to_gt)
    pre_prec = pre_tp / max(1, len(all_cands_pre))
    pre_recall = pre_tp / max(1, len(gt_steps))

    post_tp = len(set(post_to_gt.values()))
    post_fp = len(all_cands_post) - len(post_to_gt)
    post_prec = post_tp / max(1, len(all_cands_post))
    post_recall = post_tp / max(1, len(gt_steps))

    print(f"=== {sd.name} (threshold={threshold}) ===")
    print(f"  chains: {len(chain_cands)} → kept={len(chain_kept)} dropped={len(chain_dropped)}")
    print()
    print(f"  BEFORE filter: {len(all_cands_pre):>3} candidates ({pre_tp} TP + {pre_fp} FP)  "
          f"P={pre_prec:.3f} R={pre_recall:.3f}  F1={2*pre_prec*pre_recall/(pre_prec+pre_recall+1e-9):.3f}")
    print(f"  AFTER  filter: {len(all_cands_post):>3} candidates ({post_tp} TP + {post_fp} FP)  "
          f"P={post_prec:.3f} R={post_recall:.3f}  F1={2*post_prec*post_recall/(post_prec+post_recall+1e-9):.3f}")
    print()

    # Signal distribution
    sig_counts = Counter()
    for d in chain_dropped_reasons:
        for s in d["_fp_signals"]:
            sig_counts[s] += 1
    print(f"  Drop signals fired: {dict(sig_counts)}")

    # Show dropped with reasons
    if chain_dropped_reasons:
        print(f"\n  --- {len(chain_dropped_reasons)} dropped chains ---")
        for d in chain_dropped_reasons[:15]:
            still_tp = d["candidate_id"] in pre_to_gt
            tag = " [WAS TP]" if still_tp else ""
            print(f"    {d['candidate_id']} host={d['host']} user={d['user']} n={d['n_events']} "
                  f"score={d['_fp_score']} signals={d['_fp_signals']}{tag}")
        if len(chain_dropped_reasons) > 15:
            print(f"    ... +{len(chain_dropped_reasons)-15} more")

    # TP preservation: how many of the original TPs are still in post?
    pre_tp_chains = set(pre_to_gt.keys())
    post_tp_chains = set(post_to_gt.keys())
    lost_tp = pre_tp_chains - post_tp_chains
    if lost_tp:
        print(f"\n  ⚠ LOST {len(lost_tp)} TP chains:")
        for cid in lost_tp:
            d = next((x for x in chain_dropped_reasons if x["candidate_id"] == cid), None)
            if d:
                print(f"    {cid} host={d['host']} user={d['user']} n={d['n_events']} "
                      f"matched GT={pre_to_gt[cid]} score={d['_fp_score']} signals={d['_fp_signals']}")
    else:
        print(f"\n  ✓ All {pre_tp} TP chains preserved.")

    return {
        "scenario": sd.name,
        "pre": (len(all_cands_pre), pre_tp, pre_fp, pre_prec, pre_recall),
        "post": (len(all_cands_post), post_tp, post_fp, post_prec, post_recall),
        "lost_tp": len(lost_tp),
    }


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "2024-10-12-bitter-apt-q-37"
    threshold = float(sys.argv[2]) if len(sys.argv) > 2 else 0.50
    sd = ROOT / "output" / target
    run_scenario(sd, threshold=threshold)