"""Dump all chains in a scenario with full GT storyline mapping.

For each chain, show:
- members (truncated)
- which GT storyline it matched (if any)
- whether it covers multiple storyline windows
- verdict
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from defense_agent.detectors import detect_scenario  # noqa: E402
from defense_agent.evaluation.storyline_candidates import (  # noqa: E402
    build_candidates_from_detections,
)
from defense_agent.parsers import load_scenario  # noqa: E402
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


def _all_gt_windows(gt_events, gt_steps):
    return {st["storyline_id"]: _gt_win(gt_events, st["storyline_id"]) for st in gt_steps}


def render(ev):
    p = []
    pn = ev.get("process_name") or ""
    if pn:
        p.append("proc=" + pn.split("\\")[-1][:18])
    cl = ev.get("command_line") or ""
    if cl:
        p.append("cmd='" + cl[:35].replace("\n", " ") + "'")
    if ev.get("user"):
        p.append("u=" + ev["user"][:12])
    if ev.get("dst_ip"):
        p.append(f"dst={ev['dst_ip']}:{ev.get('dst_port', '?')}")
    if ev.get("file_path"):
        p.append("f=" + ev["file_path"][:30])
    if ev.get("logon_id"):
        p.append("lg=" + ev["logon_id"][:10])
    if ev.get("pid"):
        p.append(f"pid={ev['pid']}")
    return f"[{ev.get('timestamp','')[11:19]}] [{ev.get('verdict','')[:4]}/{ev.get('score',0):.2f}] " + " ".join(p)


def overlap_pct(cf, cl, gf, gl):
    """For single-point GT events: returns 1.0 if chain window contains GT time, else 0.0.
    For window GT: returns fraction of GT window covered by chain."""
    if not (cf and cl and gf and gl):
        return 0.0
    if not (cf <= gl and gf <= cl):
        return 0.0
    # If GT is a point (gl==gf), check if chain contains it
    if gl == gf:
        return 1.0 if gf <= cl and gf >= cf else 0.0
    dur = (gl - gf).total_seconds()
    if dur <= 0:
        return 0.0
    return (min(cl, gl) - max(cf, gf)).total_seconds() / dur


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "2024-10-12-bitter-apt-q-37"
    sd = ROOT / "output" / target
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
    all_cands = list(chain_cands) + [c for c in cross_cands if c["candidate_id"] not in seen]

    chain_id_to_members = {}
    for c, indices in zip(chain_cands, chains):
        chain_id_to_members[c["candidate_id"]] = [susp[i] for i in indices]

    # For each chain, find all GT storylines whose window overlaps significantly
    gt_windows = _all_gt_windows(gt_events, gt_steps)

    # Detailed chain -> GT overlap analysis
    chain_gt_overlap = {}
    for cand in all_cands:
        cf, cl = _parse_ts(cand.get("first")), _parse_ts(cand.get("last"))
        chost = cand.get("host", "")
        overlaps = []
        for st in gt_steps:
            sid = st["storyline_id"]
            gf, gl = gt_windows[sid]
            if not (cf and cl and gf and gl):
                continue
            if not (cf <= gl and gf <= cl):
                continue
            gsys = st.get("system", "")
            host_ok = chost and (chost == gsys or chost.endswith(gsys) or gsys.endswith(chost))
            if not host_ok and cand.get("user"):
                host_ok = True
            if not host_ok and cand.get("source") in ("rule_cluster", "id_union"):
                host_ok = True
            if not host_ok:
                continue
            ov = overlap_pct(cf, cl, gf, gl)
            overlaps.append((sid, round(ov, 3)))
        overlaps.sort(key=lambda kv: -kv[1])
        chain_gt_overlap[cand["candidate_id"]] = overlaps

    # Sort chains: TP first (those with overlap>0), then FP by size desc
    chain_to_best_gt = {cid: (ov[0][0] if ov else None) for cid, ov in chain_gt_overlap.items() if ov}
    chains_tp = [c for c in all_cands if c["candidate_id"] in chain_to_best_gt]
    chains_fp = [c for c in all_cands if c["candidate_id"] not in chain_to_best_gt]
    chains_tp.sort(key=lambda c: -chain_gt_overlap[c["candidate_id"]][0][1])
    chains_fp.sort(key=lambda c: -c.get("n_events", 0))

    # GT -> chain coverage map
    gt_to_chains = defaultdict(list)
    for cid, overlaps in chain_gt_overlap.items():
        for sid, ov in overlaps:
            if ov > 0:
                gt_to_chains[sid].append((cid, ov))

    print("=" * 100)
    print(f"{target}: FULL CHAIN DUMP WITH GT STORYLINE MAPPING")
    print("=" * 100)
    print(f"GT storylines: {len(gt_steps)}")
    print(f"  GT coverage: {len(gt_to_chains)}/{len(gt_steps)} storylines have at least 1 chain")
    print(f"  Missed GT storylines: {[st['storyline_id'] for st in gt_steps if st['storyline_id'] not in gt_to_chains]}")
    print()
    print(f"Total chains: {len(all_cands)}  (id_union: {len(chain_cands)} + cross: {len(cross_cands)})")
    print(f"  TP chains (≥1 GT overlap): {len(chains_tp)}")
    print(f"  FP chains (no GT overlap): {len(chains_fp)}")
    print()

    # === TP chains ===
    print("=" * 100)
    print(f"TP CHAINS ({len(chains_tp)}) — chains that match at least one GT storyline")
    print("=" * 100)
    for c in chains_tp:
        cid = c["candidate_id"]
        overlaps = chain_gt_overlap[cid]
        members = chain_id_to_members.get(cid, [])
        members.sort(key=lambda d: d.get("timestamp", ""))
        gt_str = ", ".join(f"{sid}={ov:.0%}" for sid, ov in overlaps[:3])
        n = len(members)
        n_unique_procs = len(set((m.get("process_name") or "").split("\\")[-1] for m in members if m.get("process_name")))
        n_unique_users = len(set(m.get("user", "") for m in members if m.get("user")))
        duration = ""
        if members:
            first = _parse_ts(members[0].get("timestamp"))
            last = _parse_ts(members[-1].get("timestamp"))
            if first and last:
                duration = f"({(last-first).total_seconds()/60:.0f}min span)"
        print(f"\n--- {cid} | host={c['host']} user={c['user']} n={n} procs={n_unique_procs} users={n_unique_users} {duration} ---")
        print(f"    GT overlap: {gt_str}")
        # Show all member events (or first 10)
        for m in members[:8]:
            print(f"    {render(m)}")
        if len(members) > 8:
            print(f"    ... +{len(members)-8} more events")

    # === FP chains ===
    print("\n" + "=" * 100)
    print(f"FP CHAINS ({len(chains_fp)}) — no GT storyline match")
    print("=" * 100)
    for c in chains_fp:
        cid = c["candidate_id"]
        members = chain_id_to_members.get(cid, [])
        members.sort(key=lambda d: d.get("timestamp", ""))
        n = len(members)
        n_unique_procs = len(set((m.get("process_name") or "").split("\\")[-1] for m in members if m.get("process_name")))
        n_unique_users = len(set(m.get("user", "") for m in members if m.get("user")))
        # Classify what kind of activity
        procs = [((m.get("process_name") or "").split("\\")[-1]) for m in members if m.get("process_name")]
        proc_summary = Counter(procs).most_common(3)
        proc_str = ", ".join(f"{p}×{cnt}" for p, cnt in proc_summary)
        users = [m.get("user","") for m in members if m.get("user")]
        user_summary = Counter(users).most_common(2)
        user_str = ", ".join(f"{u}×{cnt}" if u else f"none×{cnt}" for u, cnt in user_summary)
        print(f"\n--- {cid} | host={c['host']} user={c.get('user','(none)')} n={n} procs={n_unique_procs} users={n_unique_users} ---")
        print(f"    procs: {proc_str}")
        print(f"    users: {user_str}")
        for m in members[:5]:
            print(f"    {render(m)}")
        if len(members) > 5:
            print(f"    ... +{len(members)-5} more events")

    # === Multi-storyline coverage ===
    print("\n" + "=" * 100)
    print("MULTI-STORYLINE COVERAGE: does any chain cover >1 GT storyline?")
    print("=" * 100)
    multi = []
    for cid, overlaps in chain_gt_overlap.items():
        sig = [ov for ov in overlaps if ov[1] > 0.5]
        if len(sig) > 1:
            multi.append((cid, sig))
    if multi:
        print(f"\n{len(multi)} chain(s) cover multiple GT storylines:")
        for cid, sig in multi:
            cand = next(c for c in all_cands if c["candidate_id"] == cid)
            members = chain_id_to_members.get(cid, [])
            print(f"\n  {cid} host={cand['host']} user={cand['user']} n={len(members)}")
            print(f"    Covers: {[(s, f'{o:.0%}') for s, o in sig]}")
    else:
        print("  No chain covers multiple GT storylines.")

    # === GT storyline -> which chains cover it ===
    print("\n" + "=" * 100)
    print("GT STORYLINE → COVERING CHAINS (which chains cover each GT storyline)")
    print("=" * 100)
    for st in gt_steps:
        sid = st["storyline_id"]
        gf, gl = gt_windows[sid]
        covering = gt_to_chains.get(sid, [])
        print(f"\n  {sid} | {st.get('system')} | {st.get('activity','')[:60]}  GT_time={gf.strftime('%H:%M:%S') if gf else '?'}")
        if covering:
            for cid, ov in covering:
                cand = next(c for c in all_cands if c["candidate_id"] == cid)
                print(f"      covered by {cid:>10} ov={ov:.0%} host={cand['host']} user={cand['user']} n={cand['n_events']} src={cand['source']}")
        else:
            print(f"      (NO CHAIN COVERS THIS STORYLINE)")

    return 0


if __name__ == "__main__":
    sys.exit(main())