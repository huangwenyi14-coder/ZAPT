"""Report the actual chain counts at each pipeline stage.

Stages:
  S0  raw parsed events
  S2  suspicious+malicious alerts (per-event)
  S3  ID-union chains (multi-ID graph expansion → connected components)
  S4  final candidates (= cross_summary beacons/lateral/cred + S3 chains)
  S5  GT alignment

For each scenario: counts at every stage + chain-level precision/recall against GT.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from defense_agent.detectors import detect_scenario  # noqa: E402
from defense_agent.evaluation.storyline_candidates import (  # noqa: E402
    build_candidates_from_detections,
)
from defense_agent.parsers import load_scenario  # noqa: E402


def _parse_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _union_find_chains(suspicious: list[dict], time_window_sec: int = 1800) -> list[set[int]]:
    """Multi-ID union-find: merge alerts that share IDs within time_window.

    IDs used (hard edges):
      pid, uid, logon_id, dst_ip+dst_port (when both set), src_ip+src_port
    Soft edges (same-host same-user within window):
      host+user
    """
    parent = list(range(len(suspicious)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    # Build id → indices
    by_pid: dict[int, list[int]] = defaultdict(list)
    by_uid: dict[str, list[int]] = defaultdict(list)
    by_logon: dict[str, list[int]] = defaultdict(list)
    by_dst: dict[tuple, list[int]] = defaultdict(list)
    by_host_user: dict[tuple, list[int]] = defaultdict(list)

    for i, d in enumerate(suspicious):
        if d.get("pid"):
            by_pid[d["pid"]].append(i)
        if d.get("uid"):
            by_uid[d["uid"]].append(i)
        if d.get("logon_id"):
            by_logon[d["logon_id"]].append(i)
        if d.get("dst_ip") and d.get("dst_port"):
            by_dst[(d["dst_ip"], d["dst_port"])].append(i)
        if d.get("host") and d.get("user"):
            by_host_user[(d["host"], d["user"])].append(i)

    # Hard unions
    for grp in [by_pid, by_uid, by_logon, by_dst]:
        for ids in grp.values():
            for j in ids[1:]:
                union(ids[0], j)

    # Soft union: same host+user within time window
    for key, ids in by_host_user.items():
        ids_sorted = sorted(ids, key=lambda i: suspicious[i].get("timestamp") or "")
        for i in range(len(ids_sorted)):
            for j in range(i + 1, len(ids_sorted)):
                ti = _parse_ts(suspicious[ids_sorted[i]].get("timestamp"))
                tj = _parse_ts(suspicious[ids_sorted[j]].get("timestamp"))
                if ti and tj and abs((tj - ti).total_seconds()) <= time_window_sec:
                    union(ids_sorted[i], ids_sorted[j])

    # Collect components
    groups: dict[int, set[int]] = defaultdict(set)
    for i in range(len(suspicious)):
        groups[find(i)].add(i)
    return list(groups.values())


def _chain_to_candidate_format(chain_indices, suspicious):
    members = [suspicious[i] for i in chain_indices]
    members.sort(key=lambda d: d.get("timestamp", ""))
    first = members[0].get("timestamp")
    last = members[-1].get("timestamp")
    host = next((m.get("host") for m in members if m.get("host")), "")
    user = next((m.get("user") for m in members if m.get("user")), None)
    techniques = []
    for m in members:
        for r in m.get("reasons", []):
            t = r.get("technique", "")
            if t and t not in techniques:
                techniques.append(t)
    return {
        "candidate_id": f"chain-{min(chain_indices)}",
        "source": "id_union",
        "host": host,
        "user": user,
        "first": first,
        "last": last,
        "n_events": len(members),
        "technique": techniques[0] if techniques else "T1071",
        "title": f"chain of {len(members)} events on {host}",
    }


def analyze_scenario(name: str, sd: Path) -> dict:
    name_, events = load_scenario(sd)
    result = detect_scenario(events)
    detections = result["detections"]
    cross = result["cross_summary"]

    with (sd / "GROUND_TRUTH.json").open() as f:
        gt = json.load(f)
    gt_steps = gt.get("storyline_steps", []) or []
    gt_events = gt.get("events", []) or []

    susp = [d for d in detections if d.get("verdict") in ("suspicious", "malicious")]

    # S3: ID-union chains
    chains = _union_find_chains(susp, time_window_sec=1800)
    chain_cands = [_chain_to_candidate_format(c, susp) for c in chains if len(c) >= 1]

    # S4: add cross-summary candidates
    cross_cands = build_candidates_from_detections(detections, cross)

    # All candidates: union of chains + cross-summary (dedup by candidate_id)
    seen_ids = {c["candidate_id"] for c in chain_cands}
    all_cands = list(chain_cands)
    for c in cross_cands:
        if c["candidate_id"] not in seen_ids:
            all_cands.append(c)
            seen_ids.add(c["candidate_id"])

    # GT alignment
    def _gt_win(sid):
        evs = [e for e in gt_events if e.get("storyline_id") == sid]
        ts = [_parse_ts(e.get("time")) for e in evs]
        ts = [t for t in ts if t]
        if not ts:
            return None, None
        return min(ts), max(ts)

    cand_to_gt = {}
    for c in all_cands:
        cf, cl = _parse_ts(c.get("first")), _parse_ts(c.get("last"))
        chost = c.get("host", "")
        best_sid, best_score = None, -1
        for st in gt_steps:
            gf, gl = _gt_win(st["storyline_id"])
            if not (cf and cl and gf and gl):
                continue
            if not (cf <= gl and gf <= cl):
                continue
            gsys = st.get("system", "")
            host_ok = chost and (chost == gsys or chost.endswith(gsys) or gsys.endswith(chost))
            if not host_ok and c.get("user"):
                host_ok = True
            if not host_ok and c.get("source") == "rule_cluster":
                host_ok = True
            if not host_ok and c.get("source") == "id_union":
                host_ok = True
            if not host_ok:
                continue
            dur = (gl - gf).total_seconds()
            score = (min(cl, gl) - max(cf, gf)).total_seconds() / dur if dur > 0 else 0
            if score > best_score:
                best_score, best_sid = score, st["storyline_id"]
        if best_sid:
            cand_to_gt[c["candidate_id"]] = best_sid

    matched_sids = set(cand_to_gt.values())

    # How many alert events are in chains vs not
    in_chain = set()
    for c in chains:
        in_chain.update(c)

    # How many suspicious alerts are in any chain
    chained_alerts = len(in_chain)
    isolated_alerts = len(susp) - chained_alerts

    # How many suspicious alerts contain any GT event (event-level recall)
    def _gt_event_in_alerts(ge):
        attrs = ge.get("attributes") or {}
        keys = []
        if ge.get("pid") or attrs.get("pid"):
            keys.append(("pid", ge.get("pid") or attrs.get("pid")))
        if ge.get("uid") or attrs.get("uid"):
            keys.append(("uid", ge.get("uid") or attrs.get("uid")))
        if ge.get("logon_id") or attrs.get("logon_id"):
            keys.append(("logon_id", ge.get("logon_id") or attrs.get("logon_id")))
        d_ip = ge.get("dst_ip") or attrs.get("dst_ip") or attrs.get("destination_ip")
        d_pt = ge.get("dst_port") or attrs.get("dst_port") or attrs.get("destination_port")
        if d_ip:
            keys.append(("dst_ip", d_ip, d_pt))
        if not keys:
            return False
        for a in susp:
            for k in keys:
                if k[0] == "pid" and a.get("pid") == k[1]:
                    return True
                if k[0] == "uid" and a.get("uid") == k[1]:
                    return True
                if k[0] == "logon_id" and a.get("logon_id") == k[1]:
                    return True
                if k[0] == "dst_ip" and a.get("dst_ip") == k[1]:
                    if k[2] is None or a.get("dst_port") == k[2]:
                        return True
        return False

    gt_in_alerts = sum(1 for ge in gt_events if _gt_event_in_alerts(ge))

    return {
        "scenario": name,
        "n_events": len(detections),
        "n_susp": len(susp),
        "n_chains": len(chain_cands),
        "chain_max_size": max((len(c) for c in chains), default=0),
        "chain_min_size": min((len(c) for c in chains), default=0),
        "n_chained_alerts": chained_alerts,
        "n_isolated_alerts": isolated_alerts,
        "n_cross_cands": len(cross_cands),
        "n_total_cands": len(all_cands),
        "n_matched_gt_sids": len(matched_sids),
        "n_total_gt_sids": len(gt_steps),
        "n_unmatched_cands": len(all_cands) - len(cand_to_gt),
        "gt_events_in_alerts": gt_in_alerts,
        "gt_events_total": len(gt_events),
    }


def main() -> int:
    out_dir = ROOT / "output"
    scenarios = sorted([p for p in out_dir.iterdir() if p.is_dir()])
    if len(sys.argv) > 1:
        wanted = set(sys.argv[1:])
        scenarios = [p for p in scenarios if p.name in wanted]

    print(f"{'scenario':<38} {'S0':>5} {'S2':>5} {'S3':>5} {'iso':>4} {'cross':>6} {'cands':>6} {'TP':>3} {'FP':>4} {'GT_recall':>10}")
    print("-" * 110)
    rows = []
    for sd in scenarios:
        try:
            r = analyze_scenario(sd.name, sd)
            rows.append(r)
            gt_recall = f"{r['gt_events_in_alerts']}/{r['gt_events_total']}"
            print(f"{r['scenario']:<38} {r['n_events']:>5} {r['n_susp']:>5} {r['n_chains']:>5} "
                  f"{r['n_isolated_alerts']:>4} {r['n_cross_cands']:>6} {r['n_total_cands']:>6} "
                  f"{r['n_matched_gt_sids']:>3} {r['n_unmatched_cands']:>4} {gt_recall:>10}")
        except Exception as exc:
            import traceback
            print(f"!!! {sd.name}: {exc}")
            traceback.print_exc()

    return 0


if __name__ == "__main__":
    sys.exit(main())