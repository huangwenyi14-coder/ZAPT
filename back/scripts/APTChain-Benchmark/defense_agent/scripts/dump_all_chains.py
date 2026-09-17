"""Dump every candidate chain (matched + unmatched) with its actual events.

Output is meant for human inspection: which FP chains are obviously benign via
behavioral pattern, which missed GT storylines didn't even surface as a candidate.

Run:
    uv run python defense_agent/scripts/dump_all_chains.py
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


def _parse_ts(s: str | None):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _render_event(d: dict) -> str:
    """One-line per event for compactness."""
    parts = [
        d.get("source", "?"),
        d.get("event_type", "?"),
    ]
    if d.get("process_name"):
        proc = d["process_name"].split("\\")[-1]
        parts.append(f"proc={proc}")
    if d.get("command_line"):
        cmd = d["command_line"][:80].replace("\n", " ")
        parts.append(f"cmd='{cmd}'")
    if d.get("user"):
        parts.append(f"user={d['user']}")
    if d.get("dst_ip"):
        parts.append(f"dst={d['dst_ip']}:{d.get('dst_port', '?')}")
    if d.get("domain"):
        parts.append(f"qry={d['domain'][:60]}")
    if d.get("file_path"):
        parts.append(f"file={d['file_path'][:60]}")
    if d.get("registry_key"):
        parts.append(f"reg={d['registry_key'][:60]}")
    if d.get("logon_id"):
        parts.append(f"logon={d['logon_id']}")
    if d.get("pid"):
        parts.append(f"pid={d['pid']}")
    score = d.get("score", 0)
    verdict = d.get("verdict", "?")
    return f"[{d.get('timestamp', '?')[:19]}] [{verdict[:4]}/{score:.2f}] " + " ".join(parts)


def _cluster_members(detections: list[dict], cand: dict) -> list[dict]:
    """Recover the events that built this candidate.

    For beacon/lateral/cred: the events are the cross_summary entries — we
    re-find them by (src_ip, dst_ip, dst_port) / user / etc. within the cand window.

    For rule_cluster: same-host same-window filter.
    """
    cand_first = _parse_ts(cand.get("first"))
    cand_last = _parse_ts(cand.get("last"))
    src = cand.get("source")
    cand_host = cand.get("host", "")

    if not cand_first or not cand_last:
        return []

    if src == "rule_cluster":
        out = []
        for d in detections:
            t = _parse_ts(d.get("timestamp"))
            if not t:
                continue
            if t < cand_first or t > cand_last:
                continue
            if d.get("host") == cand_host:
                out.append(d)
        return out

    if src == "beaconing":
        out = []
        for d in detections:
            t = _parse_ts(d.get("timestamp"))
            if not t:
                continue
            if t < cand_first or t > cand_last:
                continue
            if d.get("dst_ip") == cand.get("dst_ip") and d.get("host") == cand_host:
                out.append(d)
        return out

    if src == "lateral_movement":
        out = []
        for d in detections:
            t = _parse_ts(d.get("timestamp"))
            if not t:
                continue
            if t < cand_first or t > cand_last:
                continue
            if d.get("user") == cand.get("user"):
                out.append(d)
        return out

    return []


def dump_scenario(name: str, sd: Path) -> dict:
    print(f"\n{'=' * 100}")
    print(f"=== {name} ===")
    print(f"{'=' * 100}")

    _, events = load_scenario(sd)
    result = detect_scenario(events)
    detections = result["detections"]
    cross = result["cross_summary"]

    with (sd / "GROUND_TRUTH.json").open() as f:
        gt = json.load(f)

    gt_steps = gt.get("storyline_steps", []) or []
    gt_events = gt.get("events", []) or []
    print(f"GT: {len(gt_steps)} storyline_steps, {len(gt_events)} events")

    # Build candidates via current pipeline
    cands = build_candidates_from_detections(detections, cross)
    print(f"Candidates: {len(cands)}")

    # Match candidates to GT storylines via time+host (same logic as eval)
    def _gt_win(sid):
        evs = [e for e in gt_events if e.get("storyline_id") == sid]
        ts = [_parse_ts(e.get("time")) for e in evs]
        ts = [t for t in ts if t]
        if not ts:
            return None, None
        return min(ts), max(ts)

    cand_to_gt: dict[str, str] = {}
    for c in cands:
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
            host_ok = chost and (
                chost == gsys or chost.endswith(gsys) or gsys.endswith(chost)
            )
            if not host_ok and c.get("user"):
                host_ok = True
            if not host_ok and c.get("source") == "rule_cluster":
                host_ok = True
            if not host_ok:
                continue
            dur = (gl - gf).total_seconds()
            score = 0
            if dur > 0:
                ov = (min(cl, gl) - max(cf, gf)).total_seconds()
                score = ov / dur
            if score > best_score:
                best_score, best_sid = score, st["storyline_id"]
        if best_sid:
            cand_to_gt[c["candidate_id"]] = best_sid

    matched = [c for c in cands if c["candidate_id"] in cand_to_gt]
    unmatched = [c for c in cands if c["candidate_id"] not in cand_to_gt]

    print(f"  matched={len(matched)} (covers GT: {len(set(cand_to_gt.values()))}/{len(gt_steps)})")
    print(f"  unmatched={len(unmatched)}")

    # Group GT storylines by matched/unmatched
    matched_sids = set(cand_to_gt.values())
    print(f"\n  GT storylines COVERED: {sorted(matched_sids)}")
    print(f"  GT storylines MISSED: {[st['storyline_id'] for st in gt_steps if st['storyline_id'] not in matched_sids]}")

    # Dump matched candidates
    print(f"\n--- MATCHED CANDIDATES ({len(matched)}) ---")
    for c in matched:
        sid = cand_to_gt[c["candidate_id"]]
        n = c.get("n_events", 0)
        print(f"\n  * {c['candidate_id']} → GT {sid}  source={c.get('source')} host={c.get('host')} user={c.get('user')} n={n}")
        print(f"    window: {c.get('first')} → {c.get('last')}")
        members = _cluster_members(detections, c)
        # Dedupe by (timestamp, source, event_type, record_id)
        seen = set()
        unique = []
        for m in members:
            k = (m.get("timestamp"), m.get("source"), m.get("event_type"), m.get("record_id"))
            if k in seen:
                continue
            seen.add(k)
            unique.append(m)
        # Show up to 8 representative events
        for m in unique[:8]:
            print(f"    {_render_event(m)}")
        if len(unique) > 8:
            print(f"    ... +{len(unique) - 8} more")

    # Dump unmatched candidates
    print(f"\n--- UNMATCHED CANDIDATES ({len(unmatched)}) ---")
    for c in unmatched:
        n = c.get("n_events", 0)
        print(f"\n  * {c['candidate_id']}  source={c.get('source')} host={c.get('host')} user={c.get('user')} n={n}")
        print(f"    window: {c.get('first')} → {c.get('last')}")
        print(f"    title: {c.get('title', '')[:120]}")
        members = _cluster_members(detections, c)
        seen = set()
        unique = []
        for m in members:
            k = (m.get("timestamp"), m.get("source"), m.get("event_type"), m.get("record_id"))
            if k in seen:
                continue
            seen.add(k)
            unique.append(m)
        for m in unique[:6]:
            print(f"    {_render_event(m)}")
        if len(unique) > 6:
            print(f"    ... +{len(unique) - 6} more")

    # Dump missed GT storylines
    missed = [st for st in gt_steps if st["storyline_id"] not in matched_sids]
    if missed:
        print(f"\n--- MISSED GT STORYLINES ({len(missed)}) ---")
        for st in missed:
            sid = st["storyline_id"]
            print(f"\n  * GT {sid}  system={st.get('system')} technique={st.get('technique')}")
            s_evs = [e for e in gt_events if e.get("storyline_id") == sid]
            for e in s_evs:
                et = e.get("event_type", "?")
                kvs = {k: v for k, v in e.items() if k not in ("storyline_id", "storyline_index", "description")}
                short = " ".join(f"{k}={v}" for k, v in kvs.items())
                print(f"    {e.get('time', '?')[:19]} [{et}] {short[:160]}")


def main() -> int:
    out_dir = ROOT / "output"
    scenarios = sorted([p for p in out_dir.iterdir() if p.is_dir()])
    if len(sys.argv) > 1:
        wanted = set(sys.argv[1:])
        scenarios = [p for p in scenarios if p.name in wanted]
    for sd in scenarios:
        try:
            dump_scenario(sd.name, sd)
        except Exception as exc:
            print(f"\n!!! {sd.name}: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())