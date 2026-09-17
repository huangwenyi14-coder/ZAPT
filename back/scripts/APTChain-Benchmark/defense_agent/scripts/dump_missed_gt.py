"""For each scenario, dump the GT events that didn't match any candidate.

For each missed GT storyline, print:
  - The GT events themselves (full content)
  - Whether they appear in the parser output at all
  - Whether they were marked suspicious in S2
  - Why they didn't form a candidate

This answers: is the GT observable in the data? if yes, why didn't we recall it?
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


def analyze_scenario(name: str, sd: Path) -> list[dict]:
    _, events = load_scenario(sd)
    result = detect_scenario(events)
    detections = result["detections"]
    cross = result["cross_summary"]

    with (sd / "GROUND_TRUTH.json").open() as f:
        gt = json.load(f)

    gt_steps = gt.get("storyline_steps", []) or []
    gt_events = gt.get("events", []) or []

    cands = build_candidates_from_detections(detections, cross)

    def _gt_win(sid):
        evs = [e for e in gt_events if e.get("storyline_id") == sid]
        ts = [_parse_ts(e.get("time")) for e in evs]
        ts = [t for t in ts if t]
        if not ts:
            return None, None
        return min(ts), max(ts)

    cand_to_gt = {}
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
            host_ok = chost and (chost == gsys or chost.endswith(gsys) or gsys.endswith(chost))
            if not host_ok and c.get("user"):
                host_ok = True
            if not host_ok and c.get("source") == "rule_cluster":
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

    # For each missed storyline, dump the GT events and try to find them in detections
    missed = []
    for st in gt_steps:
        sid = st["storyline_id"]
        if sid in matched_sids:
            continue
        s_evs = [e for e in gt_events if e.get("storyline_id") == sid]
        gsys = st.get("system", "")
        for e in s_evs:
            et = e.get("event_type", "?")
            kind = e.get("kind", "?")
            t_gt = _parse_ts(e.get("time"))
            actor = e.get("actor", "?")
            activity = e.get("activity", "")

            # GT IDs are inside "attributes" sub-dict in many scenarios
            attrs = e.get("attributes") or {}

            # Try to find this GT event in detections by gt-key
            # Common ID fields
            gt_pid = e.get("pid") or attrs.get("pid")
            gt_uid = e.get("uid") or attrs.get("uid")
            gt_dst_ip = e.get("dst_ip") or e.get("destination_ip") or attrs.get("dst_ip") or attrs.get("destination_ip")
            gt_dst_port = e.get("dst_port") or e.get("destination_port") or attrs.get("dst_port") or attrs.get("destination_port")
            gt_src_ip = e.get("src_ip") or e.get("source_ip") or attrs.get("src_ip")
            gt_logon_id = e.get("logon_id") or e.get("logonId") or attrs.get("logon_id")
            gt_cmd = e.get("command_line") or e.get("cmd") or attrs.get("command_line") or attrs.get("cmd") or ""
            gt_query = e.get("query") or e.get("queryName") or e.get("domain") or attrs.get("query") or attrs.get("queryName") or attrs.get("domain")

            # Search detections near ±2 minutes
            matches = []
            susp_match = None
            if t_gt:
                for d in detections:
                    t_d = _parse_ts(d.get("timestamp"))
                    if not t_d:
                        continue
                    if abs((t_d - t_gt).total_seconds()) > 120:
                        continue
                    # Match by pid
                    if gt_pid and d.get("pid") == gt_pid:
                        matches.append(("pid", d))
                    # Match by uid
                    elif gt_uid and d.get("uid") == gt_uid:
                        matches.append(("uid", d))
                    # Match by dst_ip+port
                    elif gt_dst_ip and d.get("dst_ip") == gt_dst_ip:
                        if not gt_dst_port or d.get("dst_port") == gt_dst_port:
                            matches.append(("dst_ip", d))
                    # Match by src_ip+logon_id
                    elif gt_logon_id and d.get("logon_id") == gt_logon_id and d.get("host", "").endswith(gsys):
                        matches.append(("logon_id", d))
                    # Match by command_line prefix
                    elif gt_cmd and d.get("command_line") and gt_cmd[:30] in d["command_line"]:
                        matches.append(("cmd_prefix", d))
                    # Match by query
                    elif gt_query and d.get("domain") == gt_query:
                        matches.append(("query", d))

            # Was any matching detection flagged suspicious?
            for how, d in matches:
                if d.get("verdict") in ("suspicious", "malicious"):
                    susp_match = (how, d)
                    break

            missed.append({
                "sid": sid,
                "system": gsys,
                "kind": kind,
                "event_type": et,
                "time": e.get("time"),
                "actor": actor,
                "activity": activity,
                "gt_pid": gt_pid,
                "gt_uid": gt_uid,
                "gt_dst_ip": gt_dst_ip,
                "gt_dst_port": gt_dst_port,
                "gt_src_ip": gt_src_ip,
                "gt_logon_id": gt_logon_id,
                "gt_cmd": gt_cmd[:80] if gt_cmd else None,
                "gt_query": gt_query,
                "matches": [(m[0], m[1].get("verdict"), m[1].get("score"), m[1].get("event_type"), m[1].get("command_line", "")[:50] if m[1].get("command_line") else "") for m in matches[:5]],
                "any_susp_match": susp_match[1].get("verdict") if susp_match else None,
                "any_match_count": len(matches),
            })
    return missed


def main() -> int:
    out_dir = ROOT / "output"
    scenarios = sorted([p for p in out_dir.iterdir() if p.is_dir()])
    if len(sys.argv) > 1:
        wanted = set(sys.argv[1:])
        scenarios = [p for p in scenarios if p.name in wanted]

    # Aggregate per-reason
    by_reason = defaultdict(int)
    all_missed = []
    for sd in scenarios:
        try:
            missed = analyze_scenario(sd.name, sd)
        except Exception as exc:
            print(f"!!! {sd.name}: {exc}")
            continue
        for m in missed:
            all_missed.append({**m, "scenario": sd.name})
            # Reason classification
            if m["any_match_count"] == 0:
                by_reason["no_match_at_all"] += 1
            elif m["any_susp_match"] is None:
                by_reason["matched_but_benign"] += 1
            else:
                by_reason["matched_and_susp"] += 1

    print("=" * 100)
    print(f"MISSED GT STORYLINES — aggregate reasons ({sum(by_reason.values())} total events)")
    print("=" * 100)
    for k, v in sorted(by_reason.items(), key=lambda kv: -kv[1]):
        print(f"  {k:<25} {v}")

    # Print detail of each missed event
    print("\n" + "=" * 100)
    print("DETAIL OF MISSED GT EVENTS")
    print("=" * 100)
    for m in all_missed:
        sid = m["sid"]
        print(f"\n[{m['scenario']}] {sid}  ({m['system']})  {m['kind']}/{m['event_type']}  actor={m['actor']}")
        print(f"  time: {m['time']}")
        print(f"  activity: {m['activity'][:120]}")
        if m["gt_pid"]:
            print(f"  GT pid={m['gt_pid']} uid={m['gt_uid']} dst={m['gt_dst_ip']}:{m['gt_dst_port']} src={m['gt_src_ip']} logon={m['gt_logon_id']}")
        elif m["gt_cmd"]:
            print(f"  GT cmd='{m['gt_cmd']}'")
        elif m["gt_query"]:
            print(f"  GT query='{m['gt_query']}'")
        else:
            print(f"  GT (no extractable IDs)")
        print(f"  matches_in_data: {m['any_match_count']}  any_suspicious: {m['any_susp_match']}")
        if m["matches"]:
            for how, verdict, score, et, cmd in m["matches"][:3]:
                print(f"    [{how:>10}] verdict={verdict:<5} score={score} type={et} cmd='{cmd}'")

    return 0


if __name__ == "__main__":
    sys.exit(main())