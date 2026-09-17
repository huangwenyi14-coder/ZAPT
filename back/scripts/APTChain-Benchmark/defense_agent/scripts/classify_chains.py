"""Aggregate all scenarios' candidate chains and classify unmatched ones by
behavioral pattern. Output is a per-scenario table:

  scenario  matched  unmatched  fp_pattern_summary...

For each unmatched candidate, classify into one of these behavioral families:
  - LATERAL_BENIGN: same admin user, multiple SSH targets — IT work
  - BACKUP_POLL: rsync / tar / nc / sshd to known infra IP
  - MONITORING: cron + sa1/sar — system monitoring noise
  - DNS_RESOLVER: systemd-resolved, dns.exe polling 10.0.0.1:53
  - SMB_INTERNAL: System process → 10.0.0.1:445 (DC) — windows internal
  - BENIGN_TOOLS: PanGPS, RuntimeBroker, vmtoolsd — vendor agents
  - RDP_NO_HIT: flow to 3389 with no matching logon (port scan or failed)
  - HIGH_PORT_BEACON: beacon to high port but no other indicators
  - UNKNOWN: can't classify

Run:
    uv run python defense_agent/scripts/classify_chains.py
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


def _parse_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _cluster_members(detections, cand):
    cf, cl = _parse_ts(cand.get("first")), _parse_ts(cand.get("last"))
    if not cf or not cl:
        return []
    src = cand.get("source")
    host = cand.get("host", "")
    out = []
    if src == "rule_cluster":
        for d in detections:
            t = _parse_ts(d.get("timestamp"))
            if not t or t < cf or t > cl:
                continue
            if d.get("host") == host:
                out.append(d)
    elif src == "beaconing":
        for d in detections:
            t = _parse_ts(d.get("timestamp"))
            if not t or t < cf or t > cl:
                continue
            if d.get("dst_ip") == cand.get("dst_ip") and d.get("host") == host:
                out.append(d)
    elif src == "lateral_movement":
        for d in detections:
            t = _parse_ts(d.get("timestamp"))
            if not t or t < cf or t > cl:
                continue
            if d.get("user") == cand.get("user"):
                out.append(d)
    return out


# Heuristic behavioral family classification on UNMATCHED candidates.
# Returns a short label like "BACKUP_POLL" or "BENIGN_TOOLS".
def _classify_unmatched(cand, members) -> tuple[str, str]:
    """Return (family_label, why_one_liner)."""
    src = cand.get("source")
    host = cand.get("host", "")
    user = cand.get("user", "") or ""
    title = cand.get("title", "")

    # Pull all text signals
    procs = [m.get("process_name", "").split("\\")[-1].lower() for m in members if m.get("process_name")]
    cmds = " ".join((m.get("command_line") or "") for m in members).lower()
    dst_ips = [m.get("dst_ip", "") for m in members if m.get("dst_ip")]
    dst_ports = [m.get("dst_port", 0) for m in members if m.get("dst_port")]
    users = [m.get("user", "") for m in members if m.get("user")]
    sources = set(m.get("source") for m in members)

    # 1. DNS resolver polling (systemd-resolved / dns.exe to :53)
    if any("systemd-resolved" in p for p in procs) or any(p == "dns.exe" for p in procs):
        return ("DNS_RESOLVER", "systemd-resolved / dns.exe polling DNS — normal resolver traffic")

    # 2. SMB to DC (System process → 10.0.0.1:445 or any internal :445)
    if any(p == "system" for p in procs) and any(d == "10.0.0.1" and pt == 445 for d, pt in zip(dst_ips, dst_ports)):
        return ("SMB_INTERNAL", "System process to DC SMB — Kerberos/auth internal traffic")

    # 3. Vendor / monitoring agents (PanGPS, RuntimeBroker, vmtoolsd, dllhost, taskhostw, MpCmdRun)
    vendor = {"pangps.exe", "runtimebroker.exe", "vmtoolsd.exe", "vmstatsprovider", "dllhost.exe",
              "taskhostw.exe", "mpcmdrun.exe", "msmpeng.exe", "cleanmgr.exe", "googleupdater.exe",
              "zsatunnel.exe", "vpnagent.exe"}
    if any(p in vendor for p in procs):
        return ("BENIGN_TOOLS", "vendor / OS maintenance process")

    # 4. Cron/sysstat — sa1/sar scheduled monitoring
    if any("sa1" in p or "sysstat" in p or "cron" in p for p in procs) or "debian-sa1" in cmds:
        return ("MONITORING_CRON", "sysstat / cron scheduled monitoring")

    # 5. SSH lateral but to infrastructure (admin → known jump hosts, regular interval)
    if src == "lateral_movement" and user in {"root", "admin", "ops", "svc_app", "svc_backup"}:
        return ("LATERAL_BENIGN", f"service user '{user}' lateral — likely scheduled job")

    # 6. Cluster contains only benign sshd/ssh_login/syslog (regular IT traffic)
    if procs and all(p in {"sshd", "/usr/sbin/sshd", "ssh", "/usr/bin/ssh"} or "ssh_login" in (m.get("event_type", "") for m in members if p in (m.get("process_name", "").lower() if m.get("process_name") else "")) for p in procs):
        return ("SSH_NO_PAYLOAD", "SSH sessions without commands — interactive or scheduled")

    # 7. Cluster is entirely systemd / dbus / snap / irqbalance (system service churn)
    sysd = {"systemd-logind", "systemd-resolved", "dbus-daemon", "snapd", "irqbalance"}
    if procs and all(p in sysd or "systemd_event" in (m.get("event_type", "") for m in members) for p in procs):
        return ("SYSTEM_CHURN", "systemd/dbus/snapd housekeeping — normal background activity")

    # 8. Cluster contains registry_value_set / registry_modify by system processes
    only_registry = members and all(m.get("event_type") in {"registry_value_set", "registry_create_delete", "registry_modify"} for m in members)
    if only_registry:
        return ("REGISTRY_NOISE", "only registry churn — no behavioral signal")

    # 9. RDP flow with no matching logon
    if 3389 in dst_ports and not any(m.get("event_type") == "logon" for m in members):
        return ("RDP_NO_LOGON", "port 3389 flow but no RDP logon — scan or failed attempt")

    # 10. Beacon to high port with very regular interval (could be C2 or could be vendor)
    if src == "beaconing":
        if cand.get("n_events", 0) > 50:
            return ("HIGH_PORT_BEACON", f"high-frequency beacon to {cand.get('dst_ip')}:{cand.get('dst_port', '?')} — long-lived C2 candidate")
        return ("BEACON_OTHER", f"beacon to {cand.get('dst_ip')}:{cand.get('dst_port', '?')} (n={cand.get('n_events')}) — needs context")

    # 11. Firewall allow-only cluster
    fw_only = members and all("firewall" in m.get("event_type", "") for m in members)
    if fw_only:
        return ("FIREWALL_NOISE", "firewall allow events only")

    # 12. Cluster has sshd + ssh_login + user_session_login but no commands after
    if procs and any("sshd" in p for p in procs) and not any(m.get("command_line") and any(kw in m["command_line"].lower() for kw in ["curl", "wget", "chmod", "rm ", "nc ", "base64"]) for m in members):
        return ("SSH_INTERACTIVE", "SSH logon but no suspicious post-auth commands")

    return ("UNKNOWN", f"procs={set(procs[:5])} users={set(users[:5])} dst={set(dst_ips[:5])}")


def analyze_scenario(name: str, sd: Path) -> dict:
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

    matched = [c for c in cands if c["candidate_id"] in cand_to_gt]
    unmatched = [c for c in cands if c["candidate_id"] not in cand_to_gt]

    fp_classes = Counter()
    fp_samples = defaultdict(list)
    for c in unmatched:
        members = _cluster_members(detections, c)
        family, why = _classify_unmatched(c, members)
        fp_classes[family] += 1
        if len(fp_samples[family]) < 2:
            fp_samples[family].append({
                "cand": c["candidate_id"],
                "host": c.get("host"),
                "user": c.get("user"),
                "n_events": c.get("n_events"),
                "src": c.get("source"),
                "title": c.get("title", "")[:80],
                "why": why,
            })

    return {
        "scenario": name,
        "gt_total": len(gt_steps),
        "gt_matched": len(set(cand_to_gt.values())),
        "matched": len(matched),
        "unmatched": len(unmatched),
        "fp_classes": dict(fp_classes),
        "fp_samples": dict(fp_samples),
        "missed_storylines": [st["storyline_id"] for st in gt_steps if st["storyline_id"] not in set(cand_to_gt.values())],
    }


def main() -> int:
    out_dir = ROOT / "output"
    scenarios = sorted([p for p in out_dir.iterdir() if p.is_dir()])
    if len(sys.argv) > 1:
        wanted = set(sys.argv[1:])
        scenarios = [p for p in scenarios if p.name in wanted]

    print(f"{'scenario':<40} {'GT':<4} {'cov':<4} {'mat':<5} {'unm':<5}  FP family breakdown")
    print("-" * 200)
    rows = []
    for sd in scenarios:
        try:
            r = analyze_scenario(sd.name, sd)
            rows.append(r)
            breakdown = ", ".join(f"{k}={v}" for k, v in sorted(r["fp_classes"].items(), key=lambda kv: -kv[1])[:8])
            print(f"{r['scenario']:<40} {r['gt_total']:<4} {r['gt_matched']:<4} {r['matched']:<5} {r['unmatched']:<5}  {breakdown}")
            if r["missed_storylines"]:
                print(f"  MISSED GT: {r['missed_storylines']}")
        except Exception as exc:
            print(f"!!! {sd.name}: {exc}")

    # Aggregate
    print("\n" + "=" * 100)
    print("AGGREGATE FP FAMILY COUNTS (across all scenarios)")
    print("=" * 100)
    agg = Counter()
    for r in rows:
        for k, v in r["fp_classes"].items():
            agg[k] += v
    for k, v in agg.most_common():
        print(f"  {k:<30} {v}")

    # Dump per-family sample across scenarios
    print("\n" + "=" * 100)
    print("SAMPLE FP CHAINS BY FAMILY")
    print("=" * 100)
    family_samples = defaultdict(list)
    for r in rows:
        for fam, samples in r["fp_samples"].items():
            for s in samples[:1]:
                family_samples[fam].append({**s, "scenario": r["scenario"]})
    for fam, samples in family_samples.items():
        print(f"\n--- {fam} ({len(samples)} samples) ---")
        for s in samples[:5]:
            print(f"  [{s['scenario']}] {s['cand']} host={s['host']} user={s['user']} n={s['n_events']} src={s['src']}")
            print(f"    title: {s['title']}")
            print(f"    why: {s['why']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())