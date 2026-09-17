"""RulesEngine — orchestrates per-event and cross-event rule evaluation.

Produces a list of Detection dicts with verdict (malicious / suspicious /
benign) and a score in [0, 1]. The output is later aligned with ground truth
by the evaluation module.

This module NEVER imports evaluation/* and NEVER reads GROUND_TRUTH.* files.
"""

from __future__ import annotations

from typing import Any, List

from ...parsers.base import CanonicalEvent
from .auth_rules import credential_dumping_correlation, evaluate_auth_event
from .ioc_patterns import evaluate_ioc_patterns
from .network_rules import (
    beaconing_detections,
    evaluate_connection,
    evaluate_dns_query,
    horizontal_movement,
)


# Each MITRE technique family carries a score weight. Weights are based on the
# signal-to-noise of that family in general DFIR telemetry — strong signals
# (credential dumping, anti-forensics, dynamic DNS) get higher weights; benign
# noise families (valid accounts, plain command interpreter use) get low weights.
TECHNIQUE_WEIGHT = {
    "T1003": 0.40,   # credential dumping — strong signal
    "T1070": 0.40,   # log clearing / anti-forensics — strong
    "T1568": 0.35,   # dynamic resolution — strong (DGA / DDNS)
    "T1572": 0.30,   # protocol tunneling
    "T1218": 0.25,   # LOLBin abuse
    "T1059": 0.20,   # command interpreter
    "T1041": 0.25,   # exfil over C2
    "T1543": 0.20,   # service install
    "T1053": 0.20,   # scheduled task
    "T1071": 0.15,   # application-layer protocol
    "T1098": 0.15,   # account manipulation
    "T1136": 0.15,   # create account
    "T1021": 0.20,   # remote services
    "T1140": 0.20,   # deobfuscate
    "T1105": 0.25,   # ingress tool transfer
    "T1078": 0.10,   # valid accounts
    "T1547": 0.20,   # boot/logon autostart
    "T1490": 0.35,   # inhibit system recovery
    "T1197": 0.20,   # BITS jobs
    "T1047": 0.20,   # WMIC
    "T1036": 0.25,   # masquerading
    "T1055": 0.30,   # process injection
}


def _score_from_hits(hits: list[dict]) -> float:
    if not hits:
        return 0.0
    score = 0.0
    for h in hits:
        technique = h.get("technique", "")
        weight = 0.10
        for prefix, w in TECHNIQUE_WEIGHT.items():
            if technique.startswith(prefix):
                weight = w
                break
        score += weight
    return min(score, 1.0)


def _verdict_from_score(score: float, hits: list[dict]) -> str:
    if score >= 0.5:
        return "malicious"
    if score >= 0.2 or hits:
        return "suspicious"
    return "benign"


def _event_to_dict(ev: CanonicalEvent) -> dict[str, Any]:
    return {
        "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
        "host": ev.host,
        "source": ev.source,
        "event_type": ev.event_type,
        "pid": ev.pid,
        "tid": ev.tid,
        "ppid": ev.ppid,
        "process_name": ev.process_name,
        "command_line": ev.command_line,
        "user": ev.user,
        "src_ip": ev.src_ip,
        "src_port": ev.src_port,
        "dst_ip": ev.dst_ip,
        "dst_port": ev.dst_port,
        "domain": ev.domain,
        "url": ev.url,
        "file_path": ev.file_path,
        "registry_key": ev.registry_key,
        "logon_id": ev.logon_id,
        "logon_type": ev.logon_type,
        "auth_package": ev.auth_package,
        "uid": ev.uid,
        "record_id": ev.record_id,
        "source_offset": ev.source_offset,
    }


def detect_events(events: List[CanonicalEvent]) -> tuple[List[dict], dict[str, list]]:
    """Run all per-event rules + scenario-level cross-event rules.

    Returns (per_event_detections, cross_event_summary).

    Each detection dict has: event fields + verdict + score + reasons + cross_refs.
    """
    detections: list[dict] = []
    for ev in events:
        hits: list[dict] = []
        hits.extend(evaluate_ioc_patterns(ev))
        hits.extend(evaluate_auth_event(ev))
        hits.extend(evaluate_dns_query(ev))
        hits.extend(evaluate_connection(ev))

        score = _score_from_hits(hits)
        verdict = _verdict_from_score(score, hits)

        d = _event_to_dict(ev)
        d["verdict"] = verdict
        d["score"] = round(score, 4)
        d["reasons"] = hits
        d["cross_refs"] = []
        detections.append(d)

    # Cross-event
    beacons = beaconing_detections(events)
    lateral = horizontal_movement(events)
    cred_dump = credential_dumping_correlation(events)

    beacon_keys = {(b["src_ip"], b["dst_ip"], b["dst_port"]): b for b in beacons}
    lateral_user_hosts = {l["user"]: l for l in lateral}
    cred_pairs = {(c["host"], c["user"], c["lsass_at"]): c for c in cred_dump}

    # Decorate detections and recompute score
    for d in detections:
        ev_key = (d.get("src_ip"), d.get("dst_ip"), d.get("dst_port"))
        if ev_key in beacon_keys:
            ref = beacon_keys[ev_key]
            d["reasons"].append({
                "rule": "beaconing_correlation",
                "technique": ref["technique"],
                "reason": ref["reason"],
            })
        if d.get("event_type") == "logon" and d.get("user") in lateral_user_hosts:
            ref = lateral_user_hosts[d["user"]]
            d["cross_refs"].append({
                "kind": "horizontal_movement",
                "technique": ref["technique"],
                "reason": ref["reason"],
            })
        if d.get("event_type") == "process_access" and (d.get("host"), d.get("user"), d.get("timestamp")) in cred_pairs:
            ref = cred_pairs[(d["host"], d["user"], d["timestamp"])]
            d["cross_refs"].append({
                "kind": "credential_dumping_chain",
                "technique": ref["technique"],
                "reason": ref["reason"],
            })

        # Recompute score with cross-event reasons folded in
        all_reasons = list(d["reasons"]) + list(d["cross_refs"])
        new_score = _score_from_hits(all_reasons)
        d["score"] = round(new_score, 4)
        d["verdict"] = _verdict_from_score(new_score, all_reasons)

    cross_summary = {
        "beacons": beacons,
        "lateral_movement": lateral,
        "credential_dumping": cred_dump,
    }
    return detections, cross_summary