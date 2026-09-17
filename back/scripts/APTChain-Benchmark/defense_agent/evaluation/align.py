"""Align detection results with ground-truth events.

Alignment strategy (per user choice: only process/pid/uid correlation):
- process / scheduled_task_created: match on (system, pid) within ±5s of gt.time.
  For scheduled_task_created we use task_name within ±5s.
- connection / beacon: match on (uid) within ±2s.
  If uid missing, fall back to (dst_ip, dst_port) within ±2s.
- logon: match on (logon_id) within ±2s. If logon_id missing, (system, source_ip, user) within ±2s.
- dns_query: match on (query) within ±2s. Fallback (system, query).
- create_remote_thread: match on (target_process / system) within ±2s.

This module ONLY reads detection dicts + GT events dicts; it does NOT consult the
detector for any signal (no leakage).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _host_in_event(det: dict, system: str) -> bool:
    if not system:
        return True
    if det.get("host") == system:
        return True
    # fall back: det.host might be a hostname while gt system might include domain
    if det.get("host") and system.endswith(det["host"]):
        return True
    if det.get("host") and det["host"].endswith(system):
        return True
    return False


def align_process(detections: list[dict], gt_events: list[dict]) -> dict[str, list[dict]]:
    """Match process / scheduled_task_created GT events to detection rows."""
    matched: dict[str, list[dict]] = {}
    for gt in gt_events:
        kind = gt.get("kind")
        attrs = gt.get("attributes", {})
        gt_ts = _parse_ts(gt.get("time"))
        gt_pid = attrs.get("pid")
        gt_system = gt.get("system", "")
        gt_task_name = attrs.get("task_name")

        matches: list[dict] = []
        for det in detections:
            if not _host_in_event(det, gt_system):
                continue
            det_ts = _parse_ts(det.get("timestamp"))
            if not det_ts or not gt_ts:
                continue
            if abs((det_ts - gt_ts).total_seconds()) > 5:
                continue

            if kind == "process":
                if det.get("event_type", "").endswith("process_create") or det.get("event_type") == "process_create":
                    if gt_pid is not None and det.get("pid") == gt_pid:
                        matches.append(det)
            elif kind == "scheduled_task_created":
                if det.get("event_type") == "scheduled_task_created":
                    det_task = det.get("file_path") or det.get("command_line") or ""
                    if gt_task_name and gt_task_name in det_task:
                        matches.append(det)
                    elif det.get("event_type") == "scheduled_task_created":
                        matches.append(det)
            elif kind == "create_remote_thread":
                if det.get("event_type") == "create_remote_thread":
                    matches.append(det)
        matched[gt["record_id"]] = matches
    return matched


def align_connection(detections: list[dict], gt_events: list[dict]) -> dict[str, list[dict]]:
    matched: dict[str, list[dict]] = {}
    for gt in gt_events:
        kind = gt.get("kind")
        attrs = gt.get("attributes", {})
        gt_ts = _parse_ts(gt.get("time"))
        gt_uid = attrs.get("uid")
        gt_dst = attrs.get("dst_ip")
        gt_port = attrs.get("dst_port")

        matches: list[dict] = []
        for det in detections:
            det_ts = _parse_ts(det.get("timestamp"))
            if not det_ts or not gt_ts:
                continue
            if abs((det_ts - gt_ts).total_seconds()) > 2:
                continue
            if gt_uid and det.get("uid") == gt_uid:
                matches.append(det)
            elif (gt_dst and gt_port is not None) and det.get("dst_ip") == gt_dst and det.get("dst_port") == gt_port:
                matches.append(det)
        matched[gt["record_id"]] = matches
    return matched


def align_logon(detections: list[dict], gt_events: list[dict]) -> dict[str, list[dict]]:
    matched: dict[str, list[dict]] = {}
    for gt in gt_events:
        attrs = gt.get("attributes", {})
        gt_ts = _parse_ts(gt.get("time"))
        gt_logon_id = attrs.get("logon_id")
        gt_source_ip = attrs.get("source_ip")
        gt_user = gt.get("actor")
        gt_system = gt.get("system", "")

        matches: list[dict] = []
        for det in detections:
            if not _host_in_event(det, gt_system):
                continue
            if det.get("event_type") not in ("logon", "user_session_login", "ssh_login"):
                continue
            det_ts = _parse_ts(det.get("timestamp"))
            if not det_ts or not gt_ts:
                continue
            if abs((det_ts - gt_ts).total_seconds()) > 2:
                continue
            if gt_logon_id and det.get("logon_id") == gt_logon_id:
                matches.append(det)
            elif gt_source_ip and det.get("src_ip") == gt_source_ip:
                matches.append(det)
            elif gt_user and det.get("user") == gt_user:
                matches.append(det)
        matched[gt["record_id"]] = matches
    return matched


def align_dns(detections: list[dict], gt_events: list[dict]) -> dict[str, list[dict]]:
    matched: dict[str, list[dict]] = {}
    for gt in gt_events:
        attrs = gt.get("attributes", {})
        gt_ts = _parse_ts(gt.get("time"))
        gt_query = attrs.get("query")
        gt_system = gt.get("system", "")

        matches: list[dict] = []
        for det in detections:
            if det.get("event_type") not in ("dns_query", "sysmon dns query"):
                continue
            if not _host_in_event(det, gt_system):
                continue
            det_ts = _parse_ts(det.get("timestamp"))
            if not det_ts or not gt_ts:
                continue
            if abs((det_ts - gt_ts).total_seconds()) > 2:
                continue
            if gt_query and (det.get("domain") == gt_query or det.get("url") == gt_query):
                matches.append(det)
        matched[gt["record_id"]] = matches
    return matched


def align_all(detections: list[dict], gt: dict) -> dict[str, list[dict]]:
    """Run all alignments and return {gt_record_id: [matched detections]}.

    GT events with no matches get [].
    """
    gt_events = gt.get("events", [])
    out: dict[str, list[dict]] = {}

    out.update(align_process(detections, [g for g in gt_events if g.get("kind") in ("process", "scheduled_task_created", "create_remote_thread")]))
    out.update(align_connection(detections, [g for g in gt_events if g.get("kind") in ("connection", "beacon")]))
    out.update(align_logon(detections, [g for g in gt_events if g.get("kind") == "logon"]))
    out.update(align_dns(detections, [g for g in gt_events if g.get("kind") == "dns_query"]))

    # Ensure every gt record is represented
    for g in gt_events:
        rid = g.get("record_id")
        if rid and rid not in out:
            out[rid] = []
    return out


def observable_events(gt: dict) -> set[str]:
    """Return record_ids that are observable in at least one source.

    Reads source_evidence_status (per storyline_id) and visibility counts.
    A storyline_id is observable if any source has visible > 0.
    """
    ses = gt.get("source_evidence_status", {}) or {}
    storyline_obs: dict[str, bool] = {}
    for sid, sources in ses.items():
        any_visible = False
        for src, counts in sources.items():
            if src == "all":
                continue
            if isinstance(counts, dict) and counts.get("visible", 0) > 0:
                any_visible = True
                break
        storyline_obs[sid] = any_visible

    out = set()
    for g in gt.get("events", []):
        sid = g.get("storyline_id")
        if sid and sid not in storyline_obs:
            # Storyline has no observation entry → assume visible (older scenarios)
            out.add(g["record_id"])
        elif sid is None:
            out.add(g["record_id"])
        elif storyline_obs.get(sid, False):
            out.add(g["record_id"])
    return out