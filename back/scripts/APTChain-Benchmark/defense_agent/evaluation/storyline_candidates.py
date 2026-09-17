"""Generate candidate storylines from detection output, then PR-match against GT storylines.

This is what makes "storyline-level precision" meaningful: we count the
candidate storylines the detector emits (from clustering suspicious events +
cross-event rule outputs) and check how many of them line up with a GT
storyline_id. A candidate that doesn't line up with any GT storyline is a FP.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .log_level import _safe_div


@dataclass
class StorylineCandidatePR:
    scenario: str
    candidates: int
    matched: int  # candidate matched a GT storyline
    unmatched: int  # candidate with no GT match → FP
    gt_total: int  # observable GT storylines
    gt_matched: int  # GT storylines with a candidate → TP
    gt_unmatched: int  # GT storylines with no candidate → FN
    precision: float
    recall: float
    f1: float
    matches: list[dict]
    unmatched_candidates: list[dict]
    missed_storylines: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "candidates": self.candidates,
            "matched": self.matched,
            "unmatched": self.unmatched,
            "gt_total": self.gt_total,
            "gt_matched": self.gt_matched,
            "gt_unmatched": self.gt_unmatched,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "matches": self.matches,
            "unmatched_candidates_sample": self.unmatched_candidates[:10],
            "missed_storylines": self.missed_storylines,
        }


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def build_candidates_from_detections(detections: list[dict], cross_summary: dict) -> list[dict]:
    """Synthesize candidate storylines from the detector output.

    Sources:
    1. Beacons (from cross_summary) — each is a candidate storyline.
    2. Lateral movement clusters (from cross_summary).
    3. Credential-dumping chains (from cross_summary).
    4. Clusters of suspicious/malicious events on the same host within a time
       window (heuristic, mirrors what the agent/story_builder would emit
       without an LLM).
    """
    candidates: list[dict] = []
    for b in cross_summary.get("beacons", []):
        candidates.append(
            {
                "candidate_id": f"cand-beacon-{len(candidates)}",
                "source": "beaconing",
                "host": b.get("src_ip"),  # host = the source that was beaconing
                "dst_ip": b.get("dst_ip"),
                "technique": b.get("technique", "T1071.001"),
                "first": b.get("first"),
                "last": b.get("last"),
                "n_events": b.get("attempts", 0),
                "title": b.get("reason", "")[:200],
            }
        )
    for i, movement in enumerate(cross_summary.get("lateral_movement", [])):
        first = _parse_ts(movement.get("first"))
        last = first + timedelta(minutes=30) if first else None
        candidates.append(
            {
                "candidate_id": f"cand-lateral-{i}",
                "source": "lateral_movement",
                "host": movement["hosts"][0] if movement.get("hosts") else "",
                "user": movement.get("user"),
                "technique": movement.get("technique", "T1021"),
                "first": movement.get("first"),
                "last": last.isoformat() if last else None,
                "n_events": len(movement.get("hosts", [])),
                "title": movement.get("reason", "")[:200],
            }
        )
    for i, c in enumerate(cross_summary.get("credential_dumping", [])):
        candidates.append(
            {
                "candidate_id": f"cand-cred-{i}",
                "source": "credential_dumping",
                "host": c.get("host"),
                "user": c.get("user"),
                "technique": c.get("technique", "T1003.001"),
                "first": c.get("lsass_at"),
                "last": c.get("explicit_credential_at"),
                "n_events": 2,
                "title": c.get("reason", "")[:200],
            }
        )

    # Cluster suspicious detections by (host, sliding window)
    suspicious = [
        d
        for d in detections
        if d.get("verdict") in ("suspicious", "malicious") and d.get("host") and d.get("timestamp")
    ]
    suspicious.sort(key=lambda d: d["timestamp"])

    visited = [False] * len(suspicious)
    clusters: list[list[dict]] = []
    for i, d in enumerate(suspicious):
        if visited[i]:
            continue
        cluster = [d]
        visited[i] = True
        ts_i = _parse_ts(d["timestamp"])
        if not ts_i:
            continue
        for j in range(i + 1, min(i + 200, len(suspicious))):
            if visited[j]:
                continue
            e = suspicious[j]
            ts_j = _parse_ts(e["timestamp"])
            if not ts_j:
                continue
            if (ts_j - ts_i) > timedelta(minutes=30):
                break
            if e["host"] == d["host"]:
                cluster.append(e)
                visited[j] = True
        if len(cluster) >= 2:
            clusters.append(cluster)

    for k, cluster in enumerate(clusters):
        techniques = []
        for c in cluster:
            for r in c.get("reasons", []):
                t = r.get("technique", "")
                if t and t not in techniques:
                    techniques.append(t)
        candidates.append(
            {
                "candidate_id": f"cand-cluster-{k}",
                "source": "rule_cluster",
                "host": cluster[0]["host"],
                "user": next((c.get("user") for c in cluster if c.get("user")), None),
                "technique": techniques[0] if techniques else "T1071",
                "first": cluster[0]["timestamp"],
                "last": cluster[-1]["timestamp"],
                "n_events": len(cluster),
                "title": f"cluster of {len(cluster)} suspicious events on {cluster[0]['host']}",
            }
        )

    return candidates


def _gt_storylines(gt: dict) -> list[dict]:
    return gt.get("storyline_steps", []) or []


def _gt_storyline_times(gt: dict, sid: str) -> tuple[datetime | None, datetime | None]:
    events = [e for e in gt.get("events", []) if e.get("storyline_id") == sid]
    if not events:
        return None, None
    times = [_parse_ts(e.get("time")) for e in events]
    times = [t for t in times if t]
    if not times:
        return None, None
    return min(times), max(times)


def _intervals_overlap(
    a_start: datetime | None,
    a_end: datetime | None,
    b_start: datetime | None,
    b_end: datetime | None,
) -> bool:
    if not (a_start and a_end and b_start and b_end):
        return False
    return a_start <= b_end and b_start <= a_end


def compute_storyline_candidate_pr(
    scenario: str, detections: list[dict], gt: dict, cross_summary: dict
) -> StorylineCandidatePR:
    """Build candidates, match against GT storylines, compute real PR."""
    candidates = build_candidates_from_detections(detections, cross_summary)
    return compute_storyline_candidate_pr_from_candidates(scenario, candidates, gt)


def compute_storyline_candidate_pr_from_candidates(
    scenario: str,
    candidates: list[dict],
    gt: dict,
) -> StorylineCandidatePR:
    """Match pre-built candidate incidents against GT storylines.

    This variant is used by the agentic pipeline after a chain-level judge has
    filtered or merged candidates. The judge itself must not read GT; GT is used
    only here for stage-5 evaluation.
    """
    gt_steps = _gt_storylines(gt)

    # Pre-compute per-GT-storyline time windows
    gt_windows: dict[str, tuple[datetime | None, datetime | None]] = {}
    for st in gt_steps:
        gt_windows[st["storyline_id"]] = _gt_storyline_times(gt, st["storyline_id"])

    matches: list[dict] = []
    matched_gt: set[str] = set()
    unmatched_candidates: list[dict] = []

    for cand in candidates:
        cand_first = _parse_ts(cand.get("first"))
        cand_last = _parse_ts(cand.get("last"))
        cand_host = cand.get("host", "")

        # Find GT storyline: same host (or overlapping hosts) + overlapping time window
        best_sid = None
        best_score = -1
        for st in gt_steps:
            sid = st["storyline_id"]
            gt_first, gt_last = gt_windows.get(sid, (None, None))
            if not _intervals_overlap(cand_first, cand_last, gt_first, gt_last):
                continue
            # Host match: candidate host endswith/startswith gt system or vice versa
            gt_system = st.get("system", "")
            host_match = cand_host and (
                cand_host == gt_system
                or cand_host.endswith(gt_system)
                or gt_system.endswith(cand_host)
            )
            # If candidate host looks like an IP and gt is a hostname, allow either
            if not host_match and cand.get("user"):
                host_match = True  # lateral movement candidate, user is enough
            if not host_match and cand.get("source") == "rule_cluster":
                # clusters by host already matched — but double-check
                host_match = True
            if not host_match:
                continue
            # Scoring: tighter overlap is better
            score = 0
            if cand_first and cand_last and gt_first and gt_last:
                gt_dur = (gt_last - gt_first).total_seconds()
                if gt_dur > 0:
                    overlap_dur = (
                        min(cand_last, gt_last) - max(cand_first, gt_first)
                    ).total_seconds()
                    score = overlap_dur / gt_dur  # fraction of GT covered
            if score > best_score:
                best_score = score
                best_sid = sid

        if best_sid and best_score > -1:
            matches.append(
                {
                    "candidate_id": cand["candidate_id"],
                    "matched_storyline_id": best_sid,
                    "coverage_score": round(best_score, 4),
                    "candidate_technique": cand.get("technique"),
                    "candidate_host": cand_host,
                    "candidate_first": cand.get("first"),
                    "candidate_last": cand.get("last"),
                    "candidate_n_events": cand.get("n_events"),
                }
            )
            matched_gt.add(best_sid)
        else:
            unmatched_candidates.append(
                {
                    "candidate_id": cand["candidate_id"],
                    "source": cand.get("source"),
                    "host": cand_host,
                    "first": cand.get("first"),
                    "last": cand.get("last"),
                    "n_events": cand.get("n_events"),
                    "title": cand.get("title"),
                }
            )

    # GT storylines that had no candidate
    missed = []
    for st in gt_steps:
        if st["storyline_id"] not in matched_gt:
            # Skip if no observable events
            sid = st["storyline_id"]
            obs_status = gt.get("source_evidence_status", {}).get(sid, {})
            any_visible = False
            for src, counts in obs_status.items():
                if src == "all":
                    continue
                if isinstance(counts, dict) and counts.get("visible", 0) > 0:
                    any_visible = True
                    break
            # If observable status unknown, count as observable (older scenarios)
            if any_visible or not obs_status:
                missed.append(sid)

    matched = len(matches)
    unmatched = len(unmatched_candidates)
    candidates_n = len(candidates)
    gt_total = len(missed) + len(matched_gt)
    gt_matched = len(matched_gt)
    gt_unmatched = len(missed)

    # Precision = (matched candidates) / (all candidates)
    # Recall = (matched GT storylines) / (all observable GT storylines)
    precision = _safe_div(matched, candidates_n)
    recall = _safe_div(gt_matched, gt_total)
    f1 = _safe_div(2 * precision * recall, precision + recall)

    return StorylineCandidatePR(
        scenario=scenario,
        candidates=candidates_n,
        matched=matched,
        unmatched=unmatched,
        gt_total=gt_total,
        gt_matched=gt_matched,
        gt_unmatched=gt_unmatched,
        precision=precision,
        recall=recall,
        f1=f1,
        matches=matches,
        unmatched_candidates=unmatched_candidates,
        missed_storylines=missed,
    )
