"""Rule-only chain-level incident judge.

This module is stage 4 of the experimental agentic workflow. It receives
candidate chains built from stage-2 detections and stage-3 correlation, then
keeps only candidates that look like coherent security incidents.

It must never read GROUND_TRUTH. Evaluation happens later in stage 5.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

DetectionBucket = list[tuple[datetime, dict[str, Any]]]

STRONG_TECHNIQUES = (
    "T1003",  # credential dumping
    "T1055",  # process injection
    "T1070",  # anti-forensics
    "T1105",  # tool transfer
    "T1197",  # BITS
    "T1547",  # autorun persistence
    "T1568",  # dynamic resolution
    "T1572",  # tunneling
)

MEDIUM_TECHNIQUES = (
    "T1021",  # remote services
    "T1036",  # masquerading
    "T1041",  # exfiltration
    "T1047",  # WMIC
    "T1053",  # scheduled task
    "T1140",  # deobfuscation
    "T1218",  # LOLBin
)

LOW_SIGNAL_TECHNIQUES = (
    "T1059",  # command interpreter, very noisy alone
    "T1071",  # generic app-layer traffic
    "T1078",  # valid accounts
)

INFRASTRUCTURE_PORTS = {53, 67, 68, 88, 123, 135, 137, 138, 139, 389, 445, 464, 636}


@dataclass(frozen=True)
class JudgeResult:
    """A scored candidate chain."""

    candidate: dict[str, Any]
    score: float
    decision: str
    reasons: list[str]
    evidence_count: int

    def to_candidate(self) -> dict[str, Any]:
        """Return the original candidate with stage-4 metadata attached."""
        enriched = dict(self.candidate)
        enriched["judge_score"] = round(self.score, 4)
        enriched["judge_decision"] = self.decision
        enriched["judge_reasons"] = self.reasons
        enriched["evidence_count"] = self.evidence_count
        return enriched


def judge_candidates(
    candidates: list[dict[str, Any]],
    detections: list[dict[str, Any]],
    *,
    min_score: float = 0.62,
    max_candidates: int = 12,
) -> dict[str, Any]:
    """Score and filter stage-3 candidate chains.

    The output intentionally looks like a final incident submission: a compact
    list of kept incident chains plus the rejected pool for diagnostics.
    """
    detection_index = _index_detections(detections)
    judged = [_score_candidate(candidate, detection_index) for candidate in candidates]
    judged.sort(
        key=lambda item: (
            -item.score,
            _parse_ts(item.candidate.get("first")) or datetime.min.replace(tzinfo=UTC),
        )
    )

    kept: list[JudgeResult] = []
    for item in judged:
        if item.score < min_score:
            continue
        if _is_duplicate(item, kept):
            continue
        kept.append(item)
        if len(kept) >= max_candidates:
            break

    rejected = [item for item in judged if item not in kept]
    return {
        "incidents": [item.to_candidate() for item in kept],
        "rejected": [item.to_candidate() for item in rejected],
        "stats": {
            "input_candidates": len(candidates),
            "kept_incidents": len(kept),
            "rejected_candidates": len(rejected),
            "min_score": min_score,
            "max_candidates": max_candidates,
        },
    }


def _score_candidate(candidate: dict[str, Any], detection_index: dict[str, Any]) -> JudgeResult:
    evidence = _candidate_evidence(candidate, detection_index)
    techniques = _techniques(candidate, evidence)
    event_types = {str(ev.get("event_type", "")) for ev in evidence if ev.get("event_type")}
    sources = {str(ev.get("source", "")) for ev in evidence if ev.get("source")}

    score = _source_prior(candidate)
    reasons: list[str] = [f"source_prior:{candidate.get('source')}={score:.2f}"]

    strong_count = _count_prefixed(techniques, STRONG_TECHNIQUES)
    medium_count = _count_prefixed(techniques, MEDIUM_TECHNIQUES)
    low_count = _count_prefixed(techniques, LOW_SIGNAL_TECHNIQUES)

    if strong_count:
        bump = min(0.45, 0.25 * strong_count)
        score += bump
        reasons.append(f"strong_techniques:+{bump:.2f}")
    if medium_count:
        bump = min(0.30, 0.10 * medium_count)
        score += bump
        reasons.append(f"medium_techniques:+{bump:.2f}")
    if low_count and not strong_count and not medium_count:
        score += 0.04
        reasons.append("low_signal_only:+0.04")

    if len(sources) >= 2:
        score += 0.12
        reasons.append("multi_source:+0.12")
    if len(event_types) >= 2:
        score += 0.12
        reasons.append("multi_event_type:+0.12")
    if _has_process_and_network(evidence):
        score += 0.15
        reasons.append("process_network_chain:+0.15")
    if _has_process_and_auth(evidence):
        score += 0.10
        reasons.append("process_auth_chain:+0.10")
    if len(evidence) >= 3:
        score += 0.08
        reasons.append("evidence_volume:+0.08")

    content_bonus = _content_bonus(candidate, evidence)
    if content_bonus:
        score += content_bonus
        reasons.append(f"attack_content:+{content_bonus:.2f}")

    penalty = _benign_pattern_penalty(candidate, evidence, techniques)
    if penalty:
        score -= penalty
        reasons.append(f"benign_pattern:-{penalty:.2f}")

    score = max(0.0, min(score, 1.0))
    decision = "keep" if score >= 0.62 else "reject"
    return JudgeResult(
        candidate=candidate,
        score=score,
        decision=decision,
        reasons=reasons,
        evidence_count=len(evidence),
    )


def _source_prior(candidate: dict[str, Any]) -> float:
    source = candidate.get("source")
    if source == "credential_dumping":
        return 0.85
    if source == "rule_cluster":
        return 0.24
    if source == "lateral_movement":
        return 0.36
    if source == "beaconing":
        return 0.18
    return 0.15


def _index_detections(detections: list[dict[str, Any]]) -> dict[str, Any]:
    by_host: dict[str, DetectionBucket] = {}
    by_user: dict[str, DetectionBucket] = {}
    by_dst_ip: dict[str, DetectionBucket] = {}
    for det in detections:
        ts = _parse_ts(det.get("timestamp"))
        if not ts:
            continue
        item = (ts, det)
        host = str(det.get("host") or "")
        user = str(det.get("user") or "")
        dst_ip = str(det.get("dst_ip") or "")
        if host:
            by_host.setdefault(host, []).append(item)
        if user:
            by_user.setdefault(user, []).append(item)
        if dst_ip:
            by_dst_ip.setdefault(dst_ip, []).append(item)
    return {"host": by_host, "user": by_user, "dst_ip": by_dst_ip}


def _candidate_evidence(
    candidate: dict[str, Any], detection_index: dict[str, Any]
) -> list[dict[str, Any]]:
    first = _parse_ts(candidate.get("first"))
    last = _parse_ts(candidate.get("last")) or first
    host = str(candidate.get("host") or "")
    user = str(candidate.get("user") or "")
    dst_ip = str(candidate.get("dst_ip") or "")
    source = candidate.get("source")

    if not first or not last:
        return []

    buckets: list[DetectionBucket] = []
    if source == "beaconing" and dst_ip:
        buckets.append(detection_index["dst_ip"].get(dst_ip, []))
    if user:
        buckets.append(detection_index["user"].get(user, []))
    if host:
        host_buckets = detection_index["host"]
        for indexed_host, bucket in host_buckets.items():
            if indexed_host == host or indexed_host.endswith(host) or host.endswith(indexed_host):
                buckets.append(bucket)

    seen: set[int] = set()
    evidence: list[dict[str, Any]] = []
    for bucket in buckets:
        for ts, det in bucket:
            if ts < first or ts > last:
                continue
            det_id = id(det)
            if det_id in seen:
                continue
            seen.add(det_id)
            evidence.append(det)
    return evidence


def _techniques(candidate: dict[str, Any], evidence: list[dict[str, Any]]) -> set[str]:
    techniques = {str(candidate.get("technique") or "")}
    for det in evidence:
        for reason in det.get("reasons", []) + det.get("cross_refs", []):
            technique = str(reason.get("technique") or "")
            if technique:
                techniques.add(technique)
    return {technique for technique in techniques if technique}


def _content_bonus(candidate: dict[str, Any], evidence: list[dict[str, Any]]) -> float:
    text_parts = [str(candidate.get("title") or "")]
    for det in evidence[:50]:
        text_parts.extend(
            [
                str(det.get("command_line") or ""),
                str(det.get("process_name") or ""),
                str(det.get("domain") or ""),
                str(det.get("url") or ""),
            ]
        )
    text = " ".join(text_parts).lower()
    bonus = 0.0
    if any(
        token in text for token in ("downloadfile", "downloadstring", "webclient", "curl", "wget")
    ):
        bonus += 0.12
    if any(token in text for token in ("-enc", "frombase64string", "base64", "shellcode")):
        bonus += 0.12
    if any(token in text for token in ("schtasks", "\\run", "startup", "service installed")):
        bonus += 0.12
    if any(token in text for token in ("dyndns", "duckdns", "servegame", "ddns", "hopto")):
        bonus += 0.16
    if any(token in text for token in ("lsass", "mimikatz", "procdump", "sekurlsa")):
        bonus += 0.18
    if any(token in text for token in ("upload", "orig_bytes", "exfil", "http post")):
        bonus += 0.10
    return min(bonus, 0.35)


def _benign_pattern_penalty(
    candidate: dict[str, Any],
    evidence: list[dict[str, Any]],
    techniques: set[str],
) -> float:
    source = candidate.get("source")
    penalty = 0.0
    dst_port = candidate.get("dst_port")
    title = str(candidate.get("title") or "").lower()
    if source == "beaconing" and dst_port in INFRASTRUCTURE_PORTS:
        penalty += 0.45
    if source == "beaconing" and any(
        token in title for token in ("dhcp", "ntp", "kerberos", "smb")
    ):
        penalty += 0.30
    if source == "beaconing" and not _has_process_and_network(evidence):
        penalty += 0.20
    if techniques and all(_starts_with_any(item, LOW_SIGNAL_TECHNIQUES) for item in techniques):
        penalty += 0.22
    if len(evidence) > 40 and not _count_prefixed(
        techniques, STRONG_TECHNIQUES + MEDIUM_TECHNIQUES
    ):
        penalty += 0.18
    return min(penalty, 0.75)


def _has_process_and_network(evidence: list[dict[str, Any]]) -> bool:
    has_process = any("process" in str(ev.get("event_type", "")) for ev in evidence)
    has_network = any(
        token in str(ev.get("event_type", ""))
        for ev in evidence
        for token in ("connection", "flow", "http", "dns")
    )
    return has_process and has_network


def _has_process_and_auth(evidence: list[dict[str, Any]]) -> bool:
    has_process = any("process" in str(ev.get("event_type", "")) for ev in evidence)
    has_auth = any(
        token in str(ev.get("event_type", ""))
        for ev in evidence
        for token in ("logon", "session", "credential")
    )
    return has_process and has_auth


def _count_prefixed(values: set[str], prefixes: tuple[str, ...]) -> int:
    return sum(1 for value in values if _starts_with_any(value, prefixes))


def _starts_with_any(value: str, prefixes: tuple[str, ...]) -> bool:
    return any(value.startswith(prefix) for prefix in prefixes)


def _is_duplicate(item: JudgeResult, kept: list[JudgeResult]) -> bool:
    first = _parse_ts(item.candidate.get("first"))
    last = _parse_ts(item.candidate.get("last")) or first
    host = str(item.candidate.get("host") or "")
    for other in kept:
        other_first = _parse_ts(other.candidate.get("first"))
        other_last = _parse_ts(other.candidate.get("last")) or other_first
        other_host = str(other.candidate.get("host") or "")
        if host and other_host and host != other_host:
            continue
        if (
            first
            and last
            and other_first
            and other_last
            and first <= other_last
            and other_first <= last
        ):
            return True
    return False


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
