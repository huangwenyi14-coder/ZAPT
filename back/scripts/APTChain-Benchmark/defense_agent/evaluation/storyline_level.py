"""Task B — storyline-level detection / coverage / reconstruction.

For each GT storyline_id, check if any of its events were detected as malicious.
Compute coverage (matched_events / total_observable_events) and detection (True/False).

Then for storyline_id that are detected, compute:
- order_ok: do detected storyline_ids follow the GT index ordering?
- coverage: matched/total for that storyline
- duration_ratio: chapter span vs GT span
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .align import align_all, observable_events
from .log_level import _safe_div


@dataclass
class StorylineMetrics:
    scenario: str
    storyline_total: int
    storyline_detected: int
    avg_coverage: float
    storyline_prf: dict[str, float]
    per_storyline: dict[str, dict[str, Any]]
    storyline_order_score: float  # 0..1

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "storyline_total": self.storyline_total,
            "storyline_detected": self.storyline_detected,
            "storyline_detection_rate": _safe_div(self.storyline_detected, self.storyline_total),
            "avg_step_coverage": self.avg_coverage,
            "storyline_prf": self.storyline_prf,
            "order_score": self.storyline_order_score,
            "per_storyline": self.per_storyline,
        }


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def compute_storyline(scenario: str, detections: list[dict], gt: dict, malicious_threshold: float = 0.2) -> StorylineMetrics:
    aligned = align_all(detections, gt)
    obs = observable_events(gt)

    gt_events = gt.get("events", [])
    gt_storylines = gt.get("storyline_steps", [])

    by_storyline: dict[str, list[dict]] = {}
    for g in gt_events:
        by_storyline.setdefault(g["storyline_id"], []).append(g)

    per_storyline: dict[str, dict[str, Any]] = {}
    detected_ids: list[str] = []
    coverage_sum = 0.0
    coverage_count = 0

    for sid, events in by_storyline.items():
        obs_events = [e for e in events if e["record_id"] in obs]
        if not obs_events:
            continue
        matched_count = 0
        earliest = None
        latest = None
        for e in obs_events:
            matches = aligned.get(e["record_id"], [])
            if any(d.get("score", 0) >= malicious_threshold for d in matches):
                matched_count += 1
                ts = _parse_ts(e.get("time"))
                if ts:
                    if not earliest or ts < earliest:
                        earliest = ts
                    if not latest or ts > latest:
                        latest = ts
        coverage = matched_count / len(obs_events)
        coverage_sum += coverage
        coverage_count += 1
        detected = matched_count > 0
        if detected:
            detected_ids.append(sid)
        per_storyline[sid] = {
            "total_events": len(events),
            "observable_events": len(obs_events),
            "matched_events": matched_count,
            "coverage": coverage,
            "detected": detected,
            "earliest_gt_ts": earliest.isoformat() if earliest else None,
            "latest_gt_ts": latest.isoformat() if latest else None,
        }

    avg_coverage = coverage_sum / coverage_count if coverage_count else 0.0

    # Order score: LCS ratio between GT storyline indices and detected storyline indices
    ordered_gt_indices = [st["index"] for st in gt_storylines if st["storyline_id"] in per_storyline]
    ordered_det_indices = [st["index"] for st in gt_storylines
                            if st["storyline_id"] in per_storyline and per_storyline[st["storyline_id"]]["detected"]]
    order_score = _lcs_ratio(ordered_gt_indices, ordered_det_indices)

    obs_storylines = [sid for sid in per_storyline.keys()]
    detected_set = set(detected_ids)
    tp = len([s for s in obs_storylines if s in detected_set])
    fn = len(obs_storylines) - tp
    fp = 0
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)

    return StorylineMetrics(
        scenario=scenario,
        storyline_total=len(obs_storylines),
        storyline_detected=tp,
        avg_coverage=avg_coverage,
        storyline_prf={"precision": precision, "recall": recall, "f1": f1},
        per_storyline=per_storyline,
        storyline_order_score=order_score,
    )


def _lcs_ratio(a: list[int], b: list[int]) -> float:
    """Longest common subsequence ratio of two integer sequences.

    Measures how much of the detected order preserves the GT order.
    1.0 = perfect order, 0.0 = no shared order.
    """
    if not a or not b:
        return 0.0
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m):
        for j in range(n):
            if a[i] == b[j]:
                dp[i + 1][j + 1] = dp[i][j] + 1
            else:
                dp[i + 1][j + 1] = max(dp[i + 1][j], dp[i][j + 1])
    return dp[m][n] / max(m, n)