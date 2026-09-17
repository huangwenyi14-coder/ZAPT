"""Unified detector entrypoint.

`detect_scenario(events)` returns the full result bundle (per-event detections
+ cross-event signals) for downstream evaluation.
"""

from __future__ import annotations

from typing import Any

from ..parsers.base import CanonicalEvent
from .rules import detect_events


def detect_scenario(events: list[CanonicalEvent]) -> dict[str, Any]:
    detections, cross_summary = detect_events(events)
    return {
        "detections": detections,
        "cross_summary": cross_summary,
        "stats": _stats(detections),
    }


def _stats(detections) -> dict[str, int]:
    from collections import Counter
    by_verdict = Counter(d["verdict"] for d in detections)
    by_source = Counter(d["source"] for d in detections)
    by_type = Counter(d["event_type"] for d in detections)
    return {
        "total": len(detections),
        "malicious": by_verdict.get("malicious", 0),
        "suspicious": by_verdict.get("suspicious", 0),
        "benign": by_verdict.get("benign", 0),
        "by_source": dict(by_source),
        "top_event_types": dict(by_type.most_common(10)),
    }