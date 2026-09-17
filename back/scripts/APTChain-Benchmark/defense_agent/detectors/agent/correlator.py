"""LLM-driven cross-event correlator (optional, requires API key).

This module is OPTIONAL: when ANTHROPIC_API_KEY is not set, `correlate()` returns
an empty list and the rule-based output is used as-is. This way the rest of the
pipeline (parsers / rules / evaluation / reports) does not depend on an external
API being available.

If the key IS available, suspicious events are clustered into time-bucketed
"chapters" and each chapter is sent to Claude for a verdict + reasoning.
The verdict is recorded but does NOT modify the per-event rule verdicts —
it adds a higher-level "storyline hypothesis" to the output for downstream
storyline-level evaluation.

Never reads GROUND_TRUTH files.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Callable, Iterable

from ...parsers.base import CanonicalEvent

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class ChapterVerdict:
    chapter_start: str  # ISO
    chapter_end: str  # ISO
    hosts: tuple[str, ...]
    hypothesis: str  # attacker action summary
    severity: str  # low | medium | high
    reasoning: str  # LLM rationale
    technique: str  # MITRE T-code
    affected_event_ids: tuple[str, ...]  # indices into the rule-detector output


def _cluster_suspicious(detections: list[dict], window_min: int = 15) -> list[list[dict]]:
    """Greedy clustering of detections marked suspicious/malicious by host + time proximity."""
    from datetime import datetime
    items = [d for d in detections if d["verdict"] in ("suspicious", "malicious") and d.get("timestamp")]
    items.sort(key=lambda d: d["timestamp"])
    clusters: list[list[dict]] = []
    for d in items:
        placed = False
        ts = datetime.fromisoformat(d["timestamp"])
        for c in clusters:
            c_last_ts = datetime.fromisoformat(c[-1]["timestamp"])
            c_first_ts = datetime.fromisoformat(c[0]["timestamp"])
            host_overlap = any(ev["host"] == d["host"] for ev in c[-3:]) if c else False
            if host_overlap and (ts - c_first_ts) <= timedelta(minutes=window_min * 4):
                if (ts - c_last_ts) <= timedelta(minutes=window_min):
                    c.append(d)
                    placed = True
                    break
        if not placed:
            clusters.append([d])
    return clusters


def _chapter_to_prompt(cluster: list[dict]) -> str:
    lines = ["You are a senior SOC analyst. Read this cluster of suspicious security events and produce a hypothesis."]
    lines.append("Respond strictly as JSON: {\"hypothesis\": \"...\", \"severity\": \"low|medium|high\", \"technique\": \"Txxxx\", \"reasoning\": \"...\"}")
    lines.append("\nEvents (chronological):")
    for d in cluster[:30]:  # cap to 30 events per chapter
        ev = d
        lines.append(
            f"- {ev['timestamp']} {ev['host']} {ev['source']}/{ev['event_type']} "
            f"user={ev.get('user')} proc={ev.get('process_name')} "
            f"cl={(ev.get('command_line') or '')[:120]} "
            f"dst={ev.get('dst_ip')}:{ev.get('dst_port')} domain={ev.get('domain')} "
            f"reasons={[r['reason'] for r in ev.get('reasons', [])][:3]}"
        )
    return "\n".join(lines)


def _call_anthropic(prompt: str, model: str = "claude-haiku-4-5-20251001") -> dict[str, Any]:
    """Call Anthropic Messages API and parse JSON response. Imported lazily to keep deps optional."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")
    try:
        import anthropic
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("anthropic package not installed") from exc

    client = anthropic.Anthropic(api_key=api_key)
    msg = client.messages.create(
        model=model,
        max_tokens=512,
        system="You are a SOC analyst. Always reply with JSON only.",
        messages=[{"role": "user", "content": prompt}],
    )
    text = ""
    for block in msg.content:
        if getattr(block, "type", None) == "text":
            text += block.text
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    return json.loads(text)


def correlate(detections: list[dict], use_llm: bool = True) -> list[ChapterVerdict]:
    """Cluster suspicious detections, optionally ask LLM for a hypothesis per cluster.

    Returns list of ChapterVerdict. If LLM unavailable, returns empty list
    (callers should fall back to per-event rule verdicts).
    """
    clusters = _cluster_suspicious(detections)
    LOG.info("agent: clustered %d suspicious detections into %d chapters", len(detections), len(clusters))

    if not use_llm or not os.environ.get("ANTHROPIC_API_KEY"):
        LOG.info("agent: LLM disabled (no API key) — emitting clustering only")
        return []

    verdicts: list[ChapterVerdict] = []
    for cluster in clusters:
        prompt = _chapter_to_prompt(cluster)
        try:
            resp = _call_anthropic(prompt)
        except Exception as exc:
            LOG.warning("agent: LLM call failed (%s) — skipping cluster", exc)
            continue

        verdict = ChapterVerdict(
            chapter_start=cluster[0]["timestamp"],
            chapter_end=cluster[-1]["timestamp"],
            hosts=tuple(sorted({ev["host"] for ev in cluster})),
            hypothesis=str(resp.get("hypothesis", "")),
            severity=str(resp.get("severity", "medium")),
            technique=str(resp.get("technique", "T1071")),
            reasoning=str(resp.get("reasoning", "")),
            affected_event_ids=tuple(str(id(ev)) for ev in cluster),
        )
        verdicts.append(verdict)
    return verdicts


def verdict_dicts(verdicts: list[ChapterVerdict]) -> list[dict]:
    return [
        {
            "chapter_start": v.chapter_start,
            "chapter_end": v.chapter_end,
            "hosts": list(v.hosts),
            "hypothesis": v.hypothesis,
            "severity": v.severity,
            "technique": v.technique,
            "reasoning": v.reasoning,
            "n_events": len(v.affected_event_ids),
        }
        for v in verdicts
    ]