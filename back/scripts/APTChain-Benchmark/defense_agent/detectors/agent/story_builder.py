"""Storyline builder — uses Chapters (LLM verdicts or rule-only clusters) to form a Storyline reconstruction.

A storyline is a hypothesis: "this cluster of events represents action X"
attributed to a specific actor and time window. We build storylines purely from
detections, never from GROUND_TRUTH.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .correlator import ChapterVerdict


@dataclass
class Storyline:
    storyline_id: str  # ours, e.g., "agent-story-0001"
    host: str
    actor: str
    title: str
    chapter_start: datetime
    chapter_end: datetime
    technique: str
    severity: str
    event_count: int
    event_offsets: list[int] = field(default_factory=list)  # indices into detections list

    def to_dict(self) -> dict[str, Any]:
        return {
            "storyline_id": self.storyline_id,
            "host": self.host,
            "actor": self.actor,
            "title": self.title,
            "chapter_start": self.chapter_start.isoformat(),
            "chapter_end": self.chapter_end.isoformat(),
            "technique": self.technique,
            "severity": self.severity,
            "event_count": self.event_count,
            "event_offsets": self.event_offsets,
        }


def build_storylines(detections: list[dict], chapters: list[ChapterVerdict]) -> list[Storyline]:
    """Convert ChapterVerdicts (or fallback clusters) to Storyline objects.

    If chapters is empty (LLM unavailable), we synthesize lightweight storylines
    from clusters of rule-flagged events so the storyline-level evaluation
    still has something to evaluate.
    """
    from .correlator import _cluster_suspicious
    storylines: list[Storyline] = []
    if not chapters:
        # Synthesize from cluster grouping
        clusters = _cluster_suspicious(detections)
        for i, cluster in enumerate(clusters, start=1):
            if not cluster:
                continue
            top = cluster[0]
            techniques = sorted({r["technique"] for d in cluster for r in d.get("reasons", []) if r.get("technique", "").startswith("T")})
            title = f"Rule-cluster {i}: {','.join(techniques[:3]) or 'suspicious activity'}"
            storylines.append(
                Storyline(
                    storyline_id=f"agent-story-{i:04d}",
                    host=top.get("host", ""),
                    actor=top.get("user", "") or "unknown",
                    title=title,
                    chapter_start=datetime.fromisoformat(cluster[0]["timestamp"]),
                    chapter_end=datetime.fromisoformat(cluster[-1]["timestamp"]),
                    technique=techniques[0] if techniques else "T1071",
                    severity="medium" if any(d["verdict"] == "malicious" for d in cluster) else "low",
                    event_count=len(cluster),
                )
            )
    else:
        for i, ch in enumerate(chapters, start=1):
            storylines.append(
                Storyline(
                    storyline_id=f"agent-story-{i:04d}",
                    host=ch.hosts[0] if ch.hosts else "",
                    actor="unknown",
                    title=ch.hypothesis[:200],
                    chapter_start=datetime.fromisoformat(ch.chapter_start),
                    chapter_end=datetime.fromisoformat(ch.chapter_end),
                    technique=ch.technique,
                    severity=ch.severity,
                    event_count=len(ch.affected_event_ids),
                )
            )
    return storylines