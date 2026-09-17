"""Evaluation package — log-level + storyline-level metrics."""

from .align import align_all, observable_events
from .log_level import LogLevelMetrics, compute_log_level, compute_pr_curve
from .storyline_candidates import (
    StorylineCandidatePR,
    build_candidates_from_detections,
    compute_storyline_candidate_pr,
    compute_storyline_candidate_pr_from_candidates,
)
from .storyline_level import StorylineMetrics, compute_storyline

__all__ = [
    "align_all",
    "observable_events",
    "LogLevelMetrics",
    "compute_log_level",
    "compute_pr_curve",
    "StorylineMetrics",
    "compute_storyline",
    "StorylineCandidatePR",
    "build_candidates_from_detections",
    "compute_storyline_candidate_pr",
    "compute_storyline_candidate_pr_from_candidates",
]
