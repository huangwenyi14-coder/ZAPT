"""Agent package — LLM-based correlator + storyline builder."""

from .correlator import ChapterVerdict, correlate, verdict_dicts
from .story_builder import Storyline, build_storylines

__all__ = ["ChapterVerdict", "correlate", "verdict_dicts", "Storyline", "build_storylines"]