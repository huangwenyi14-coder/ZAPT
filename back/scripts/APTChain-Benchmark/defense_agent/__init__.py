"""defense_agent — multi-source threat detection + evaluation harness for EvidenceForge.

This package consumes the `output/<scenario>/data/` directory tree, parses
heterogeneous log formats into a CanonicalEvent model, applies rule-based
detection (with optional LLM-assisted correlation), and evaluates the output
against `GROUND_TRUTH.json` to produce log-level and storyline-level metrics.

The detector modules MUST NOT read any GROUND_TRUTH.* files; the evaluation
modules read GT only for post-hoc alignment.
"""

__version__ = "0.1.0"