# EvidenceForge Provenance Graph Lab

This directory converts the seven selected EvidenceForge datasets into a
DARPA Transparent Computing/Common Data Model-inspired provenance graph. The
conversion boundary is deliberately explicit:

- Graph inputs come only from each dataset's `data/` directory.
- `data/**/ecar.json` is the canonical v0.1 provenance source because it already
  carries process, file, flow, registry, module, thread, and session identities.
- Parallel raw Security, Sysmon, Zeek, syslog, ASA, and Snort rows are inventoried
  but not duplicated into the causal graph in v0.1.
- Ground truth is joined only after graph construction and written to a separate
  `labels.jsonl`. A detector must never read that file during inference.

The output is CDM-inspired, not byte-for-byte DARPA CDM18/CDM20 Avro. It preserves
the same useful abstraction—subjects, objects, principals, timestamped typed
events—and adds a direct SPADE JSON representation.

## Quick start

From the EvidenceForge repository root:

```bash
uv run python -m provenance_graph.cli convert-all
```

Generated artifacts are written to `provenance_graph/graphs/` and intentionally
ignored by Git because they are derived from the datasets.

For one dataset:

```bash
uv run python -m provenance_graph.cli convert-one \
  output/2024-11-26-apt-c-48-cnc
```

## Artifacts

Each dataset directory contains:

| File | Role | Safe detector input? |
|---|---|---|
| `nodes.jsonl` | Typed graph entities | Yes |
| `edges.jsonl` | Timestamped event/causal edges | Yes |
| `spade.jsonl` | Vertices then edges for SPADE's JSON Reporter | Yes |
| `labels.jsonl` | Offline malicious/benign and storyline labels | **No** |
| `manifest.json` | Counts, integrity checks, input inventory, readiness score | Evaluation only |

See [SCHEMA.md](SCHEMA.md) for field semantics and
[TOOL_SELECTION.md](TOOL_SELECTION.md) for the framework decision.

## SPADE import

`spade.jsonl` uses SPADE's accepted JSON keys:

- vertex: `id`, `type`, `annotations`
- edge: `from`, `to`, `type`, `annotations`

All vertices precede all edges because SPADE resolves edge endpoints from already
seen vertices. In a SPADE controller, configure a storage backend and then load:

```text
add reporter JSON input=/absolute/path/to/spade.jsonl
```

The official SPADE source is pinned separately from EvidenceForge:

```bash
uv run python -m provenance_graph.fetch_tools
uv run python -m provenance_graph.spade_probe
```

The probe builds SPADE's native JSON import path, imports all seven datasets in
memory, compares vertex/edge/type counts with every manifest, and validates
execution, file, registry, and network causal directions. All seven passed at
revision `3859bbde8db6c0b985dde11dfb32fd43938d3a10`; see
`results/SPADE_ROUNDTRIP.md`.

The exporter uses CDM vertex types `Subject`, `Object`, `Principal` and
`SimpleEdge`, with original event kinds retained as `cdm.type` annotations.

## What the current score means

The readiness score in `manifest.json` and `graphs/SUMMARY.md` measures whether a
scenario is suitable for provenance-graph experiments. It combines storyline
coverage, malicious-edge directness, actor attribution, process lifecycle
completeness, endpoint integrity, and malicious-subgraph connectivity.

The diagnostic weights are 40%, 15%, 15%, 10%, 10%, and 10%, respectively. They
are an explicit project rubric—not a published benchmark—and can be changed
without rebuilding the graph.

It is **not** detector accuracy, precision, recall, or F1. Those metrics require a
specific published detector, a leakage-free training/evaluation split, and an
explicit alert-to-ground-truth matching policy.
