# Tool Selection for the Seven EvidenceForge Datasets

Assessment date: 2026-07-20.

## Decision

Use the checked-in neutral graph converter as the format boundary and **SPADE as
the first engineering backend**. Do not treat SPADE as the detector that produces
the final precision/recall/F1 score.

The practical pipeline is:

```text
data/**/ecar.json
        │
        ├── nodes.jsonl + edges.jsonl ── paper-specific detector adapters
        │
        └── spade.jsonl ──────────────── SPADE storage/query/visualization

RECORD_GROUND_TRUTH.jsonl ────────────── labels.jsonl (offline evaluation only)
```

This split fits the datasets because eCAR already contains the stable identities
that provenance systems need: process `objectID`/`actorID`, file and flow UUIDs,
host/PID lifetimes, principals, sessions, and nanosecond-compatible timestamps.
Raw Sysmon, Windows Security, Zeek, syslog, ASA, and Snort remain available for a
later evidence-enrichment layer without duplicating the canonical eCAR event.

## Candidate matrix

| Tool | Fit to these datasets | Engineering role | Main limitation here | Recommendation |
|---|---|---|---|---|
| **SPADE** | High | Plugin-style ingestion, storage, query; JSON and CDM paths | Middleware, not an APT detector/benchmark by itself; GPL-3.0 | **Adopt as first backend** |
| **KRYSTAL** | Medium-high | RDF/SPARQL graph plus tag propagation, signatures, reconstruction | Public implementation currently says audit data/DARPA TC; needs CDM or RDF adapter and JVM/triplestore | Second experiment after SPADE |
| **ShadeWatcher** | Medium | Published recommendation-guided detector over audit/CDM data | Official repo targets Ubuntu 16.04, Python 3.6.5, and TensorFlow-GPU 1.14 | Source-native probe plus modern objective-port benchmark completed separately |
| **ProvCon** | Medium-low | Useful Sysmon/Sysdig-to-graph design reference | Data/path appears prototype-oriented; direct eCAR/CDM ingestion is absent | Reference mapping logic, not primary platform |
| **Auto-Prov** | Unproven | Heterogeneous/evolving log-to-graph research direction | Very new LLM-based work; mature public implementation was not verified | Revisit later, not the reproducible baseline |
| **CamFlow** | Low for existing data | High-fidelity live Linux collection; can emit SPADE/W3C formats | Requires controlled Linux kernel/collector deployment; not an offline Windows/eCAR converter | Exclude from these seven offline tests |
| **log2prov/logprov** | Low | W3C PROV for workflows/application execution | Models workflow provenance rather than security host audit semantics | Exclude from first benchmark |

## Why SPADE first

1. SPADE's JSON Reporter accepts a simple vertex/edge stream, so no Avro round trip
   is needed and the current data maps without information loss.
2. SPADE separates reporters, filters, storage, and queries. That is useful when
   Zeek or Sysmon enrichment is added later.
3. SPADE also has a CDM Reporter, which keeps the experiment close to the DARPA TC
   ecosystem and provides a path for comparing exact CDM adapters.
4. The same neutral graph remains usable if SPADE's Java/Neo4j stack becomes an
   operational burden.

## Validation status and what to test next

Pinned SPADE revision `3859bbde8db6c0b985dde11dfb32fd43938d3a10` imported all seven
scenarios through its official JSON Reporter. All 73,301 vertices, 84,986 edges,
per-event-type counts, and execution/file/registry/network causal directions
matched the converter manifests. The repeatable evidence is in
`results/SPADE_ROUNDTRIP.md` and `results/spade_roundtrip.json`.

1. Add persistent storage/query benchmarks only when a concrete backend (for
   example Neo4j or PostgreSQL) is selected; in-memory format compatibility is
   already verified.
2. ShadeWatcher now provides the CDM-oriented detector baseline through a clearly
   labeled modern objective port; KRYSTAL remains the semantic/RDF comparison.
3. Freeze scenario-level train/validation/test splits before training. Never split
   individual edges from the same scenario across train and test.
4. Report event-level and storyline-level precision, recall, F1, time-to-detect,
   and false positives per million benign edges.

## Primary references

- DARPA Transparent Computing program and released CDM datasets:
  <https://www.darpa.mil/research/programs/transparent-computing>
- DARPA Transparent Computing public repository:
  <https://github.com/darpa-i2o/Transparent-Computing>
- SPADE source and documentation: <https://github.com/ashish-gehani/SPADE>
- KRYSTAL source: <https://github.com/sepses/Krystal>
- ShadeWatcher source: <https://github.com/jun-zeng/ShadeWatcher>
- CamFlow project and output formats: <https://camflow.org/>
- W3C PROV overview: <https://www.w3.org/TR/prov-overview/>
