# Record-Level Ground Truth

## Status

Implemented locally on 2026-07-11. The checkout is a source snapshot without a
`.git` directory, so no branch or commit SHA is available. This worklog is the
handoff record for replaying or merging the change after refreshing from the
upstream Git repository.

## Goal

Add exact physical-record labels without injecting synthetic identifiers into
Sysmon, Windows Security, Zeek, syslog, eCAR, web/proxy, Bash history, IDS, or
firewall source records. The generated instructor bundle now includes
`RECORD_GROUND_TRUTH.jsonl` with one row per final logical log record.

## Decisions

- Preserve three distinct identities:
  - `storyline_id`: scenario step.
  - `logical_event_id`: canonical `SecurityEvent` before source fan-out.
  - `physical_record_id`: final record in one source file/sensor instance.
- Assign logical provenance in `EventDispatcher`, where storyline and
  red-herring context is still known.
- Register physical receipts only after emitter-specific sorting, source timing,
  sensor UID derivation, and Windows `EventRecordID` assignment.
- Keep source logs unchanged. The record-level sidecar is instructor-only and
  must be excluded from blind-test/reviewer bundles.
- Treat an XML `<Event>` and a multi-line Bash history timestamp/command pair as
  one record. `record_index` is a logical-record index, not a text-line number.
- Records emitted outside dispatcher provenance are conservatively labeled
  `benign` with `provenance_kind=unattributed`; they are never guessed to be
  malicious.
- `storyline` currently covers both the authored action and its generated
  causal/source companions. A later upstream enhancement may set
  `parent_logical_event_ids` and a more detailed provenance subtype when the
  causal engine exposes explicit parentage.

## Sidecar Schema

Every JSONL row contains:

- schema and dataset IDs;
- `physical_record_id`, `logical_event_id`, optional `storyline_id`;
- `label`: `malicious`, `red_herring`, or `benign`;
- `provenance_kind` and `event_type`;
- optional `parent_logical_event_ids`;
- `source_format`, `source_instance`, `relative_path`;
- final `record_index`, `byte_offset`, `byte_length`;
- SHA-256 over the logical rendered record without the writer-added delimiter;
- source-native identifiers and observed time when extractable.

Physical IDs are deterministic hashes of dataset ID, final relative path,
record index, and record content hash. Identical scenario input remains
bit-perfect across repeated generation.

## Files Added

- `src/evidenceforge/events/record_ground_truth.py`
- `tests/unit/test_record_ground_truth.py`
- `docs/worklog/2026-07-11-record-level-ground-truth.md`

## Files Modified

- `TODO.md`
- `src/evidenceforge/events/base.py`
- `src/evidenceforge/events/dispatcher.py`
- `src/evidenceforge/generation/engine/core.py`
- `src/evidenceforge/generation/engine/emitter_setup.py`
- `src/evidenceforge/generation/emitters/base.py`
- `src/evidenceforge/generation/emitters/host_base.py`
- `src/evidenceforge/generation/emitters/zeek_base.py`
- `src/evidenceforge/generation/emitters/bash_history.py`
- `src/evidenceforge/generation/emitters/cisco_asa.py`
- `src/evidenceforge/generation/emitters/ecar.py`
- `src/evidenceforge/generation/emitters/syslog.py`
- `src/evidenceforge/generation/emitters/windows.py`
- `src/evidenceforge/generation/emitters/sysmon.py`
- `src/evidenceforge/cli/commands.py`
- `commands/eforge/generate.md`
- `commands/eforge/references/evidence-formats.md`
- `docs/reference/EVIDENCE_FORMATS.md`
- `tests/integration/test_deterministic_generation.py`
- `tests/support/output_equivalence.py`
- `tests/unit/test_cli.py`
- `tests/unit/test_engine.py`

## Merge Guidance

Replay the new event-sidecar module first, then merge in this order:

1. `SecurityEvent` provenance fields and dispatcher activation.
2. Base emitter queue-envelope/context propagation.
3. Host/Zeek/Bash low-level writer receipts.
4. Windows/Sysmon deferred provenance through dict buffering and SQLite spool.
5. Engine lifecycle and CLI transactional sidecar handling.
6. Tests and documentation.

Likely conflict hotspots after an upstream refresh:

- `SecurityEvent` fields if the canonical model changes;
- `EventDispatcher.dispatch()` observation/timing flow;
- `_SingleHostWriter` and `_SingleZeekWriter` buffering/sorting;
- Windows spool encoding and final `EventRecordID` loops;
- eCAR final lifecycle normalization and syslog final presentation normalization,
  both of which temporarily rewrite writer buffers;
- CLI staging/rollback matched-set handling;
- generated command/reference documentation copies.

Do not resolve conflicts by assigning physical IDs in dispatcher: that would
regress final Sysmon ID, Zeek sensor, ordering, and file-location accuracy.

## Follow-Up

- The current recorder keeps receipt dictionaries in memory until final JSONL
  serialization. This is simple and deterministic, but multi-million-record
  datasets should move the receipt store to an append-only/SQLite spool while
  preserving `remove_path()` semantics for Bash truncation and Zeek final
  rewrites.
- Populate `parent_logical_event_ids` from explicit causal-engine lineage when
  upstream exposes stable parent/child IDs. Labels and storyline ownership are
  already correct without this enrichment.

## Schema v2 Correlation And Integrity Follow-Up

Implemented later on 2026-07-11 after reviewing the storyline-to-record mapping
contract:

- Added `correlation_features` extraction for Windows/Sysmon process, logon,
  identity, image, command, hash, file, DNS, and network fields; Zeek connection,
  DNS, HTTP, file, and TLS fields; eCAR actor/object/process/session/network
  properties; RFC5424/RFC3164 syslog; web/proxy access; Cisco ASA; Snort; and
  Bash history.
- Expanded native identifiers with eCAR `actorID`, ASA message/connection IDs,
  and Snort GID/SID/revision. Expanded observed-time extraction to eCAR,
  syslog, web/proxy, ASA, Snort, and Bash history.
- Added `attribution_status`, `mapping_method`, `causal_parentage_status`,
  `contributing_logical_event_ids`, `contributing_storyline_ids`, and
  `contributing_event_types`. Multiple logical contributors use malicious over
  red-herring over benign label precedence.
- Added a final integrity gate that rejects unattributed/partially attributed
  receipts, duplicate physical IDs, missing files/offsets, and any mismatch
  between the sidecar hash and the final on-disk byte range.
- Fixed Cisco ASA post-flush connection-ID rewriting by refreshing hashes,
  native IDs, offsets, and correlation fields from the final file while
  preserving provenance by record position.
- Fixed inserted syslog PAM opener provenance by inheriting the explained
  logind row's provenance instead of matching by rendered content.
- Replaced Zeek digest-only provenance recovery with exact rendered-record
  queues, preserving stable provenance for byte-identical duplicate rows and
  eliminating content-hash collision ambiguity.
- Strengthened the blind-source leakage integration test to reject
  `storyline_id`, `logical_event_id`, `physical_record_id`, labels, provenance
  kinds, and internal provenance keys in every actual source file referenced by
  the sidecar.

Explicit causal parents remain `causal_parentage_status=not_available` until the
causal/action-bundle layer exposes stable parent IDs; the generator does not
invent a PID/time-based parent relationship.

## Validation

Completed before handoff:

- `uv run ruff check src tests`: passed.
- `tests/unit/test_record_ground_truth.py`: passed.
- emitter, Windows record-ID, engine, semantic GT, and observation-manifest unit
  suites: passed.
- deterministic generation integration test: passed and verifies sidecar count
  equals the evaluation parsers' physical-record count.
- storyline integration test: passed and verifies one logical event fans out to
  multiple uniquely identified malicious physical records while source logs
  contain no provenance field.
- adversarial-payload multi-source generation: sidecar count 1,132 exactly
  matched evaluation-parser count 1,132 across eCAR, syslog, and web access;
  CRLF log forging produced two separately identified malicious physical rows.
- all 1,132 multi-source receipts were read back by `byte_offset` and
  `byte_length`; every sliced on-disk record matched its recorded SHA-256.
- real CLI staged generation: exit 0 and installed a 262-record
  `RECORD_GROUND_TRUTH.jsonl` beside the other report sidecars.
- complete default suite: 4,863 passed, 41 environment-dependent tests skipped,
  0 failed (`uv run pytest --no-cov -q`).
- schema-v2 follow-up validation: repository-wide Ruff lint and format checks
  passed; the expanded complete suite finished with 4,876 passed, 41 skipped,
  and 0 failed in 341.70 seconds. The 70 deterministic/adversarial integration
  cases also passed with strict attribution and final-byte integrity enabled.

Run again after merging upstream:

```bash
uv run ruff check src tests
uv run pytest --no-cov tests/unit/test_record_ground_truth.py \
  tests/unit/test_emitters.py tests/unit/test_windows_record_ids.py \
  tests/unit/test_engine.py tests/unit/test_ground_truth.py \
  tests/unit/test_observation_manifest.py tests/unit/test_cli.py
uv run pytest --no-cov tests/integration/test_deterministic_generation.py
```
