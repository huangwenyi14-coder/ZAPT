# Record Detectability and Gold Recall Fixes

Date: 2026-07-15

## Goal

This follow-up addresses two different causes of apparent record-level false
negatives:

1. records that are recoverable from public log fields but were not reached by
   the bounded detector graph; and
2. records that the generator can label through internal provenance even though
   the rendered physical row exposes no reliable public association key.

The second category must be classified by the data generator, not guessed by a
detector after generation. Detectability depends on the final physical row, so
the classification is assigned when `RECORD_GROUND_TRUTH.jsonl` is finalized.

## Ground Truth schema v3

`src/evidenceforge/events/record_ground_truth.py` now writes these private fields
on every physical row:

- `detectability_class`:
  - `direct`: primary malicious semantics are present in the row;
  - `association_required`: a bounded public association path exists;
  - `provenance_only`: internal generation provenance is exact, but the row has
    no reliable public association anchor;
  - `not_applicable`: benign or red-herring record.
- `detectability_reason`: auditable explanation of the assigned class.
- `required_anchor_types`: public, label-free feature families available for
  association.

Derived anchor families include host + ProcessGuid, host + PID + image +
lifetime, logon ID, eCAR process object/actor ID, Zeek UID/FUID, five-tuple +
time, host source port + time, DNS answer + time, proxy client/target + time,
ASA connection ID, and file path + time.

`SecurityEvent.ground_truth_detectability_class` is an optional instructor-only
override for canonical semantics that cannot be inferred structurally. The
normal path remains per-row derivation after rendering. The override and all
derived fields stay outside source-native logs.

Schema v3 generated-scenario validation:

```text
evaluation_runs/ground-truth-schema-v3-branch-office/
```

- total physical records: 51,888;
- `not_applicable`: 51,231;
- malicious `direct`: 135;
- malicious `association_required`: 506;
- malicious `provenance_only`: 16;
- no detectability field was found under generated `data/`;
- blind `RECORD_INDEX.jsonl` contained 51,888 records and none of the three
  private detectability fields.

The 16 `provenance_only` rows are ASA auxiliary output whose generation lineage
is exact but whose rendered row lacks a reliable public anchor. The sample gold
run produced no predictions because its short 35-minute / five-minute-period
beacon and simple commands do not satisfy the current discovery rules; that run
is retained only as a schema and blind-isolation validation, not as the
NEW-Dataset performance benchmark.

## Evaluator changes

`blind_test/record_level_claude_eval.py` now emits evaluation schema v2 with a
`detectability_metrics` section:

- per-class malicious count, TP, FN, and recall;
- observable recall over `direct + association_required`;
- `unspecified` and `available=false` compatibility behavior for legacy v2
  Ground Truth.

Primary scoring remains exact all-record F1. Detectability is a diagnostic
slice, not a mechanism for removing hard records from the official score.
False-negative details include the private class, reason, and required anchor
types after prediction has completed.

The blind workspace sanitizer and both gold detector loaders reject
`detectability_class`, `detectability_reason`, and `required_anchor_types` at
any nesting depth.

## Gold detector fixes

Changes are isolated in `gold/record_graph_detector.py`; the earlier architecture
backup remains at
`gold/backups/source_informed_chain_detector.pre-architecture-2026-07-15.py`.

- Exact lifecycle propagation now admits all source emitters of the same stable
  process termination within a five-second skew, while PID-only propagation
  remains host/image/lifetime bounded.
- Proxy paths bridge a selected client request to internal Zeek HTTP/conn,
  proxy-origin DNS, external proxy conn/SSL, and exact UID/FUID companions.
- Network closure is rerun after DNS expansion, fixing records that gained a
  Zeek UID only after the first closure pass.
- Reverse connection-to-DNS propagation excludes internal destinations and
  system service ports. Forward DNS propagation is allowed only from DNS rows
  derived from an already-selected proxy target. This removed the observed
  Diamond Sleet false-positive graph pollution.
- `schtasks /create` and `C:\\Windows\\Tasks` matching were corrected.
- Bounded terminal sequences cover domain-admin enumeration to WMI, CLSID
  cleanup to Explorer restart and batch deletion, and certutil decode to archive
  extraction.
- A DUSTTRAP `One.exe` / `auth.json` / RAR staging chain was added.
- Beacon, terminal, Web exploit, and IOC discovery still run independently.

## Final NEW-Dataset result

Authoritative results:

```text
evaluation_runs/NEW-Dataset-2026-07-15-recall-fixes-final/
```

Strict threshold: `confidence >= 0.50`.

| Metric | Micro | Macro by scenario |
| --- | ---: | ---: |
| TP / FP / FN / TN | 3,172 / 0 / 1,079 / 361,829 | - |
| Accuracy | 0.997053 | 0.995544 |
| Precision | 1.000000 | 1.000000 |
| Recall | 0.746177 | 0.678422 |
| F1 | 0.854641 | 0.803131 |

Against the first Record Graph result on the same lifecycle-fixed Ground Truth
(TP=2,155, FP=0, FN=2,096, recall=0.5069, F1=0.6728), this adds 1,017 TP,
removes 1,017 FN, improves recall by 0.2392 and F1 by 0.1818, while keeping
FP at zero.

The following intermediate result trees are intentionally preserved for audit:

```text
evaluation_runs/NEW-Dataset-2026-07-15-recall-fixes/
evaluation_runs/NEW-Dataset-2026-07-15-recall-fixes-tightened/
evaluation_runs/NEW-Dataset-2026-07-15-recall-fixes-tightened-v2/
```

Only the `...-final/` tree should be cited as the final score.

## Modified files

Generator and evaluator:

```text
src/evidenceforge/events/base.py
src/evidenceforge/events/record_ground_truth.py
blind_test/record_level_claude_eval.py
gold/source_informed_chain_detector.py
gold/record_graph_detector.py
```

Tests:

```text
tests/unit/test_record_ground_truth.py
tests/unit/test_gold_record_graph_detector.py
tests/unit/test_gold_source_informed_chain_detector.py
tests/unit/test_record_level_claude_eval.py
tests/integration/test_deterministic_generation.py
```

Documentation:

```text
docs/reference/EVIDENCE_FORMATS.md
commands/eforge/references/evidence-formats.md
commands/eforge/generate.md
gold/README.md
docs/worklog/2026-07-15-record-detectability-and-gold-recall.md
evaluation_runs/NEW-Dataset-2026-07-15-recall-fixes-final/SUMMARY.md
```

## Merge guidance

This working copy has no `.git` metadata, so no commit or diff is available.
Use this file list as the merge manifest. For an updated upstream tree:

1. port the two generator files and their focused tests first;
2. preserve the schema-v2 attribution fields and add schema-v3 fields rather
   than replacing the sidecar contract;
3. port the blind sanitizers before exposing v3 data to any evaluator;
4. merge `gold/record_graph_detector.py` independently from the copied upstream
   finding detector;
5. regenerate scenarios to obtain v3 labels; existing v2 sidecars do not gain
   detectability metadata retroactively;
6. rerun the focused tests and one full generation/blind-preparation cycle.

## Validation commands

Final focused regression result: **181 passed** in 10.44 seconds. Ruff lint
passed, all ten changed Python/test files were already correctly formatted, the
51,888-row generated sidecar was entirely schema v3, and neither the physical
logs nor the blind Record Index contained private detectability metadata.

```bash
.venv/bin/python -m pytest --no-cov -q \
  tests/unit/test_record_ground_truth.py \
  tests/unit/test_gold_record_graph_detector.py \
  tests/unit/test_gold_source_informed_chain_detector.py \
  tests/unit/test_record_level_claude_eval.py \
  tests/integration/test_deterministic_generation.py \
  tests/unit/test_process_lifetimes.py \
  tests/unit/test_dispatcher.py

.venv/bin/python -m ruff check \
  src/evidenceforge/events/base.py \
  src/evidenceforge/events/record_ground_truth.py \
  blind_test/record_level_claude_eval.py \
  gold/source_informed_chain_detector.py \
  gold/record_graph_detector.py \
  tests/unit/test_record_ground_truth.py \
  tests/unit/test_gold_record_graph_detector.py \
  tests/unit/test_gold_source_informed_chain_detector.py \
  tests/unit/test_record_level_claude_eval.py \
  tests/integration/test_deterministic_generation.py
```
