# Process Lifecycle Ground-Truth Inheritance

Date: 2026-07-15

## Goal

Fix record-level provenance for process lifecycle events. A termination emitted
after the storyline dispatcher has left its active cluster must inherit the
origin of the exact process instance instead of falling back to
`label=benign`/`provenance_kind=baseline`.

The motivating DUSTTRAP record was the eCAR process object
`d97be9c3-1c84-4444-852f-aff71e66359f`: its malicious `process_create` at
`2024-06-12T07:55:48.310Z` was followed by a termination 20.388 seconds later,
but the old sidecar labeled the termination benign.

## Root Cause

`RecordGroundTruthRecorder.provenance_for_event()` derives a label from
`SecurityEvent.storyline_cluster_id`. The dispatcher attaches that cluster only
while the storyline or red-herring step is active. Deferred process termination
could run after that context ended. Although `storyline_origin=True` was present,
that flag controls source timing/rendering behavior and intentionally does not
distinguish malicious storylines from red herrings.

The running-process state previously retained PID, start time, eCAR object ID,
image, user, and activity time, but not creation provenance.

## Implementation

### Exact process-instance state

`RunningProcess` now retains the process-create event's:

- `creation_storyline_cluster_id`;
- `creation_ground_truth_label`;
- `creation_provenance_kind`; and
- `creation_logical_event_id`.

`StateManager.apply()` captures these values when the canonical
`process_create` event is dispatched. State remains keyed by host and current
PID; PID reuse creates a new `RunningProcess` and therefore cannot inherit the
prior instance's provenance. The existing start time and eCAR object ID remain
the stable instance-level correlation evidence.

### Termination inheritance and precedence

`ActivityGenerator._execute_process_termination_bundle()` copies creation
provenance to a deferred termination when no storyline/red-herring cluster is
currently active. It also records the process-create logical event in
`parent_logical_event_ids`, making lifecycle parentage explicit in the sidecar.

If a termination is explicitly emitted while another cluster is active, the
current cluster wins. This prevents a process originally created by a malicious
step from overriding a later explicit red-herring termination, and vice versa.

### Files changed

- `src/evidenceforge/models/state.py`
- `src/evidenceforge/generation/state_manager.py`
- `src/evidenceforge/generation/activity/generator.py`
- `tests/unit/test_process_lifetimes.py`
- this worklog

The checkout is still a source snapshot without `.git`; this document is the
merge/replay record for a later upstream refresh.

## Regression Tests

Added tests verify:

1. a deferred termination inherits malicious label, storyline, provenance kind,
   and the create logical-event parent;
2. an explicitly active red-herring cluster overrides inherited creation
   provenance; and
3. the existing reused-PID termination contract still passes.

Validation completed:

```bash
uv run ruff check src/evidenceforge/models/state.py \
  src/evidenceforge/generation/state_manager.py \
  src/evidenceforge/generation/activity/generator.py \
  tests/unit/test_process_lifetimes.py
uv run ruff format --check src/evidenceforge/models/state.py \
  src/evidenceforge/generation/state_manager.py \
  src/evidenceforge/generation/activity/generator.py \
  tests/unit/test_process_lifetimes.py
uv run pytest --no-cov -q tests/unit/test_process_lifetimes.py \
  tests/unit/test_record_ground_truth.py tests/unit/test_state_manager.py \
  tests/unit/test_dispatcher.py
uv run pytest --no-cov -q tests/unit/test_activity.py tests/unit/test_engine.py \
  tests/integration/test_deterministic_generation.py
```

Results: 201 focused provenance/state tests passed; the wider activity, engine,
and deterministic-generation group passed all 360 tests. Ruff lint and format
checks passed.

## Regenerated NEW-Dataset

All ten scenarios were regenerated into sibling directories named
`generated-lifecycle-fixed-2026-07-15`. Existing `generated/` directories were
not overwritten or deleted.

Every old and new `data/` directory compared byte-for-byte equal. All 366,080
`(relative_path, record_index, record_sha256)` keys remained identical, so
physical record IDs and blind detector inputs did not drift.

| Scenario | Records | Malicious old | Malicious fixed | Red herring old | Red herring fixed |
| --- | ---: | ---: | ---: | ---: | ---: |
| apt28-gooseegg | 15,884 | 68 | 68 | 13 | 13 |
| apt28-roundpress | 11,388 | 81 | 86 | 15 | 15 |
| apt29-wineloader-rootsaw | 16,404 | 216 | 216 | 9 | 9 |
| apt41-dusttrap-onedrive | 51,219 | 744 | 753 | 112 | 118 |
| diamond-sleet-cyberlink | 25,467 | 373 | 373 | 71 | 71 |
| earth-baxia-geoserver | 25,403 | 417 | 417 | 24 | 24 |
| oilrig-mango-juicy-mix | 21,959 | 1,539 | 1,539 | 25 | 25 |
| sandworm-microscada-caddywiper | 137,900 | 38 | 38 | 7 | 7 |
| turla-tinyturla-ng | 37,438 | 532 | 532 | 37 | 37 |
| volt-typhoon-lotl | 23,018 | 223 | 229 | 9 | 9 |
| **Total** | **366,080** | **4,231** | **4,251** | **322** | **328** |

The only label transitions were 20 `benign -> malicious` and six
`benign -> red_herring`, all for `process_terminate`. Other termination rows
gained exact create-event parentage without changing their labels.

The motivating DUSTTRAP termination now has:

```json
{
  "physical_record_id": "pr-bb98ed3638dbf7b254fe423e",
  "event_type": "process_terminate",
  "label": "malicious",
  "storyline_id": "apt41-dust-003-service-persistence",
  "parent_logical_event_ids": ["le-57296bcd9b55074849f59e29"],
  "causal_parentage_status": "explicit"
}
```

## Gold Detector Re-evaluation

The detector was rerun once per scenario using the previously blinded data and
label-free record index. This is valid because the regenerated raw logs,
physical IDs, locators, and hashes were verified identical. New predictions and
evaluations are stored under:

`evaluation_runs/NEW-Dataset-2026-07-15-lifecycle-fixed/gold/`

| Scenario | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| apt28-gooseegg | 1 | 1 | 67 | 15,815 | 0.9957 | 0.5000 | 0.0147 | 0.0286 |
| apt28-roundpress | 0 | 0 | 86 | 11,302 | 0.9924 | 1.0000 | 0.0000 | 0.0000 |
| apt29-wineloader-rootsaw | 0 | 0 | 216 | 16,188 | 0.9868 | 1.0000 | 0.0000 | 0.0000 |
| apt41-dusttrap-onedrive | 302 | 1 | 451 | 50,465 | 0.9912 | 0.9967 | 0.4011 | 0.5720 |
| diamond-sleet-cyberlink | 0 | 0 | 373 | 25,094 | 0.9854 | 1.0000 | 0.0000 | 0.0000 |
| earth-baxia-geoserver | 180 | 1 | 237 | 24,985 | 0.9906 | 0.9945 | 0.4317 | 0.6020 |
| oilrig-mango-juicy-mix | 955 | 2 | 584 | 20,418 | 0.9733 | 0.9979 | 0.6205 | 0.7652 |
| sandworm-microscada-caddywiper | 0 | 0 | 38 | 137,862 | 0.9997 | 1.0000 | 0.0000 | 0.0000 |
| turla-tinyturla-ng | 0 | 0 | 532 | 36,906 | 0.9858 | 1.0000 | 0.0000 | 0.0000 |
| volt-typhoon-lotl | 0 | 0 | 229 | 22,789 | 0.9901 | 1.0000 | 0.0000 | 0.0000 |
| **Micro total** | **1,438** | **5** | **2,813** | **361,824** | **0.9923** | **0.9965** | **0.3383** | **0.5051** |

Before the label fix, the same detector produced TP=1,438, FP=5, FN=2,793,
TN=361,844, Accuracy=0.9924, Precision=0.9965, Recall=0.3399, and F1=0.5069.
The fixed score is slightly lower because the detector does not currently
expand its process findings to the newly correct termination records; TP and FP
are unchanged while FN increases by 20. This is an expected ground-truth
correction, not a detector regression caused by changed input logs.

## Merge Guidance

When replaying onto an updated upstream checkout, merge in this order:

1. add creation-provenance fields to `RunningProcess`;
2. capture provenance in `StateManager.apply(process_create)` after dispatcher
   labeling but before any later termination removes the state entry;
3. inherit that provenance in the process-termination action only when no
   current cluster is active;
4. preserve `parent_logical_event_ids` for exact lifecycle auditability; and
5. replay both lifecycle tests, then rerun the focused and deterministic suites.

Do not implement this by treating every `storyline_origin=True` event as
malicious: that would incorrectly convert red-herring lifecycle events. Do not
key inheritance by PID alone outside `RunningProcess`; PID reuse must replace
the entire instance and its provenance.
