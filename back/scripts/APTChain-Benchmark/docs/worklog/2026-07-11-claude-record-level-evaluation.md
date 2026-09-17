# Claude Record-Level Evaluation Harness

## Status

Implemented locally on 2026-07-11 in the source snapshot without a `.git`
directory. This worklog records the design and validation for later upstream
merge.

## Goal

Run `claude -p` against one generated scenario without exposing instructor
labels, collect exact physical-record malicious predictions, and score them
against `RECORD_GROUND_TRUTH.jsonl`.

## Design

- `prepare` copies only the scenario `data/` directory to an isolated blind
  workspace and writes a strict allowlisted `RECORD_INDEX.jsonl`.
- The label-free index exposes physical IDs and source-derived locators/native
  correlation features, but never storyline, logical-event, label, provenance,
  or causal-parent fields.
- The private Ground Truth path is not persisted under the work directory.
- Symlinks are rejected and the work directory cannot be nested inside the
  scenario directory. The default work directory is under the system temporary
  root.
- Claude runs in print/safe mode with JSON Schema output. Only Read, Glob, and
  Grep are allowed; Bash, editing, web, task, and notebook tools are explicitly
  denied.
- The prompt asks for a sparse, high-confidence, cross-source-supported chain,
  warns about benign administration and red herrings, and requires exact IDs
  from the blind index.
- `evaluate` performs one-to-one matching on the tuple
  `(physical_record_id, relative_path, record_index)`. Unknown or inconsistent
  references are false positives.
- Primary score is exact physical-record F1 multiplied by 100. The report also
  contains record recall, storyline/logical-event coverage, per-source and
  per-storyline results, and bounded error details.

## Files Added

- `blind_test/__init__.py`
- `blind_test/record_level_claude_eval.py`
- `blind_test/README.md`
- `tests/unit/test_record_level_claude_eval.py`
- `docs/worklog/2026-07-11-claude-record-level-evaluation.md`

## Validation

- Unit tests cover blind-index leakage, exact TP/FP/FN arithmetic, confidence
  thresholds, duplicate IDs, unknown IDs, locator mismatches, red-herring false
  positives, baseline-only scoring, Claude JSON wrappers/event arrays, isolated
  subprocess cwd, tool flags, and report files.
- A real minimal EvidenceForge scenario generated 262 physical records across
  Windows Security, Sysmon, Zeek conn/DHCP/files/HTTP/OCSP/SSL/X.509. `prepare`
  copied ten source files and the sanitized index; a recursive scan found none
  of the forbidden label/provenance fields or private filenames.
- Controlled empty prediction on the real baseline-only scenario scored
  100/100 with TP=0, FP=0, FN=0, confirming the no-positive edge case.
- The first live Sonnet invocation exposed two CLI compatibility issues, now
  fixed: current JSON output can be an event array, and tool allowlists must be
  passed as one comma-separated argument. The live request itself was refused
  by Claude's provider-side cyber safeguard; the runner now extracts and
  reports such refusal messages from stdout rather than returning an empty
  error.
- A second constrained live invocation confirmed the corrected tool flags:
  Bash, editing, web, and notebook tools were absent, while Read/Glob/Grep and
  structured output remained available. The intentionally tiny USD 0.05 cap
  then stopped the run; event-array budget errors are now surfaced as
  `Reached maximum budget` instead of an empty message.
- Repository-wide Ruff lint and formatting checks passed. The complete default
  suite finished with 4,888 passed, 41 skipped, and 0 failed in 350.78 seconds.

## Merge Guidance

This harness depends only on Python's standard library and sidecar schema fields
already produced by `record_ground_truth.py`. After an upstream merge, rerun:

```bash
uv run ruff check blind_test tests/unit/test_record_level_claude_eval.py
uv run ruff format --check blind_test tests/unit/test_record_level_claude_eval.py
uv run pytest --no-cov -q tests/unit/test_record_level_claude_eval.py
```

## Per-Scenario Batch Follow-Up

Added after clarifying that a `scenarios/` evaluation must never feed multiple
scenarios to one Claude invocation:

- Added a `batch` subcommand that discovers generated children containing both
  `data/` and `RECORD_GROUND_TRUTH.jsonl`.
- The loop is deliberately sequential. Every scenario gets a unique blind/work
  directory and a new `claude -p` process with no session persistence. The next
  scenario is not prepared for Claude until the current process has returned.
- Per-scenario predictions, raw Claude output, evaluation, and errors remain in
  that case directory. No logs, indexes, or prompts are concatenated.
- Local post-processing writes `batch_summary.json` and `batch_summary.md` with
  per-case status, micro record metrics, and macro scenario metrics. Claude is
  not involved in aggregation.
- Added repeated `--scenario-glob`, `--max-scenarios`, `--resume`,
  `--fail-fast`, and explicit per-scenario budget/timeout controls.
- Unit coverage creates two generated scenario fixtures and verifies two
  distinct blind indexes and two separate prediction calls, plus scenario
  discovery/filtering and aggregate report creation.
- An end-to-end controlled CLI smoke test duplicated the real 262-record
  baseline fixture into `case-a` and `case-b`, used a deterministic fake Claude
  executable, and observed two sequential subprocess calls, two unique case
  IDs/workspaces, two independent evaluations, and a valid aggregate JSON/MD
  report. No combined detector input was created.

## Operation Dragon Whistle Live Run

The source scenario was validated without modification. Validation emitted one
non-blocking warning: the DMZ segment has no SPAN-style Zeek sensor for
link-local DHCP. This does not affect the central workstation-to-C2 storyline.
To preserve the pre-existing generated files, the upgraded generator wrote a
new sibling scenario directory:

`/Users/xhb/Desktop/Project/TASK/2026TASK/供应链安全检测/Mythos/Tools/EvidenceForge-main/scenarios/operation-dragon-whistle-record-eval`

Generation produced 39,020 physical records in 33 source files across 16
formats. The hidden sidecar contains 38,487 benign, 493 malicious, and 40 red
herring records. All 39,020 `physical_record_id` values are unique; every row
has its required source locator and hash fields; every mapping has
`mapping_method=generation_provenance` and `attribution_status=exact`. All nine
malicious storyline steps have at least one physical record.

### Live attempt 1

- Model argument: `claude-sonnet-4-6`. The local Claude configuration uses the
  Volcengine Ark compatibility endpoint, and response events identify the
  underlying model as `doubao-seed-2.0-code`; this is not a direct Anthropic
  endpoint run.
- Limits: USD 5, 1,800 seconds, Read/Glob/Grep only.
- Result: failed before structured output because the USD limit was reached.
- Runtime: 1,709.916 seconds; reported cost: USD 5.0019726.
- Work: 76 turns, 39 Read calls, 27 Grep calls, and 8 Glob calls; 639,715 input
  tokens, 80,718 output tokens, and 6,240,192 cache-read input tokens.
- No `predictions.json` was produced, so TP/FP/FN, precision, recall, F1, and
  score are undefined. This must not be reported as a zero score.
- Audit directory: `/tmp/evidenceforge-dragon-whistle-claude-eval/results`.

The trace showed that the model started sequentially reading chunks of the
34.4 MB record index. The prompt was therefore tightened to require completion
within 24 tool calls, prohibit sequential index enumeration, search source logs
first, look up candidate IDs only by distinctive record-local values, and
reserve a final tool-free turn for structured output.

### Live attempt 2 after prompt tightening

- Limits: USD 3, 900 seconds, in a fresh Claude process and fresh `-v2` work
  directory.
- Result: the compatibility service returned HTTP 429 before structured output,
  stating that the five-hour usage quota was exhausted and would reset at
  2026-07-11 20:36:01 +0800.
- Runtime: 321.802 seconds; reported cost before rejection: USD 1.0494792.
- Work: 26 turns and 24 valid read/search calls (13 Grep, 10 Read, 1 Glob), so
  the revised prompt substantially bounded the investigation. One attempted
  `RunShellCommand` hallucination was rejected as an unavailable tool and did
  not execute.
- No prediction or scoring files were produced; metrics remain undefined.
- Audit directory: `/tmp/evidenceforge-dragon-whistle-claude-eval-v2/results`.

After the quota resets, reproduce the bounded run with:

```bash
python3 blind_test/record_level_claude_eval.py run \
  --scenario-dir "/Users/xhb/Desktop/Project/TASK/2026TASK/供应链安全检测/Mythos/Tools/EvidenceForge-main/scenarios/operation-dragon-whistle-record-eval" \
  --work-dir /tmp/evidenceforge-dragon-whistle-claude-eval-v3 \
  --force \
  --model claude-sonnet-4-6 \
  --max-budget-usd 3.00 \
  --timeout-seconds 900 \
  --confidence-threshold 0.50
```

The prompt-only revision passed Ruff check, Ruff format check, and all 14
record-level evaluator unit tests.

## GLM-5.2 Uncapped Live Run

At the user's request, the runner now treats `max_budget_usd` as optional. When
it is omitted, the generated Claude command contains no `--max-budget-usd`
argument; explicitly supplied numeric limits continue to work. The parser
defaults for `predict`, `run`, and per-scenario `batch` were updated
accordingly. A regression test also verifies that the generated command omits
the budget flag while retaining the requested model. Ruff check, Ruff format
check, and all 15 evaluator unit tests passed after this change.

One fresh single-scenario run used model `glm-5.2`, no USD limit, a 1,800-second
timeout, and the existing Read/Glob/Grep-only blind workspace contract:

```bash
python3 blind_test/record_level_claude_eval.py run \
  --scenario-dir "/Users/xhb/Desktop/Project/TASK/2026TASK/供应链安全检测/Mythos/Tools/EvidenceForge-main/scenarios/operation-dragon-whistle-record-eval" \
  --work-dir /tmp/evidenceforge-dragon-whistle-glm52-eval \
  --force \
  --model glm-5.2 \
  --timeout-seconds 1800 \
  --confidence-threshold 0.50
```

The run completed successfully in 917.642 seconds and returned 38 predictions.
The service reported 47 turns, 25 Grep calls, 18 Read calls, 2 Glob calls, one
StructuredOutput call, and USD 4.448713 total cost. Although the prompt asked
for at most 24 tool calls, GLM-5.2 did not obey that soft limit.

Exact record-level evaluation:

| Metric | Result |
| --- | ---: |
| TP | 0 |
| FP | 38 |
| FN | 493 |
| Precision | 0.0000 |
| Recall | 0.0000 |
| F1 / score | 0.0000 / 0.00 |
| Storyline recall | 0/9 |
| Logical-event recall | 0/172 |
| Invalid IDs | 0 |
| Locator mismatches | 0 |
| Red-herring false positives | 0 |
| Benign false positives | 38 |

All 38 predictions were valid, correctly located records from
`ZEEK-CZ-CORE/dns.json`, but all were benign baseline records. GLM-5.2 inferred
that randomized domains queried by DMZ host WEB-CZ-01 were a sustained DGA C2
campaign. It therefore produced a coherent but entirely incorrect attack
story around the wrong host.

The true malicious chain was on WS-STU-042: spearphishing and user logon,
malicious LNK/VBS execution, Bandizip DLL sideloading, anti-analysis,
AMSI/ETW bypass, persistence, and C2 beaconing. The 493 malicious records span
ECAR, Windows Security, Sysmon, Cisco ASA, Zeek conn/DNS/SSL, and DC telemetry.
GLM-5.2 hit none of them. This is a semantic detection failure, not an ID or
record-locator failure.

Artifacts:

- `/tmp/evidenceforge-dragon-whistle-glm52-eval/results/predictions.json`
- `/tmp/evidenceforge-dragon-whistle-glm52-eval/results/evaluation.json`
- `/tmp/evidenceforge-dragon-whistle-glm52-eval/results/evaluation.md`
- `/tmp/evidenceforge-dragon-whistle-glm52-eval/results/claude_run.json`
- `/tmp/evidenceforge-dragon-whistle-glm52-eval/results/claude_stdout.txt`

## Prompt Optimization After the GLM-5.2 False Positive

The fixed 24-tool-call instruction was removed. Read/Glob/Grep remain the only
tools because they enforce blind-workspace isolation, but a hard call limit can
force premature convergence on the first plausible anomaly. In the GLM-5.2
run, that behavior contributed to anchoring on WEB-CZ-01's benign randomized
DNS baseline without adequately comparing endpoint execution chains across all
hosts.

The prompt now uses three explicit phases:

1. Inventory every host/source and maintain competing host hypotheses. Endpoint
   process, user-execution, script, DLL/image-load, defense-evasion,
   persistence, identity, and file evidence outrank network-only anomalies.
2. Construct and attempt to falsify a causal cross-source chain. Random domains,
   NXDOMAINs, periodic traffic, denied flows, scans, and isolated IDS alerts are
   insufficient by themselves when endpoint telemetry exists.
3. After identifying the chain, expand it into every independently malicious
   physical record, including repeated beacons and separate cross-source
   observations, and verify every exact locator through the label-free index.

The previous default cap of 200 predictions was also incompatible with exact
record recall: Dragon Whistle contains 493 malicious physical records, making
the theoretical maximum recall only 200/493 = 40.57%. The default is now 2,000
while remaining configurable through `--max-predictions`.

### Optimized-prompt rerun

A fresh `glm-5.2` run used the optimized prompt, no USD limit, a 2,000-record
prediction capacity, and a 1,800-second timeout. It did not return structured
predictions before the timeout and was terminated by the runner. No Claude
process remained afterward. Because no prediction set exists, this outcome is
`timed_out`, not a zero score, and TP/FP/FN are undefined.

The timeout occurred after the prompt broadened the investigation from the
first network anomaly to all hosts and full physical-record expansion. This
shows the opposite failure mode from the earlier run: the old prompt converged
prematurely and scored zero, while the fully open investigation failed to
converge within 30 minutes. A production follow-up should split discovery and
record expansion into two bounded phases rather than relying on one long agent
turn.

The runner previously discarded partial subprocess output on timeout. It now
persists available stdout, stderr, prompt, and a `claude_run.json` audit marked
`status=timed_out` before raising the timeout error.

## Two-Stage Discovery and Physical-Record Expansion

The single long detector turn was replaced with two fresh sequential
`claude -p` processes per scenario:

1. **Discovery:** runs with `blind/data/` as its working directory and therefore
   cannot read `RECORD_INDEX.jsonl`. It outputs only candidate attack hosts,
   bounded time ranges, process chains, IOCs, and reproducible evidence
   anchors. Physical record IDs and record indexes are
   forbidden and validated before stage two starts.
2. **Expansion:** runs from the blind root, receives the validated discovery
   JSON as a hypothesis, verifies its anchors against source logs, and maps the
   supported chain through the label-free index to exact
   `(physical_record_id, relative_path, record_index)` predictions. Only this
   output is evaluated against the private sidecar.

The discovery prompt includes both network-first and endpoint-first routes. The
network-first route searches for successful, stable heartbeat traffic,
extracts the destination IP/domain/SNI and internal source IP, maps that source
to a host, then pivots backward from the first heartbeat into user/file/process
execution and forward into recurring communications. A Beacon remains an entry
point rather than proof: failed DNS, denied flows, scans, or periodic traffic
without endpoint causal support must be rejected or de-rated.

The default timeout is now 2,400 seconds for **each** stage. Batch scenarios
remain sequential; each scenario completes discovery, expansion, and local
evaluation before the next scenario begins. Optional USD limits, when supplied,
also apply independently to each stage.

The evaluator's default model is now `glm-5.2`, matching the validated local
compatibility-endpoint configuration. `--model` can still override it.

New primary artifacts are:

- `discovery.json`
- `discovery_prompt.txt` and `discovery_claude_{run,stdout,stderr}.*`
- `expansion_prompt.txt` and `expansion_claude_{run,stdout,stderr}.*`
- `predictions.json`, `evaluation.json`, and `evaluation.md`

Expansion-stage `prompt.txt` and `claude_*` aliases are still written for
compatibility with existing audit consumers.

Stage-one strings are treated as untrusted log-derived data in the expansion
prompt. Angle brackets are escaped before embedding the JSON, and stage two is
explicitly instructed never to follow instructions quoted inside discovery
fields. This prevents a log-carried string from closing the discovery delimiter
or redefining the expansion task.

### Dragon Whistle two-stage GLM-5.2 live result

A complete uncapped run used the generated `operation-dragon-whistle-record-eval`
scenario, `glm-5.2`, and a 2,400-second timeout for each stage. Both stages
completed successfully:

- Discovery: 510.260 seconds, 31 turns, 15 Read + 13 Grep + 1 Glob, reported
  cost USD 1.948810.
- Expansion: 1,590.487 seconds, 49 turns, 16 Read + 30 Grep + 1 Glob, reported
  cost USD 5.223394.
- Total model time: 2,100.747 seconds (about 35 minutes); reported combined
  cost USD 7.172204.

Discovery correctly selected `WS-STU-042.changzhou-univ.cn` (`10.12.4.42`) and
reconstructed the phishing/LNK/VBS/Bandizip/ark.x64.dll/AMSI+ETW/Cobalt Strike
chain. It identified `lysander.asia` and `60.205.186.162:443`, connected the
near-five-minute TLS heartbeats to Bandizip PID 6848, and explicitly rejected
WEB-CZ-01's failed random-domain DNS activity as a network-only red herring.

Expansion returned 239 predictions. Exact scoring was:

| Metric | Result |
| --- | ---: |
| TP | 235 |
| FP | 4 |
| FN | 258 |
| Precision | 0.9833 |
| Recall | 0.4767 |
| F1 / score | 0.6421 / 64.21 |
| Storyline recall | 6/9 = 0.6667 |
| Logical-event recall | 83/172 = 0.4826 |

The four counted false positives were locator mismatches rather than unknown
IDs: GLM supplied valid `conn.json` physical IDs with the same record indexes
but claimed `dhcp.json` paths. The underlying records were benign DHCP lease
connections, so they also should not have been expanded as malicious; DHCP was
useful only for host attribution.

Recall by important source was Sysmon 52/59 (0.8814), Zeek DNS 27/29 (0.9310),
Zeek SSL 25/25 (1.0000), Cisco ASA 50/100 (0.5000), ECAR 56/117 (0.4786), Zeek
conn 25/54 (0.4630), and Windows Security 0/109. The 258 false negatives were
dominated by 109 Windows Security records, 58 ECAR connection records, 50 ASA
NAT build/teardown companion records, and 29 Zeek DNS transport connections.
Consequently, persistence, victim logon, and spearphish-email storyline recall
remained zero, while C2 record recall was 179/406 (0.4409).

This run demonstrates that two-stage discovery fixes the catastrophic wrong-host
failure (previous F1 0.0) and yields excellent semantic precision, but LLM-only
physical expansion still misses source-native companion observations. A likely
next improvement is a deterministic anchor expander or an explicit per-source
expansion checklist, especially for Windows Security/WFP, DNS transport, ASA
NAT companions, and responder-side ECAR records.

Artifacts are under `/tmp/evidenceforge-dragon-whistle-two-stage/results/`.
