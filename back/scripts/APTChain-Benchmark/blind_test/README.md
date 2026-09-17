# Claude Record-Level Blind Evaluation

## `predict.json` v2 三部分判分

`score_predictions_v2.py` 是独立的、无需调用大模型的 v2 判分器。它读取私有
`GOLD_Label.json` 和选手的两部分 `predict.json`，默认按 TA F1、物理 ID F1、
攻击步骤得分 `0.3:0.2:0.5` 汇总；攻击步骤内部默认按步骤 Recall、物理 ID
Precision `0.5:0.5` 汇总。完整格式与公式见
[`PREDICT_V2_SCORING_CONTRACT.md`](../docs/reference/PREDICT_V2_SCORING_CONTRACT.md)。

```bash
uv run python blind_test/score_predictions_v2.py \
  --gold /absolute/path/GOLD_Label.json \
  --prediction /absolute/path/predict.json \
  --output /absolute/path/score_v2.json
```

下面的 `record_level_claude_eval.py` 是原有三层盲测评估器，v2 的加入没有改变其
提交格式或评分逻辑。

`record_level_claude_eval.py` runs Claude Code in print mode against one
generated EvidenceForge scenario and scores exact physical-record predictions
against the private `RECORD_GROUND_TRUTH.jsonl` sidecar.

The model-independent output contract for Claude, other agents, and traditional
detectors is documented in
[`docs/reference/PREDICTIONS_JSON_AGENT_CONTRACT.md`](../docs/reference/PREDICTIONS_JSON_AGENT_CONTRACT.md).

## Multiple scenarios: two Claude stages per scenario

Use `batch` when a directory contains multiple generated scenarios:

```text
generated-scenarios/
  scenario-a/
    data/
    RECORD_GROUND_TRUTH.jsonl
  scenario-b/
    data/
    RECORD_GROUND_TRUTH.jsonl
```

```bash
python3 blind_test/record_level_claude_eval.py batch \
  --scenarios-root /absolute/path/to/generated-scenarios \
  --work-dir /tmp/evidenceforge-record-batch \
  --force \
  --model glm-5.2 \
  --timeout-seconds-per-stage 2400 \
  --confidence-threshold 0.50
```

The batch command is a sequential loop equivalent to:

```text
for each generated scenario:
    create a new scenario-only blind directory
    start a fresh discovery claude -p process against source logs only
    wait for discovery.json
    start a fresh expansion claude -p process with discovery.json + label-free index
    wait for predictions.json
    evaluate that scenario against its own private sidecar
after all scenarios:
    aggregate only the numeric evaluation results locally
```

It never combines logs, record indexes, prompts, or Claude conversation state
across scenarios. Every stage uses a unique explicit persistent `--session-id`
and a unique case directory. Persistence makes an interrupted stage resumable;
it does not share state with another scenario. The aggregate step does not call
Claude.

Useful controls:

```bash
# Only scenario directories matching one or more patterns
--scenario-glob 'apt-*' --scenario-glob 'operation-*'

# Small pilot before spending the full budget
--max-scenarios 1

# Continue an interrupted batch and reuse finished evaluation files
--resume

# Stop immediately on the first failed/refused/timed-out Claude invocation
--fail-fast
```

Budget limits are optional. If `--max-budget-usd-per-stage` (or the
single-scenario `--max-budget-usd`) is omitted, the runner does not pass a USD
limit to Claude. When configured, the limit is applied independently to the
discovery and expansion processes. For 10 scenarios at USD 5 per stage, the
configured maximum is therefore USD 100, not USD 50 total.

Batch outputs:

```text
<work-dir>/
  batch_summary.json
  batch_summary.md
  scenarios/
    <scenario-name>-<path-hash>/
      blind/
        data/
        RECORD_INDEX.jsonl
      results/
        discovery.json
        discovery_prompt.txt
        discovery_claude_run.json
        discovery_claude_stream.jsonl
        discovery_claude_stdout.txt
        discovery_claude_stderr.txt
        expansion_prompt.txt
        expansion_claude_run.json
        expansion_claude_stream.jsonl
        expansion_checkpoint.json
        expansion_claude_stdout.txt
        expansion_claude_stderr.txt
        predictions.json
        evaluation.json
        evaluation.md
        claude_run.json
        claude_stdout.txt
        claude_stderr.txt
        claude_sessions.json
```

`batch_summary.json` reports per-scenario status and metrics, micro record-level
Precision/Recall/F1 over all completed scenarios, and macro averages where each
scenario receives equal weight. Failed scenarios are reported but excluded
from numeric aggregation; `--resume`-reused evaluations remain included.

## One-command run

Run from the repository root. Keep the work directory outside the scenario;
the default is the system temporary directory.

```bash
python3 blind_test/record_level_claude_eval.py run \
  --scenario-dir /absolute/path/to/generated-scenario \
  --work-dir /tmp/evidenceforge-record-eval \
  --force \
  --model glm-5.2 \
  --timeout-seconds 2400 \
  --confidence-threshold 0.50
```

The scenario directory must contain:

```text
generated-scenario/
  data/
  RECORD_GROUND_TRUTH.jsonl
```

## Separate phases

Prepare a label-free workspace:

```bash
python3 blind_test/record_level_claude_eval.py prepare \
  --scenario-dir /absolute/path/to/generated-scenario \
  --work-dir /tmp/evidenceforge-record-eval \
  --force
```

Run both fresh `claude -p` stages without regenerating the workspace:

```bash
python3 blind_test/record_level_claude_eval.py predict \
  --work-dir /tmp/evidenceforge-record-eval \
  --model glm-5.2 \
  --timeout-seconds 2400
```

Resume only an interrupted expansion from its existing discovery and prompt:

```bash
python3 blind_test/record_level_claude_eval.py resume-expansion \
  --scenario-dir /absolute/path/to/generated-scenario \
  --work-dir /tmp/evidenceforge-record-eval \
  --output-dir /tmp/evidenceforge-record-eval-recovery \
  --model LongCat-2.0 \
  --schema-mode prompt \
  --timeout-seconds 1200 \
  --soft-deadline-seconds 600 \
  --max-predictions 500
```

This skips discovery and reuses `results/discovery.json` plus
`results/expansion_prompt.txt`. To continue the exact saved model context, add
`--resume-session-id <uuid>` using the expansion UUID recorded in
`claude_sessions.json`. Use a new `--output-dir` so the original failed-run
artifacts remain auditable.

Re-evaluate an existing prediction file without calling Claude:

```bash
python3 blind_test/record_level_claude_eval.py evaluate \
  --scenario-dir /absolute/path/to/generated-scenario \
  --work-dir /tmp/evidenceforge-record-eval \
  --predictions /tmp/evidenceforge-record-eval/results/predictions.json \
  --confidence-threshold 0.50
```

Optionally score evidence-scoped ATT&CK tactic claims at hidden Storyline level:

```bash
python3 blind_test/record_level_claude_eval.py evaluate \
  --scenario-dir /absolute/path/to/generated-scenario \
  --work-dir /tmp/evidenceforge-record-eval \
  --predictions /tmp/evidenceforge-record-eval/results/predictions.json \
  --confidence-threshold 0.50 \
  --evaluate-storyline-tactics \
  --storyline-tactic-labels /absolute/path/to/scenario.labels.json
```

The detector/agent does not submit or see the hidden Storyline ID. Optional
`storyline_tactic_predictions` reference an already submitted physical-record
prediction. Only after prediction does the evaluator resolve that evidence to
the private Storyline ID and score unique `(storyline_id, tactic)` pairs. Omit
the flag to preserve the original three evaluation levels.

## Blindness contract

The tool copies only `data/` into `<work-dir>/blind/`. It creates a sanitized
`RECORD_INDEX.jsonl` containing:

- `physical_record_id` and exact path/index/byte locators;
- source format and source instance;
- native source identifiers and observed time;
- source-derived correlation features.

It does not copy labels, storyline IDs, logical-event IDs, provenance kinds,
scenario YAML, `GROUND_TRUTH.*`, or the record-level Ground Truth sidecar. The
private sidecar path is not written into the work directory. Symlinked source
inputs are rejected.

Discovery runs with only `Read`, `Glob`, and `Grep`. Expansion also receives
`Write`, but the prompt restricts it to maintaining the single
`PREDICTIONS.checkpoint.json` file in the blind root. Bash, Edit, web access,
task delegation, and notebook tools remain explicitly denied. The prompt also
requires all reads and the checkpoint write to remain inside the isolated blind
directory. For strongest isolation, use the default `/tmp` location or another
dedicated temporary directory rather than a directory inside the source
repository.

This restriction protects blind-test isolation: a model cannot run arbitrary
commands that read the private sidecar, inspect parent directories, change
evidence, or use the network. It makes large JSON/XML datasets slower to
analyze than an unrestricted shell with `jq` or custom scripts. The prompt does
not impose a fixed tool-call cap; instead it directs Claude to search source
logs first and use distinctive native values to retrieve only candidate rows
from the label-free index.

The discovery process runs with `<work-dir>/blind/data/` as its current
directory, so it receives source logs but no record index. It outputs candidate
hosts, time ranges, process chains, IOCs, and evidence anchors to
`discovery.json`. The expansion process then runs from `<work-dir>/blind/`,
receives the discovery JSON in its prompt, and maps verified anchors to exact
physical records through `RECORD_INDEX.jsonl`. The configured timeout applies
independently to each stage; the default is 2,400 seconds (40 minutes).

Both stages are captured as `stream-json`, including tool activity and the
terminal usage/modelUsage event when Claude exits normally. Expansion is told
to write a small valid high-confidence checkpoint early and refresh it after
each anchor or small batch. Low recall is explicitly preferable to losing the
whole scenario. On timeout, API failure, or invalid final output, the evaluator
validates and adopts the latest legal checkpoint. `--soft-deadline-seconds`
sets the prompt's finalization target below the outer hard timeout.

## Prediction protocol

Claude returns only predicted malicious records. Unlisted records are treated
as benign. Every prediction contains:

```json
{
  "physical_record_id": "pr-...",
  "relative_path": "host/windows_event_sysmon.xml",
  "record_index": 42,
  "label": "malicious",
  "confidence": 0.91,
  "reason": "Concise record-local and cross-source evidence"
}
```

The evaluator requires all three locator fields to agree with the hidden
sidecar. Unknown IDs and locator mismatches count as false positives. Duplicate
IDs are reduced to the highest-confidence prediction.

The default maximum is 2,000 predictions. This is deliberately larger than a
typical scenario's malicious record count: exact record recall requires all
independently malicious physical records, including repeated beacons and
separate endpoint/network observations, rather than only a short incident
summary. Override it with `--max-predictions` when necessary.

## Metrics and score

Detector output matching is exact and one-to-one at physical-record level. The
private evaluator then aggregates valid physical predictions into three metric
levels:

- `physical_record_id`: exact atomic records;
- `logical_event_id`: canonical security events;
- `storyline_id`: attack/red-herring steps, plus one benign null-ID background
  group per scenario.

All three levels report TP, FP, FN, TN, accuracy, precision, recall, F1, and a
`100 * F1` score:

```text
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 * Precision * Recall / (Precision + Recall)
Score     = 100 * F1
```

The primary benchmark score remains physical-record F1. Logical-event and
storyline scores are secondary diagnostic scores calculated only after the
detector finishes, using the private sidecar. Background records with
`storyline_id=null` are collapsed into one benign storyline group per scenario:
no background prediction yields one TN, while one or more background
predictions yield one FP. Invalid physical references also remain FPs at both
higher levels so they cannot improve precision by avoiding ID attribution.

The report additionally includes specificity, balanced accuracy, per-source
metrics, per-storyline and per-logical-event record recall, red-herring false
positives, invalid references, locator mismatches, and bounded FP/FN details.

A baseline-only dataset with no malicious records and no predictions receives
100 points. Any prediction on that dataset is a false positive.

## Outputs

```text
<work-dir>/
  blind/
    data/
    RECORD_INDEX.jsonl
  results/
    prepare_manifest.json
    discovery_prompt.txt
    discovery_claude_stdout.txt
    discovery_claude_stderr.txt
    discovery_claude_run.json
    discovery_claude_stream.jsonl
    discovery.json
    expansion_prompt.txt
    expansion_claude_stdout.txt
    expansion_claude_stderr.txt
    expansion_claude_run.json
    expansion_claude_stream.jsonl
    expansion_checkpoint.json
    claude_sessions.json
    predictions.json
    evaluation.json
    evaluation.md
```

Claude may independently refuse a cybersecurity-classification request under
its service-side safeguards. The runner preserves stdout/stderr and reports the
refusal; it does not attempt to bypass provider policy. Choose an authorized
model/account configuration when this benchmark is within your approved use.
