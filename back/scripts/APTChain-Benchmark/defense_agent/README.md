# defense_agent — EvidenceForge threat-detection harness

`defense_agent/` consumes the `output/<scenario>/data/` tree produced by
EvidenceForge's deterministic generator and answers two questions:

1. **Task A — Log-level:** *For each individual log line, is it part of the attack?*
   Report per-log-line precision / recall / F1 against `GROUND_TRUTH.json`.
2. **Task B — Storyline-level:** *Did we reconstruct the attack chain?*
   Report per-storyline coverage, detection rate, and ordering fidelity.

The detection pipeline is built **independently of the ground truth** —
no GT field is ever inspected during detection; the evaluation module only
reads GT for post-hoc alignment.

## Quick start

Run on one scenario:

```bash
uv run python defense_agent/scripts/run_detect.py 2018-09-20-apt-c-01
```

Run on every scenario:

```bash
uv run python defense_agent/scripts/run_all.py
```

Reports land in `defense_agent/reports/`:
- `<scenario>/summary.md` — per-scenario human-readable report
- `<scenario>/log_level_metrics.json` — log-level P/R/F1 + per-kind breakdown
- `<scenario>/pr_curve.json` — precision/recall at 8 score thresholds
- `<scenario>/storyline_level_metrics.json` — per-storyline coverage + order score
- `<scenario>/cross_summary.json` — beacons / lateral-movement / cred-dumping chains
- `<scenario>/detections.jsonl` — every CanonicalEvent with verdict + reasons
- `global/report.md` — aggregated table across all 14 scenarios
- `global/all_scenarios.csv` / `all_scenarios.json` — machine-readable summary

## Architecture

```
parsers/         →  CanonicalEvent  →  detectors/  →  detections.jsonl
                                          ↓
                                       evaluation/  →  reports/
```

- `parsers/` (no GT) — Windows Security XML, Sysmon XML, eCAR JSONL,
  Zeek conn/dns/http/files/ssl/x509/dhcp/ntp/ocsp/pe JSONL, syslog RFC-3164.
- `detectors/rules/` — process-name & command-line IOC patterns,
  network heuristics (beaconing, DGA, dynamic DNS, external destinations,
  asymmetric uploads), authentication heuristics (LSASS access, audit-log
  clearing, scheduled-task creation, lateral movement). No ground truth is
  read here.
- `detectors/agent/` (optional) — LLM-based correlator. Reads clusters of
  suspicious detections and (if `ANTHROPIC_API_KEY` is set) asks Claude for
  a hypothesis + severity + MITRE technique. Falls back to no-op without API.
- `evaluation/align.py` — only here do we read GT. Aligns each GT event to
  matching detection rows using `pid`/`uid`/`dst_ip:dst_port`/`query`/`logon_id`
  within ±2-5 s time windows.
- `evaluation/log_level.py` — Task A metrics.
- `evaluation/storyline_level.py` — Task B metrics.
- `evaluation/report.py` — JSON / Markdown / CSV writers.

## Output interpretation

For each scenario the report prints:

```
parse 0.1s detect 0.2s eval 0.2s
  log-level (t=0.2): TP=6 FP=189 FN=9  P=0.031 R=0.400 F1=0.057
  storyline: 6/15 coverage=0.40 order=0.40
```

- **TP/FP/FN** — TP: GT events with matching detection ≥threshold. FP: in-scope
  detections ≥threshold with no matching GT event. FN: observable GT events
  with no matching detection.
- **Precision** = TP/(TP+FP) — of all alerts, how many were real attacks.
- **Recall** = TP/(TP+FN) — of all observable attack events, how many we caught.
- **F1** = harmonic mean.
- **Storyline coverage** — fraction of GT storyline steps that had ≥1 matched event.
- **Order score** — LCS ratio of detected storyline order vs GT storyline index.

The PR curve shows the precision/recall trade-off at 8 different score thresholds
so you can pick the operating point that fits your use case.

## Cross-event signals (separate from per-event scores)

- **Beacons**: any (src_ip, dst_ip, dst_port) bucket with ≥5 attempts and
  inter-arrival CV < 0.4.
- **Lateral movement**: a single user authenticating to ≥3 distinct hosts
  in a 30-minute window.
- **Credential dumping chains**: Sysmon Event 10 access to lsass.exe followed
  within 1h by Event 4648 explicit credential use.

## Design notes & caveats

- The detector is intentionally **rule-only by default**. It targets
  documented MITRE ATT&CK technique families and common DFIR signals, NOT
  scenario-specific paths or IPs from the ground truth.
- Some scenarios (retail-store-ftp-attack, 2022-07-20-apt-q-39-sidewinder)
  have GT events whose referenced hosts are either missing from the
  `data/` tree or whose PIDs do not appear in the visible log window.
  These score 0% — that's a data issue, not a detector failure. Reports
  list them in the per-scenario summary.
- LLM-correlator is gated by `ANTHROPIC_API_KEY`. Without the key the
  pipeline runs end-to-end on rules alone (default). Set the key and
  rerun `run_all.py` to add chapter-level reasoning on top of rule output.