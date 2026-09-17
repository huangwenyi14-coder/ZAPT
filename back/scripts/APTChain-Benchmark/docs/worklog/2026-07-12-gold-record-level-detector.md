# 2026-07-12 Gold Record-Level Detector

## Goal

Copy the source-informed finding detector into `gold/`, preserve its legacy
interface, add label-free physical-record expansion, and evaluate it against the
generated `operation-dragon-whistle-record-eval` scenario.

## Source baseline

- Source: `/Users/xhb/Desktop/Project/TASK/2026TASK/供应链安全检测/Mythos/Tools/EvidenceForge-main/blind_test/detectors/source_informed_chain_detector.py`
- Source SHA-256 at copy time:
  `9d628747858e89776dfd8b86813953b7d1bf114f1238bab2293e0d3ef2a3000a`
- Destination: `gold/source_informed_chain_detector.py`
- Final destination SHA-256:
  `a909785cec0935e903289f8c410a872348477e97022d4dea4f384093957c8ee1`

## Changes

- Added `--data-dir`, `--record-index`, and `--findings-output` record mode.
- Added strict rejection of private label fields in the record index.
- Added exact finding-evidence mapping and Beacon-first C2 expansion.
- Added immutable process seeds based on PID, ProcessGuid, ECAR objectID, and actorID.
- Explicitly excluded LogonId and parent PID from process identity expansion.
- Added C2 IP/domain/SNI, DNS, Sysmon Event 22, Security Event 5156, and ASA NAT
  companion correlation.
- Added exact 4624/4698 identity and persistence companions.
- Added unit tests and `gold/README.md` with reproduction commands.

The first expansion attempt achieved TP=491, FP=386, FN=2. The false positives
were caused by transitive expansion through shared LogonId and parent process
identities. Replacing that logic with one-pass, same-host, immutable process
seeds reduced the result to TP=491, FP=3, FN=2. Explicit event-family filtering
removed the three unrelated `taskhostw.exe` records, while exact DNS-tick
correlation recovered the final two Sysmon Event 22 companions.

## Hardening follow-up

The initial copied detector retained `parents[2]` from its old
`blind_test/detectors/` location. From `gold/`, this resolved one directory above
the repository and silently disabled all baseline catalogs. The detector now
discovers the checkout root by the `src/evidenceforge` and `pyproject.toml`
markers; the live catalog counts changed from all zero to 190 baseline domains,
341 baseline IPs, 73 application executables, and 215 system executables.

Additional corrections:

- IPv4/IPv6 literals remain exact while FQDNs receive full and short aliases.
- PID and stable process identities are scoped by host.
- ECAR actorID, PROCESS objectID, and non-process objectID roles are separate.
- Windows 4688 creator `ProcessId` and `NewProcessId` roles are separate.
- Record expansion no longer requires a periodic Beacon.
- IOC matching uses named structured fields rather than flattened substrings.
- DNS uses host/client, port, domain/reverse-PTR, and Zeek UID relationships.
- ASA NAT records require the expected adjacent 302013/302014 native pair.
- XML finding lines map directly to physical record indexes.
- Time-only companions remain auditable at confidence 0.35 rather than counting
  as strong default predictions.
- Blind-index validation is recursive and verifies uniqueness, path containment,
  byte ranges, contiguous indexes, and record hashes against `data/`.

## Final strict evaluation

- Records: 39,020
- Raw candidates: 493
- Selected at confidence 0.50: 461
- TP: 461
- FP: 0
- FN: 32
- TN: 38,527
- Accuracy: 0.9991799077396207
- Precision: 1.0
- Recall: 0.9350912778904665
- F1: 0.9664570230607966
- Storyline recall: 9/9
- Logical-event recall: 143/172
- Invalid physical IDs or locator mismatches: 0

The 32 sub-threshold candidates are 29 DC Security 5156 records, one Sysmon
Event 22, one Zeek DNS record, and its same-UID Zeek conn record. They are
records that the current physical fields support only through time proximity.
At the explicit audit-inclusive threshold of 0.30, all 493 candidates are
selected and TP=493, FP=0, FN=0, with Accuracy/Precision/Recall/F1 all equal to
1.0. The 0.50 strict result remains the default reported metric.

The Ground Truth sidecar was used only by the evaluator after prediction. This
is a scenario-informed golden ceiling, not evidence that the detector will score
100% on unseen scenarios.

## Artifacts

- `gold/source_informed_chain_detector.py`
- `gold/README.md`
- `tests/unit/test_gold_source_informed_chain_detector.py`
- `gold/operation-dragon-whistle-record-eval/findings.json`
- `gold/operation-dragon-whistle-record-eval/predictions.json`
- `gold/operation-dragon-whistle-record-eval/results/evaluation.json`
- `gold/operation-dragon-whistle-record-eval/results/evaluation.md`
- `gold/operation-dragon-whistle-record-eval/audit-inclusive/results/evaluation.json`
- `gold/operation-dragon-whistle-record-eval/audit-inclusive/results/evaluation.md`
