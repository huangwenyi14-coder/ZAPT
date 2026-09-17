---
name: eforge-regenerate-apt
license: Copyright (c) 2026 Cisco Systems and its affiliates; SPDX-License-Identifier: MIT
description: >
  Batch-convert APT-report JSON scripts to high-quality EvidenceForge scenario YAML
  + GROUND_TRUTH.md. Use this skill whenever the user provides a JSON file derived
  from a threat-intel APT report and asks for it to be turned into an EvidenceForge
  scenario, or wants to regenerate an existing scenario with higher quality. The
  skill encodes a kill-chain phase reorder, realistic-name substitution, C2 server
  node injection, ATT&CK ID validation, and real parameter extraction (MD5, SHA256,
  URLs, command lines, scheduled-task names). The full SOP lives in
  docs/worklog/2026-07-06-apt-scenario-rebuild.md and the implementation in
  scripts/regenerate_apt_scenarios.py.
---

# EvidenceForge APT-Report Regenerator

You are helping the user convert APT-report JSON scripts into high-quality
EvidenceForge scenario YAML files. The legacy `scripts/convert_apt_json.py`
produces scenarios with broken kill-chain order, generic actor names, missing C2
endpoints, and dropped real parameters — this skill uses
`scripts/regenerate_apt_scenarios.py` to fix all of that.

## When to Use

- User provides an APT-report-derived JSON file and asks for an EvidenceForge scenario
- User wants to regenerate an existing APT scenario with higher quality
- User asks to batch-convert a directory of JSON files into scenarios
- User invokes `/eforge regenerate-apt` with file paths or directory paths as args

## Source JSON Layout

Each JSON has:
- `meta`: `{ report_name, APT group, target country, target industry,
  malware_families, vulnerabilities, references, description }`
- `scene_nodes`: list of `{ id, name, os, role }` (typically 3 fixed entries —
  id 142 = linux attacker, id 145 = Windows victim, id 143 = Linux victim)
- `steps`: list of `{ step_id, order, name, action_type, scene_tag, src, end,
  os, description, notes, params: { attack_mapping, iocs, email, process,
  command, network, files, persistence, registry, evidence } }`

Common source directory: `/Users/sunpeishuai/2026/saixun/API模版示例/0剧本列表/`
(417+ JSON files across `10篇/`, `20篇/`, `AcidBox/`, `APT1/`, etc.).

## Quick Start

```bash
# Single file → scenarios-v2/<slug>/
uv run python scripts/regenerate_apt_scenarios.py /path/to/report.json --out scenarios-v2

# Batch over a directory (use find + xargs for hundreds of files)
find /Users/sunpeishuai/2026/saixun/API模版示例/0剧本列表/10篇 -name "*.json" \
  -exec uv run python scripts/regenerate_apt_scenarios.py {} --out scenarios-v2 \;

# Validate every output
for f in scenarios-v2/*/scenario.yaml; do
  uv run eforge validate "$f"
done
```

## Quality Rules Encoded in the Script

1. **Kill-chain phase reorder**: steps are reordered by MITRE ATT&CK tactic so
   prerequisites precede their effects
   (`recon → initial_access → execution → defense_evasion → discovery →
   persistence → c2_setup → c2_communication → collection → exfiltration → cleanup`).
   `ioc_summary` and other meta-only steps are skipped.
2. **Actor/system resolution**: phishing steps run on `ATK-LNX-01` with the
   attacker's real name; execution steps run on `WS-VICTIM-01` with the
   victim's real name; C2 traffic carries `→ C2-SERVER-01` in the activity
   field. `end: 0` is never produced.
3. **Realistic name substitution**: actor names come from
   `NAMES_BY_REGION` pools aligned with the target country (CN/IN/RU/JP/GLOBAL).
   No `attacker` / `victim.user`.
4. **ATT&CK ID validation**: TCP beacons cannot use `T1071.001`; Mobile-only IDs
   are dropped from desktop scenarios; protocol/technique mismatches are corrected.
5. **Process image path extraction**: pulls real paths from
   `params.process.target_process` and `params.files[].file_path`, falls back to
   the `INTERPRETER_TO_PROCESS_WIN` dictionary, never defaults to `powershell.exe`
   for a step whose target is a different binary.
6. **Real parameter extraction**: MD5/SHA256 from `params.files`, URLs from
   `params.network` and `params.iocs.urls`, scheduled-task names from `/tn`
   inside `params.command.command_line`, registry paths from `params.registry`
   are all pushed into typed event fields.
7. **C2 server node injection**: when C2 domains exist that are not modeled by
   the source's three scene_nodes, a `C2-SERVER-01` (10.10.99.99, ssh+https,
   `c2_infra` role) is added and registered as a Zeek monitoring segment.
8. **Network identity IP dedup**: avoids the validator "shared IP across
   identities" warning that fires when multiple C2 domains share one IP.
9. **Time distribution**: 6-minute cadence for the first hour, 30-minute cadence
   thereafter — closer to real attacker pacing than the legacy script's
   fixed `60//total` formula.
10. **Engine schema compliance**: every emitted event validates against
    `docs/reference/scenario-reference.md`; `dns_query` always carries an
    `answer`; `process` events never use deprecated keys.

## Standard Workflow for New Reports

```bash
# 1. Generate
uv run python scripts/regenerate_apt_scenarios.py <input.json> --out scenarios-v3

# 2. Validate
uv run eforge validate scenarios-v3/<slug>/scenario.yaml

# 3. Self-check
grep -L "actor: attacker" scenarios-v3/<slug>/scenario.yaml   # should print the file
grep -L "end: 0" scenarios-v3/<slug>/scenario.yaml             # should print the file

# 4. Sample generate to confirm Zeek/Security/Sysmon carry the right evidence
uv run eforge generate scenarios-v3/<slug>/scenario.yaml \
  --output /tmp/test-new --duration 1h

# 5. Promote
mv scenarios-v3/<slug> scenarios/<slug>
```

## When the Script Needs Human Review

The script handles ~80% of APT-report shapes automatically. Things that still
need manual review:

- **Multi-branch / multi-version chains** (SideWinder 3-sample parallel,
  透明部落 V1/V2/V3): script merges into one timeline; for strict parallel
  branches, split manually or use `red_herrings` after generation.
- **Report-redacted fields** (`hxxp://*****.com`, blank sender/subject):
  script preserves the placeholder; fill in from secondary intel if available.
- **Out-of-catalog process paths** (custom malware sample paths): script
  pushes them through, but validator may warn "differs from configured
  canonical path". Add an `application_catalog/system_processes` overlay if
  the warning needs to be silenced at scale.
- **Mobile-only reports**: `actor: victim.lnx` on `LNX-VICTIM-01` is a
  workaround for the existing three-node template; for true mobile scenarios,
  add an Android scene_node manually.

## References

- Implementation: `scripts/regenerate_apt_scenarios.py`
- Detailed SOP + 10-rule reference: `docs/worklog/2026-07-06-apt-scenario-rebuild.md`
- Scenario schema: `docs/reference/scenario-reference.md`
- Event type reference: `commands/eforge/references/scenario-reference.md`
- Legacy script (now DEPRECATED): `scripts/convert_apt_json.py`