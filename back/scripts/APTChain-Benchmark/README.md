# APTChain-Benchmark

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

> ## 项目声明 / Attribution
>
> 本项目基于开源项目 **[Cisco-Talos/EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge)** 进行二次开发和深度改造,
> 用于构建**多源异构日志 APT 攻击链关联发现基准数据集**。
>
> - **上游项目 (Upstream):** [Cisco-Talos/EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge)
> - **本仓库 fork 基于的上游 commit:** `7cbcc6a9` (Merge PR #346)
> - **License:** MIT (继承自上游)
>
> 在原项目基础上,本仓库新增/修改了以下能力(非完整列表):
> - APT 剧本高质量批量重生成流水线 (`scripts/regenerate_apt_scenarios.py`, `commands/eforge/regenerate-apt.md`)
> - 面向多源异构日志攻击链关联发现的赛题构建脚本 (`scripts/build_competition_docx.py`, `scripts/build_competition_labels.py`, `scripts/join_gt_to_logs.py`)
> - 数据质量评估文档与幻灯片输出 (`scripts/build_eval_pptx.py`, `docs/reference/data-quality-scoring-overview.md`)
> - 防守代理原型 (`defense_agent/`)
> - 场景模型、剧情引擎、活动流量配置的多项本地化调整
>
> 感谢 Cisco Talos 团队的原始工作。本仓库为**私有研究/竞赛用途**,如需生产用途请回到上游主线。

---

## Original Description (from upstream)

Generate realistic synthetic security logs for cybersecurity threat hunting training and research.

For background on the upstream project and why they built it, read Talos' announcement:
[Introducing EvidenceForge: synthetic security logs that don't look (as) fake](https://blog.talosintelligence.com/introducing-evidenceforge-synthetic-security-logs-that-dont-look-as-fake).

## What Makes EvidenceForge Different

Most synthetic log generators produce isolated, single-format data that experienced analysts identify as fake within seconds. EvidenceForge takes a fundamentally different approach:

- **Consistency by construction.** A canonical `SecurityEvent` model feeds all log formats from a single source of truth. Two emitters cannot disagree about a port number, timestamp, or LogonID because there is only one value — on the event object. This eliminates the cross-source inconsistencies that are the #1 tell of synthetic data.

- **Causal event ordering.** Events respect real-world dependencies — DNS queries precede connections, Kerberos TGT/TGS precede domain logons, audit events follow administrative commands. A composable rule engine auto-generates prerequisites with realistic timing offsets, so the data tells a coherent causal story across log sources.

- **Self-exciting temporal dynamics.** User activity follows a Hawkes process — events trigger bursts that taper off naturally, matching real human work patterns. System traffic uses periodic intervals with jitter. Day-of-week variation models Monday login storms, Friday early departures, and near-zero weekends. Most generators use uniform random timing that experienced analysts spot instantly.

- **20+ correlated log formats.** Windows Security (30 event IDs), Sysmon, 13 Zeek log types, eCAR EDR/XDR, syslog, bash history, Snort IDS, web access, and proxy logs — all from the same event pipeline.

- **Network visibility modeling.** Define sensor placement (SPAN/TAP), monitored segments, and direction. EvidenceForge determines which connections each sensor can see and only emits network logs where they'd realistically appear.

- **Deterministic engine, LLM-assisted authoring.** Scenario creation uses Claude Code Skills for interactive, research-backed attack planning. Log generation is fully deterministic — no LLM calls, no API costs, reproducible output every time.

- **Built-in quality evaluation.** A 4-pillar scoring framework (20 sub-scores) measures parseability, plausibility, causality, and timing. Know exactly how good your data is before using it.

## Quick Start

```bash
# Install
git clone https://github.com/Cisco-Talos/EvidenceForge.git
cd EvidenceForge
uv sync

# Install agent skills (Claude Code by default)
uv run eforge install-skills

# Or install Codex skills
uv run eforge install-skills --agent codex

# Create a scenario interactively
# /eforge scenario

# Or generate from an existing scenario
uv run eforge generate scenarios/branch-office-example/scenario.yaml -o ./output

# Validate a scenario file
uv run eforge validate scenarios/branch-office-example/scenario.yaml

# Evaluate generated data quality
uv run eforge eval ./output/data --scenario scenarios/branch-office-example/scenario.yaml
```

## 从威胁报告生成数据集

本分支支持把格式不固定的威胁报告转换为 EvidenceForge 原生数据集。当前输入仅支持
`.txt` 和具有可复制文字层的 `.pdf`；扫描版 PDF 暂不支持 OCR。

生成链路不再让模型直接编写最终场景，而是分成三个职责独立的 MiniMax 阶段：A 只抽取带来源片段的事实、
B 只审核遗漏和错绑、C 只填写确定性编译器明确申请的内部仿真字段。每个阶段都使用独立 JSON Schema，
并且在首次响应无效时最多定向修复一次。进程、URI、HTTP 方法、注册表读写和日志通道由本地编译器决定，
模型不能越过事实关系擅自复用。

先安装依赖：

```bash
uv sync
```

MiniMax 凭据推荐通过环境变量设置：

```bash
export MINIMAX_API_KEY="你的 API Key"
export MINIMAX_BASE_URL="https://api.minimaxi.com/anthropic"
```

也可以使用凭据文件。文件可采用本项目 `1.txt` 的两行格式：第一行是官方 API 基地址，第二行是
API Key。凭据文件不会复制到输出目录，也不应提交到 Git。

生成示例：

```bash
uv run python scripts/generate_from_report.py \
  "/path/to/report.pdf" \
  --output "/path/to/result" \
  --api-key-file "/path/to/1.txt"
```

程序会显示八个处理阶段。单分块报告正常调用 MiniMax 三次（A/B/C）；长报告只增加 A 的分块调用。成功后，
输出目录固定包含原项目标准产物：`data/`、
`GROUND_TRUTH.md`、`GROUND_TRUTH.json`、`GOLD_Label.json`、
`RECORD_GROUND_TRUTH.jsonl`，并额外保留可复现的 `scenario.yaml` 和脱敏质量摘要
`REPORT_FIDELITY.json`。当场景使用非完整观测配置时，
原项目还会生成 `OBSERVATION_MANIFEST.json`；当输出目标不是 `default` 时，会生成
`OUTPUT_TARGET.txt`。报告抽取原文、模型原始响应和中间结构化 JSON 都只在临时目录中使用，
不会作为最终产物交付。

报告生成的事件使用 `GROUND_TRUTH.json` schema v2 保留事实编号、PDF 页码或 TXT 段落、
字段级来源与预期日志可见性。`GROUND_TRUTH.md` 会在“来源与仿真说明”中明确区分
原报告事实、AI 补全字段和引擎生成属性，并在“原始报告保留信息”中列出报告 IOC 以及仅能保留在
Ground Truth 中的事实，不会将补全内容冒充为原文。

发布前后各有一道确定性质量门：精确来源引用、AI/引擎字段标记和报告 IOC 保留必须达到 100%，
可物化来源行为覆盖率不得低于 90%，综合分不得低于 85 分。生成首先在目标目录同级的唯一临时目录进行；
只有生成后的 Ground Truth、记录级标签和来源 ID 链全部通过时才原子发布。即使使用 `--force`，质量失败也不会覆盖
旧输出。

输出目录默认必须不存在或为空。确认需要覆盖已有生成结果时，显式增加 `--force`。其他可选参数：

```bash
uv run python scripts/generate_from_report.py --help
```

生成后可以在不调用 MiniMax 的情况下重新检查已发布产物的来源链、事实—事件 ID 和记录级标签：

```bash
uv run python scripts/evaluate_report_fidelity.py "/path/to/result"
uv run python scripts/evaluate_report_fidelity.py "/path/to/result" --json
```

离线重评不会重新解读原报告；它用于发现已发布的 Ground Truth、来源元数据或记录级标签后续被删改。

## Agent Skills (Recommended)

EvidenceForge includes agent skills for interactive, guided workflows. These are the preferred way to use EvidenceForge.

| Skill | Description |
|-------|-------------|
| `/eforge scenario` | Guided scenario creation through a structured interview. Researches TTPs via MITRE ATT&CK, builds environment/network/personas, outputs validated YAML + student context document. |
| `/eforge generate` | Validates the scenario, runs the generation engine, monitors output, and diagnoses errors. |
| `/eforge validate` | Checks a scenario for schema correctness and cross-reference integrity. Fixes simple issues, escalates structural problems. |
| `/eforge evaluate` | Runs the data quality evaluation, interprets scores, reviews records for realism, and suggests improvements. |
| `/eforge config` | Add, modify, or remove personas, domains, applications, and other configuration data. Handles cross-file dependencies automatically. See [Customizing Configuration](docs/reference/CUSTOMIZING_CONFIG.md). |

Install Claude Code skills with `uv run eforge install-skills` (project scope) or `uv run eforge install-skills --global`. Install Codex skills with `uv run eforge install-skills --agent codex`.

## CLI Reference

For scripted or non-interactive use:

| Command | Description |
|---------|-------------|
| `eforge generate <scenario.yaml> -o <dir>` | Generate logs from a scenario file |
| `eforge validate <scenario.yaml>` | Validate scenario schema and cross-references |
| `eforge eval <output_dir> -s <scenario.yaml>` | Evaluate data quality (4 pillars, 20 sub-scores) |
| `eforge info [field]` | Show installation info, config paths, and data inventories. Pass a dot-path field for a specific value (e.g., `eforge info personas`). Use `--fields` to list available fields, `--json` for machine output. |
| `eforge validate-config` | Validate config files for cross-reference integrity. Use `--json` for machine output. |
| `eforge install-skills [--agent claude\|codex] [--global]` | Install agent skills (`--global` is Claude-only) |
| `eforge version` | Show version |

Useful command flags: `generate` accepts `--verbose` / `--debug` for logging,
`--output` / `-o` for output directory overrides, `--force` / `-f` to overwrite
existing output without prompting, and `--target default|sof-elk|splunk` to choose the
generated file layout. The `default` target is SIEM-neutral; `sof-elk` emits
target-specific variants such as Snare Windows events and year-partitioned
RFC3164 syslog for parser validation, and `splunk` emits Splunk-friendly
Windows XML event streams. `eval` uses `--scenario` / `-s` and
`--format text|json`; `info` and `validate-config` support `--json` for machine
output.

All commands accept `--help` and `-h` for usage information.

## Customizing Configuration

EvidenceForge ships with 50+ YAML config files controlling DNS domains, applications, personas, traffic profiles, and more. You can customize these using a project-local overlay at `.eforge/config/` — your changes survive package upgrades and merge automatically with built-in defaults.

The recommended approach is the Claude Code skill:

```
/eforge config add a nurse persona for a healthcare scenario
```

For details on the overlay system, manual editing, and cross-file dependencies, see **[Customizing Configuration](docs/reference/CUSTOMIZING_CONFIG.md)**.

## What It Does

EvidenceForge creates multi-format security log datasets from YAML scenario definitions. You describe an environment (users, systems, network topology) and a storyline (attack events), and EvidenceForge generates temporally consistent logs across all formats simultaneously — complete with cross-referenced LogonIDs, PIDs, timestamps, and UIDs.

Every generated scenario includes a `GROUND_TRUTH.md` file, an instructor-only `RECORD_GROUND_TRUTH.jsonl` sidecar, and a compact `GOLD_Label.json` answer key. Attack scenarios document exactly what happened, when, and where; the sidecars map final physical records to stable provenance, ATT&CK v18.1 tactic IDs, and ordered storyline steps without changing source-native logs. Baseline-only scenarios explicitly document that no malicious events were generated.

### Key Capabilities

- **Cross-log consistency** — Shared LogonIDs, PIDs, timestamps, and Zeek UIDs across all formats
- **Causal expansion engine** — Auto-generates prerequisite events (DNS, Kerberos, audit events) with composable rules
- **Realistic baseline noise** — 26 lateral movement patterns, process→network correlation, network-level red herrings, and 18 Linux syslog categories create noise that analysts must work through
- **OS-aware generation** — Windows systems produce Windows Event + Sysmon logs; Linux systems produce syslog + bash history
- **Network visibility modeling** — Define sensor placement (SPAN/TAP), direction, and monitored segments
- **Record-level ground truth** — Every run generates semantic ground truth plus `RECORD_GROUND_TRUTH.jsonl` with stable physical IDs, byte locators, correlation features, labels, and detectability classes
- **Compact GOLD labels** — `GOLD_Label.json` groups malicious physical IDs by ATT&CK tactic number and ordered `S1...Sn` storyline steps while keeping locators in the existing record index
- **Participant-safe ATT&CK catalog** — [`ATTACK_TACTICS_v18.1.json`](docs/reference/ATTACK_TACTICS_v18.1.json) publishes the allowed public Tactic ID/name mapping without dataset labels or scoring answers
- **Three-part v2 scorer** — [`score_predictions_v2.py`](blind_test/score_predictions_v2.py) scores participant TA evidence, physical-ID F1, and attack-step coverage with configurable ratios; the [`predict.json` v2 contract](docs/reference/PREDICT_V2_SCORING_CONTRACT.md) documents the exact formulas
- **Parallel generation** — Threaded emitters write all formats simultaneously with temporal consistency
- **Scenario validation** — Cross-reference checking, uniqueness constraints, and network topology validation
- **Data quality evaluation** — 4-pillar scoring framework (20 sub-scores) with acceptance criteria
- **Multi-timezone support** — Pattern-based timezone overrides per system hostname

## Supported Log Formats

| Format | Category | Description |
|--------|----------|-------------|
| Windows Security Events | Host | 30 event IDs: authentication (4624/4625/4634/4648/4672), process (4688/4689), Kerberos (4768/4769/4770/4771/4776), persistence (4697/4698-4701), account mgmt (4720/4723/4724/4726/4738), group membership (4728/4729/4732/4733/4756/4757), firewall (5156), defense evasion (1102) |
| Windows Sysmon | Host | Process create (Event 1), terminate (Event 5), remote thread injection (Event 8), process access (Event 10) |
| Zeek (13 log types) | Network | conn, dns, http, ssl, files, x509, dhcp, ntp, weird, pe, ocsp, packet_filter, reporter |
| eCAR | Host | EDR/XDR telemetry in MITRE CAR-based format (PROCESS, FILE, FLOW, REGISTRY, MODULE, THREAD, USER_SESSION, SERVICE) |
| Syslog | Host | Linux authentication and system logs (BSD format) |
| Bash History | Host | Per-user timestamped command history |
| Snort Alert | Network | IDS alert format (fast alert) |
| Web Access | Network | Apache/Nginx combined log format |
| HTTP Proxy | Host | Forward proxy access log (W3C Extended format, CONNECT entries, cache status, proxy action hints) |

See [Evidence Formats Reference](docs/reference/EVIDENCE_FORMATS.md) for detailed field documentation, output paths, and known limitations. The ID formulas and stability contract are documented in [Record Identity and ID Generation](docs/reference/RECORD_IDENTITY_AND_ID_GENERATION.md).

## Scenario Structure

Scenarios are YAML files describing an environment, personas, time window, and optional attack storyline:

```yaml
version: "1.0"
name: my-scenario
description: "Description of the scenario"

environment:
  description: "Corporate office network"
  timezone:
    default: "America/New_York"
  users: [...]
  systems: [...]
  network:             # Optional: segments and sensors
    segments: [...]
    sensors: [...]

personas: [...]        # User behavior patterns

time_window:
  start: "2024-01-15T08:00:00Z"
  duration: "8h"

baseline_activity:
  description: "Normal office activity"
  intensity: medium
  variation: low

storyline:             # Optional: attack events
  - time: "+2h"
    actor: attacker
    system: TARGET-01
    activity: "Lateral movement via pass-the-hash"
    events:
      - type: process
        process_name: "C:\\Windows\\System32\\cmd.exe"
        command_line: "cmd.exe /c whoami"

output:
  logs: [{format: windows_event_security}, {format: zeek}]
  destination: ./output
```

See [Scenario Reference](docs/reference/scenario-reference.md) for complete schema documentation.

## Example Scenarios

| Scenario | Users | Duration | Description |
|----------|-------|----------|-------------|
| [branch-office-example](scenarios/branch-office-example/scenario.yaml) | 5 | 6 hours | Beginner branch office scenario with Windows, Zeek, eCAR, syslog, bash history, Snort, ASA, web, and proxy logs |
| [minimal.yaml](tests/fixtures/scenarios/minimal.yaml) | 1 | 1 hour | Minimal baseline-only scenario |
| [attack.yaml](tests/fixtures/scenarios/attack.yaml) | 2 | 4 hours | Lateral movement + exfiltration |
| [retail-store-ftp-attack.yaml](tests/fixtures/scenarios/retail-store-ftp-attack.yaml) | 20+ | 24 hours | Retail store with FTP RCE attack, full network topology |

## Data Quality Evaluation

EvidenceForge includes a built-in evaluation framework that scores generated data across 4 pillars:

| Pillar | Weight | What it measures |
|--------|--------|-----------------|
| Parseability | 30% | Spec conformance, format constraints |
| Plausibility | 25% | Value/OS correctness, co-occurrence, distributions, user diversity, anomaly rate |
| Causality | 25% | Causal ordering, event presence, indicator accuracy, pivot linkability |
| Timing | 20% | Attack-chain timing, burstiness, diurnal patterns, volume adequacy |

**Two-tier acceptance**: hard gates (minimum, must pass) + aspirational targets (stretch goals, informational). Hard gates: Spec Conformance ≥ 95%, Value Plausibility ≥ 95%, Causal Ordering ≥ 90%, Event Presence ≥ 85%. Thresholds are configurable in `src/evidenceforge/config/evaluation/thresholds.yaml`.

```bash
uv run eforge eval ./output -s scenario.yaml
```

## Architecture

```
Scenario YAML
    |
    v
Validation (Pydantic schema + cross-reference checks)
    |
    v
GenerationEngine (hour-by-hour orchestration)
    |
    v
WorldModel / WorldPlanner (compile host roles, user placement, session bootstrap)
    |
    v
ActivityGenerator (builds SecurityEvents with composable contexts)
    |
    v
EventDispatcher (routes to StateManager + matching emitters)
    |
    +---> WindowsEventEmitter ---> default XML / sof-elk Snare / splunk XML stream
    +---> SysmonEmitter ---------> default XML / sof-elk Snare / splunk XML stream
    +---> ZeekEmitter(s) --------> sensor/conn,dns,http,ssl,... (NDJSON)
    +---> EcarEmitter -----------> ecar.json (NDJSON)
    +---> SyslogEmitter ---------> default+splunk RFC5424 / sof-elk RFC3164 year layout
    +---> BashHistoryEmitter ----> per-user bash history
    +---> SnortEmitter ----------> snort_alert.log
    +---> CiscoAsaEmitter -------> default+splunk flat / sof-elk year layout
    +---> WebEmitter ------------> web_access.log
    +---> ProxyEmitter ----------> proxy_access.log
```

Generation records the selected output target in `OUTPUT_TARGET.txt` and
emitters apply it only where file shape differs.

`WorldModel` compiles authoritative host and user capabilities from scenario fields like `primary_system`, `roles`, `services`, and workstation assignments. `WorldPlanner` then chooses realistic interactive, network, SSH, and RDP session paths before `ActivityGenerator` emits the correlated evidence.

See [Architecture Documentation](docs/ARCHITECTURE.md) for the full deep dive including the world-model layer, SecurityEvent model, state management, and emitter system.

## Development

```bash
# Install dependencies and development tools
uv sync --all-extras

# Run tests without coverage instrumentation (skips slow by default)
uv run pytest --no-cov

# Run slow comprehensive workload tests without coverage instrumentation
uv run pytest --include-slow -m slow --no-cov --durations=20

# Run optional third-party parser validation tests.
# Requires Docker Compose v2 or Podman Compose.
uv run pytest --include-external-parsers -m external_parser --no-cov

# Run the release coverage gate before a dev -> main PR
uv run pytest --cov=evidenceforge --cov-report=term-missing --cov-report=xml --cov-fail-under=70

# Do not combine slow tests with coverage during release validation.
# Slow tests are run with --no-cov; coverage is measured on the default non-slow suite.

# Run specific test suite
uv run pytest tests/unit/test_network_visibility.py -v

# Lint and format
uv run ruff check .
uv run ruff format --check .
```

See [External Parser Validation](docs/external-parser-validation/README.md)
for the third-party parser validation quickstart, external-parser harness architecture,
full-dataset runner command, and failure report details.

### Tech Stack

- Python 3.11+ with [uv](https://docs.astral.sh/uv/)
- Pydantic v2 for schema validation
- Jinja2 for log format templates
- Typer + Rich for CLI
- pytest (3700+ tests)

## Documentation

- [Scenario Reference](docs/reference/scenario-reference.md) — Complete YAML schema documentation
- [Evidence Formats Reference](docs/reference/EVIDENCE_FORMATS.md) — All log types, field details, known limitations
- [Record Identity and ID Generation](docs/reference/RECORD_IDENTITY_AND_ID_GENERATION.md) — Ground Truth ID formulas, stability boundaries, and evaluation keys
- [Architecture](docs/ARCHITECTURE.md) — How the generation engine works
- [Contributing](CONTRIBUTING.md) — How to contribute to EvidenceForge
- [AGENTS.md](AGENTS.md) — Coding conventions for AI agents

### Design Documents

- [PRD](docs/design/PRD.md) — Product requirements and specifications
- [Event Model Design](docs/design/event-model-prd.md) — Canonical SecurityEvent architecture
- [Data Quality Design](docs/design/data-quality-prd.md) — Evaluation framework design
- [Research Report](docs/design/synthetic-log-generation-research.md) — Analysis of existing tools

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on reporting issues, sending pull requests, and setting up a development environment.

## Acknowledgements

SOF-ELK® is a registered trademark of Lewes Technology Consulting, LLC. Used with permission.

## License

[MIT License](LICENSE) - Copyright (c) 2026 Cisco Systems, Inc.
