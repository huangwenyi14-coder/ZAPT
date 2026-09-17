# TestandValid 源码合并记录（2026-07-15）

## 目标与边界

将下列工作目录中与 Record-level Ground Truth、生命周期标签继承、
Claude record-level 评测和黄金检测器有关的源码改动，适配式合并到
APTChain-Benchmark：

- 源目录：`/Users/xhb/Desktop/Project/TASK/2026TASK/供应链安全检测/Mythos/Tools/TestandValid/EvidenceForge-main`
- 目标目录：`/Users/xhb/Documents/数字逸境/VERSION/APTChain-Benchmark`
- 目标分支：`codex/merge-record-level-ground-truth`
- 目标基线：`1e7e274a07942e6853d8e7e0f03b503425bfc2a1`
- 源版本标识：`EvidenceForge 1.11.1`（源目录不是可用的 Git 工作树）
- 目标原始版本：`EvidenceForge 1.9.0` + APTChain-Benchmark 定制提交
- 合并后版本：`EvidenceForge 1.11.1` + APTChain-Benchmark + Record-level 扩展
- 官方上游源码导入节点：`a4368801`（来源为官方 tag `v1.11.1`）

本次不复制生成数据、场景输出、预测结果、运行会话、缓存或系统元数据。
目标仓库现有 APT 场景、`defense_agent/`、流量倍率配置和定制 storyline/
ground-truth 逻辑均保留。

## 合并方法

由于源目录与目标仓库分别基于 EvidenceForge 1.11.1 和 1.9.0，不能直接
覆盖整个文件。先以官方 EvidenceForge v1.11.1 为参照分离源目录的本地
改动，再把这些本地改动逐文件适配到目标 1.9.0 代码结构。这样避免把
1.10/1.11 的全部上游变化误当成本项目改动，也避免覆盖 APTChain 的既有
定制。

随后按用户要求执行第二阶段：将官方 `v1.11.1`
（`a18957d157ba27df700ac106c72717a765ad63cd`）相对 1.9.0 的 120 个提交
完整合入目标源码。官方升级涉及 176 个非场景文件、38,209 行新增和
6,196 行删除。合并时保留 APTChain 的品牌、流量倍率、场景模型扩展、
`defense_agent/` 和场景目录；官方新增 Email Evidence、Artifacts
Manifest、Collection Profile、Zeek SMTP、配置、解析器、评测和测试均已
进入目标。

官方 tag 还包含 462 个 `scenarios/iteration-test-expanded/blind-test/`
生成结果文件、约 345 万行日志和评测产物。它们属于生成数据，不属于
源码升级，按本任务边界排除。官方升级与 APTChain 仅在
`events/ground_truth.py` 和 `engine/storyline.py` 发生源码冲突，最终保留
双方能力；恢复 Record-level 改动时的六处冲突也均按“官方 1.11.1 能力 +
Record Ground Truth”组合解决。

## 已合并的功能

### 1. Record-level Ground Truth

- 新增 `src/evidenceforge/events/record_ground_truth.py`。
- 为 canonical `SecurityEvent` 分配稳定 `logical_event_id`，并在最终写盘时
  生成 `physical_record_id`。
- 生成 schema-v3 `RECORD_GROUND_TRUTH.jsonl`，记录物理记录路径、序号、
  字节偏移/长度、SHA-256、原生日志 ID、可关联特征、贡献事件和
  `detectability_class`。
- provenance 通过上下文和 writer 缓冲区传递，不向 Sysmon、Security、
  Zeek、eCAR、ASA、Syslog、Bash、Web/Proxy 等源生日志泄漏标签字段。
- 最终发布 sidecar 前验证记录数量、定位、文件内容哈希和 attribution。
- CLI 的覆盖检测、暂存、事务替换、回滚和结果列表均纳入
  `RECORD_GROUND_TRUTH.jsonl`。

### 2. 生命周期标签继承

- `process_create` 的 storyline/label/provenance 和创建逻辑事件 ID 保存到
  精确运行进程实例。
- 没有新的显式 storyline 上下文时，后续同一进程实例的
  `process_terminate` 继承创建标签，并通过
  `parent_logical_event_ids` 保留因果关系。
- 显式 storyline/red-herring 上下文优先，避免旧生命周期标签覆盖当前
  攻击步骤。

### 3. Record-level 评测器

- 新增 `blind_test/record_level_claude_eval.py` 和配套说明。
- 保留逐场景、发现/展开两阶段、session 持久化、stream-json、checkpoint、
  超时保底和四指标计算逻辑。
- 只合并评测代码，不合并任何评测运行目录、中间会话或预测输出。

### 4. 黄金检测器

- 新增 `gold/source_informed_chain_detector.py` 和
  `gold/record_graph_detector.py`。
- 合并主机隔离的 PID/进程实例图、eCAR actorID/objectID 语义分离、
  自适应 Beacon、独立终端/Web/IOC 发现、受限图传播和 record-index
  白名单消费逻辑。
- 保留架构调整前备份：
  `gold/backups/source_informed_chain_detector.pre-architecture-2026-07-15.py`，
  SHA-256 为
  `9398ab8c1e35e4680544d0868bbbc165291cf31feb562fc63b87761cc238724b`。
- 只合并检测器和报告，不合并 `gold/*/findings.json`、
  `predictions.json` 等运行产物。

### 5. 测试和文档

- 新增 Record Ground Truth、评测器、黄金检测图单元测试。
- 增补 emitter/确定性生成/进程生命周期回归断言。
- 合并 ID 生成合同、Record Ground Truth、Claude 评测、黄金检测器、
  生命周期和 detectability 相关文档。
- 更新 README、生成命令和 Evidence Formats 文档，使新 sidecar 的用途、
  私有性和 blind-test 排除规则明确。

## 主要修改文件

生成链路：

- `src/evidenceforge/events/base.py`
- `src/evidenceforge/events/dispatcher.py`
- `src/evidenceforge/events/record_ground_truth.py`
- `src/evidenceforge/generation/activity/generator.py`
- `src/evidenceforge/generation/emitters/base.py`
- `src/evidenceforge/generation/emitters/host_base.py`
- `src/evidenceforge/generation/emitters/zeek_base.py`
- `src/evidenceforge/generation/emitters/bash_history.py`
- `src/evidenceforge/generation/emitters/cisco_asa.py`
- `src/evidenceforge/generation/emitters/ecar.py`
- `src/evidenceforge/generation/emitters/syslog.py`
- `src/evidenceforge/generation/emitters/sysmon.py`
- `src/evidenceforge/generation/emitters/windows.py`
- `src/evidenceforge/generation/engine/core.py`
- `src/evidenceforge/generation/engine/emitter_setup.py`
- `src/evidenceforge/generation/state_manager.py`
- `src/evidenceforge/models/state.py`
- `src/evidenceforge/cli/commands.py`

检测与评测：

- `blind_test/record_level_claude_eval.py`
- `gold/source_informed_chain_detector.py`
- `gold/record_graph_detector.py`
- `gold/backups/source_informed_chain_detector.pre-architecture-2026-07-15.py`

测试：

- `tests/unit/test_record_ground_truth.py`
- `tests/unit/test_record_level_claude_eval.py`
- `tests/unit/test_gold_source_informed_chain_detector.py`
- `tests/unit/test_gold_record_graph_detector.py`
- `tests/unit/test_process_lifetimes.py`
- `tests/unit/test_cli.py`
- `tests/unit/test_engine.py`
- `tests/integration/test_deterministic_generation.py`
- `tests/support/output_equivalence.py`

## 明确排除的内容

- `scenarios/NEW-Dataset/` 和其他已生成场景数据。
- 官方 `scenarios/iteration-test-expanded/blind-test/` 中随 tag 提交的日志、
  review-data、评测报告和循环运行产物。
- `evaluation_runs/`、Claude stream/checkpoint/session 输出。
- `gold/operation-dragon-whistle-record-eval/` 下的 findings/predictions。
- 所有 `__pycache__/`、`.DS_Store` 和临时文件。
- 仅与数据集生成/评测结果有关而不影响源码合同的 2026-07-13、
  2026-07-14 工作记录。

## 验证结果

### 通过

- `git diff --check`：通过。
- Python `compileall`：通过。
- Ruff（本次修改源码、检测器、评测器及测试）：通过。
- 官方升级节点合并后，官方/APT storyline、Ground Truth、Email Evidence、
  Collection Profile、引擎和格式集成测试 402 项通过；仅命中下述 medium
  旧断言。
- Record Ground Truth、Claude 评测器、黄金检测器、生命周期、CLI、引擎、
  Email Evidence、Collection Profile 和确定性生成：226 项通过。
- dispatcher、emitters、Sysmon、eCAR、ASA、Zeek、state manager：
  662 项通过。
- 确定性生成集成测试：2 项通过；验证 sidecar 数量等于可解析物理记录数、
  ID 唯一、标签正确且私有字段不泄漏到源生日志。
- 合并后全量测试：4,933 项通过，41 项按环境条件跳过，3 项已知基线
  失配明确排除；无新增失败，耗时 433.57 秒。

### 目标仓库既有的三处测试/资产失配

这些路径均不在本次修改列表中：

1. `test_calculate_events_for_hour_intensity_medium` 仍假设 medium
   `user_activity=15`，但 APTChain 自身的
   `src/evidenceforge/config/activity/traffic_rates.yaml` 已改为 30。
2. `test_default_medium_risk` 同样仍按均值约 15 断言，实际配置基线为 30。
3. `test_clean_twin_shares_a_byte_identical_baseline` 依赖
   `scenarios/llm-injection-demo/scenario-clean.yaml`，该文件在目标仓库基线中
   不存在。

本次没有擅自修改 APTChain 的流量倍率或补造缺失场景，以免把无关基线
修复混入 Record-level 源码合并。

## 后续合并建议

当前目标已同步到官方 EvidenceForge 1.11.1。后续同步更高版本时，以
`a4368801` 为官方上游源码基线，以本分支后续 Record Ground Truth 提交为
项目侧版本；重点三方检查 `dispatcher.py`、`core.py`、`ecar.py`、
`sysmon.py` 和 `commands.py`。黄金检测器入口、Record Graph 实现和
pre-architecture 备份已经拆分，可分别比较，避免再次形成单文件大冲突。
