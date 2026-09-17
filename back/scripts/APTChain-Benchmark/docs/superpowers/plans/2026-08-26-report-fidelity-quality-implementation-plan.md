# 报告驱动数据生成质量治理实施计划

## 1. 计划目标

本计划落实《报告驱动数据生成端到端质量治理设计》，目标是在不改变 EvidenceForge 标准交付形态的前提下，让用户输入可复制文字的 PDF 或 TXT 后，通过一次命令稳定生成与原报告语义贴合、可审计、可验证的数据集。

最终用户仍主要获得项目原有输出，例如场景、事件日志、Ground Truth、验证与评估结果；原文抽取结果和 MiniMax 中间 JSON 不作为用户交付物。Ground Truth 必须能说明哪些内容来自报告、哪些是为使场景可执行而推导或由 AI 补全、哪些由生成引擎产生。

设计依据：

- `docs/superpowers/specs/2026-08-26-report-fidelity-quality-design.md`
- `docs/superpowers/specs/2026-08-26-report-to-dataset-design.md`

基线提交：`09512e1`。

## 2. 实施原则

1. **测试先行**：每个工作包先增加能暴露当前缺陷的失败测试，再实施最小修复，最后进行回归测试。
2. **事实优先**：MiniMax 负责理解非结构化报告，但本地确定性代码负责引用校验、实体关系约束、场景编译和质量门裁决。
3. **补全受控**：允许补全运行场景所需的内部环境和技术细节，但禁止伪造新的外部攻击事实。
4. **一次生成高质量**：质量门在发布结果前自动执行；不依赖人工查看输出后再手工修正。
5. **标准输出兼容**：不要求 Web 层理解 MiniMax 中间格式，后续 Web 只需上传文件、触发命令并展示标准输出与质量摘要。
6. **事务式发布**：先写入同文件系统的临时目录，全部检查通过后再发布到目标目录；失败时保留旧结果并返回清晰原因。
7. **小步中文提交**：每完成一个独立工作包并通过对应测试后提交一次，提交信息使用中文 Conventional Commit；不修改或合并历史提交。
8. **保护密钥与报告**：`1.txt`、API 密钥、模型原始响应和受版权保护的完整报告不得加入 Git，也不得出现在日志中。

## 3. 目标处理链路

```text
PDF/TXT
  │
  ├─ 文本抽取与带页码/字符区间的来源片段
  │
  ├─ MiniMax A：事实抽取
  │
  ├─ 本地事实账本校验、实体归一化、关系校验
  │
  ├─ MiniMax B：完整性审核（只提建议，不直接修改）
  │
  ├─ 本地应用引用有效且不冲突的审核建议
  │
  ├─ MiniMax C：受控补全
  │
  ├─ 报告专用场景编译器
  │
  ├─ 生成前来源贴合质量门
  │
  ├─ EvidenceForge 标准数据生成（临时目录）
  │
  ├─ 生成后事件/IOC/Ground Truth 质量门
  │
  └─ 原子发布标准输出
```

正常短文档预计调用 MiniMax 三次：事实抽取、完整性审核、受控补全。每一阶段最多允许一次结构修复，因此单分块文档最多六次调用，不能无限重试。长文档只对事实抽取按块调用，审核与补全在合并后的事实账本上执行。

## 4. 字段来源与补全边界

所有影响语义的字段必须带来源类型：

- `source`：报告明确陈述，必须有可验证的页码或字符区间引用。
- `derived`：由来源事实确定性推导，例如 HTTPS 默认端口 443、URL 拆分出的主机和路径。
- `ai_completed`：模型为可执行性补全，但报告没有明确陈述。
- `engine_generated`：EvidenceForge 在渲染事件时生成，例如事件 ID 或满足约束的微小时序。

每个攻击步骤还需汇总成三类：

- 报告事实步骤：核心行为与关键实体均由报告支撑。
- 部分 AI 补全步骤：核心行为有报告支撑，仅运行细节被补全。
- 完全合成步骤：为连接可执行链路而新增，必须明确标记且不能被描述成报告事实。

允许补全的典型内容：

- 内部用户名、主机名、内部 IP。
- 报告未给出的恶意进程本地路径和下载落地路径。
- 邮件发送者、收件者、主题和内部邮件服务器。
- 合理的父进程、会话、DNS、登录、文件放置和相对时序等运行前置条件。

允许确定性推导的典型内容：

- `https` 对应 443 端口。
- URL 对应的主机、端口和 URI。
- 明确“下载”行为对应 GET，明确“上传”行为对应 POST。
- 已知计划任务信息对应的任务 XML。
- 自删除行为作用于同一个已建立身份的恶意文件。

禁止补全或篡改的内容：

- 报告中的攻击域名、IP、URL 和哈希。
- 将一个 URL 的路径绑定到另一个网络行为。
- 因为未知恶意程序而凭空指定 PowerShell、CMD 或其他解释器。
- 报告没有给出的精确命令、漏洞、恶意家族和绝对时间。
- 报告没有描述的独立攻击阶段。

## 5. 工作包与提交顺序

### 工作包 0：固定基线与测试脚手架

**目的**

先把当前已知正确与错误行为写入机器可重复执行的期望，避免后续只凭主观阅读判断质量。

**新增或修改文件**

- `tests/fixtures/report_ingest/apt_c48_expectations.json`
- `tests/fixtures/report_ingest/synthetic_txt_expectations.json`
- `tests/fixtures/report_ingest/minimal_no_ioc.txt`
- `tests/fixtures/report_ingest/network_only.txt`
- `tests/fixtures/report_ingest/multi_artifact.txt`
- `tests/support/report_semantics.py`
- `tests/integration/test_report_to_dataset_semantics.py`
- `docs/worklog/2026-08-26-report-fidelity-quality.md`

**先写测试**

1. 用期望文件描述 APT-C-48 报告中必须保留的 3 个 MD5、4 个攻击 URL、域名/IP、两个计划任务及路径、精确 CMD 命令、诱饵和组件下载、用户名/进程/模块外传、BIOS 注册表查询、反分析和自删除。
2. 为后续语义测试提供统一断言辅助函数，覆盖以下禁止项：不得凭空生成攻击 PowerShell；不得让 CMD 承担后续 C2、下载或计划任务；不得把 `Architecture.pdf` 路径继承给普通心跳；不得把注册表查询渲染成写入。
3. 给三类独立 TXT 建立只包含人工可核对事实的期望，不提交完整 PDF 报告或模型响应。
4. 测试应能区分“尚未实现”与环境缺少 MiniMax 密钥，离线单元测试不得依赖网络。
5. 工作包 0 只提交能通过的期望文件模式校验、夹具加载和测试辅助设施；具体语义断言在对应功能工作包中先确认红灯，再与最小实现一起变绿后提交，Git 中不保留故意失败的测试。

**验证命令**

```bash
uv run pytest --no-cov tests/integration/test_report_to_dataset_semantics.py
```

该阶段只运行期望模式、夹具加载和辅助函数自测，结果必须通过。后续工作包新增真实语义断言时，先将其单独运行并把预期失败现象记录到工作日志；完成实现后再次运行至通过再提交。

**提交**

```text
test: 固化报告语义质量回归基线
```

### 工作包 1：建立来源片段、事实账本和引用契约

**目的**

把“模型输出一份大 JSON”改为“先建立可引用、可归一化、可判断冲突的事实账本”。

**新增或修改文件**

- `src/evidenceforge/report_ingest/extractors.py`
- `src/evidenceforge/report_ingest/models.py`
- `src/evidenceforge/report_ingest/iocs.py`
- `tests/unit/test_report_ingest.py`

**先写测试**

1. TXT 来源片段包含稳定的字符起止区间；PDF 来源片段包含页码和页内文本区间。
2. 引用必须能在规范化前后的抽取文本中定位，越界、空引用和错页引用被拒绝。
3. 相同实体可以有多个别名，但不能因大小写、URL 尾斜杠或哈希大小写重复建模。
4. 多个计划任务、多条 URL、多项哈希不得被单例字段折叠。
5. 事实、实体和关系分别建模，关系必须引用已存在的实体 ID。
6. 每个精确外部攻击事实只能标记为 `source`，且必须包含引用；补全字段不能伪装成来源事实。

**实施要点**

- 增加 `SourceSpan`、事实、实体、关系、字段来源和置信度模型。
- 保留原始抽取文本只供当前进程校验，不写入最终用户输出。
- 将 IOC 抽取从“发现字符串”升级为“IOC + 来源片段 + 规范化值”。
- 提供确定性的实体去重、引用校验和关系完整性校验函数。

**验证命令**

```bash
uv run pytest --no-cov tests/unit/test_report_ingest.py
uv run ruff check src/evidenceforge/report_ingest tests/unit/test_report_ingest.py
uv run ruff format --check src/evidenceforge/report_ingest tests/unit/test_report_ingest.py
```

**提交**

```text
feat: 建立报告事实账本与来源引用契约
```

### 工作包 2：拆分 MiniMax 事实抽取、审核与受控补全

**目的**

让模型每次只处理一个职责，并用本地校验阻止审核模型或补全模型引入无来源攻击事实。

**新增或修改文件**

- `src/evidenceforge/report_ingest/prompts.py`
- `src/evidenceforge/report_ingest/minimax.py`
- `src/evidenceforge/report_ingest/models.py`
- `tests/unit/test_report_ingest.py`

**先写测试**

1. A 阶段提示词只抽取事实、实体、关系和引用，不要求生成场景节点或日志路由。
2. B 阶段收到合并后的事实账本与报告片段，只能返回缺失、冲突、引用问题和修改建议。
3. 本地代码只接受引用可定位、实体存在且不与已有事实冲突的 B 阶段建议。
4. C 阶段提示词明确列出允许与禁止补全项，输出中每个补全字段必须标记 `ai_completed`。
5. MiniMax 客户端按调用传入工具名和 JSON Schema，不再硬编码单一 `ReportExtraction`。
6. JSON 非法时只进行一次结构修复；第二次仍非法则停止并返回阶段化错误。
7. 分块结果合并后不能丢失重复类型的任务、URL 和哈希。
8. API 密钥、原始模型响应和完整报告正文不出现在异常文本或普通日志里。

**实施要点**

- 为 A/B/C 三阶段分别建立版本化中文系统提示词和用户提示词。
- 采样温度使用 MiniMax 当前接口支持的最低稳定值。
- 为每次调用记录安全元数据：阶段、提示词版本、耗时、令牌统计、是否修复，不记录密钥和原始正文。
- 短文档通常执行 A、B、C 三次；长文档按块执行 A，再对合并账本执行一次 B 和一次 C。
- 保留有限重试策略，任何阶段失败都返回可定位错误，不继续生成低可信场景。

**验证命令**

```bash
uv run pytest --no-cov tests/unit/test_report_ingest.py
uv run ruff check src/evidenceforge/report_ingest/prompts.py src/evidenceforge/report_ingest/minimax.py src/evidenceforge/report_ingest/models.py tests/unit/test_report_ingest.py
uv run ruff format --check src/evidenceforge/report_ingest/prompts.py src/evidenceforge/report_ingest/minimax.py src/evidenceforge/report_ingest/models.py tests/unit/test_report_ingest.py
```

**提交**

```text
feat: 拆分 MiniMax 抽取审核与补全流程
```

### 工作包 3：新增报告专用场景编译器

**目的**

由确定性编译器把事实账本转换成 EvidenceForge 场景，避免模型直接决定进程归属、网络 URI 复用和渲染通道。

**新增或修改文件**

- `src/evidenceforge/report_ingest/compiler.py`
- `src/evidenceforge/report_ingest/models.py`
- `tests/unit/test_report_compiler.py`

**先写测试**

1. 只有报告明确给出或受控补全建立的进程，才能成为后续行为主体。
2. 已知 CMD 下载命令仅覆盖其明确下载行为，不能自动成为后续 C2、计划任务和外传主体。
3. 网络上下文按单条行为绑定，允许复用主机/端口，但不得把某个 URL 的 URI 和方法复制到其他行为。
4. 两个计划任务生成两个独立节点，任务名、执行路径和触发信息不能相互覆盖。
5. 注册表读取编译为 `registry_query`，写入或持久化才编译为 `registry_set`。
6. 报告只描述行为但没有可观测主机事件时，编译器明确降级并记录原因，不能悄悄伪造精确命令。
7. 每个节点保留其来源事实 ID、字段来源和预期可见性。
8. 完全合成的桥接步骤必须有必要性原因，且不能携带新的外部 IOC。

**实施要点**

- 编译器按“主体—动作—客体—通道”关系生成节点，不使用“最后一个进程”全局兜底。
- 为 URL、任务、文件、注册表键和外传对象使用稳定实体 ID。
- 将事件类型选择和可见性决策放在本地规则表中，模型只提供事实和允许的补全候选。
- 编译结果在进入生成引擎前完成模式、关系和来源校验。

**验证命令**

```bash
uv run pytest --no-cov tests/unit/test_report_compiler.py
uv run ruff check src/evidenceforge/report_ingest/compiler.py src/evidenceforge/report_ingest/models.py tests/unit/test_report_compiler.py
uv run ruff format --check src/evidenceforge/report_ingest/compiler.py src/evidenceforge/report_ingest/models.py tests/unit/test_report_compiler.py
```

**提交**

```text
feat: 新增报告专用场景编译器
```

### 工作包 4：让 EvidenceForge 原生支持注册表查询与来源标记

**目的**

修复“读取 BIOS 注册表被输出为写入”的语义错误，并让来源信息贯穿场景、事件与 Ground Truth。

**新增或修改文件**

- `src/evidenceforge/models/scenario.py`
- `src/evidenceforge/events/contexts.py`
- `src/evidenceforge/generation/engine/storyline.py`
- `src/evidenceforge/generation/emitters/ecar.py`
- `src/evidenceforge/events/ground_truth.py`
- `src/evidenceforge/events/record_ground_truth.py`
- `src/evidenceforge/generation/ground_truth.py`
- `tests/unit/test_models.py`
- `tests/unit/test_events.py`
- `tests/unit/test_ecar_spec_compliance.py`
- `tests/unit/test_ground_truth.py`
- `tests/unit/test_record_ground_truth.py`

**先写测试**

1. `registry_query` 可通过场景模式验证，并产生 eCAR `READ` 行为。
2. `registry_query` 不得产生 Sysmon 注册表写入事件；若当前没有可靠读取事件来源，应只输出 eCAR 并声明可见性。
3. 现有 `registry_set` 行为保持不变，避免回归。
4. 场景节点、恶意事件标签和 Ground Truth 能追溯到来源事实 ID。
5. Ground Truth 同时展示步骤级来源类别和关键字段级来源，不能把 `engine_generated` 时间戳表述为报告时间。
6. 原有不带来源元数据的手写场景仍能兼容运行。

**实施要点**

- 将 `registry_query` 纳入支持的事件类型、上下文和渲染映射。
- 对来源元数据使用向后兼容的可选字段，并在报告专用流水线中强制要求。
- Ground Truth 中增加紧凑的“报告贴合摘要”和每步来源说明，不输出原报告全文或模型 JSON。
- 更新所有枚举、模式和用户文档中维护的事件类型清单。

**验证命令**

```bash
uv run pytest --no-cov tests/unit/test_models.py tests/unit/test_events.py tests/unit/test_ecar_spec_compliance.py tests/unit/test_ground_truth.py tests/unit/test_record_ground_truth.py
uv run ruff check src/evidenceforge/models/scenario.py src/evidenceforge/events/contexts.py src/evidenceforge/generation/engine/storyline.py src/evidenceforge/generation/emitters/ecar.py src/evidenceforge/events/ground_truth.py src/evidenceforge/events/record_ground_truth.py src/evidenceforge/generation/ground_truth.py tests/unit/test_models.py tests/unit/test_events.py tests/unit/test_ecar_spec_compliance.py tests/unit/test_ground_truth.py tests/unit/test_record_ground_truth.py
uv run ruff format --check src/evidenceforge/models/scenario.py src/evidenceforge/events/contexts.py src/evidenceforge/generation/engine/storyline.py src/evidenceforge/generation/emitters/ecar.py src/evidenceforge/events/ground_truth.py src/evidenceforge/events/record_ground_truth.py src/evidenceforge/generation/ground_truth.py tests/unit/test_models.py tests/unit/test_events.py tests/unit/test_ecar_spec_compliance.py tests/unit/test_ground_truth.py tests/unit/test_record_ground_truth.py
```

**提交**

```text
feat: 支持注册表查询与来源标记
```

### 工作包 5：增加生成前后来源贴合质量门与事务式发布

**目的**

让低质量场景在写入最终目录前自动失败，并用确定性指标衡量“贴合报告”而不是只衡量内部格式正确。

**新增或修改文件**

- `src/evidenceforge/report_ingest/quality.py`
- `src/evidenceforge/report_ingest/pipeline.py`
- `scripts/generate_from_report.py`
- `scripts/evaluate_report_fidelity.py`
- `tests/unit/test_report_quality.py`
- `tests/unit/test_report_ingest.py`

**先写测试**

1. 生成前检查精确来源事实的引用覆盖率、实体关系完整性、禁止补全项和可物化行为覆盖率。
2. 生成后检查 `RECORD_GROUND_TRUTH.jsonl` 的恶意记录、Ground Truth、报告 IOC 和预期可见性。
3. TLS 中不可见的完整 URI 若在 Ground Truth 中被明确说明，不应被误判为丢失；未说明则失败。
4. 硬门槛任一失败时，不发布临时结果，也不覆盖已有目标目录。
5. 全部通过时，在同一文件系统内把临时目录原子发布为最终目录。
6. 路径保护拒绝根目录、仓库根目录、空路径和无法确认的递归删除目标。
7. `ReportPipelineResult` 返回质量分、覆盖率、MiniMax 调用次数和失败原因，但不泄露密钥或模型原始响应。
8. `--force` 只能作用于解析后的明确输出目录，并采用可恢复或先备份后替换的策略。

**硬门槛**

- 精确来源事实引用覆盖率：100%。
- AI 补全和引擎生成字段标记率：100%。
- 报告 IOC 在 Ground Truth 中的登记率：100%。
- 无来源的进程、命令和 URL 关系：0。
- 可物化来源行为覆盖率：至少 90%。
- 未记录原因的语义降级：0。
- 综合质量分：至少 85 分。

**综合分权重**

- 来源事实精确性：30 分。
- 行为覆盖：25 分。
- 实体与关系一致性：20 分。
- IOC 保留：15 分。
- 日志物化与可见性说明：10 分。

硬门槛不能被综合分抵消。

**实施要点**

- 输出先生成到目标目录同级的唯一临时目录，确保最终重命名可原子完成。
- 生成后以 `RECORD_GROUND_TRUTH.jsonl` 为主要恶意事件索引，同时核对标准 Ground Truth 文件。
- `scripts/evaluate_report_fidelity.py` 支持离线重评已有输出，供回归测试和 Web 展示质量摘要。
- CLI 退出码区分输入错误、模型错误、编译错误、质量门失败和文件发布错误。

**验证命令**

```bash
uv run pytest --no-cov tests/unit/test_report_quality.py tests/unit/test_report_ingest.py
uv run ruff check src/evidenceforge/report_ingest/quality.py src/evidenceforge/report_ingest/pipeline.py scripts/generate_from_report.py scripts/evaluate_report_fidelity.py tests/unit/test_report_quality.py tests/unit/test_report_ingest.py
uv run ruff format --check src/evidenceforge/report_ingest/quality.py src/evidenceforge/report_ingest/pipeline.py scripts/generate_from_report.py scripts/evaluate_report_fidelity.py tests/unit/test_report_quality.py tests/unit/test_report_ingest.py
```

**提交**

```text
feat: 增加报告来源贴合质量门
```

### 工作包 6：收紧旧 APT 场景转换器的危险兜底

**目的**

即使旧脚本仍被单独使用，也不能继续产生已知的高风险语义伪造。

**新增或修改文件**

- `scripts/regenerate_apt_scenarios.py`
- `tests/unit/test_regenerate_apt_scenarios.py`

**先写测试**

1. `_merge_network_context` 只能合并允许共享的主机、端口等上下文，URI 和方法必须保持行为级绑定。
2. 找不到进程主体时不得默认使用 PowerShell，也不得无依据沿用“最后一个进程”。
3. 注册表键只有在报告明确描述写入时才生成 `registry_set`；读取生成 `registry_query`。
4. 未知主体或不可表达行为必须产生显式降级信息，不能静默生成看似精确的事件。

**实施要点**

- 删除或限制全局网络上下文和最后进程兜底。
- 将危险兜底改为显式错误或带来源标记的最小合成主体。
- 保留旧脚本已有合法输入的兼容性。

**验证命令**

```bash
uv run pytest --no-cov tests/unit/test_regenerate_apt_scenarios.py
uv run ruff check scripts/regenerate_apt_scenarios.py tests/unit/test_regenerate_apt_scenarios.py
uv run ruff format --check scripts/regenerate_apt_scenarios.py tests/unit/test_regenerate_apt_scenarios.py
```

**提交**

```text
fix: 收紧旧 APT 场景转换器危险兜底
```

### 工作包 7：打通离线端到端语义回归

**目的**

把前述单元能力组合成无需真实 API 的稳定端到端测试，确保后续提示词或引擎改动不会再次破坏报告语义。

**新增或修改文件**

- `tests/integration/test_report_to_dataset_semantics.py`
- `tests/fixtures/report_ingest/apt_c48_expectations.json`
- 三类 TXT 夹具及其期望文件
- 为 A/B/C 阶段准备的最小、脱敏 MiniMax 响应夹具

**先写测试**

1. 注入确定性的 MiniMax 假客户端，完整运行抽取、审核、补全、编译、生成和生成后质量门。
2. APT-C-48 期望中的必须项全部进入场景或 Ground Truth；禁止项全部不存在。
3. 三类 TXT 分别验证：无 IOC 的简短文本不被强行添加外部 IOC；仅网络行为文本不被扩写成完整入侵链；多任务/多文件/多 URL 不被折叠或串绑。
4. 同一输入和固定随机种子产生稳定的语义结构；允许事件 ID 等明确标记的引擎字段变化。
5. 质量门失败时目标目录无半成品；成功时所有 EvidenceForge 标准文件齐全。

**验证命令**

```bash
uv run pytest --no-cov tests/integration/test_report_to_dataset_semantics.py
uv run pytest --no-cov tests/unit/test_report_ingest.py tests/unit/test_report_compiler.py tests/unit/test_report_quality.py
```

**提交**

```text
test: 增加报告到日志语义回归测试
```

### 工作包 8：真实 MiniMax 循环验收与根因修复

**目的**

用真实、不受控输入验证单轮命令的稳定性。每次失败都修复通用根因，不针对样例硬编码答案。

**前置条件**

- `../1.txt` 中存在可用的 MiniMax API 配置，文件被 Git 忽略。
- 示例 PDF 可复制文字：`/Users/kanghangkai/Downloads/数据社区_谢江版/2024.11.26 - Analysis report on recent phishing attacks by APT-C-48 (CNC).pdf`。
- 每次运行使用新的空输出目录，不手工编辑模型中间结果或最终场景。

**APT-C-48 必须通过的语义矩阵**

- 保留 3 个 MD5、4 个攻击 URL、报告域名和 IP。
- 保留两个计划任务及其不同任务名和路径。
- 保留报告中的精确 CMD 命令、诱饵下载和组件下载。
- 表达用户名、进程与模块信息外传事实。
- 表达 BIOS 注册表查询、反分析和自删除。
- 不生成无来源的攻击 PowerShell。
- 不让 CMD 无依据承担后续 C2、下载、计划任务或外传。
- 不把 `Architecture.pdf` URI 复制给其他网络行为。
- 不把注册表查询渲染为写入。
- 所有精确来源主张有引用，所有补全内容有来源类型。

**真实运行命令模板**

```bash
uv run python scripts/generate_from_report.py \
  "/Users/kanghangkai/Downloads/数据社区_谢江版/2024.11.26 - Analysis report on recent phishing attacks by APT-C-48 (CNC).pdf" \
  --output "/Users/kanghangkai/Downloads/数据社区_谢江版/quality-runs/apt-c48-run-01" \
  --api-key-file "/Users/kanghangkai/Downloads/数据社区_谢江版/1.txt"
```

第二次和第三次分别使用 `apt-c48-run-02`、`apt-c48-run-03`。随后对三个独立 TXT 各执行至少一次同样的一键生成。日常迭代使用较小数据窗口；最终验收至少一次使用正式规模数据，避免只验证小样本。

**每轮循环**

1. 从干净的新目录执行一次完整命令。
2. 运行标准场景验证、EvidenceForge 内部评估和来源贴合评估。
3. 对照语义矩阵记录硬门槛、综合分及具体失败事实。
4. 将失败归因到提示词、事实合并、编译规则、引擎能力、可见性声明或质量门，不按样例字符串增加特判。
5. 先增加可复现失败的单元或集成测试，再修复通用根因。
6. 运行受影响测试和完整离线回归。
7. 每个独立根因修复单独提交，使用如 `fix: 修复报告网络行为串绑` 的中文提交信息。
8. 再从新的空目录运行，直到连续三次 PDF 运行和三类 TXT 全部通过。

**通过标准**

- APT-C-48 PDF 连续三次一键运行全部达到综合分 85 分以上，且所有硬门槛通过。
- 三类 TXT 均一键运行通过，没有因输入简短而伪造完整攻击链。
- 输出无需人工编辑。
- 失败重试次数有界，调用次数与修复情况可审计。
- 同一类根因已被离线测试覆盖。

**提交**

每个通用根因分别提交，不把多类修复压成一个提交。完成最终验收后提交：

```text
docs: 记录报告生成质量验收结果
```

### 工作包 9：完整验证、中文文档与交付清理

**目的**

确保代码、命令、文档和后续 Web 接入边界一致，工作区不包含密钥、临时结果和未说明的基线问题。

**新增或修改文件**

- `README.md` 或现有报告导入中文说明文档
- `TODO.md`
- `docs/worklog/2026-08-26-report-fidelity-quality.md`
- 必要的 `.gitignore` 条目，但不得误忽略需要提交的测试夹具

**文档内容**

- 支持 TXT 与可复制文字 PDF，不承诺 OCR。
- 一键运行方法、配置文件格式和标准输出目录说明。
- Ground Truth 来源类型和质量分含义。
- 常见失败类型、退出码和安全重试方式。
- Web 层未来只需要的输入、进度、结果和错误接口，不在本阶段实现 Web。

**完整验证命令**

```bash
uv run pytest --no-cov
uv run ruff check .
uv run ruff format --check .
git diff --check
git status --short
```

仓库当前存在与本任务无关的 Ruff 基线问题。每个工作包必须保证所有本次修改文件通过定向 Ruff 检查；最终完整 Ruff 的剩余错误要在工作日志中与基线对比，不能自动格式化或顺手修改无关文件。

**提交**

```text
docs: 完善报告数据生成中文使用说明
```

## 6. 质量评估细则

### 6.1 生成前质量门

生成前检查事实账本和场景编译结果：

- 所有 `source` 精确主张都有能在抽取文本中定位的引用。
- 所有引用的实体和关系均存在，没有孤立 ID。
- 多值事实未被单例模型覆盖。
- AI 补全没有新增外部攻击 IOC、漏洞、恶意家族或精确命令。
- 进程主体、网络 URI、任务与文件的绑定不跨行为串联。
- 每个可物化来源行为有对应节点，不能物化的行为有明确原因。

### 6.2 生成后质量门

生成后从实际事件和 Ground Truth 反向验证：

- 报告攻击步骤是否确实产生了预期的恶意事件或被明确声明为不可见。
- 实际恶意记录的进程、网络、文件、计划任务和注册表语义是否与场景一致。
- 报告 IOC 是否完整进入 Ground Truth；受加密或数据源限制不可直接观察的值是否有解释。
- 是否出现事实账本中不存在且未标记补全的新攻击实体或关系。
- 步骤级来源分类与字段级来源是否一致。

### 6.3 与原有验证的关系

原有 `validate` 和 `eval` 继续负责场景模式、时间、事件和标签的内部一致性。新的来源贴合质量门负责判断输出是否忠于输入报告。两者必须同时通过，任何一方通过都不能替代另一方。

## 7. 测试层级与执行频率

| 层级 | 内容 | 执行频率 |
| --- | --- | --- |
| 单元测试 | 引用、归一化、MiniMax 契约、编译规则、质量分、路径安全 | 每次相关修改后 |
| 离线集成测试 | 假 MiniMax 响应驱动完整流水线 | 每个工作包提交前 |
| 全量离线测试 | 全仓 pytest | 关键工作包和最终交付前 |
| 真实 MiniMax 小规模测试 | PDF/TXT 一键输入输出 | 提示词、合并或编译规则变化后 |
| 正式规模验收 | 完整数据量和连续三次运行 | 最终交付前 |

真实 API 测试不应替代离线测试，也不在普通单元测试中默认触发。需要通过显式命令和存在密钥配置两个条件才运行。

## 8. 失败处理与安全要求

- 文本层为空的 PDF 立即报告“当前版本不支持扫描件 OCR”，不调用 MiniMax。
- MiniMax 认证失败、限流、超时、结构错误分别返回可理解的中文错误。
- 模型结构连续两次不合法时停止，不以正则或猜测方式拼接不可信 JSON。
- 质量门失败时保留诊断摘要，但不发布标准结果目录。
- 临时目录必须是目标目录同级、带唯一后缀且经过路径校验的明确路径。
- 禁止对 `$HOME`、`~`、根目录、仓库根目录或未展开变量执行递归删除。
- 日志只记录安全元数据和事实 ID，不打印 `1.txt` 内容、Authorization 头、完整报告正文或模型原始响应。
- 真实运行产物默认置于仓库外或 Git 忽略目录。

## 9. 计划完成定义

只有同时满足以下条件，才可将本实施计划标记为完成：

1. 工作包 1 至 7 的离线测试全部通过。
2. 新增 `registry_query` 与来源标记没有破坏现有手写场景。
3. APT-C-48 示例 PDF 连续三次真实一键生成全部通过硬门槛且综合分不低于 85。
4. 三类独立 TXT 全部通过，且没有被补全成报告未描述的完整攻击链。
5. 至少一次正式规模数据生成通过标准验证、内部评估和来源贴合评估。
6. 用户交付物仍是 EvidenceForge 标准输出，Ground Truth 已包含足够的来源审计信息。
7. 中文使用文档、工作日志和 TODO 状态已更新。
8. 所有实施提交均为独立中文提交，工作区中没有密钥、报告副本或临时运行产物。
