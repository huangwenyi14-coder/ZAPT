# 智能体 `predictions.json` 结果契约

更新日期：2026-07-21

适用对象：Claude、Codex、通义、GLM、LongCat、自研 Agent、传统检测器以及其他
能够分析 EvidenceForge 场景日志的检测系统。

评分代码绝对路径：

```text
/Users/xhb/Documents/数字逸境/VERSION/APTChain-Benchmark/blind_test/record_level_claude_eval.py
```

## 1. 目的

每个智能体必须针对**一个场景**生成一份 `predictions.json`，列出它认为属于攻击
活动的物理日志记录。评分器不要求结果由 Claude 生成；只要文件符合本契约，任何
智能体或检测器都可以使用同一套 Physical Record、Logical Event 和 Storyline
指标进行比较。

本文件是单个 JSON 对象，不是 JSONL，不得在 JSON 前后附加 Markdown 代码围栏、
解释文字、日志或工具调用输出。

## 2. 盲测输入边界

推荐先由评测组织者为每个场景建立隔离工作区：

```text
<case-work-dir>/
  blind/
    data/                 # 该场景的无标签原始日志
    RECORD_INDEX.jsonl    # 无标签物理记录索引
  results/
```

智能体只能读取：

```text
<case-work-dir>/blind/data/
<case-work-dir>/blind/RECORD_INDEX.jsonl
```

智能体不能读取或搜索：

- `RECORD_GROUND_TRUTH.jsonl`；
- `scenario.yaml` 中的攻击答案；
- `label`、`storyline_id`、`logical_event_id`；
- `detectability_class`、归因字段或其他私有标签；
- 其他智能体的预测和评分结果。

每个场景应启动独立分析任务并生成独立的 `predictions.json`。不得把多个场景的
日志、Record Index、会话上下文或预测结果混在一个文件中。

## 3. 顶层格式

```json
{
  "analysis_summary": "简要说明发现了什么攻击活动以及主要证据链。",
  "predictions": [],
  "storyline_tactic_predictions": []
}
```

| 字段 | 类型 | 必填 | 是否参与数值评分 | 说明 |
| --- | --- | --- | --- | --- |
| `analysis_summary` | string | 是 | 否 | 对本场景分析结论的简短摘要；没有发现时也必须提供字符串 |
| `predictions` | array | 是 | 是 | 预测为恶意的物理记录数组；没有发现时使用空数组 |
| `storyline_tactic_predictions` | array | 否 | 仅开启战术评分时 | 由已提交物理证据支撑的 ATT&CK 战术声明；未要求战术预测时应省略 |

只提交预测为恶意的记录。没有出现在 `predictions` 数组中的记录一律视为预测
良性，不需要也不允许提交 `"label": "benign"`。

## 4. 单条预测格式

```json
{
  "physical_record_id": "pr-aca24f29b25d20680e90fe94",
  "relative_path": "DC-PMC-01.pacific-mapping.local/ecar.json",
  "record_index": 410,
  "label": "malicious",
  "confidence": 0.985,
  "reason": "同一精确进程实例在恶意载荷执行后发起外连"
}
```

| 字段 | 类型/范围 | 必填 | 约束 |
| --- | --- | --- | --- |
| `physical_record_id` | string | 是 | 必须从本场景 `RECORD_INDEX.jsonl` 原样复制，格式为 `pr-` 加小写十六进制字符 |
| `relative_path` | string | 是 | 必须从同一索引记录原样复制；相对于 `blind/data/`，使用 POSIX 路径 |
| `record_index` | integer，≥0 | 是 | 必须从同一索引记录原样复制；它是文件内从 0 开始的原子记录序号 |
| `label` | string | 是 | 固定为 `malicious`，其他值无效 |
| `confidence` | number，0～1 | 是 | 恶意判断置信度；默认只有 `confidence >= 0.50` 的记录进入评分 |
| `reason` | string | 是 | 说明该物理记录为什么恶意，以及关联到了什么锚点；用于审计，不直接改变分数 |

`physical_record_id + relative_path + record_index` 是不可拆分的三字段定位键。三个
字段必须来自 `RECORD_INDEX.jsonl` 的**同一行**，不得自行构造 ID、根据文本行号
猜测 index，或把一个 ID 与另一条记录的路径/index 拼接。

`record_index` 是解析后的原子记录序号，不保证等于文本行号。JSON 数组、多行 XML
和多行日志尤其不能用编辑器行号替代。详细定义见
[`三字段精准定位契约.md`](三字段精准定位契约.md)。

### 4.1 可选 Storyline 战术声明

检测阶段看不到真实 `storyline_id`，因此不得猜测或提交隐藏 ID。需要预测战术
阶段时，通过一条已经存在于 `predictions` 中的物理记录承载战术声明：

```json
{
  "evidence_physical_record_id": "pr-02e13f949b31df74a09db24e",
  "tactic": "Defense Evasion",
  "confidence": 0.96,
  "reason": "Office 启动 mshta 代理执行远程载荷"
}
```

| 字段 | 类型/范围 | 约束 |
| --- | --- | --- |
| `evidence_physical_record_id` | string | 必须引用本文件 `predictions` 中一条超过阈值且三字段定位有效的记录 |
| `tactic` | string | 必须使用下面列出的标准 ATT&CK Enterprise tactic 名称 |
| `confidence` | number，0～1 | 该战术判断的独立置信度 |
| `reason` | string | 说明物理证据为什么支撑该战术判断 |

允许的战术名称：

```text
Reconnaissance
Resource Development
Initial Access
Execution
Persistence
Privilege Escalation
Defense Evasion
Credential Access
Discovery
Lateral Movement
Collection
Command and Control
Exfiltration
Impact
```

评分阶段才会利用私有 Ground Truth，把 `evidence_physical_record_id` 映射到真实
`storyline_id`。同一 storyline 的重复战术声明会合并为一个
`(storyline_id, tactic)` 对。证据 ID 不存在、定位无效、低于 Physical Record
阈值或没有出现在 `predictions` 中时，该战术声明属于无效证据引用并计入战术 FP。

## 5. 完整有效示例

```json
{
  "analysis_summary": "WINWORD.EXE 启动 mshta 访问外部脚本，随后由同一进程链创建载荷并发起单次 C2 连接。",
  "predictions": [
    {
      "physical_record_id": "pr-02e13f949b31df74a09db24e",
      "relative_path": "WS-01/sysmon.jsonl",
      "record_index": 381,
      "label": "malicious",
      "confidence": 0.99,
      "reason": "Office 进程启动带远程 URL 的 mshta，属于高置信 Office→LOLBin 行为"
    },
    {
      "physical_record_id": "pr-4631333a063f6b6e5e2e5c55",
      "relative_path": "WS-01/zeek/conn.log",
      "record_index": 1072,
      "label": "malicious",
      "confidence": 0.86,
      "reason": "五元组和时间与已确认恶意进程的单次外连完全对应"
    }
  ],
  "storyline_tactic_predictions": [
    {
      "evidence_physical_record_id": "pr-02e13f949b31df74a09db24e",
      "tactic": "Defense Evasion",
      "confidence": 0.96,
      "reason": "Office 启动 mshta 代理执行远程载荷"
    },
    {
      "evidence_physical_record_id": "pr-4631333a063f6b6e5e2e5c55",
      "tactic": "Command and Control",
      "confidence": 0.9,
      "reason": "恶意进程发起与远程控制基础设施关联的连接"
    }
  ]
}
```

如果没有足够证据，应返回合法空结果：

```json
{
  "analysis_summary": "未发现达到提交阈值的恶意物理记录。",
  "predictions": []
}
```

空结果可以被正常评分；在有恶意 Ground Truth 的场景中，相应恶意记录会计为 FN，
但不会因为文件格式错误导致整个评测失败。

## 6. 标准 JSON Schema

需要结构化输出约束的智能体可以直接使用以下 Schema：

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "EvidenceForge Record-Level Predictions",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "analysis_summary": {
      "type": "string"
    },
    "predictions": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "physical_record_id": {
            "type": "string",
            "pattern": "^pr-[0-9a-f]+$"
          },
          "relative_path": {
            "type": "string",
            "minLength": 1
          },
          "record_index": {
            "type": "integer",
            "minimum": 0
          },
          "label": {
            "const": "malicious"
          },
          "confidence": {
            "type": "number",
            "minimum": 0,
            "maximum": 1
          },
          "reason": {
            "type": "string"
          }
        },
        "required": [
          "physical_record_id",
          "relative_path",
          "record_index",
          "label",
          "confidence",
          "reason"
        ]
      }
    },
    "storyline_tactic_predictions": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "evidence_physical_record_id": {
            "type": "string",
            "pattern": "^pr-[0-9a-f]+$"
          },
          "tactic": {
            "type": "string",
            "enum": [
              "Reconnaissance",
              "Resource Development",
              "Initial Access",
              "Execution",
              "Persistence",
              "Privilege Escalation",
              "Defense Evasion",
              "Credential Access",
              "Discovery",
              "Lateral Movement",
              "Collection",
              "Command and Control",
              "Exfiltration",
              "Impact"
            ]
          },
          "confidence": {
            "type": "number",
            "minimum": 0,
            "maximum": 1
          },
          "reason": {
            "type": "string"
          }
        },
        "required": [
          "evidence_physical_record_id",
          "tactic",
          "confidence",
          "reason"
        ]
      }
    }
  },
  "required": [
    "analysis_summary",
    "predictions"
  ]
}
```

## 7. 评分处理顺序

评分器对 `predictions` 依次执行：

1. 校验顶层结构和每条预测的必填字段；
2. 丢弃低于 `--confidence-threshold` 的预测，默认阈值为 0.50；
3. 按 `physical_record_id` 去重，重复时保留置信度最高的一条；
4. 在私有 Ground Truth 中查找 `physical_record_id`；
5. 校验 `relative_path` 和 `record_index` 是否与该 ID 的真实定位一致；
6. 对有效记录读取私有标签并计算 TP、FP、FN、TN；
7. 使用私有 `logical_event_id` 和 `storyline_id` 将有效 Physical Record 预测聚合，
   计算 Logical Event 和 Storyline 指标。

具体计分：

| 预测情况 | 结果 |
| --- | --- |
| ID、路径、index 均正确，私有标签为 `malicious` | TP |
| ID、路径、index 均正确，私有标签为 `benign` 或 `red_herring` | FP |
| `physical_record_id` 不存在 | 无效引用，计入 FP |
| ID 存在但路径或 index 不一致 | locator mismatch，计入 FP |
| 私有恶意记录没有有效预测 | FN |
| 私有良性记录没有有效预测 | TN |

指标公式：

```text
Accuracy  = (TP + TN) / (TP + FP + FN + TN)
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 * Precision * Recall / (Precision + Recall)
```

Storyline 评分中，一个场景内所有 `storyline_id = null` 的普通背景记录合并成一个
良性背景组。智能体不需要、也不能在预测中提交 Storyline ID 或 Logical Event ID。

启用 `--evaluate-storyline-tactics` 后，评分器额外执行：

1. 过滤低于战术置信度阈值的声明；未单独设置时沿用 Physical Record 阈值；
2. 校验战术证据 ID 是否属于一条有效且已选中的物理预测；
3. 在评分阶段将证据 ID 映射到私有 `storyline_id`；
4. 对唯一 `(storyline_id, tactic)` 对计算微平均 Precision、Recall 和 F1；
5. Accuracy 定义为：真实和预测 Storyline 组中，战术集合完全一致的组所占比例。

战术 F1 是额外指标，不替代默认的 Physical Record F1。未启用参数时，评分器完全
忽略可选战术字段，不生成战术指标。

## 8. 常见无效结果

以下结果不能直接评分或会产生 FP：

- 输出 Markdown 代码围栏，而不是纯 JSON；
- 输出 JSONL、多段 JSON、自然语言列表、CSV 或 IOC 列表；
- 只输出文件路径和“第几行”，没有 `physical_record_id`；
- 自行计算或编造 `physical_record_id`；
- 把 `record_index` 当作所有格式的文本行号；
- ID 来自一个场景，但路径/index 来自另一个场景；
- 提交 `"label": "benign"`、`"suspicious"` 或其他标签；
- `confidence` 使用 85、`"85%"` 等非 0～1 数值；
- 把同一条逻辑事件涉及的所有日志都无条件判恶，而没有逐条物理证据；
- 在战术声明中直接提交、猜测或泄露真实 `storyline_id`；
- 战术证据 ID 没有同时作为有效 Physical Record 预测提交；
- 在一份文件中混合多个场景的预测。

## 9. 给智能体的最短指令模板

可以把下面这段指令与本契约一起交给智能体：

```text
你正在分析一个独立的 EvidenceForge 盲测场景。只允许读取 blind/data/ 和
blind/RECORD_INDEX.jsonl，不得读取 Ground Truth、scenario.yaml、标签字段、其他
场景或其他检测器结果。

识别恶意活动后，把每一条有充分证据的恶意物理日志记录写入 predictions.json。
三字段 physical_record_id、relative_path、record_index 必须从 RECORD_INDEX.jsonl
同一条索引记录原样复制。只输出 label=malicious；没有输出的记录默认良性。

最终文件必须严格遵守《智能体 predictions.json 结果契约》，只包含一个 JSON
对象，不要添加 Markdown 围栏、解释文字或运行日志。证据不足时允许输出空数组，
不得猜测或伪造记录 ID。

如果任务要求 Storyline 战术预测，再输出可选 storyline_tactic_predictions 数组。
每条战术声明必须引用 predictions 中一条有效物理记录，不得提交或猜测真实
storyline_id；tactic 必须使用契约规定的标准 ATT&CK 名称。证据不足时省略声明。
```

## 10. 提交前自检

智能体或适配器在提交前应确认：

- [ ] 文件名为 `predictions.json`，编码为 UTF-8；
- [ ] 文件可以被标准 JSON 解析器解析为单个对象；
- [ ] 顶层同时包含字符串 `analysis_summary` 和数组 `predictions`；
- [ ] 每条预测恰好包含六个约定字段；
- [ ] `label` 全部为 `malicious`；
- [ ] `confidence` 全部为 0～1 的数值；
- [ ] 三字段均来自当前场景 Record Index 的同一条记录；
- [ ] 没有混入 Ground Truth 字段或其他场景 ID；
- [ ] 如提交战术声明，每个证据 ID 都存在于有效 `predictions` 中；
- [ ] 战术名称全部属于契约规定的 14 个标准名称；
- [ ] 没有提交、推测或泄露真实 `storyline_id`；
- [ ] 没有 Markdown、日志、注释、尾随逗号或第二个 JSON 对象。

## 11. 独立评分命令

评测组织者在智能体结束后运行；不要把包含 Ground Truth 的原始场景目录暴露给
被测智能体：

```bash
cd "/Users/xhb/Documents/数字逸境/VERSION/APTChain-Benchmark"

.venv/bin/python \
  "/Users/xhb/Documents/数字逸境/VERSION/APTChain-Benchmark/blind_test/record_level_claude_eval.py" \
  evaluate \
  --scenario-dir "/absolute/path/to/generated-scenario" \
  --work-dir "/absolute/path/to/agent-evaluation" \
  --predictions "/absolute/path/to/agent-output/predictions.json" \
  --confidence-threshold 0.50
```

评分产物：

```text
/absolute/path/to/agent-evaluation/results/evaluation.json
/absolute/path/to/agent-evaluation/results/evaluation.md
```

`evaluate` 命令只读取已有预测，不会调用 Claude，也不依赖预测由哪一种智能体或
检测器生成。

启用可选 Storyline 战术评分：

```bash
.venv/bin/python \
  "/Users/xhb/Documents/数字逸境/VERSION/APTChain-Benchmark/blind_test/record_level_claude_eval.py" \
  evaluate \
  --scenario-dir "/absolute/path/to/generated-scenario" \
  --work-dir "/absolute/path/to/agent-evaluation" \
  --predictions "/absolute/path/to/agent-output/predictions.json" \
  --confidence-threshold 0.50 \
  --evaluate-storyline-tactics \
  --storyline-tactic-labels "/absolute/path/to/<scenario>.labels.json"
```

可使用 `--storyline-tactic-confidence-threshold` 为战术声明设置独立阈值；省略时
使用 `--confidence-threshold`。
