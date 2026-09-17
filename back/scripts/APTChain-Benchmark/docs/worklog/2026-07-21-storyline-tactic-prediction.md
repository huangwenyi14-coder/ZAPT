# 黄金检测器 v1.4：可选 Storyline 战术阶段预测与评分

日期：2026-07-21

## 目标

在不破坏盲测边界和现有三层评分的前提下，增加可选的 ATT&CK 战术阶段预测。
检测器默认不输出战术；评分器默认不读取战术标签，也不生成战术指标。

## 标签来源

20260717 的战术标签位于：

```text
/Users/xhb/Desktop/Project/TASK/2026TASK/ShuZiYiJing/Datacon2026比赛支持/数据质量评估/20260717/label/<scenario>.labels.json
```

真实映射使用：

```text
predicted_storyline[].storyline_id
predicted_storyline[].ta
```

六个被测场景共 86 个带战术标签的 Storyline，使用 Execution、Persistence、
Defense Evasion、Command and Control、Credential Access、Discovery、Collection、
Exfiltration 和 Initial Access 九类标签。

## 盲测设计

真实 `storyline_id` 不在无标签 Record Index 中，检测器不能直接输出真实
Storyline ID。本实现使用“证据承载声明”：

```json
{
  "evidence_physical_record_id": "pr-...",
  "tactic": "Execution",
  "confidence": 0.95,
  "reason": "selected command or process execution"
}
```

该证据 ID 必须同时存在于 Physical Record 预测中。评分阶段才读取私有 Ground
Truth，将证据 ID 映射到真实 `storyline_id`。检测器运行期间不读取 `label/`、
`RECORD_GROUND_TRUTH.jsonl`、TTP 或战术答案。

## 参数

黄金检测器：

```text
--predict-storyline-tactics
```

评分器 `evaluate` 子命令：

```text
--evaluate-storyline-tactics
--storyline-tactic-labels <scenario>.labels.json
--storyline-tactic-confidence-threshold <0..1>   # 可选，默认沿用记录阈值
```

## 计分定义

- Precision、Recall、F1：对唯一 `(storyline_id, tactic)` 对做微平均；
- Accuracy：真实和预测 Storyline 组中，预测战术集合与真实战术集合完全一致的
  组所占比例；
- 同一 Storyline、同一战术由多条物理证据重复支持时只计一次；
- 证据 ID 不存在、定位无效、低于记录阈值或未作为 Physical Record 提交时，
  该战术声明按无效引用计入 FP；
- 漏检 Storyline 或未给出正确战术会产生 FN；
- 新指标不替代 Physical Record F1。

启用战术评分时 `evaluation.json` 使用 schema version 4；默认三层评分仍使用
schema version 3。

## 代码改动

- `gold/record_graph_detector.py`：公开证据规则到 ATT&CK tactic 的保守映射；
- `gold/source_informed_chain_detector.py`：增加可选检测参数；
- `blind_test/record_level_claude_eval.py`：标签加载、声明校验、证据到隐藏
  Storyline 映射、pair-level 指标和 Markdown 报告；
- `tests/unit/test_gold_record_graph_detector.py`：检测开关和证据引用测试；
- `tests/unit/test_record_level_claude_eval.py`：可选开关、标签场景校验、错误引用、
  pair 指标和报告测试；
- `docs/reference/PREDICTIONS_JSON_AGENT_CONTRACT.md`：智能体结果契约扩展。

## 20260717 六场景结果

| 指标层级 | TP | FP | FN | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Storyline × Tactic | 50 | 18 | 36 | 0.558140 | 0.735294 | 0.581395 | 0.649351 |

原有三层指标没有变化：

| 层级 | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: |
| Physical Record | 0.999262 | 1.000000 | 0.647706 | 0.786192 |
| Logical Event | 0.999406 | 1.000000 | 0.641791 | 0.781818 |
| Storyline | 0.836957 | 1.000000 | 0.825581 | 0.904459 |

战术预测当前是行为语义基线，不读取 TTP 答案。主要剩余误差来自同一公开行为在
具体攻击上下文中的阶段歧义，例如普通外连既可能是 C2，也可能承载侦察或外传；
文件落地可能属于下载、解码、持久化或执行。结果因此应与 Storyline 检出率分开
报告。

结果目录：

```text
/Users/xhb/Desktop/Project/TASK/2026TASK/ShuZiYiJing/Datacon2026比赛支持/数据质量评估/20260717/evaluation_runs/gold-v1.4-tactics-2026-07-21/
```
