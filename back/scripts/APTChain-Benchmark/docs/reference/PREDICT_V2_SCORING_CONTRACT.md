# `predict.json` v2 提交与判分契约

更新日期：2026-07-22

适用判分脚本：

```text
blind_test/score_predictions_v2.py
```

v2 判分只读取组织方私有的 `GOLD_Label.json` 和做题者提交的 `predict.json`。
它不会调用大模型，也不读取 `RECORD_GROUND_TRUTH.jsonl`。`GOLD_Label.json` 不得
发布给参赛者。

## 1. 做题者提交格式

`predict.json` 必须是一个 JSON 对象，并且只有下面两个顶层字段：

```json
{
  "ta_physical_ids": {
    "TA0002": "pr-执行阶段任一正确物理ID",
    "TA0011": "pr-命令与控制阶段任一正确物理ID"
  },
  "physical_id_set": [
    "pr-做题者判断为攻击记录的物理ID-1",
    "pr-做题者判断为攻击记录的物理ID-2"
  ]
}
```

要求：

- `ta_physical_ids` 中每个 TA 阶段只提交一个证据物理 ID，标准格式是字符串。
- 为兼容误写为数组的提交，判分器也接受 `"TA0002": ["pr-a", "pr-b"]`，但只
  使用第一个 ID；被忽略的数量会写入判分报告。
- `physical_id_set` 是做题者预测的全部攻击物理 ID。重复 ID 会先去重，并在报告
  中记录去重数量。
- 两个部分独立判分：TA 证据 ID 不强制同时出现在 `physical_id_set` 中。
- TA 编号采用 Enterprise ATT&CK v18.1 编号。可发布目录见
  [`ATTACK_TACTICS_v18.1.json`](ATTACK_TACTICS_v18.1.json)。
- 不允许额外顶层字段、空 TA 证据值或非字符串物理 ID。

## 2. 第一部分：TA 阶段得分

对做题者提交的每个 `(TA编号, 证据物理ID)`：

- TA 存在于 GOLD，且证据 ID 属于该 TA 在 GOLD 中的物理 ID 集合：`TP + 1`；
- TA 不存在，或证据 ID 不属于该 TA：`FP + 1`；
- GOLD 中没有被正确命中的 TA：`FN + 1`。

错误证据会同时造成一个 FP，并使对应的真实 TA 保持为 FN。然后计算：

```text
TA Precision = TP / (TP + FP)
TA Recall    = TP / (TP + FN)
TA F1        = 2 × Precision × Recall / (Precision + Recall)
```

第一部分分数为 `TA F1`。这种计算会同时惩罚漏报 TA、额外 TA 和 TA 下证据选错。

## 3. 第二部分：物理 ID 集合 F1

将 `predict.json.physical_id_set` 去重后与 GOLD 的 `physical_id_set` 做集合比较：

```text
TP = 预测集合 ∩ GOLD集合
FP = 预测集合 - GOLD集合
FN = GOLD集合 - 预测集合
```

按标准 Precision、Recall 和 F1 公式计算，第二部分分数为 `Physical ID F1`。

## 4. 第三部分：攻击步骤得分

第三部分先执行用户要求的错误 ID 过滤：

```text
正确预测ID = 做题者physical_id_set ∩ GOLD physical_id_set
```

再依次检查 GOLD 中的 `S1`、`S2`、……。只要某个步骤的 ID 集合与“正确预测 ID”
至少有一个交集，该步骤就命中一次：

```text
Step Recall = 命中步骤数 / GOLD步骤总数
```

错误 ID 不能命中任何步骤。第三部分的精准率严格按以下公式计算：

```text
Physical ID Precision = 正确预测ID数 / (正确预测ID数 + 错误预测ID数)
```

默认将 Recall 和 Precision 各占一半：

```text
Attack Step Score = 0.5 × Step Recall + 0.5 × Physical ID Precision
```

这个内部比例可用 `--step-weights RECALL:PRECISION` 修改，例如
`--step-weights 0.7:0.3`。

## 5. 总分

三部分默认比例为 `0.3:0.2:0.5`：

```text
总分 = 0.3 × TA F1
     + 0.2 × Physical ID F1
     + 0.5 × Attack Step Score
```

判分报告同时输出 `overall_score`（0～1）和 `overall_score_100`（0～100）。
`--weights` 和 `--step-weights` 接受任意非负比例，脚本会自动归一化，例如
`3:2:5` 与 `0.3:0.2:0.5` 完全等价。

## 6. 运行命令

在仓库根目录运行：

```bash
uv run python blind_test/score_predictions_v2.py \
  --gold /绝对路径/GOLD_Label.json \
  --prediction /绝对路径/predict.json \
  --output /绝对路径/score_v2.json
```

显式修改两组比例：

```bash
uv run python blind_test/score_predictions_v2.py \
  --gold /绝对路径/GOLD_Label.json \
  --prediction /绝对路径/predict.json \
  --output /绝对路径/score_v2.json \
  --weights 0.3:0.2:0.5 \
  --step-weights 0.5:0.5
```

如果省略 `--output`，完整报告只输出到标准输出。输入格式错误时退出码为 2。

## 7. 边界规则

- 当 GOLD 中存在正例而做题者没有提交对应预测时，该部分 Precision、Recall 和
  F1 记为 0。
- 当某个集合在 GOLD 和提交中同时为空时，该集合对应的 Precision、Recall 和 F1
  记为 1，表示空答案与空 GOLD 完全一致。
- GOLD 的步骤必须按 `S1...Sn` 连续排列，且每一步至少包含一个 GOLD 物理 ID；
  否则判分器拒绝运行，避免产生做题者永远无法命中的步骤。
- 判分输出只包含统计量，不回显 GOLD 的具体物理 ID、TA 答案或逐步骤答案。
