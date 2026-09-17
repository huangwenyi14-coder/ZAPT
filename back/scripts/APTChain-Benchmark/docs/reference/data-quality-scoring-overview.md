# EvidenceForge 数据质量判分 — 维度与判分依据

> 聚焦两件事:**用哪几个维度打分**、**每个维度按什么判分**。其它工程细节、报告样式、规则文件位置全部略过。

---

## Slide 1 — 一页总览

评估体系 = **4 个维度(支柱)× 双档阈值(hard gate + aspirational)**

| # | 维度 | 权重 | 答的问题 | 硬门槛(必过) |
|---|---|---|---|---|
| 1 | **Parseability**(可解析性) | 30% | SIEM parser 吃不吃得下这行? | `spec_conformance ≥ 95` |
| 2 | **Plausibility**(合理性) | 25% | 字段值 / 组合 / 分布像不像真东西? | `value_plausibility ≥ 95` |
| 3 | **Causality**(因果) | 25% | 攻击剧情在数据里顺序对、来源对、IOA 对吗? | `causal_ordering ≥ 90`<br>`event_presence ≥ 85` |
| 4 | **Timing**(时序) | 20% | 人的节奏、系统的节奏、攻击链的节奏合理吗? | (无硬门,纯拉分) |

> **Overall = Σ(pillar_score × pillar_weight)**。Overall ≥ 70 才算可用,≥ 85 为优秀。
> 任何 hard gate 不过 → `acceptance_passed = False`,数据集拒收。

---

## Slide 2 — Pillar 1: Parseability(权重 30%)

**判分依据**:用真实下游 parser 的口径跑 strict 模式验证。

| Sub-score | 权重 | 判分依据 | 评分公式 |
|---|---|---|---|
| **spec_conformance** | 0.55 | 记录能否被 strict parser 解析 + 必填字段齐备 + 字段类型正确 | `100 × 通过条数 / 总条数` |
| **format_constraints** | 0.45 | enum / 范围 / regex / coerce 约束是否被违反(可 parse 但破 schema) | `100 × 通过条数 / 总条数` |

**判定流程**:
1. Windows 事件用 `EventID → variant` 映射选变体;
2. `STRICT_FORMATS`(syslog、zeek_*)再走一次字节级 `validate_strict()`;
3. 错误归类为 `parse_error / missing_field / strict_validation / constraint_violation`,作为失败摘要返回。

---

## Slide 3 — Pillar 2: Plausibility(权重 25%)

**判分依据**:逐条看值、组合、分布、跨源是否合理。

| Sub-score | 权重 | 判分依据 | 评分公式 |
|---|---|---|---|
| **value_plausibility** | 0.25 | OS 不窜台(Linux 上没 `C:\Windows`)+ 主机名在 scenario 中 | `100 × 通过 / 总数` |
| **co_occurrence** | 0.20 | 字段必现/互斥/范围规则(`co_occurrence.yaml` 里的规则) | `100 × 通过 / 适用条数` |
| **distribution_fit** | 0.15 | 字段值分布 vs `distributions.yaml` 参考分布 | `JSD ≤ 0 → 100`;`JSD ≥ 2×tolerance → 0`;中间线性 |
| **field_agreement** | 0.15 | 跨源 pivot join 后字段值一致(`cross_source_pairs.yaml`) | `100 × 一致对 / 匹配对` |
| **user_diversity** | 0.15 | 不同 user 事件类型分布两两余弦相似度低 | `sim ≤ 0.5 → 100`;`sim ≥ 0.9 → 0`;中间线性 |
| **anomaly_rate** | 0.10 | 异常但良性的事件占 1–5% 是金标准 | `0% → 0`;`1–5% → 100`;`>10% → 0`;中间带衰减 |

**关键判据**:
- `co_occurrence`:每条规则 `condition` 命中后跑 `checks`(present / not_equal / equals / min_length / min_value / max_value / in / matches);
- `field_agreement`:支持 `lower / path_basename_ci / cn_from_dn` 归一化,支持 `tolerance` 数值容差,支持 `time_window_seconds`。

---

## Slide 4 — Pillar 3: Causality(权重 25%)

**判分依据**:验证攻击剧情在数据里"该有的痕迹都到位、IOA 对得上、前后顺序不乱、相邻步骤能 pivot"。

| Sub-score | 权重 | 判分依据 | 评分公式 |
|---|---|---|---|
| **causal_ordering** | 0.25 | 已知前后事件对顺序正确(从 `causal_pairs.yaml` 读规则) | `100 × 正确对 / 总对` |
| **event_presence** | 0.20 | 每条剧情事件在 sensor 视野内留了至少 1 条 trace | `100 × 找到 / 应见` |
| **indicator_accuracy** | 0.15 | 找到的 trace 中 actor / hostname / IP 与剧本一致(IPv4-mapped 兼容) | `100 × 正确项 / 检查项` |
| **pivot_linkability** | 0.15 | 相邻剧情事件之间有可 pivot 的公共指示(actor、system、IP、trace 字段) | `100 × 可 pivot 对 / 邻接对` |
| **temporal_integrity** | 0.15 | trace 时间与剧情时间在 ±`TIME_TOLERANCE` 内 | `100 × 合规 / 应见` |
| **storyline_trace_coverage** | 0.10 | 剧情在所有期望 format-group 都落有 trace | `100 × 覆盖组 / 期望组` |

**关键判据**:
- **trace 搜索**:`(hostname 或 IP, 60s 时间桶)` 建索引,FQDN 额外存 bare-hostname;
- **observation-profile 调整**:非 `complete` 的源按 `OBSERVATION_MANIFEST.json` 排除不可见事件,但不豁免 hard correctness 错误(parse 失败、不可能值、源-本地矛盾);
- **spillage / adversarial_payload**:从 `GROUND_TRUTH.json` 读实际渲染字符串,在原文(支持 CRLF 切分)里搜——不靠重新跑合成,只信实际落到磁盘上的文本。

---

## Slide 5 — Pillar 4: Timing(权重 20%)

**判分依据**:节奏对得上真实环境——人不是等距发指令、系统不是等距跑 cron、攻击链不会瞬间完成。

| Sub-score | 权重 | 判分依据 | 评分公式 |
|---|---|---|---|
| **attack_chain_timing** | 0.15 | 相邻剧情事件间隔在 `timing_bounds.yaml` 的 min/max 窗口内 | `100 × 窗口内对 / 总对` |
| **burstiness** | 0.20 | 人 inter-event 时间呈突发性(剔 system account,5s 去重,算 CV) | `CV ∈ [1,3] → 100`;`CV < 0.5 → 0`;中间带衰减 |
| **system_regularity** | 0.15 | 同 (host, service) 的服务类事件呈周期性 | `CV ∈ [0.15, 1.0] → 100`;`CV > 2 → 0` |
| **diurnal_pattern** | 0.20 | 用户活动按 persona work_hours 聚集、跨工作日(7×24 二维直方图) | `JSD < 0.01 → 0`;`JSD ≥ 0.4 → 0`;中间线性 |
| **volume_adequacy** | 0.20 | 背景噪声与攻击信号比例达标 | `ratio ≥ target → 100`;`ratio ≤ target/2 → 0`;中间线性 |
| **rate_plausibility** | 0.10 | 物理上不可能的速率(5s 内 ≥ 21 条、>10Gbps 连接) | `100 × 合规 / 检查` |

**目标 noise:signal 比**:`low = 200:1` / `medium = 2000:1` / `high = 5000:1`。

**短场景保护**:`diurnal_pattern` 需 ≥ 24h 跨度 + ≥ 2 weekday 才算;`burstiness` 单用户 < 30 条跳过;N/A 项自动从分母拿掉,不影响其它子分。

---

## Slide 6 — 总分与判分规则

### 6.1 单个 pillar 的得分
```
pillar_score = Σ(sub_score_i × sub_score_weight_i)
```
sub-score 权重在各 pillar 模块顶部定义,总和 1.0。

### 6.2 Overall 得分
```
overall = Σ(pillar_score_i × pillar_weight_i) / Σ(可用 pillar_weight_i)
```
可用 pillar 不足时按剩余 pillar 重归一化(防止单个 pillar 异常把总分压成零)。

### 6.3 两档阈值
| 阈值 | 含义 | 后果 |
|---|---|---|
| `minimum` | **hard gate** | 不达 → `acceptance_passed = False`,拒收 |
| `aspirational` | 努力目标 | 不达 → 仅在报告中展示达成率(`met / total`),不拒收 |

**目前 4 条 hard gate**:
- `parseability.spec_conformance ≥ 95`
- `plausibility.value_plausibility ≥ 95`
- `causality.causal_ordering ≥ 90`
- `causality.event_presence ≥ 85`

**整体兜底**:
- `overall_score ≥ 70` → 可用
- `overall_score ≥ 85` → 优秀

---

## Slide 7 — 4 维度 × 判分依据 速查卡

```
Pillar 1  Parseability  ── 严格 parser 能不能过 + 字段约束有没有破
              spec_conformance (0.55)  ── strict parse + 必填 + 类型
              format_constraints (0.45) ── enum/range/regex/coerce

Pillar 2  Plausibility  ── 字段值、组合、分布、跨源、人差、异常率
              value_plausibility (0.25) ── OS 不窜台、host 存在
              co_occurrence     (0.20) ── 字段必现/互斥规则
              distribution_fit  (0.15) ── JSD vs 参考分布
              field_agreement   (0.15) ── 跨源 pivot + 一致性
              user_diversity    (0.15) ── 两两余弦相似度低
              anomaly_rate      (0.10) ── 1–5% 异常良性

Pillar 3  Causality     ── 攻击剧情完整、对、顺序通、能 pivot
              causal_ordering        (0.25) ── 前后对顺序
              event_presence         (0.20) ── 应见就有 trace
              indicator_accuracy     (0.15) ── IOA(IP/host/user)对
              pivot_linkability      (0.15) ── 相邻步能 pivot
              temporal_integrity     (0.15) ── 时间窗内、有序
              storyline_trace_coverage (0.10) ── 期望源都覆盖

Pillar 4  Timing        ── 节奏:人突发、系统周期、攻击间隔、体量、速率
              attack_chain_timing (0.15) ── 剧情间隔在窗口内
              burstiness          (0.20) ── 人 CV 1–3
              system_regularity   (0.15) ── 服务 CV 0.15–1.0
              diurnal_pattern     (0.20) ── 2D JSD vs persona
              volume_adequacy     (0.20) ── noise:signal 达标
              rate_plausibility   (0.10) ── 物理速率合理
```

> 14 个子分、4 个硬门、1 条整体 ≥ 70/85 兜底 —— 整套判分规则就是这些。
