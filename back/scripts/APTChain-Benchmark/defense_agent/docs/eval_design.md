# 评测设计 (eval_design.md)

## 总目标

对 **检测器输出** 与 `GROUND_TRUTH.json` 做对齐, 输出两类指标:

1. **Task A — log-level**: 单条日志级精确率/召回率/F1
2. **Task B — storyline-level**: 攻击步骤还原度

> **关键约定**: 评测阶段才读 GT, 检测器**禁止**用 GT 中具体值 (PID/IP/路径) 作为特征。
> 检测器只接收来自 parsers 的 CanonicalEvent, 不能访问 GROUND_TRUTH.* 任何字段。

## 1. 对齐策略 (与用户约定)

> 用户选择: "仅按 process/pid/uid 关联"。

### 1.1 process 类型

GT.events 中 `kind == "process"`:
- 真值集合: `(system, pid)` → 该事件
- 检测结果: 同 `(system, pid)` 的原始日志行 → malicious

**注意 PID 复用**: 同 host 的 PID 可能跨时刻复用。需要在原始日志中按时间窗
(GT.time ± 5s) 限定, 否则会误把无关进程对齐。

```
gt_record.key = (record_id, kind, storyline_id)
match(g) = {
    for ev in raw_events_of_kind(g.system, g.kind):
        if abs(ev.timestamp - g.time) <= 5s
           and (g.pid == ev.pid or g.process_name == ev.process_name):
            yield ev
}
```

### 1.2 connection 类型

GT.events 中 `kind == "connection"`:
- 对齐键: `(uid, dst_ip, dst_port)` + ±2s 时间窗
- 在 Zeek conn.json / eCAR FLOW / syslog 防火墙日志中找匹配 UID

### 1.3 logon 类型

- 对齐键: `(logon_id, system)` + ±2s
- 在 Windows Security 4624 / eCAR USER_SESSION LOGIN 中匹配 logon_id

### 1.4 dns_query 类型

- 对齐键: `(query, system)` + ±2s
- 在 Zeek dns.json / Sysmon Event 22 中匹配 query

### 1.5 scheduled_task_created / beacon / create_remote_thread

- 各自按 attribute 中的标识字段对齐 (task_name / dst_ip+interval / target_process)
- 如果某种 kind 在所有原始日志中无对应格式, 该 kind 的事件记为 "unmatchable",
  在评测报告中标记为 N/A 而非 FN (避免假性 FN)。

### 1.6 不可见事件

读 `OBSERVATION_MANIFEST.json` 的 `source_evidence_status[storyline_id][<source>]`:
- 若 visible == 0 且 dropped / out_of_window > 0, 标记为 "not_observable"
- not_observable 的事件**不算** FN, 但在报告中单独列出占比

## 2. Task A — log-level 指标

设:
- `TP_set` = 检测器判为 malicious 且 GT.events 中确实有对应记录
- `FP_set` = 检测器判为 malicious 但 GT.events 中**无**对应记录
- `FN_set` = GT.events 中存在对应记录, 但检测器未判为 malicious
- `TN_set` = 检测器判为 benign 且确实不在 GT 中 (数量级可能非常大, 用采样估算)

```
Precision = |TP| / (|TP| + |FP|)
Recall    = |TP| / (|TP| + |FN|)
F1        = 2 * P * R / (P + R)
FPR       = |FP| / |TN_sampled|
```

**注意:**
- 只算真阳/假阳/假阴; 真阴数用采样估算 (避免扫描全部原始日志)
- 对每个 (scenario, source) 分别出指标, 再汇总
- 不同 verdict 阈值 (malicious / suspicious / benign) 可调, 输出 P-R 曲线

## 3. Task B — storyline-level 指标

对每个 GT.storyline_id:

```
detected      = (storyline_id 至少有一条事件被检出)
coverage      = matched_events / total_events_for_storyline
reorder_score = adjusted_for_temporal_order (penalty if order violated)
```

汇总:
- `Storyline_Detection_Rate` = 检测出的 storyline_id 数 / GT storyline 数
- `Avg_Step_Coverage` = 各 storyline 覆盖度均值
- `Storyline_Reconstruction_F1` = 对 storyline 视为一类 (全检全 / 漏检) 的 F1

### 还原度 (reconstruction)

任务 (B) 的"还原"主要看:
1. **覆盖**: GT.storyline_steps 列表中, 检测器覆盖了几个
2. **时序**: 检出的 storyline_id 是否大致按 index 顺序
3. **跨度**: 第一个检出事件到最后一个检出事件的时长 vs GT 跨度
4. **混淆度**: 一个真实 storyline 被切成几个不同 storyline_id (误分裂)

输出 JSON:
```json
{
  "storyline_id": "evt-2018-09--04",
  "gt_step_count": 1,
  "detected": true,
  "covered_steps": 1,
  "coverage": 1.0,
  "order_ok": true,
  "duration_ratio": 1.0,
  "score": 1.0
}
```

## 4. 反对"抄答案"的保护

- 检测器模块**只 import** `parsers/` 和 `detectors/`; 不能 `import` evaluation 或读取 GT
- 评测模块**不参与**训练 / 调参, 只是后置对齐
- 每个规则文件 (`detectors/rules/*.py`) 顶部有 `RATIONALE` 注释, 说明该规则的通用知识来源
- 测试 (`tests/`) 验证: 拿掉 GT 文件后, 检测器依然能输出结果
- CI 检查 (可选): grep 检测器目录, 确认无 ground_truth 字样

## 5. 报告产出

`reports/<scenario>/<detector>/` 下:
- `detections.jsonl` — 每条 CanonicalEvent + verdict + reason
- `log_level_metrics.json` — Task A 指标
- `storyline_level_metrics.json` — Task B 指标
- `summary.md` — 人读报告

`reports/global/` 下:
- `all_scenarios.csv` — 每场景一行: P/R/F1 + storyline 还原率
- `report.md` — 总体结论 + 强弱场景对比