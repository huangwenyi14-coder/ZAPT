# Record-Level 黄金检测器

更新日期：2026-07-21

当前黄金检测器版本为 v1.5；版本边界和逐版本评测见
[`GOLD_DETECTOR_CHANGELOG.md`](GOLD_DETECTOR_CHANGELOG.md)。

NEW-Dataset 逐场景运行时间、测试环境和复现口径见
[`GOLD_DETECTOR_RUNTIME_REPORT_2026-07-15.md`](GOLD_DETECTOR_RUNTIME_REPORT_2026-07-15.md)。

## 文件与来源

黄金检测器：

```text
gold/source_informed_chain_detector.py
gold/record_graph_detector.py
```

它从下列检测器完整复制后改造：

```text
/Users/xhb/Desktop/Project/TASK/2026TASK/供应链安全检测/Mythos/Tools/EvidenceForge-main/blind_test/detectors/source_informed_chain_detector.py
```

复制时的上源 SHA-256：

```text
9d628747858e89776dfd8b86813953b7d1bf114f1238bab2293e0d3ef2a3000a
```

本次架构调整前的完整备份：

```text
gold/backups/source_informed_chain_detector.pre-architecture-2026-07-15.py
SHA-256: 9398ab8c1e35e4680544d0868bbbc165291cf31feb562fc63b87761cc238724b
```

当前文件 SHA-256：

```text
gold/source_informed_chain_detector.py
55bf4507a2126327039888dbbeeee2163f3a02703b2777f1b0d30cf12ce37598

gold/record_graph_detector.py
4275b3e59531a3060c98fce33f8730470913514254cc69b33affab3900018b6c
```

后续合并上游时，可用上游复制基线、`pre-architecture`
备份和当前入口脚本进行三方比较；新的 Record Graph 逻辑集中在
`record_graph_detector.py`，避免继续放大上游合并冲突。

## Record-Level 改造

原检测器只输出 finding 级结果。黄金版保留原有 `--input`
模式，并新增：

- `--data-dir`：只含日志的场景数据目录；
- `--record-index`：无标签的 `RECORD_INDEX.jsonl`；
- `--findings-output`：保存原 finding 级中间结果；
- `--output`：输出精确的 `physical_record_id + relative_path + record_index`
  预测。
- `--predict-storyline-tactics`：可选；输出由已选物理证据支撑的 ATT&CK
  Storyline 战术阶段声明。默认关闭。

当前 Record-Level 模式由 `record_graph_detector.py` 执行，逻辑为：

1. 仅从无标签 `RECORD_INDEX.jsonl` 读取明确的格式和字段白名单，统一
   标准化 Sysmon、Security、Zeek、eCAR、ASA、Proxy、Web、Snort、Syslog
   和 Bash 记录。
2. Beacon、终端行为、计划任务、端点行为、进程异常、模块行为、Web exploit、
   单次网络事务、身份异常、制品序列和 IOC 十一个发现引擎每次都独立运行，
   任何一路命中都不会阻止其他引擎。
3. Beacon 使用 20 秒到 4 小时的自适应周期拟合，并检查完整间隔序列。短周期
   至少需要 8 个间隔，长周期至少需要 4 个间隔；所有间隔都必须能由同一基础
   周期或其整数倍解释，避免从随机背景流量中挑选局部等间隔子序列。目的地址
   为私网时仍按原策略排除，不在 v1.3 中放宽。
4. 终端规则是 Sigma 风格的复合行为规则，包括 SAM/NTDS 导出、
   comsvcs MiniDump、portproxy、可写目录持久化和高置信工具名；
   不依赖 YARA 扫描原始文件内容。
5. GeoServer `valueReference=exec(Runtime...)`、JNDI 和模板表达式命令执行
   由 Web 引擎直接生成锚点，无需等待终端或 Beacon 证据。
6. 进程图区分 eCAR `actorID/objectID`，使用 `host+ProcessGuid` 或
   `host+PID+生命周期+image`；已命中的 `process_create` 会确定性地纳入
   同一精确实例的 `process_terminate`。PID 复用后的记录不会继承。
7. 父子进程只允许一跳；子进程自身的精确生命周期可完整展开，但不继续
   向孙进程扩散。长时间共享浏览器也不会因一次 C2 连接而纳入其他流量。
8. 网络展开只使用有边界强边：eCAR FLOW `actorID`、五元组+时间窗、
   Zeek UID/FUID、DNS answer→后续连接、ASA connection ID 和相邻 NAT 对。
   缺少目的字段的 Security 5156 必须同时满足主机、精确源端口和
   500 ms 时间窗。
9. Proxy 请求先通过客户端 IP、目标域名、代理端口和 5 秒窗口映射到
   内部 Zeek HTTP/conn，再通过代理主机 DNS 和外连五元组展开。只允许
   从已选中 Proxy 锚点派生的 DNS 正向传播，内网系统端口连接不能反向
   污染 DNS 图。
10. 终端规则修正了 `schtasks /create` 和 `C:\\Windows\\Tasks` 匹配，并新增
    有边界的复合序列（域管理员枚举→WMI、CLSID 清理→Explorer 重启、
    certutil 解码→解压）以及 DUSTTRAP `One.exe/auth.json/.rar` 链。
11. v1.3 新增 Office→LOLBin、可写目录执行、双扩展、系统程序仿冒和
    Security 4698 计划任务规则；单次网络事务只有在精确进程实例或
    `host+PID+生命周期` 已被高置信行为规则命中时才形成锚点。
12. Security 记录按 EventID 使用专用字段映射：4688 区分新进程与创建者，
    4698 提取任务名称/内容，5156 提取应用、方向、地址、端口和协议；不再跨
    EventID 混用同名字段。
13. 禁止按“同 PID 全部记录”、“同主机时间窗”或“跨长时间 ProcessGuid”
   无条件传播。每条预测都输出 `association_strength` 和 `anchor_engine`
   以便审计。
14. v1.5 增加高约束的 Flash/SWF 与“RTF 打开后同一精确进程落地可执行
    制品”入口锚点；精确同主机文件路径可以展开到后续模块加载。
15. Storyline 战术推断使用有界进程和网络事务上下文：凭据语义优先于通用
    文件读取，连通性探测、凭据暂存后外传、下载后精确落地分别映射为
    Discovery、Exfiltration 和 Command and Control；LOLBin 战术不再传播到
    同一进程产生的全部文件记录。
16. 生成框架与 blind workspace 对齐完整 Sysmon 公开字段，包含模块路径、
    签名状态及注册表 `TargetObject/Details`；旧数据会从原始 Windows 日志字节
    重建公开 Record Index，不读取或复制标签。

### 无标签约束

黄金检测器只读取场景日志和经过清洗的 `RECORD_INDEX.jsonl`。
`load_record_index()` 会递归拒绝任意层级的 `label`、`storyline_id`、
`logical_event_id` 等私有标签/归因字段，并校验：

- `physical_record_id` 和 `(relative_path, record_index)` 唯一；
- record index 连续性；
- 路径不能逃逸 `data/`；
- byte offset/length 有效；
- `record_sha256` 与当前日志字节完全一致。

`RECORD_GROUND_TRUTH.jsonl` 仅由评测器在预测完成后读取，不会传入检测器。
启用战术预测时，检测器也不会读取 `label/*.labels.json`；它不知道真实
`storyline_id`，只提交证据物理 ID、战术名称、置信度和原因。

## 运行方法

先准备隔离且无标签的工作区：

```bash
python3 blind_test/record_level_claude_eval.py prepare \
  --scenario-dir /Users/xhb/Desktop/Project/TASK/2026TASK/供应链安全检测/Mythos/Tools/EvidenceForge-main/scenarios/operation-dragon-whistle-record-eval \
  --work-dir /private/tmp/evidenceforge-dragon-whistle-gold \
  --force
```

运行黄金检测器：

```bash
python3 gold/source_informed_chain_detector.py \
  --data-dir /private/tmp/evidenceforge-dragon-whistle-gold/blind/data \
  --record-index /private/tmp/evidenceforge-dragon-whistle-gold/blind/RECORD_INDEX.jsonl \
  --findings-output gold/operation-dragon-whistle-record-eval/findings.json \
  --output gold/operation-dragon-whistle-record-eval/predictions.json \
  --predict-storyline-tactics
```

只在预测完成后评测：

```bash
python3 blind_test/record_level_claude_eval.py evaluate \
  --scenario-dir /Users/xhb/Desktop/Project/TASK/2026TASK/供应链安全检测/Mythos/Tools/EvidenceForge-main/scenarios/operation-dragon-whistle-record-eval \
  --work-dir gold/operation-dragon-whistle-record-eval \
  --predictions gold/operation-dragon-whistle-record-eval/predictions.json \
  --confidence-threshold 0.50
```

评测结果同时输出三套指标：

- `record_metrics`：以 `physical_record_id` 为单位；
- `logical_event_metrics`：评测端根据私有 Ground Truth 回挂
  `logical_event_id` 后聚合；
- `storyline_metrics`：评测端根据 `storyline_id` 聚合。普通背景日志的
  `storyline_id=null` 在每个场景内合并成一个良性背景组，未误报时计为
  一个 TN，任意背景记录被预测为恶意时计为一个 FP。

三套结果均包含 TP、FP、FN、TN、Accuracy、Precision、Recall 和 F1。
主分数仍是 record-level F1，高层指标用于衡量 canonical 事件和攻击步骤
覆盖效果。检测器本身仍然看不到 `storyline_id` 或 `logical_event_id`。

可选 Storyline 战术评分：

```bash
python3 blind_test/record_level_claude_eval.py evaluate \
  --scenario-dir /absolute/path/to/generated-scenario \
  --work-dir /absolute/path/to/evaluation-work \
  --predictions /absolute/path/to/predictions.json \
  --confidence-threshold 0.50 \
  --evaluate-storyline-tactics \
  --storyline-tactic-labels /absolute/path/to/<scenario>.labels.json
```

战术评分按唯一 `(storyline_id, tactic)` 对计算 Precision、Recall 和 F1；
Accuracy 定义为真实与预测 Storyline 组中战术集合完全一致的组所占比例。主分数
仍为 Physical Record F1，战术分数是独立的附加指标。

只用于审计全部时间推断候选的包含式评估：

```bash
python3 blind_test/record_level_claude_eval.py evaluate \
  --scenario-dir /Users/xhb/Desktop/Project/TASK/2026TASK/供应链安全检测/Mythos/Tools/EvidenceForge-main/scenarios/operation-dragon-whistle-record-eval \
  --work-dir gold/operation-dragon-whistle-record-eval/audit-inclusive \
  --predictions gold/operation-dragon-whistle-record-eval/predictions.json \
  --confidence-threshold 0.30
```

## Dragon Whistle 历史实测结果（2026-07-12 旧展开器）

数据集总记录数 39,020，其中恶意 493、非恶意 38,527（含 40 条
red herring）。检测器输出 493 条候选：461 条强/组合关联，32 条仅时间
关联。

默认严格评估（`confidence >= 0.50`）：

| 指标 | 数值 |
| --- | ---: |
| TP | 461 |
| FP | 0 |
| FN | 32 |
| TN | 38,527 |
| Accuracy | 0.9992 |
| Precision | 1.0000 |
| Recall | 0.9351 |
| F1 | 0.9665 |

32 条仅时间关联记录为：29 条域控 Security 5156、1 条 Sysmon Event
22、1 条 Zeek DNS 和 1 条同 UID Zeek conn。它们仍保留用于审计。若使用
`confidence >= 0.30` 的包含式评估，TP=493、FP=0，四项指标仍为 1.0；
该结果不应与默认严格指标混用。

详细产物：

```text
gold/operation-dragon-whistle-record-eval/findings.json
gold/operation-dragon-whistle-record-eval/predictions.json
gold/operation-dragon-whistle-record-eval/results/evaluation.json
gold/operation-dragon-whistle-record-eval/results/evaluation.md
gold/operation-dragon-whistle-record-eval/audit-inclusive/results/evaluation.json
gold/operation-dragon-whistle-record-eval/audit-inclusive/results/evaluation.md
```

这是架构调整前的场景定向结果，仅用于回溯，不能与新的
Record Graph 模式混用。

## NEW-Dataset 最终回归评测

2026-07-15 对 10 个场景、366,080 条物理记录进行严格
`confidence >= 0.50` 评测。Ground Truth 来自各场景的
`generated-lifecycle-fixed-2026-07-15`，预测过程只读无标签 blind 数据和
Record Index。

| 指标 | 微平均 | 宏平均（场景） |
| --- | ---: | ---: |
| TP / FP / FN / TN | 3,172 / 0 / 1,079 / 361,829 | — |
| Accuracy | 0.9971 | 0.9955 |
| Precision | 1.0000 | 1.0000 |
| Recall | 0.7462 | 0.6784 |
| F1 | 0.8546 | 0.8031 |

相比同一 Ground Truth 上的 Record Graph 首版（TP=2,155、FP=0、
Recall=0.5069、F1=0.6728），本次增加 1,017 个 TP，减少 1,017 个 FN，
Recall 提升 0.2392，F1 提升 0.1818，且 FP 保持为 0。详细评测和审计见：

```text
evaluation_runs/NEW-Dataset-2026-07-15-recall-fixes-final/SUMMARY.md
evaluation_runs/NEW-Dataset-2026-07-15-recall-fixes-final/gold/<scenario>/results/
docs/worklog/2026-07-15-record-detectability-and-gold-recall.md
```

## 验证

```bash
uv run ruff check gold/source_informed_chain_detector.py \
  gold/record_graph_detector.py \
  tests/unit/test_gold_source_informed_chain_detector.py \
  tests/unit/test_gold_record_graph_detector.py
uv run ruff format --check gold/source_informed_chain_detector.py \
  gold/record_graph_detector.py \
  tests/unit/test_gold_record_graph_detector.py
uv run pytest -q tests/unit/test_gold_source_informed_chain_detector.py \
  tests/unit/test_gold_record_graph_detector.py
```
