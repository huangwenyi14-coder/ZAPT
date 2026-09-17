# 黄金检测器版本记录

## v1.5（2026-07-21）

v1.5 针对 20260717 回归中 DarkHotel 的入口链缺失和 Donot/Lazarus/Spyder
的战术误归因做了结构化修复：

- 增加 Explorer→旧版 Flash→SWF 和 Explorer→Word→RTF 后同一精确进程
  落地 DLL/EXE 的高约束入口锚点；
- 精确同主机制品路径可展开到后续模块加载，仍不允许同 PID、整台主机或长
  ProcessGuid 无条件传播；
- 战术推断改用有界进程实例与 30 秒网络事务上下文，区分凭据访问、凭据暂存、
  外传、连通性探测、下载落地、压缩包解包和 LOLBin 精确载荷引用；
- 普通同进程 DLL 加载不再自动产生 Execution；仅精确落地后加载或显式未签名
  模块加载产生 Execution，真正的侧载理由仍归 Defense Evasion；
- 生成框架的 Sysmon 公开 sidecar 新增 `ImageLoaded`、签名、注册表
  `TargetObject/Details` 等字段；blind workspace 对旧场景会从原始 Sysmon 与
  Security 日志字节重建这些公开字段，全程不读取标签；
- Donot 的 `T1074.001` 两个事件由 Execution 更正为 Collection：
  `evt-donot-copy-gtue` 与 `evt-donot-write-credential-output`。

20260717 六场景、260,138 条物理记录最终回归：

| 层级 | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Physical Record | 389 | 0 | 156 | 259,593 | 0.999400 | 1.000000 | 0.713761 | 0.832976 |
| Logical Event | 142 | 0 | 59 | 120,940 | 0.999513 | 1.000000 | 0.706468 | 0.827988 |
| Storyline | 81 | 0 | 5 | 6 | 0.945652 | 1.000000 | 0.941860 | 0.970060 |
| Storyline × Tactic | 70 | 7 | 16 | — | 0.790698 | 0.909091 | 0.813953 | 0.858896 |

相对 v1.4，Physical Record TP 增加 36、F1 从 0.786192 提升到 0.832976；
Storyline F1 从 0.904459 提升到 0.970060；Storyline × Tactic F1 从
0.649351 提升到 0.858896。DarkHotel Storyline F1 从 0.666667 提升到
1.000000，Donot Storyline × Tactic F1 从 0.458333 提升到 0.943396。

最终结果目录：

```text
/Users/xhb/Desktop/Project/TASK/2026TASK/ShuZiYiJing/Datacon2026比赛支持/数据质量评估/20260717/evaluation_runs/gold-v1.5-final2-2026-07-21/
```

详细说明见 `docs/worklog/2026-07-21-gold-detector-v1.5.md`。

## v1.4（2026-07-21）

v1.4 新增默认关闭的 Storyline 战术阶段预测：

- 黄金检测器增加 `--predict-storyline-tactics`；
- 检测器仍看不到真实 `storyline_id`、`ta` 或 TTP 标签，只输出由已预测
  `physical_record_id` 支撑的 `storyline_tactic_predictions`；
- 评分器增加 `--evaluate-storyline-tactics` 和
  `--storyline-tactic-labels`，只在预测完成后将证据映射到私有 Storyline；
- 战术 Precision、Recall 和 F1 按唯一 `(storyline_id, tactic)` 对计算；
  Accuracy 是每个 Storyline 的战术集合完全匹配率；
- 默认不开启时，原有 Physical Record、Logical Event 和 Storyline 输出与
  评分路径不增加战术字段。

20260717 六场景回归：原三层指标与 v1.3 完全一致；新增战术指标为：

| 层级 | TP | FP | FN | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Storyline × Tactic | 50 | 18 | 36 | 0.558140 | 0.735294 | 0.581395 | 0.649351 |

战术标签来自预测完成后才由评分器读取的
`label/<scenario>.labels.json::predicted_storyline[].ta`。检测器没有读取该目录。

结果目录：

```text
/Users/xhb/Desktop/Project/TASK/2026TASK/ShuZiYiJing/Datacon2026比赛支持/数据质量评估/20260717/evaluation_runs/gold-v1.4-tactics-2026-07-21/
```

## v1.3（2026-07-17）

v1.3 的代码版本号同时写入
`gold/record_graph_detector.py::DETECTOR_VERSION`、`gold/DETECTOR_VERSION`
和预测结果的 `detector_version` 字段。

主要变化：

- Beacon 改为校验完整回连间隔序列：短周期至少 8 个间隔，长周期至少 4 个
  间隔；所有间隔都必须能由同一个基础周期或其整数倍解释，直接周期间隔占比
  至少 75%，不再从噪声连接中挑选局部等间隔子序列；
- 保留原有私网目的地址 Beacon 排除条件，本版本没有放宽该条件；
- 新增 Office→LOLBin、用户可写目录执行、双扩展、系统程序仿冒、计划任务和
  进程所有权明确的单次网络事务发现规则；
- 新增 Security EventID 专用公开字段映射，分别处理 4624、4688、4689、4698
  和 5156，修正 4688 父/子 PID、镜像角色以及 5156 网络字段语义；
- blind workspace 在准备阶段按原始日志字节重新提取 Security 公开关联字段，
  旧版 Record Index 也可以使用新映射，同时不接触 Ground Truth；
- 收紧 PowerShell、模块加载与可写目录规则，普通 `Compress-Archive` 和 Zoom
  用户目录模块不会被误判。

20260717 数据集 6 场景、260,138 条物理记录最终回归：

| 层级 | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Physical Record | 353 | 0 | 192 | 259,593 | 0.999262 | 1.000000 | 0.647706 | 0.786192 |
| Logical Event | 129 | 0 | 72 | 120,940 | 0.999406 | 1.000000 | 0.641791 | 0.781818 |
| Storyline | 71 | 0 | 15 | 6 | 0.836957 | 1.000000 | 0.825581 | 0.904459 |

相比同一数据上的 v1.2，Physical Record TP 从 7 增至 353、FP 从 209
降至 0、F1 从 0.018397 提升到 0.786192。原先由局部周期误判产生的
Beacon 背景锚点已全部消除。

最终结果目录：

```text
/Users/xhb/Desktop/Project/TASK/2026TASK/ShuZiYiJing/Datacon2026比赛支持/数据质量评估/20260717/evaluation_runs/gold-v1.3-2026-07-17/
```

## v1.2（2026-07-16）

v1.2 的代码版本号同时写入
`gold/record_graph_detector.py::DETECTOR_VERSION` 和预测结果的
`detector_version` 字段。

主要变化：

- 新增独立的终端行为、复合进程异常、模块行为、单次网络行为、身份异常和
  高风险制品序列发现引擎；
- 新增文件落地到后续执行、网络会话到登录、精确 Logon ID 的有边界关联边；
- 扩充 Sysmon、Security 和 eCAR 的公开 Record Index 字段白名单，支持模块路径、
  签名状态、原始文件名、身份认证和进程访问字段；
- 收紧长生命周期进程的普通模块传播，后续模块必须独立满足侧载或签名异常；
- 身份展开只能从登录/认证证据出发，避免 SYSTEM SubjectLogonId 污染；
- 新增 v1.2 低误报规则、文件图、模块图和身份图单元测试。

NEW-Dataset 10 场景、366,080 条物理记录最终回归：

| 层级 | TP | FP | FN | Precision | Recall | F1 | 场景宏 F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Physical Record | 3,313 | 0 | 938 | 1.000000 | 0.779346 | 0.875992 | 0.848891 |
| Logical Event | 1,072 | 0 | 327 | 1.000000 | 0.766262 | 0.867665 | 0.838014 |
| Storyline | 50 | 0 | 9 | 1.000000 | 0.847458 | 0.917431 | 0.878419 |

最终结果目录：

```text
/Users/xhb/Desktop/Project/TASK/2026TASK/供应链安全检测/Mythos/Tools/TestandValid/EvidenceForge-main/evaluation_runs/NEW-Dataset-2026-07-16-gold-v1.2-final/
```

## v1.1（基线）

v1.1 对应 v1.2 修改前的 Record Graph 检测器，Git 基线提交为：

```text
61a7ec57b92d1726bd160728b3373aa90a8cd0c8
```

NEW-Dataset 基线结果：

| 层级 | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Physical Record | 3,172 | 0 | 1,079 | 1.000000 | 0.746177 | 0.854641 |
| Storyline | 33 | 0 | 26 | 1.000000 | 0.559322 | 0.717391 |

基线结果目录：

```text
/Users/xhb/Desktop/Project/TASK/2026TASK/供应链安全检测/Mythos/Tools/TestandValid/EvidenceForge-main/evaluation_runs/NEW-Dataset-2026-07-15-recall-fixes-final/
```

从 v1.1 到 v1.2：Physical Record TP 增加 141，Storyline TP 增加 17，两个
层级的 FP 都保持为 0。
