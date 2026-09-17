# Storyline、Logical Event 与 Physical Record 三层关系说明

更新日期：2026-07-16

适用范围：EvidenceForge 数据生成、Record Ground Truth、黄金检测器和三层评测

## 1. 一句话理解

三层 ID 分别回答三个不同问题：

```text
storyline_id：攻击者正在完成哪个攻击步骤？
logical_event_id：为了完成该步骤，系统实际发生了哪个动作？
physical_record_id：这个动作最终在哪个日志源中留下了哪条记录？
```

对应关系通常是：

```text
一个 Storyline
  └── 多个 Logical Event
        └── 每个 Logical Event 扇出为一条或多条 Physical Record
```

也可以简化为：

```text
攻击步骤 → 系统动作 → 日志记录
Storyline → Logical Event → Physical Record
```

## 2. 三种 ID 的定义

| ID | 粒度 | 主要含义 | 产生方式 |
| --- | --- | --- | --- |
| `storyline_id` | 攻击步骤级 | 一段有业务语义的攻击活动 | 场景作者在 scenario YAML 中命名 |
| `logical_event_id` | canonical 事件级 | 系统中一次具体的安全动作 | 生成器为 canonical `SecurityEvent` 自动分配 |
| `physical_record_id` | 最终物理记录级 | 某个具体日志源中的一条最终原子记录 | 日志输出完成后根据位置和内容自动生成 |

### 2.1 storyline_id

`storyline_id` 表示一个完整攻击步骤，例如：

```text
baxia-002-curl-delivery
```

该步骤的语义可以是：

> 被入侵的 GeoServer 使用 curl 下载 Edge.exe、msedge.dll 和 Logs.txt。

Storyline 关注的是攻击叙事和步骤覆盖，不等于一条日志，也不等于一个系统调用。
一个 Storyline 通常需要多个系统动作共同完成。

### 2.2 logical_event_id

`logical_event_id` 表示系统中一次 canonical 安全事件，例如：

- 一次进程创建；
- 一次网络连接；
- 一次 DNS 查询；
- 一次文件创建；
- 一次登录；
- 一次进程终止。

示例：

```text
le-process-curl    curl.exe 被启动
le-http-download  curl 建立一次 HTTP 下载连接
le-file-create    Edge.exe 被写入磁盘
```

这些名称是为了便于阅读而写的概念示例。真实 EvidenceForge ID 通常是：

```text
le-9a0e9e7d426fb0a1745b3930
```

Logical Event 用来解决多日志源重复观察同一动作的问题。例如，同一次进程启动
可能同时产生 Sysmon、Windows Security 和 eCAR 记录，但它在系统语义上仍然
只发生了一次。

### 2.3 physical_record_id

`physical_record_id` 表示最终输出中的一条物理日志记录，例如：

```text
pr-aca24f29b25d20680e90fe94
```

这里的“物理记录”是指最终发布日志文件中的原子记录，而不是生成器内部尚未
渲染的临时事件。

例如，同一次进程启动可以产生：

```text
Sysmon Event 1       → 一个 physical_record_id
Security Event 4688  → 一个 physical_record_id
eCAR PROCESS/CREATE  → 一个 physical_record_id
```

每条物理记录拥有自己的文件路径、文件内序号、字节位置和内容哈希。

## 3. 完整的通俗示例

假设攻击者执行一个步骤：

> 使用 curl 下载 Edge.exe。

整个攻击步骤为：

```text
storyline_id = baxia-002-curl-delivery
```

为了完成该步骤，系统中至少发生三个 Logical Event。

### 3.1 Logical Event 1：启动 curl.exe

```text
logical_event_id = le-process-curl
event_type       = process_create
```

同一个进程启动动作可能被三个日志源观察到：

```text
Sysmon Event 1       → physical_record_id = pr-001
Security Event 4688  → physical_record_id = pr-002
eCAR PROCESS/CREATE  → physical_record_id = pr-003
```

### 3.2 Logical Event 2：建立 HTTP 下载连接

```text
logical_event_id = le-http-download
event_type       = connection
```

同一个网络动作可能扇出为：

```text
Zeek conn.log         → physical_record_id = pr-004
Zeek http.log         → physical_record_id = pr-005
Proxy access log      → physical_record_id = pr-006
Cisco ASA connection  → physical_record_id = pr-007
eCAR FLOW             → physical_record_id = pr-008
```

### 3.3 Logical Event 3：Edge.exe 写入磁盘

```text
logical_event_id = le-file-create
event_type       = file_create
```

可能产生：

```text
Sysmon Event 11   → physical_record_id = pr-009
eCAR FILE/CREATE  → physical_record_id = pr-010
```

### 3.4 完整层级

```text
storyline_id = baxia-002-curl-delivery
│
├── logical_event_id = le-process-curl
│   ├── pr-001  Sysmon Event 1
│   ├── pr-002  Security Event 4688
│   └── pr-003  eCAR PROCESS/CREATE
│
├── logical_event_id = le-http-download
│   ├── pr-004  Zeek conn
│   ├── pr-005  Zeek HTTP
│   ├── pr-006  Proxy
│   ├── pr-007  Cisco ASA
│   └── pr-008  eCAR FLOW
│
└── logical_event_id = le-file-create
    ├── pr-009  Sysmon Event 11
    └── pr-010  eCAR FILE/CREATE
```

这个示例中的 ID 和扇出数量用于解释概念，实际生成结果取决于场景、日志源部署、
网络可见性和 observation profile。

## 4. 为什么不能只保留 Storyline 和 Physical Record

如果没有 `logical_event_id`，同一个进程启动的三个日志投影会被理解成三件独立
的事情：

```text
Sysmon Event 1
Security Event 4688
eCAR PROCESS/CREATE
```

但它们实际都在描述：

```text
同一次 curl.exe 进程启动
```

`logical_event_id` 将这些多源记录统一到一个 canonical 动作下：

```text
pr-001、pr-002、pr-003
  → logical_event_id = le-process-curl
```

因此 Logical Event 是攻击步骤和物理日志之间不可缺少的中间层。

## 5. 三层评测分别衡量什么

检测器始终提交 `physical_record_id + relative_path + record_index`。评测器读取
私有 Ground Truth 后，将有效物理预测向上聚合到 Logical Event 和 Storyline。

### 5.1 Physical Record 层

衡量原子日志证据是否被完整、准确地标出：

```text
命中一条恶意 physical_record_id → 一个 Record TP
误报一条良性 physical_record_id → 一个 Record FP
漏掉一条恶意 physical_record_id → 一个 Record FN
```

它主要回答：

> 具体标出的日志行是否正确，所有物理证据是否完整展开？

### 5.2 Logical Event 层

同一 `logical_event_id` 下只要命中至少一条有效物理记录，就认为该 Logical
Event 被发现。

它主要回答：

> 系统中发生的进程、连接、文件、登录等具体动作发现了多少？

### 5.3 Storyline 层

同一恶意 `storyline_id` 下只要至少一个 Logical Event 的物理记录被命中，就认为
该攻击步骤被发现。

它主要回答：

> 整条攻击叙事中的攻击步骤发现了多少？

## 6. 为什么三层 Recall 不一样

继续使用前面的示例。假设：

```text
1 个恶意 Storyline
3 个恶意 Logical Event
10 条恶意 Physical Record
```

检测器只命中了 Zeek HTTP 对应的 `pr-005`，则：

```text
Physical Record Recall = 1 / 10 = 0.10
Logical Event Recall   = 1 / 3  = 0.33
Storyline Recall       = 1 / 1  = 1.00
```

它们没有互相矛盾，而是在回答不同问题：

- Record Recall 低：大量具体日志证据尚未展开；
- Logical Event Recall 较低：三个系统动作只发现了一个；
- Storyline Recall 为 1：已经知道“curl 下载 Edge.exe”这个攻击步骤存在。

因此不能只用一个层级的分数替代另外两个层级。

## 7. 背景记录为什么合并为一个良性组

普通背景日志通常没有攻击步骤，因此：

```text
storyline_id = null
```

但它们仍然具有 `logical_event_id` 和 `physical_record_id`。

当前评测策略将每个场景中所有 `storyline_id=null` 的普通背景记录合并为一个
良性背景组：

```text
场景内全部普通背景记录
  ├── 正常进程、网络与文件活动
  ├── 同一动作的多日志源物理记录
  └── 其他没有攻击步骤归属的基线噪声

→ 共同组成一个 storyline_id=null 的良性背景组
```

该组的计分规则是：

```text
未命中任何背景物理记录 → 背景组贡献一个 TN
命中一条或多条背景记录 → 背景组贡献一个 FP
```

因此，Storyline 层只回答检测器是否把普通背景误判成攻击步骤，不按照背景
`logical_event_id` 的数量重复计算 FP。具体误报数量和范围仍由 Physical Record
层与 Logical Event 层分别衡量。

## 8. 基线和 Red Herring 的区别

| 类型 | `storyline_id` | 标签 | 评测含义 |
| --- | --- | --- | --- |
| 恶意攻击步骤 | 非空 | `malicious` | 正类 Storyline |
| Red Herring | 通常为 `red_herring:<id>` | `red_herring` | 有完整叙事的困难负样本 |
| 普通背景 | `null` | `benign` | 每个场景合并成一个良性背景组 |

Red Herring 本身是一段专门设计的良性活动，因此可以拥有 Storyline；普通基线
日志不是攻击叙事的一部分，所以没有 Storyline。

## 9. 常见误解

### 误解一：一个 storyline_id 就是一条日志

错误。一个 Storyline 可以包含多个 Logical Event，并进一步产生大量物理日志。

### 误解二：一个 logical_event_id 只能对应一条日志

错误。一个 canonical 动作可以被多个日志源同时观察，因此通常对应多条
Physical Record。

### 误解三：相同 PID 的日志都是同一个 logical_event_id

错误。同一个进程实例可以产生进程创建、文件操作、网络连接、模块加载和进程
终止等多个不同 Logical Event。PID 只是关联特征，不是事件主键。

### 误解四：Physical Record 是生成器内部最早的事件

错误。`physical_record_id` 对应最终日志文件中已经完成渲染和排序的原子记录；
生成器内部更早的统一语义对象是 canonical `SecurityEvent`，由
`logical_event_id` 标识。

### 误解五：Storyline Recall 高就表示日志定位完整

错误。Storyline Recall 只说明攻击步骤被发现，具体物理记录是否完整应继续查看
Logical Event Recall 和 Physical Record Recall。

## 10. 使用建议

建议评测报告始终同时输出：

```text
Storyline Recall       攻击步骤覆盖率
Logical Event Recall   系统动作覆盖率
Physical Record Recall 原子日志覆盖率
Physical Record Precision/F1 具体日志误报和综合定位质量
```

三层指标的合理解释是：

```text
Storyline 层确认“有没有发现攻击步骤”；
Logical Event 层确认“发现了哪些具体行为”；
Physical Record 层确认“具体证据是否完整且准确”。
```

## 11. 相关文档

- [`三字段精准定位契约.md`](三字段精准定位契约.md)：说明
  `physical_record_id + relative_path + record_index` 如何精确定位日志记录；
- [`RECORD_IDENTITY_AND_ID_GENERATION.md`](RECORD_IDENTITY_AND_ID_GENERATION.md)：
  说明三种 ID 的生成公式、稳定性边界和完整评测契约。
