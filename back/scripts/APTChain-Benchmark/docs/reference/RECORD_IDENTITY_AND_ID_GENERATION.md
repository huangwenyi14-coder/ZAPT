# EvidenceForge 记录身份与 ID 生成契约

更新日期：2026-07-15
适用范围：`RECORD_GROUND_TRUTH.jsonl` schema v3

## 1. 目的与范围

本文档用于统一场景编写、数据生成、检测、标注和评测人员对以下
标识符的理解：

- `dataset_id`：生成数据集标识；
- `storyline_id`：攻击或 red-herring 步骤标识；
- `logical_event_id`：canonical `SecurityEvent` 标识；
- `physical_record_id`：最终原子物理日志记录标识。

本契约描述当前代码的实际行为，不把“数据集内唯一”夸大为跨版本、
跨数据发布永久不变的 UUID 承诺。

## 2. ID 层级

```text
dataset_id
  └── storyline_id                         攻击步骤，由场景作者命名
        └── logical_event_id                  canonical SecurityEvent
              ├── physical_record_id              Sysmon Event
              ├── physical_record_id              Windows Security Event
              ├── physical_record_id              Zeek conn/http/dns
              ├── physical_record_id              eCAR FLOW/PROCESS
              └── physical_record_id              ASA/Proxy/Web/Snort 等
```

一个 `storyline_id` 可以包含多个 `logical_event_id`。一个逻辑事件可以被多种
日志源观测，因此可以扇出多个 `physical_record_id`。

基线噪声记录的 `storyline_id` 为 `null`，但仍然拥有 `logical_event_id` 和
`physical_record_id`。

## 3. dataset_id

### 3.1 当前公式

```text
dataset_key =
    scenario.name
    | scenario.time_window.start.isoformat()
    | output_target.value

dataset_id =
    "ds-" + SHA256(UTF8(dataset_key)).hexdigest()[0:24]
```

示例：

```text
ds-df021ef6cd52022394d71793
```

24 个十六进制字符等于 96 bit 截断 SHA-256。

### 3.2 唯一性边界

当前 `dataset_id` **不包含**完整 scenario YAML 内容哈希、随机种子、
EvidenceForge 版本、Ground Truth schema 版本和生成结束时间。

因此，如果两份不同 YAML 拥有相同的场景名、开始时间和 output target，
它们会得到相同的 `dataset_id`。当前实现保证的是已生成数据集内的记录
一致性，不是所有历史数据发布之间的强全局唯一性。

## 4. storyline_id

### 4.1 生成方式

`storyline_id` 不是哈希值。它直接来自 scenario YAML 中由作者编写的 ID：

```yaml
storyline:
  - id: evt-001
    time: "+55m"
    actor: www-data
    system: WEB-BO-01
    events:
      - type: web_scan
```

```text
普通攻击步骤：storyline_id = scenario.storyline[i].id
red herring：   storyline_id = "red_herring:" + scenario.red_herrings[i].id
baseline/raw：  storyline_id = null
```

### 4.2 唯一性和稳定性

- validator 要求 `scenario.storyline[].id` 在当前场景中不重复；
- 只要场景作者不改名，`storyline_id` 就可以跨重生成保持稳定；
- 它本身不承诺跨场景唯一，不同场景都可以有 `evt-001`；
- 跨场景交换时，应使用 `(dataset_id, storyline_id)` 表达所属关系。

## 5. logical_event_id

### 5.1 生成公式

Record Ground Truth recorder 在每次生成中从 `logical_counter = 0` 开始。
当 canonical `SecurityEvent` 尚无 ID 时，在分发顺序上加一并生成：

```text
logical_counter = logical_counter + 1

logical_payload =
    dataset_id
    | "logical"
    | logical_counter
    | event_type

logical_event_id =
    "le-" + SHA256(UTF8(logical_payload)).hexdigest()[0:24]
```

示例：

```text
le-f6a021bbeff1f1b9e472f760
```

### 5.2 语义和稳定性

`logical_event_id` 标识一个 canonical `SecurityEvent`，例如一次 process create、
process terminate、connection、DNS query、logon 或 file create。它不是最终
物理日志数量。

`logical_event_id` 依赖 `logical_counter`，而 counter 依赖 canonical 事件分发顺序。
因此：

- 同一代码、同一场景、同一随机配置和相同分发顺序下可复现；
- 插入一个新 canonical 事件可能使之后所有 counter 位移；
- 更改 causal expansion、事件排序或生成器版本可能改变 ID；
- 它不应被当作跨不同重生成版本永久不变的业务 ID。

## 6. physical_record_id

### 6.1 生成公式

在所有 emitter/finalizer 完成后，对每个最终原子物理记录计算：

```text
record_sha256 = SHA256(final_record_bytes).hexdigest()

physical_payload =
    dataset_id
    | "physical"
    | relative_path
    | record_index
    | record_sha256

physical_record_id =
    "pr-" + SHA256(UTF8(physical_payload)).hexdigest()[0:24]
```

示例：

```text
pr-c0ce111969b6c257dc5bcdc3
```

### 6.2 记录定位

`physical_record_id` 是不可逆的记录主键，不能从 ID 反解出文件和行号。
精确定位使用下列 sidecar 字段：

```text
relative_path          相对于生成 data 根目录的 POSIX 路径
record_index           该文件中从 0 开始的原子记录序号
byte_offset            记录起始字节偏移
byte_length            记录字节长度
record_sha256          最终记录字节的完整 SHA-256
```

对一行一记录的日志，`record_index = 914` 通常对应文本编辑器中的
第 915 行。对 XML `<Event>`、多行 Bash history 或其他多行记录，
`record_index` 不等于文本行号，应使用字节偏移和哈希定位。

源文件如果在 finalizer 阶段被重写，recorder 会从最终文件重新计算
记录序号、字节定位、`record_sha256` 和 `physical_record_id`。

### 6.3 ID 变化条件

任一下列变化都会使 `physical_record_id` 变化：

- `dataset_id` 变化；
- 文件相对路径变化；
- 前面插入/删除记录，导致 `record_index` 变化；
- 字段、空格、换行或编码变化，导致 `record_sha256` 变化。

因此它表示“这一版数据中这一条最终物理记录”，不是日志内容在所有
未来重生成中的永久身份。

## 7. 完整扇出示例

当前 branch-office 数据中：

```text
dataset_id       = ds-df021ef6cd52022394d71793
storyline_id     = evt-001
logical_event_id = le-f6a021bbeff1f1b9e472f760
event_type       = connection
```

这一个 logical connection 扇出为 7 条物理记录：

| source_format | physical_record_id | 原子日志位置 |
| --- | --- | --- |
| `cisco_asa` | `pr-c0ce111969b6c257dc5bcdc3` | `FW-BO-EDGE/cisco_asa.log`, index 914 |
| `cisco_asa` | `pr-ebdb26225fd01808ecaf6e43` | `FW-BO-EDGE/cisco_asa.log`, index 915 |
| `snort_alert` | `pr-1d4e0133639133d3e7e05766` | `IDS-BO-EDGE/snort_alert.log`, index 12 |
| `ecar` | `pr-833f140b9a85327f53759a96` | `WEB-BO-01.northstar-branch.local/ecar.json`, index 344 |
| `web_access` | `pr-2aebf7acc6f519b58290a51d` | `WEB-BO-01.northstar-branch.local/web_access.log`, index 125 |
| `zeek_conn` | `pr-4397a18dd63f8110c1969618` | `ZEEK-BO-CORE/conn.json`, index 948 |
| `zeek_http` | `pr-11a9ea9e19ba18a9e3348544` | `ZEEK-BO-CORE/http.json`, index 101 |

```text
攻击步骤数量      != canonical 事件数量
canonical 事件数量 != 物理日志记录数量
```

## 8. 聚合与因果字段

常规情况是一个 `logical_event_id` 扇出多个 `physical_record_id`。
但某些 emitter/finalizer 也可能把多个逻辑贡献聚合为一条物理记录。
这时不能只看单值 `logical_event_id`，还必须读取：

```text
contributing_logical_event_ids
contributing_storyline_ids
contributing_event_types
```

因果展开事件还可通过下列字段表达父事件：

```text
parent_logical_event_ids
causal_parentage_status
```

## 9. 跨团队使用契约

| 任务 | 主键/统计单位 | 不应使用 |
| --- | --- | --- |
| 攻击步骤覆盖率 | `(dataset_id, storyline_id)` | 物理行数 |
| canonical 事件覆盖率 | `(dataset_id, logical_event_id)` | `storyline_id` |
| Record-level TP/FP/FN/TN | `physical_record_id` | PID、Zeek UID 或行文本 |
| 预测定位校验 | `physical_record_id + relative_path + record_index` | 仅文件名 |
| 字节级审计 | `relative_path + byte_offset + byte_length + record_sha256` | 仅行号 |
| 源内关联 | `native_record_id` 和 `correlation_features` | 把源内 ID 当作全局 ID |

统一要求：

1. Record-level 评测必须以 `physical_record_id` 为核心；
2. 评测器应同时校验 `relative_path` 和 `record_index`，防止伪造或错位引用；
3. `record_sha256` 用于证明评测时的日志记录与生成时一致；
4. `storyline_id`、`logical_event_id`、标签、归因和 detectability 字段
   只存在私有 Ground Truth，不得进入 blind 日志或 `RECORD_INDEX.jsonl`；
5. `physical_record_id` 及其无标签定位字段必须进入 blind `RECORD_INDEX.jsonl`，
   供检测器返回精确记录主键，但不应嵌入源日志内容；
6. 不得默认对不同重生成版本直接 join `logical_event_id` 或
   `physical_record_id`；先确认生成输入、版本、顺序和输出字节一致。

### 9.1 日志、Blind Index 和私有 Ground Truth 边界

| 字段类型 | 源日志 `data/` | Blind `RECORD_INDEX.jsonl` | 私有 `RECORD_GROUND_TRUTH.jsonl` |
| --- | --- | --- | --- |
| `dataset_id` | 否 | 是 | 是 |
| `physical_record_id` | 否 | 是 | 是 |
| 路径/index/offset/length/hash | 否 | 是 | 是 |
| `native_record_id` / `correlation_features` | 源内字段自然存在 | 是，只含公开日志特征 | 是 |
| `storyline_id` / `logical_event_id` | 否 | 否 | 是 |
| label/provenance/contributor/parent IDs | 否 | 否 | 是 |
| detectability class/reason/anchors | 否 | 否 | 是 |

Blind Index 中出现 `physical_record_id` 不构成标签泄漏：它只是原子记录主键，
本身不表达 malicious/benign、storyline 或 logical-event 归属。

### 9.2 三层评测聚合规则

检测器始终只提交 `physical_record_id + relative_path + record_index`。评测器在
预测结束后读取私有 Sidecar，并分别按 `physical_record_id`、
`logical_event_id` 和 `storyline_id` 计算 TP、FP、FN、TN、Accuracy、
Precision、Recall 与 F1。

ID 层级的标签和预测聚合规则如下：

1. 同一非空 ID 下只要存在恶意物理记录，该 ID 就是恶意评测单元；
2. 检测器命中该 ID 下任意有效物理记录，即视为预测该 ID；
3. red-herring 和良性 ID 都作为负类；
4. 每个场景内所有 `storyline_id=null` 的普通背景记录合并为一个良性
   背景组；未命中任何背景记录时贡献一个 TN，命中一条或多条背景记录时
   贡献一个 FP；
5. 无效 `physical_record_id` 和定位不一致的预测无法映射到高层 ID，但仍在
   Logical-event 和 Storyline 层各计一个额外 FP；
6. 主评分保持 `physical_record_id` 层 F1，另外两层作为攻击事件和攻击步骤
   覆盖质量的辅助评分。

## 10. 稳定性速查表

| ID | 主要输入 | 当前保证 | 常见变化原因 |
| --- | --- | --- | --- |
| `dataset_id` | 场景名、开始时间、target | 同一 key 可复现 | 修改名称/开始时间/target |
| `storyline_id` | YAML `id` | 场景内唯一 | 作者改名 |
| `logical_event_id` | dataset、counter、event type | 单次数据集内唯一 | 插入事件、分发顺序/规则变化 |
| `physical_record_id` | dataset、路径、序号、内容哈希 | 单次数据集内唯一 | 路径、排序、格式或内容变化 |

## 11. 已知局限与后续建议

当前局限：

1. `dataset_id` 未覆盖完整生成输入；
2. `logical_event_id` 依赖全局分发 counter，局部插入事件可以引起后续 ID 批量变化；
3. `physical_record_id` 包含 `record_index`，文件中的前置插入会改变后续记录 ID；
4. 96 bit 截断哈希的碰撞概率极低，但不是数学上的绝对不可能；
   final validation 会拒绝同一 sidecar 中的重复 `physical_record_id`。

如未来要求跨版本强稳定 ID，应在新 schema 中设计新 ID 版本，不在原公式上
静默改动。可考虑：

- `dataset_id_v2`：纳入 canonical scenario hash、seed、generator version 和 target；
- `logical_event_id_v2`：使用场景步骤 ID、typed-event index、causal-rule ID 和局部子序号，
  减少全局 counter 位移；
- 保留当前 `physical_record_id` 作为“具体数据发布内的物理记录 ID”，
  另增跨版本语义指纹。

任何公式变更都应同时更新 schema version、生成器、blind index 生成器、
评测器和本契约，并禁止把两种 ID 版本无标识混用。

## 12. 代码对应位置

```text
src/evidenceforge/generation/engine/core.py
  dataset_id 计算

src/evidenceforge/generation/engine/storyline.py
  storyline YAML id 注入 dispatcher

src/evidenceforge/events/dispatcher.py
  storyline_cluster_id 注入 SecurityEvent

src/evidenceforge/events/record_ground_truth.py
  logical_event_id / physical_record_id 计算、定位、校验和 JSONL 输出

src/evidenceforge/validation/schema.py
  storyline id 唯一性校验
```
