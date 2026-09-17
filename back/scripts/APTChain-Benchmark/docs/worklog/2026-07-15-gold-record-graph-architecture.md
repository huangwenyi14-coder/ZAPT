# Gold Record Graph Architecture Worklog

日期：2026-07-15

## 目标

将黄金检测器的 Record-Level 模式调整为：

- 自适应 Beacon 周期；
- Beacon、终端行为、Web exploit、IOC 独立发现；
- 统一消费无标签 Record Index；
- 用强身份和时间边界构建关联图；
- 将已命中的 `process_create` 展开到同一精确进程实例的
  `process_terminate`，而不把终止动作当作独立可疑规则。

## 备份和哈希

调整前对旧黄金检测器做了字节级备份：

```text
gold/backups/source_informed_chain_detector.pre-architecture-2026-07-15.py
SHA-256: 9398ab8c1e35e4680544d0868bbbc165291cf31feb562fc63b87761cc238724b
```

备份与开始修改前的 `gold/source_informed_chain_detector.py` 已用 `cmp`
和 SHA-256 双重确认完全一致。本次没有删除旧文件。

当前主文件：

```text
gold/source_informed_chain_detector.py
SHA-256: 13c74b6f1bb752ed7491834bb6b594d18e176b4fcd4304cb8cdbd8dad54845f2

gold/record_graph_detector.py
SHA-256: f971336b9959c171f05027ebe64ba5e2a97f29b65284b14e71224b2dff2cd5ce
```

## 文件变更

### `gold/source_informed_chain_detector.py`

- 保留原 `--input` finding-only 模式。
- `--data-dir + --record-index` 模式改为调用新 Record Graph 引擎。
- 继续复用原有 `load_record_index()` 完成私有标签递归拒绝、路径、
  byte offset/length、SHA-256 和唯一性验证。
- 修正 blind 工作区下的 `case_id` 为真实场景目录名。

### `gold/record_graph_detector.py`

新增独立 Record-Level 引擎，主要包含：

1. 19 种已见数据源的顶层和嵌套字段白名单。
2. ISO、Windows 100 ns、Apache/Proxy、ASA、Snort 和 epoch 时间归一化。
3. 20 秒至 4 小时的鲁棒周期估计，支持抖动、插入 tick 和会话暂停。
4. Beacon、终端行为、Web exploit 和 IOC 四路无短路独立运行。
5. `host+ProcessGuid`、`host+PID+lifetime+image`、一跳父子进程和
   确定性 create→terminate 生命周期边。
6. eCAR FLOW actorID、五元组+时间、Zeek UID/FUID、DNS answer、
   ASA connection ID/NAT 和字段缺失时的严格 WFP 备选边。
7. Proxy 的目的主机、URI 形状和自适应周期。
8. 每条输出保留 `association_strength`、`anchor_engine` 和诊断计数。

### `tests/unit/test_gold_record_graph_detector.py`

新增 6 组架构回归测试：

- 白名单忽略未审核和私有嵌套字段；
- 短周期、数小时周期和长暂停鲁棒拟合；
- 四引擎独立产生锚点与 GeoServer 直接 Web 命中；
- 精确 terminate 继承和 PID 复用隔离；
- 父子只一跳、子进程自身 terminate 继承、不向孙进程传播；
- 进程→eCAR FLOW→五元组→Zeek UID/FUID 的完整物理记录展开。

### 文档和评测产物

```text
gold/README.md
evaluation_runs/NEW-Dataset-2026-07-15-graph/SUMMARY.md
evaluation_runs/NEW-Dataset-2026-07-15-graph/gold/<scenario>/results/findings.json
evaluation_runs/NEW-Dataset-2026-07-15-graph/gold/<scenario>/results/predictions.json
evaluation_runs/NEW-Dataset-2026-07-15-graph/gold/<scenario>/results/evaluation.json
evaluation_runs/NEW-Dataset-2026-07-15-graph/gold/<scenario>/results/evaluation.md
```

## 关键逻辑和边界

### 生命周期

- IOC 规则显式排除 `process_terminate`。
- 终止记录只能通过同主机精确 stable ID，或同主机 PID+图像+
  创建到最近终止时间边界纳入。
- 如果 PID 终止后被不同图像或不同 stable ID 复用，不会继承标签。
- Security 4688 缺 `NewProcessId` 时，仅允许同主机、完全相同 image+
  command line、±1.5 秒的跨格式 canonical fan-out。

### 防过度传播

- 不使用主机时间窗全选。
- 不使用不带主机和生命周期的 PID。
- 不在数小时后继续沿用 ProcessGuid。
- 长生命周期浏览器/协作客户端不从单个可疑流反向标记整个进程，
  解决 RoundPress 试运行中的无关 Firefox 连接扩散问题。

## 发现的实现问题

1. Python 3.10 `datetime.fromisoformat()` 不接受 Windows 事件的 7 位小数秒，
   必须先裁剪为 6 位；否则 Sysmon/Security 时间均为空。
2. Python `ipaddress.is_private` 会把 `198.51.100.0/24`、`192.0.2.0/24`
   等文档网段判为 non-global，EvidenceForge 恰好用它们模拟外网 C2。
   现在只排除 RFC1918、loopback 和 link-local 端点网段。
3. 最初将任何格式的 `id` 当成 Zeek FUID，会污染边类型审计。
   现在 `id` 仅在 Zeek X509/OCSP/PE 格式中解释为 FUID。
4. 周期拟合如果要求全部相邻间隔通过 CV，会漏掉 Mango 的长暂停、
   Turla 的插入连接和 RoundPress 的数小时周期。现在拟合最大一致
   间隔簇，但仍使用域名/IP baseline 和重复数门槛。

## 验证

执行：

```bash
python3 -m py_compile gold/record_graph_detector.py \
  gold/source_informed_chain_detector.py
.venv/bin/ruff check gold/record_graph_detector.py \
  gold/source_informed_chain_detector.py \
  tests/unit/test_gold_record_graph_detector.py \
  tests/unit/test_gold_source_informed_chain_detector.py
.venv/bin/python -m pytest -q \
  tests/unit/test_gold_record_graph_detector.py \
  tests/unit/test_gold_source_informed_chain_detector.py
```

结果：Python 3.10 编译通过，Ruff 通过，21 个定向单元测试全部通过。

10 场景严格评测微平均：Accuracy=0.9943、Precision=1.0000、
Recall=0.5069、F1=0.6728；TP=2,155、FP=0、FN=2,096、TN=361,829。

## 后续与 Git 上游合并

1. 不要覆盖 `gold/backups/source_informed_chain_detector.pre-architecture-2026-07-15.py`。
2. 先将新上游检测器与该备份比较，识别上游 finding-only 变更。
3. `gold/source_informed_chain_detector.py` 仅有文件顶部说明和 `main()` 的
   Record-Level 分支需人工保留；其余 finding-only 部分可按上游更新。
4. `gold/record_graph_detector.py` 是新增独立文件，通常不与上游检测器
   发生文本冲突。
5. 合并后重跑上述 21 个单元测试和
   `evaluation_runs/NEW-Dataset-2026-07-15-graph` 的 10 场景命令。
