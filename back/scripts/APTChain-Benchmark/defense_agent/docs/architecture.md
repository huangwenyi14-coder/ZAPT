# defense_agent 架构

**目的:** 消费 `output/<scenario>/data/` 下的多源异构日志，独立于 `GROUND_TRUTH.json`
做威胁检测，然后与 ground truth 对齐做两类评测 — 单条日志级 (Task A) 与 攻击步骤/剧本
级 (Task B)。

**原则 (与用户约定):**
- 检测逻辑**不得**直接抄 ground truth 中的答案 (例如把 GT 里的 PID/IP/进程名硬编码到规则里)。
- GT 只用于评测阶段的对齐，不参与检测阶段的特征构造。
- 评测输出 precision / recall / F1 (log-level) 和覆盖率 / 还原率 (storyline-level)。

## 1. 目录结构

```
defense_agent/
├── docs/                       # 设计与参考文档
│   ├── architecture.md         # 本文件
│   ├── data_inventory.md       # output 数据格式清单 (基于探索结果)
│   └── eval_design.md          # 评测指标与对齐策略
├── parsers/                    # 多源日志 → 统一 CanonicalEvent
│   ├── base.py                 # CanonicalEvent 数据模型
│   ├── windows_security.py     # Windows Security/Event XML
│   ├── windows_sysmon.py       # Sysmon XML
│   ├── ecar.py                 # eCAR JSONL
│   ├── zeek.py                 # Zeek conn/dns/http/files/ssl/x509/dhcp/ntp/ocsp/pe JSONL
│   ├── syslog_linux.py         # RFC3164 syslog
│   └── loader.py               # scenario_dir → List[CanonicalEvent]
├── detectors/                  # 检测引擎
│   ├── rules/
│   │   ├── ioc_patterns.py     # 命令行/进程名/扩展名 IOC 模式
│   │   ├── network_rules.py    # 可疑端口/外部 IP/DGA/beaconing
│   │   ├── auth_rules.py       # 异常登录/横向/凭据访问
│   │   └── engine.py           # 规则注册/调度
│   ├── agent/
│   │   ├── correlator.py       # LLM 跨事件关联
│   │   └── story_builder.py    # 剧本还原 (Task B)
│   └── unified.py              # 对外统一接口
├── evaluation/                 # 评测脚本 (纯函数, 无 LLM)
│   ├── align.py                # 检测结果 ↔ GT 对齐
│   ├── log_level.py            # Task A: precision/recall/F1
│   ├── storyline_level.py      # Task B: 步骤覆盖/还原率
│   └── report.py               # 汇总报告生成
├── scripts/                    # CLI 入口
│   ├── run_detect.py           # 单场景跑检测
│   ├── run_eval.py             # 单场景评测
│   └── run_all.py              # 全量跑所有场景
├── reports/                    # 评测输出 (gitignore)
└── tests/                      # 单元/集成测试
```

## 2. CanonicalEvent 统一模型

```python
@dataclass(frozen=True)
class CanonicalEvent:
    timestamp: datetime          # UTC
    host: str                    # 来源主机
    source: str                  # windows_security / sysmon / ecar / zeek_conn / zeek_dns / syslog
    event_type: str              # process_create / logon / connection / dns_query / file_write ...
    pid: int | None              # 主进程 ID (如有)
    process_name: str | None
    command_line: str | None
    user: str | None
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None
    url: str | None
    domain: str | None
    file_path: str | None
    raw: dict                    # 原始字段 (供 LLM 使用)
    source_offset: int           # 在源文件中的行号/记录号, 用于回溯
```

## 3. 两类任务

### Task A — 单条日志检测 (log-level)

**输入:** 单一 CanonicalEvent  
**输出:** `(verdict: malicious | suspicious | benign, score: float, reason: str)`  
**评测:**
- 对齐: GT.events 中 `kind=process` 用 `pid+host+±5s` 关联，`kind=connection` 用 `uid+host`，其他类型用 `attributes` 特征关联
- TP: GT 标记的事件中被检出 malicious
- FP: 被检出 malicious 但不在 GT 中
- FN: GT 标记但未被检出
- 输出: precision / recall / F1 / ROC-AUC

**检测器选择:**
- `RulesEngine`: 默认启用，基于 IOC 模式 + 启发式
- `LLMDetector`: 可选 (需 API key)，对低置信告警升级

### Task B — 攻击步骤还原 (storyline-level)

**输入:** 整个 scenario 的 CanonicalEvent 序列  
**输出:** `List[StorylineDetection]`，每个含 storyline_id (候选) + 覆盖步骤 + 还原率  
**评测:**
- GT storyline_id 在 detection 中是否被检出 (≥1 个事件命中)
- 覆盖度: 命中 GT 事件的占比
- 还原度: 按 storyline_id 顺序 + 时序匹配度 (允许乱序, 扣分)
- 输出: per-storyline P/R + 全场景综合分

**关联引擎:**
- 规则关联: 同一剧本内的已知因果链 (钓鱼→HTA→PowerShell→C2)
- LLM 关联: 把单条告警 + 邻近上下文送给模型, 决定归属哪个剧本 / 是否扩展

## 4. 评测脚本设计

评测脚本是**只读 ground truth 的**:
1. `align.py`: 根据 GT.events 的 attributes.pid/uid 等字段, 在原始日志中找出对应原始行, 把该行 ID 加入真阳性集合 (与检测器输出对比)
2. `log_level.py`: 用对齐集合 + 检测器输出算 P/R/F1
3. `storyline_level.py`: 按 GT.storyline_id 把事件聚类, 看检测结果是否覆盖每条 storyline
4. 不读 GT 也不读 GT 中的字符串到规则里 — 仅做后置对齐

## 5. 反对"作弊"的保护

- 规则文件 (`detectors/rules/`) 中所有 IOC 都是**通用模式** (例如 `mshta.exe` + `DownloadFile`, `powershell.exe -WindowStyle Hidden` 模式), 而不是从 GT 中复制特定路径/IP
- 每个规则都有**理由说明** (`reason` 字段), 表明是基于通用 ATT&CK 知识
- 评测时单独跑 `rules-only` 和 `llm-only`, 方便拆解贡献

## 6. 性能目标

- 14 个场景 × 平均 50MB 日志 → 单场景解析 ≤ 30s (Python, 单进程)
- 规则检测 ≤ 5s/场景
- LLM 检测: 可选, 默认关闭, 跑时单独标注
- 全量评测 ≤ 10 分钟 (不含 LLM)