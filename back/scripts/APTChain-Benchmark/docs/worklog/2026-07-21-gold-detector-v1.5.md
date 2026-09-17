# 黄金检测器 v1.5 修复与 20260717 回归报告

日期：2026-07-21

## 结论

本次修复没有增加场景名、攻击组织名或固定 IOC 硬编码。所有新增逻辑都依赖
无标签 Record Index 中可审计的原生字段，并具有进程、路径或时间边界。

六场景 Physical Record 维持 `FP=0`，TP 从 v1.4 的 353 提升到 389；
DarkHotel Storyline F1 达到 1.000000，Donot Storyline × Tactic F1 达到
0.943396。

## 根因与修复

### 1. DarkHotel 入口链没有锚点

原检测器无法把 Explorer 打开的 SWF 绑定到旧版 Flash 处理器，也无法把 RTF
打开与同一 Word 精确进程后续落地的可执行制品关联。v1.5 增加两条复合锚点：

- `Explorer + legacy Flash handler + user-writable .swf`；
- `Explorer + Word + user-writable .rtf + same process instance drops DLL/EXE`。

两条规则均要求父子/进程实例和路径信号同时成立，普通 Office 文档不会仅因
扩展名被选中。

### 2. Sysmon sidecar 丢失原生字段

旧 `_WINDOWS_CORRELATION_FIELDS` 没有完整导出 `ImageLoaded`、签名字段及
注册表 `TargetObject/Details`。因此原始 XML 明明包含模块路径和 Run Key，
检测器在 blind Record Index 中却看不到。

修复内容：

- 生成框架导出模块路径、签名、源/目标镜像和注册表字段；
- blind workspace 同时重建 Security 与 Sysmon 的公开关联字段；
- `prepare_manifest.json` 记录 Security、Sysmon 和总 Windows 重建数；
- 字段仍经过显式白名单，标签、三层 ID 映射和 detectability 不会进入盲测目录。

### 3. 战术规则传播过宽或优先级错误

v1.5 增加 `TacticEvidenceContext`，只采用以下有界证据：

- 同主机 `ProcessGuid`，或 PID + image + 生命周期；
- 精确五元组在 30 秒事务窗口内的跨源记录；
- 同一进程先读取凭据材料、再写暂存文件、最后网络发送；
- 同一进程先写压缩包、后写 DLL/EXE；
- 非标准扩展载荷被后续 LOLBin 命令按精确路径引用；
- 同主机精确文件路径的落地→模块加载。

普通同进程模块不再自动获得 Execution。显式未签名可写路径模块加载按 T1129
归 Execution；有明确 side-load 理由的记录仍归 Defense Evasion。LOLBin
进程本身的 Defense Evasion 也不再传播到它生成的所有文件。

### 4. Donot 标签语义更正

外部标签文件：

```text
/Users/xhb/Desktop/Project/TASK/2026TASK/ShuZiYiJing/Datacon2026比赛支持/数据质量评估/20260717/label/2021-11-23-donot-apt-q-38.labels.json
```

下列两个 `T1074.001 - Local Data Staging` 事件由 Execution 更正为
Collection：

- `evt-donot-copy-gtue`
- `evt-donot-write-credential-output`

## 最终指标

| 层级 | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Physical Record | 389 | 0 | 156 | 259,593 | 0.999400 | 1.000000 | 0.713761 | 0.832976 |
| Logical Event | 142 | 0 | 59 | 120,940 | 0.999513 | 1.000000 | 0.706468 | 0.827988 |
| Storyline | 81 | 0 | 5 | 6 | 0.945652 | 1.000000 | 0.941860 | 0.970060 |
| Storyline × Tactic | 70 | 7 | 16 | — | 0.790698 | 0.909091 | 0.813953 | 0.858896 |

Storyline × Tactic 的 Accuracy 是 86 个 Storyline 组中战术集合完全匹配的
比例，68 个组完全匹配。

### 分场景 F1

| 场景 | Physical | Logical | Storyline | Tactic |
| --- | ---: | ---: | ---: | ---: |
| DarkHotel | 0.941176 | 0.928571 | 1.000000 | 0.823529 |
| Lazarus | 0.741071 | 0.646154 | 0.900000 | 0.900000 |
| Donot APT-Q-38 | 0.821705 | 0.808511 | 1.000000 | 0.943396 |
| Spyder | 0.820513 | 0.826087 | 1.000000 | 0.833333 |
| Bitter APT-Q-37 | 0.980000 | 1.000000 | 1.000000 | 0.818182 |
| APT-C-48 | 0.840000 | 0.862069 | 0.896552 | 0.740741 |

结果目录：

```text
/Users/xhb/Desktop/Project/TASK/2026TASK/ShuZiYiJing/Datacon2026比赛支持/数据质量评估/20260717/evaluation_runs/gold-v1.5-final2-2026-07-21/
```

每个场景包含 `blind/RECORD_INDEX.jsonl`、`results/findings.json`、
`results/predictions.json`、`results/evaluation.json` 和
`results/evaluation.md`。

## 验证

```text
uv run ruff check ...
uv run ruff format --check ...
uv run pytest -q --no-cov tests/unit/test_record_ground_truth.py \
  tests/unit/test_record_level_claude_eval.py \
  tests/unit/test_gold_record_graph_detector.py
```

针对性测试共 77 项，全部通过。全仓 5006 项结果为 4962 通过、41 跳过、
3 个存量失败：`llm-injection-demo/scenario-clean.yaml` 缺失，以及两个与本次
改动无关的活动强度历史断言失败。全仓 Ruff 同样被 `defense_agent/` 和历史
脚本中的 123 个存量问题阻断；本次修改涉及的全部 Python 文件 Ruff 通过。
