# 黄金检测器 v1.3：完整 Beacon 序列与缺失行为规则

日期：2026-07-17

## 修改范围

本次修改解决 20260717 数据集上两个相互独立的问题：旧 Beacon 算法会从包含
大量噪声的连接序列中挑出局部等间隔点，造成背景流量误报；同时，Office 拉起
LOLBin、可写目录执行、双扩展、计划任务和单次进程网络事务缺少直接发现入口。

版本由 v1.2 升为 v1.3。机器可读版本位于 `gold/DETECTOR_VERSION`，预测结果
也写入 `detector_version: "1.3"`。

明确的版本边界：本次**没有修改** Beacon 对私网目的地址的排除条件。私网单次
连接只有在可疑进程已由独立高置信行为规则发现，并且连接能通过精确进程实例或
有生命周期约束的 `host+PID` 关联时，才可能由单次网络事务引擎召回；这不是
Beacon 判定。

## 发现规则

### Office→LOLBin

当 Word、Excel、PowerPoint、Outlook 等 Office 进程直接启动
`rundll32`、`regsvr32`、`mshta`、`wscript`、`cscript`、`powershell` 等
LOLBin，并且参数包含 URL、脚本、DLL、用户可写路径或隐藏/绕过标志时产生
锚点。仅有 Office 父进程或仅有 LOLBin 名称不足以命中。

### 可写目录执行与双扩展

覆盖 AppData、Temp、Downloads、ProgramData、Public 等用户可写/高风险
目录。新增以下高置信组合：

- 可写目录中的系统程序仿冒名；
- `*.pdf.exe`、`*.docx.scr` 等双扩展可执行文件；
- LOLBin 或安装器启动的罕见、裸参数可写目录子进程；
- 长诱饵式文件名的下载目录可执行文件。

普通安装程序和合法用户目录模块保留负向测试，避免把“位于可写目录”单独当作
恶意结论。

### 计划任务

Security 4698 作为独立发现源。只有任务动作指向用户可写路径、LOLBin 载荷、
双扩展，或 ProgramData 中的高频短周期动作时产生锚点。Program Files 下的
普通维护任务不命中。

### 单次网络事务

单次连接不再依赖 Beacon 重复性，但必须归属于已由终端、端点行为或进程异常
规则确认的精确进程。优先使用稳定进程标识；缺失时使用主机、PID、镜像和一小时
生命周期边界。相同五元组出现超过两次时不走该规则，以免与周期检测重复。

## Beacon 完整序列判断

v1.3 不再枚举并选择局部“最好看”的周期子序列，而是对同一目标/URI/SNI 分组
的完整时间间隔进行拟合：

1. 周期范围仍为 20 秒到 4 小时；
2. 小于 30 分钟的周期至少需要 8 个间隔，较长周期至少需要 4 个间隔；
3. 每一个间隔必须接近基础周期或其整数倍，整数倍用于解释暂停/缺测；
4. 至少 75% 的间隔必须是基础周期本身，而不能全靠大倍数解释；
5. 对完整序列计算抖动，长周期使用更严格的 10% 上限，短周期为 18%；
6. 私网目的地址排除逻辑保持不变。

这使旧版 209 条背景误报和 90 个错误 Beacon 直接锚点在本数据上全部消失。

## Security EventID 专用字段映射

`record_ground_truth.py` 和黄金检测器使用同一组公开语义，但不读取标签字段：

| EventID | 字段角色 |
| --- | --- |
| 4624 | 登录类型、源 IP/端口、工作站、认证包、目标用户/域、Logon ID |
| 4688 | `NewProcessId`=子进程 PID，`ProcessId`=父 PID，`NewProcessName`=子镜像，`ParentProcessName`/`CreatorProcessName`=父镜像，另提取命令行 |
| 4689 | 终止进程 PID、镜像和账户字段 |
| 4698 | 任务名称和任务 XML/内容 |
| 5156 | 进程 ID、应用、方向、源/目的地址与端口、协议 |

字段按 EventID 白名单提取，同名字段不会跨事件类型错误继承。准备 blind workspace
时，评测工具会按 Record Index 的 byte offset/length 从原始 Security 日志重新
提取这些公开字段，因此旧 schema-v3 sidecar 也能使用新映射；Ground Truth、
Storyline ID、Logical Event ID 和 detectability 字段仍不会传入检测器。

## 改动文件

- `gold/record_graph_detector.py`
- `gold/DETECTOR_VERSION`
- `src/evidenceforge/events/record_ground_truth.py`
- `blind_test/record_level_claude_eval.py`
- `tests/unit/test_gold_record_graph_detector.py`
- `tests/unit/test_record_ground_truth.py`
- `gold/README.md`
- `gold/GOLD_DETECTOR_CHANGELOG.md`

## 20260717 回归结果

数据范围：6 个场景、260,138 条物理记录；严格阈值
`confidence >= 0.50`。

| 层级 | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Physical Record | 353 | 0 | 192 | 259,593 | 0.999262 | 1.000000 | 0.647706 | 0.786192 |
| Logical Event | 129 | 0 | 72 | 120,940 | 0.999406 | 1.000000 | 0.641791 | 0.781818 |
| Storyline | 71 | 0 | 15 | 6 | 0.836957 | 1.000000 | 0.825581 | 0.904459 |

逐场景 Physical Record F1：Darkhotel 0.6765、Lazarus 0.7411、DONOT
0.7280、Spyder 0.8205、Bitter 0.9800、APT-C-48 0.8400。

与同一数据上的 v1.2 相比：

- TP：7 → 353；
- FP：209 → 0；
- FN：538 → 192；
- Physical Record F1：0.018397 → 0.786192；
- Logical Event F1：0.024096 → 0.781818；
- Storyline F1：0.043011 → 0.904459。

结果目录：

```text
/Users/xhb/Desktop/Project/TASK/2026TASK/ShuZiYiJing/Datacon2026比赛支持/数据质量评估/20260717/evaluation_runs/gold-v1.3-2026-07-17/
```

## 已知边界

剩余 192 条 Physical Record FN 主要来自 association 类事件（169 条），包括
缺少稳定进程所有权或强五元组边的连接、生命周期事件和模块加载。v1.3 没有使用
“同主机时间窗全选”“同 PID 无生命周期传播”等宽松策略换取召回，以保持本轮
FP=0。direct detectability 的召回率为 106/128（0.828125）。
