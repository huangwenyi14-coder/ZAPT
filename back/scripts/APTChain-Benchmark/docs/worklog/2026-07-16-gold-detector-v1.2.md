# 黄金检测器 v1.2：独立发现引擎与低误报因果图

日期：2026-07-16

## 目标与版本边界

- 修改前黄金检测器定义为 v1.1；
- 当前实现定义为 v1.2；
- v1.1 的 Git 基线为 `61a7ec57b92d1726bd160728b3373aa90a8cd0c8`；
- v1.2 的机器可读版本位于 `gold/DETECTOR_VERSION`，运行结果同时包含
  `detector_version: "1.2"`。

本次优化以保持低误报为硬约束。发现规则不能仅依赖可写目录、同一 PID、同一
主机时间窗或单次失败连接；必须使用高置信行为，或者至少两个以上独立信号组成
的复合异常。

## 独立发现引擎

v1.2 的 Record Graph 同时运行十个发现引擎：

1. 自适应周期 Beacon；
2. 原有终端规则与有界终端序列；
3. 高置信终端行为；
4. 复合进程异常；
5. 模块加载与远程线程行为；
6. Web exploit；
7. 单次高风险网络事务；
8. 身份异常；
9. 高风险制品生产到归档序列；
10. 高置信 IOC。

新增终端行为覆盖数据库批量导出、密码库收集并归档、可移动盘批处理、可写目录
批处理加载 DLL、下载文件复制到 Windows Tasks、暂存数据归档和强制清理。

复合进程异常只有在以下条件同时成立时才产生锚点：

- 当前场景内进程镜像罕见；
- 镜像位于用户可写或高风险目录；
- 命令行是无附加参数的裸启动；
- 父进程是服务控制进程，或者 Explorer 启动 ProgramData/Windows Tasks 文件。

普通下载目录安装程序带有安装参数时不会命中该规则。

## 文件、模块和身份因果图

文件图新增的强边：

- 已选命令的明确输出路径到同主机、同路径、五分钟内的文件创建；
- 已选文件创建到同主机、同完整路径、四小时内的后续进程执行；
- 已落地脚本到 PowerShell/cmd/wscript/cscript/mshta/rundll32 的明确脚本引用。

关联不会使用“同名文件”“同主机任意路径”或“同一时间范围内全部进程”。

模块图只直接锚定：

- 可写目录中的无效或未签名模块；
- 与可写目录宿主程序同目录、且不是常见系统 DLL 的模块；
- 已满足复合进程异常的精确进程实例发起的远程线程。

为避免长生命周期进程误报，普通系统 DLL 只有在进程创建后的五秒内才继承该
进程锚点；更晚的模块加载必须独立满足模块规则。

身份图新增的强边：

- 公网源地址成功连接内网 RDP；
- RDP 五元组到相同主机、源地址、源端口和五秒时间窗内的 eCAR LOGIN；
- 同主机精确 Logon ID 的 eCAR、4624 和 4672 扇出；
- 同一用户由外部 RDP 主机在两小时内移动到第二台内网主机，且存在精确 SMB/RDP
  支撑连接。

身份扇出只能由登录或认证记录触发，进程记录中的 SYSTEM SubjectLogonId 不会
启动身份传播。

## Record Index 白名单

新增的公开字段主要包括：

- Sysmon：`ImageLoaded`、`Signed`、`Signature`、`SignatureStatus`、
  `OriginalFileName`、`Company`、`Product`、`SourceImage`、`TargetImage`、
  `GrantedAccess`；
- Security：`LogonType`、`IpAddress`、`IpPort`、`WorkstationName`、
  `AuthenticationPackageName`；
- eCAR：模块路径、文件哈希、签名状态、源/目标进程镜像。

Ground Truth、Storyline ID、Logical Event ID、detectability 字段仍不在白名单内。

## 最终回归结果

数据范围：NEW-Dataset 10 个场景、366,080 条物理记录；阈值
`confidence >= 0.50`。

| 层级 | TP | FP | FN | TN | Precision | Recall | F1 | 场景宏 F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Physical Record | 3,313 | 0 | 938 | 361,829 | 1.000000 | 0.779346 | 0.875992 | 0.848891 |
| Logical Event | 1,072 | 0 | 327 | 187,729 | 1.000000 | 0.766262 | 0.867665 | 0.838014 |
| Storyline | 50 | 0 | 9 | 26 | 1.000000 | 0.847458 | 0.917431 | 0.878419 |

相比 v1.1：

- Physical Record TP：3,172 → 3,313；
- Physical Record F1：0.854641 → 0.875992；
- Storyline TP：33/59 → 50/59；
- Storyline F1：0.717391 → 0.917431；
- Physical Record FP：0 → 0；
- Storyline FP：0 → 0。

新增召回的主要 Storyline 包括 GooseEgg 投放与利用、WINELOADER 获取与侧载、
DUSTTRAP WebShell/进程/导出/归档/清理、Baxia 两个侧载阶段、Mango 启动、
Sandworm 批处理、Turla 密码库收集，以及 Volt Typhoon 外部 RDP、域控登录和归档。

仍未命中的 9 个 Storyline 主要是邮件投递/阅读、供应链合法下载与单次回连等缺少
充分公开判别特征的步骤。为保持零误报，v1.2 没有把这些普通外观事件直接判恶。

最终结果：

```text
/Users/xhb/Desktop/Project/TASK/2026TASK/供应链安全检测/Mythos/Tools/TestandValid/EvidenceForge-main/evaluation_runs/NEW-Dataset-2026-07-16-gold-v1.2-final/
```

## 验证

```bash
.venv/bin/python -m ruff check \
  gold/record_graph_detector.py \
  tests/unit/test_gold_record_graph_detector.py

.venv/bin/python -m pytest --no-cov -q \
  tests/unit/test_gold_record_graph_detector.py \
  tests/unit/test_gold_source_informed_chain_detector.py
```

结果：34 个测试通过，Ruff 通过。
