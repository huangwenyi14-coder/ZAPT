# 黄金检测器运行时间实测报告

日期：2026-07-15

## 结论

黄金检测器在 NEW-Dataset 的 10 个 blind 场景、共 366,080 条物理日志
记录上顺序执行，总检测时间为 **277.67 秒（约 4 分 38 秒）**。

| 汇总项 | 结果 |
| --- | ---: |
| 场景数 | 10 |
| 总记录数 | 366,080 |
| 总墙钟时间 | 277.67 秒 |
| 平均每场景 | 27.77 秒 |
| 场景耗时中位数 | 21.24 秒 |
| 整体处理速度 | 约 1,318 records/s |
| 最短场景 | 8.03 秒 |
| 最长场景 | 81.69 秒 |

## 分场景结果

| 场景 | 物理记录数 | 墙钟时间 | 平均处理速度 |
| --- | ---: | ---: | ---: |
| apt28-gooseegg | 15,884 | 8.32 秒 | 1,909 records/s |
| apt28-roundpress | 11,388 | 8.03 秒 | 1,418 records/s |
| apt29-wineloader-rootsaw | 16,404 | 10.48 秒 | 1,565 records/s |
| apt41-dusttrap-onedrive | 51,219 | 55.13 秒 | 929 records/s |
| diamond-sleet-cyberlink | 25,467 | 24.68 秒 | 1,032 records/s |
| earth-baxia-geoserver | 25,403 | 17.80 秒 | 1,427 records/s |
| oilrig-mango-juicy-mix | 21,959 | 29.20 秒 | 752 records/s |
| sandworm-microscada-caddywiper | 137,900 | 81.69 秒 | 1,688 records/s |
| turla-tinyturla-ng | 37,438 | 33.59 秒 | 1,115 records/s |
| volt-typhoon-lotl | 23,018 | 8.75 秒 | 2,631 records/s |

Sandworm 数据量最大，占总记录数约 37.7%，单场景耗时 81.69 秒，
是本次总耗时的主要构成部分。检测时间不与记录数完全线性对应，
还受日志格式、完整性校验、候选锚点数量和关联图展开规模影响。

## 计时口径

每个场景使用独立黄金检测器进程，通过 `/usr/bin/time -p` 记录 `real`
墙钟时间。测量范围包括：

- 读取场景 `data/` 和无标签 `RECORD_INDEX.jsonl`；
- Record Index 结构、路径、字节范围和 SHA-256 完整性校验；
- Beacon、终端行为、Web exploit 和 IOC 发现；
- 进程生命周期、Proxy/DNS、Zeek UID/FUID、五元组和 ASA 连接图展开；
- 写出 `findings.json` 和 `predictions.json`。

不包括：

- blind workspace 准备和日志复制时间；
- 读取私有 Ground Truth 的评分时间；
- 数据生成时间；
- Claude 或其他模型的运行时间。

10 个场景按顺序执行，未并行运行。因此 277.67 秒是单机串行处理
的实际总墙钟时间。

## 测试环境

```text
Operating system: macOS 14.7.3 (23H417)
Processor: Apple M2
Memory: 16 GiB
Python: 3.12.11
Execution mode: sequential, one detector process per scenario
```

本次输入来自：

```text
evaluation_runs/NEW-Dataset-2026-07-14/gold/<scenario>/blind/
```

重跑生成的检测产物保留在：

```text
/private/tmp/evidenceforge-gold-timing-20260715/<scenario>/
```

## 检测器版本

```text
gold/source_informed_chain_detector.py
SHA-256: 1f9a6adb99ff944355818aded263d3fb33ddd8c5279783649a2156188818047b

gold/record_graph_detector.py
SHA-256: 5cfaa76ff6a6256cf4cc70fe64ce02a2441fe922ac0059e871c80973c0a50cb8
```

本工作副本没有 `.git` 元数据，因此使用文件 SHA-256 锁定本次实测的
黄金检测器版本。

## 同版本检测效果

同版本黄金检测器在这 10 个场景的生命周期修复版 Ground Truth 上，
严格阈值 `confidence >= 0.50` 的微平均结果为：

| TP | FP | FN | TN | Accuracy | Precision | Recall | F1 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 3,172 | 0 | 1,079 | 361,829 | 0.997053 | 1.000000 | 0.746177 | 0.854641 |

检测效果的完整分场景报告位于：

```text
evaluation_runs/NEW-Dataset-2026-07-15-recall-fixes-final/SUMMARY.md
```

## 复现命令

```bash
/usr/bin/time -p .venv/bin/python gold/source_informed_chain_detector.py \
  --data-dir evaluation_runs/NEW-Dataset-2026-07-14/gold/<scenario>/blind/data \
  --record-index evaluation_runs/NEW-Dataset-2026-07-14/gold/<scenario>/blind/RECORD_INDEX.jsonl \
  --findings-output /private/tmp/evidenceforge-gold-timing-20260715/<scenario>/findings.json \
  --output /private/tmp/evidenceforge-gold-timing-20260715/<scenario>/predictions.json
```
