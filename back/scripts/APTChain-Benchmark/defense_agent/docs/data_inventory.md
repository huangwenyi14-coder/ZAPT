# output/ 数据格式清单

> 基于对 `output/` 下 14 个场景的探索性扫描。

## 1. 场景概览

| Scenario | Hosts | 剧情步骤 | 事件类型 |
|---|---|---|---|
| 2015-12-31-darkhotel | 4 (1 DC, 1 WS, 2 LNX) | 6 | process, logon |
| 2018-09-20-apt-c-01 | 4 | 15 | process, logon, connection, beacon, scheduled_task_created, dns_query |
| 2021-01-30-lazarus | 4 | 9 | process, logon, connection, beacon |
| 2021-11-23-donot-apt-q-38 | 4 | 20 | process, logon, connection, beacon, dns_query |
| 2022-07-20-apt-q-39-sidewinder | 4 | 9 | process, logon, connection |
| 2023-07-04-spyder | 4 | 12 | process, logon, connection, beacon |
| 2024-10-12-bitter-apt-q-37 | 4 | 11 | process, logon, connection, beacon, scheduled_task_created |
| 2024-11-26-apt-c-48-cnc | 4 | 9 | process, logon, connection |
| apt-c48-cnc-sbie | 7 + Zeek-core | 10 | process, logon, connection, create_remote_thread |
| apt36 | 4 | 16 | process, logon, connection, beacon, dns_query |
| lazarus-researcher-attack | 6 + Zeek-core | 10 | process, logon, connection, beacon |
| oceanlotus | 4 | 9 | process, logon, connection, beacon |
| oceanlotus-sb-topic | 6 + Zeek-core | 10 | process, logon, connection, beacon |
| retail-store-ftp-attack | 16 + core-switch-tap | 22 | process, connection |

OUTPUT_TARGET 全部为 `default`。

## 2. 数据文件分布

```
output/<scenario>/
├── GROUND_TRUTH.json
├── GROUND_TRUTH.md
├── OBSERVATION_MANIFEST.json
├── OUTPUT_TARGET.txt
└── data/
    ├── <HOST1>/                # 端点主机
    │   ├── ecar.json           # Linux eCAR EDR (NDJSON)
    │   ├── syslog.log          # Linux syslog (RFC 3164)
    │   ├── windows_event_security.xml   # Windows Security/Event XML
    │   └── windows_event_sysmon.xml     # Sysmon XML
    ├── <ZEEK-CORE>/            # Zeek 传感器
    │   ├── conn.json
    │   ├── dns.json
    │   ├── http.json
    │   ├── files.json
    │   ├── ssl.json
    │   ├── x509.json
    │   ├── dhcp.json
    │   ├── ntp.json
    │   ├── ocsp.json
    │   └── pe.json
    └── <core-switch-tap>/      # 部分场景含
        └── conn.json ...
```

**统计:** 14 场景 × 平均 ~14 数据文件 ≈ 202 数据文件, 总计 56 ecar + 46 winsec + 36 sysmon + 23 syslog + 4×10 Zeek + 4 个 retail switch tap conn.json 等。

## 3. 字段约定 (各格式抽样)

### 3.1 Windows Security/Event XML

`<Event>` 节点: `<System><Provider>` 区分 Security-Auditing / Sysmon;
`<EventID>` 是核心标识; `<TimeCreated SystemTime="...">` 是 UTC; `<Computer>` 是主机名;
`<EventData>` 内若干 `<Data Name="...">` 字段。

常见 EventID:
- `4624` 登录成功 (LogonType, TargetUserName, IpAddress, LogonId)
- `4625` 登录失败
- `4634/4647` 注销
- `4672` 特权登录
- `4688` 进程创建 (NewProcessName, CommandLine, ParentProcessName)
- `4689` 进程退出
- `4698` 计划任务创建
- `4720/4722/4723/4724/4728/4732/4756` 账户/组成员变更
- `4768/4769/4771` Kerberos
- `5140/5145` 网络共享访问
- `1102` 日志清除

### 3.2 Sysmon XML

`<EventID>`:
- `1` 进程创建 (Image, CommandLine, ParentImage, User, ProcessGuid)
- `2` 文件创建时间变更
- `3` 网络连接 (Image, DestinationIp, DestinationPort, Protocol, Initiated)
- `5` 进程结束
- `7` 镜像加载 (ImageLoaded)
- `8` CreateRemoteThread (SourceImage, TargetImage, NewThreadId)
- `10` ProcessAccess (SourceProcess, TargetProcess, GrantedAccess)
- `11` 文件创建
- `12/13/14` 注册表
- `17/18` 管道
- `22` DNS 查询 (QueryName, QueryResults)
- `25` 进程篡改

### 3.3 eCAR JSONL

每行一条 JSON, 字段:
- `timestamp_ms` (epoch ms)
- `id`, `objectID`, `actorID` (UUID)
- `hostname`, `object`, `action` (e.g., PROCESS/CREATE, FLOW/CLOSE, USER_SESSION/LOGIN/LOGOUT, MODULE_LOAD/LOAD)
- `pid`, `tid`, `ppid`
- `principal` (user)
- `properties` (command_line, image_path, parent_image_path, src_ip, src_port, logon_id, ...)

对象类型 (常见):
PROCESS/USER_SESSION/FLOW/MODULE_LOAD/FILE

### 3.4 Zeek conn.json

每行: `ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration,
orig_bytes, resp_bytes, conn_state (SF/S0/S1/REJ/RSTO/...), history, orig_pkts, resp_pkts,
missed_bytes`.

`conn_state == "S0"` 且 `duration == 0` 即空连接 (扫描迹象)。

### 3.5 Zeek dns.json

每行: `ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, trans_id, query,
qtype_name (A/AAAA/MX/...), rcode_name (NOERROR/NXDOMAIN/...), answers[], TTLs[]`.

NXDOMAIN burst / 长随机子域名 → DGA / DNS tunnel。

### 3.6 Zeek http.json

每行: `ts, uid, id.orig_h, id.resp_p, method, host, uri, user_agent, status_code,
status_msg, request_body_len, response_body_len, resp_mime_type`。

### 3.7 Syslog

`<priority>timestamp hostname program[pid]: message` 格式。

例: `<86>1 2021-01-30T10:01:26.326837Z ATK-LNX-01 sshd 667152 - - pam_unix(sshd:session): session closed for user attacker`

`<86> = facility 10 (auth) + severity 6 (info)`。

## 4. Ground Truth 结构

`GROUND_TRUTH.json`:
```json
{
  "schema_version": 1,
  "scenario_name": "...",
  "storyline_steps": [
    {"storyline_id": "evt-2018-09--02", "index": 2, "actor": "victim.user",
     "system": "WS-VICTIM-01", "activity": "CVE-2012-0158漏洞触发执行恶意代码",
     "event_types": ["process"], "ground_truth_section": "storyline"}
  ],
  "red_herring_steps": [],   // 全部场景为空
  "events": [
    {"record_id": "evt-2018-09--02#0", "kind": "process", "storyline_id": "evt-2018-09--02",
     "time": "2018-09-20T10:03:35Z", "actor": "victim.user", "system": "WS-VICTIM-01",
     "activity": "...", "attributes": {"command_line": "...", "pid": 7960,
        "process_name": "..."}, "emitted": true}
  ]
}
```

**`red_herring_steps` 在所有 14 个场景均为空** — 不需要单独建模误报噪音。

`events[].attributes` 中可用的对齐字段 (取决于 kind):
- process: `pid`, `process_name`, `command_line`
- connection: `uid`, `dst_ip`, `dst_port`, `source_ip`
- logon: `logon_id`, `source_ip`
- dns_query: `query`, `qtype`, `rcode`
- scheduled_task_created: `task_name`
- beacon: `dst_ip`, `dst_port`, `attempt_count`, `interval`
- create_remote_thread: `target_process`, `source_process` (推断)

`OBSERVATION_MANIFEST.json` 提供 `source_evidence_status`, 说明每个 storyline_id
在不同源 (ecar/sysmon/security) 上的可见数量 (visible/dropped/out_of_window)。
评测对齐时应尊重该状态 — 不可见的事件不应当作 FN。