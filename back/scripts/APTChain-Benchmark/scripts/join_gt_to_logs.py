#!/usr/bin/env python3
"""演示：如何用 GROUND_TRUTH.json 去反查真实日志。

核心方法论（按可信度从高到低）：

  JOIN 1: 三元组（高置信，唯一）
    match GT.attributes.pid
       AND abs(time_delta) < 2s
       AND command_line 包含/相同

  JOIN 2: 二元组 + 时间窗（中置信）
    match GT.attributes.logon_id（如有）
       AND time window

  JOIN 3: 单 PID + 时间窗（中置信）
    match GT.attributes.pid
       AND abs(time_delta) < 5s

  JOIN 4: 仅时间 + command_line 模糊（低置信，多匹配）

  JOIN 5: 仅 storyline_id（最粗，不能区分 beacon 多 beats）

对 1 条 GT 事件，会查所有可能的 log 源：
  - Windows Security 4688/4624/4768...:  按 NewProcessId/NewLogonId
  - Sysmon Event 1/2/3/5/8/10/11/13...:  按 ProcessId + 字段特化
  - eCAR PROCESS/REGISTRY/NETWORK...:    按 properties.pid
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    from lxml import etree
    LXML = True
except ImportError:
    import xml.etree.ElementTree as ET
    LXML = False


# ---------------------------------------------------------------------------
# 解析各种日志格式为结构化记录
# ---------------------------------------------------------------------------

def parse_xml_log(path: Path) -> list[dict[str, Any]]:
    """把 Windows/Sysmon XML 解析成 (ts, eid, datas) 元组列表。"""
    if not path.exists():
        return []
    if LXML:
        tree = etree.parse(str(path))
        root = tree.getroot()
    else:
        tree = ET.parse(path)
        root = tree.getroot()
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    out = []
    for ev in root.findall("e:Event", ns):
        sys = ev.find("e:System", ns)
        eid_el = sys.find("e:EventID", ns)
        ts_el = sys.find("e:TimeCreated", ns)
        eid = int(eid_el.text) if eid_el is not None else 0
        ts_str = ts_el.get("SystemTime") if ts_el is not None else ""
        datas: dict[str, str] = {}
        for d in ev.findall("e:EventData/e:Data", ns):
            name = d.get("Name", "")
            val = d.text or ""
            if name:
                datas[name] = val
        out.append({"ts": ts_str, "eid": eid, "datas": datas, "src": path.name})
    return out


def parse_ecar(path: Path) -> list[dict[str, Any]]:
    """eCAR 是 NDJSON。返回 (ts_ms, object, action, principal, properties) 列表。"""
    if not path.exists():
        return []
    out = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts_ms = e.get("timestamp_ms", 0)
            out.append({
                "ts_ms": ts_ms,
                "object": e.get("object", "?"),
                "action": e.get("action", "?"),
                "principal": e.get("principal", "?"),
                "pid": e.get("pid", 0),
                "properties": e.get("properties", {}),
                "src": path.name,
            })
    return out


# ---------------------------------------------------------------------------
# JOIN 策略
# ---------------------------------------------------------------------------

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"  # 备用


def find_xml_matches(gt_event: dict, xml_logs: list[dict], tolerance_s: float = 5.0) -> list[dict]:
    """对一条 GT 事件，找 XML 日志里的所有匹配候选。

    匹配策略：
      1. 拿 GT.attributes.pid，转十六进制 (e.g. 6664 → 0x1a08)
      2. 拿 GT.attributes.command_line，做字符串包含匹配
      3. 拿 GT.attributes.logon_id，转十六进制
      4. 拿 dst_ip/dst_port 给 Sysmon Event 3 用
    """
    attrs = gt_event.get("attributes", {})
    pid = attrs.get("pid")
    cmd = attrs.get("command_line", "")
    logon_id = attrs.get("logon_id")
    dst_ip = attrs.get("dst_ip")
    dst_port = attrs.get("dst_port")
    eid_filter = attrs.get("expected_eid")

    # GT 时间 → 毫秒
    from datetime import datetime
    gt_ms = int(datetime.fromisoformat(gt_event["time"].replace("Z", "")).timestamp() * 1000)

    matches = []
    for rec in xml_logs:
        # 时间窗过滤（粗筛）
        try:
            rec_ms = int(datetime.fromisoformat(rec["ts"].replace("Z", "")).timestamp() * 1000)
        except Exception:
            continue
        if abs(rec_ms - gt_ms) > tolerance_s * 1000:
            continue
        # EID 过滤（可选）
        if eid_filter and rec["eid"] != eid_filter:
            continue
        # 字段匹配
        score = 0
        reasons = []

        if pid is not None:
            # 4688: NewProcessId="0x1a08" -> 6664
            np = rec["datas"].get("NewProcessId", "")
            if np:
                m = re.match(r"0x([0-9a-fA-F]+)", np)
                if m and int(m.group(1), 16) == pid:
                    score += 50
                    reasons.append(f"NewProcessId={np}==pid={pid}")
            # Sysmon Event 1: ProcessId="6664"
            if str(pid) == rec["datas"].get("ProcessId"):
                score += 50
                reasons.append(f"ProcessId={pid}")
            # Logon id 类型（4624/4768/4625 用 TargetLogonId）
            if logon_id is not None:
                tl = rec["datas"].get("TargetLogonId", "")
                m = re.match(r"0x([0-9a-fA-F]+)", tl)
                if m and int(m.group(1), 16) == logon_id:
                    score += 30
                    reasons.append(f"TargetLogonId={tl}==logon_id={logon_id}")

        if cmd:
            xml_cmd = rec["datas"].get("CommandLine", "")
            if cmd == xml_cmd:
                score += 80
                reasons.append("CommandLine 完全一致")
            elif cmd in xml_cmd:
                score += 50
                reasons.append("CommandLine 包含")

        if dst_ip and dst_ip == rec["datas"].get("DestinationIp"):
            score += 30
            reasons.append(f"DestinationIp={dst_ip}")
        if dst_port is not None and str(dst_port) == rec["datas"].get("DestinationPort"):
            score += 10
            reasons.append(f"DestinationPort={dst_port}")

        # 时间近度加分（毫秒级）
        dt_ms = abs(rec_ms - gt_ms)
        score -= dt_ms / 1000  # 每秒扣 1 分
        reasons.append(f"dt={dt_ms}ms")

        if score >= 30:  # 至少要有一个匹配信号
            matches.append({
                "src": rec["src"],
                "eid": rec["eid"],
                "ts": rec["ts"],
                "score": score,
                "reasons": reasons,
                "data_snippet": {
                    k: v for k, v in list(rec["datas"].items())[:8]
                },
            })

    matches.sort(key=lambda x: -x["score"])
    return matches


def find_ecar_matches(gt_event: dict, ecar_logs: list[dict], tolerance_s: float = 5.0) -> list[dict]:
    """对 GT 事件找 eCAR 匹配。"""
    attrs = gt_event.get("attributes", {})
    pid = attrs.get("pid")
    cmd = attrs.get("command_line", "")
    dst_ip = attrs.get("dst_ip")
    dst_port = attrs.get("dst_port")

    from datetime import datetime
    gt_ms = int(datetime.fromisoformat(gt_event["time"].replace("Z", "")).timestamp() * 1000)

    matches = []
    for rec in ecar_logs:
        dt_ms = abs(rec["ts_ms"] - gt_ms)
        if dt_ms > tolerance_s * 1000:
            continue
        score = 0
        reasons = [f"dt={dt_ms}ms"]
        # 对象类型匹配
        kind = gt_event.get("kind", "")
        if kind == "process" and rec["object"] == "PROCESS":
            score += 5
        if kind == "beacon" and rec["object"] == "NETWORK":
            score += 5
        # pid
        if pid is not None and rec["pid"] == pid:
            score += 50
            reasons.append(f"pid={pid}")
        # command_line
        ecmd = rec["properties"].get("command_line", "")
        if cmd and cmd == ecmd:
            score += 80
            reasons.append("command_line 完全一致")
        elif cmd and cmd in ecmd:
            score += 40
            reasons.append("command_line 包含")
        # network
        if dst_ip and rec["properties"].get("dst_ip") == dst_ip:
            score += 30
            reasons.append(f"dst_ip={dst_ip}")
        # 时间近度扣分
        score -= dt_ms / 1000
        if score >= 30:
            matches.append({
                "src": rec["src"],
                "object": rec["object"],
                "action": rec["action"],
                "ts_ms": rec["ts_ms"],
                "score": score,
                "reasons": reasons,
                "properties": {k: v for k, v in list(rec["properties"].items())[:8]},
            })
    matches.sort(key=lambda x: -x["score"])
    return matches


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def main(scenario_output: Path, target_ids: list[str]):
    """对指定 storyline_id 列表做 join 演示。

    Usage:
        uv run python scripts/join_gt_to_logs.py output/2021-01-30-lazarus \
            --ids evt-2021-01--05 evt-2021-01--06 evt-2021-01--07
    """
    gt_path = scenario_output / "GROUND_TRUTH.json"
    gt = json.loads(gt_path.read_text(encoding="utf-8"))

    events = gt["events"]
    if target_ids:
        events = [e for e in events if e.get("storyline_id") in target_ids]

    # 收集所有 host 目录
    data_dir = scenario_output / "data"
    hosts = [d for d in data_dir.iterdir() if d.is_dir()]
    print(f"Hosts: {[h.name for h in hosts]}")

    # 加载所有 XML + eCAR
    xml_logs: list[dict] = []
    ecar_logs: list[dict] = []
    for h in hosts:
        xml_logs.extend(parse_xml_log(h / "windows_event_security.xml"))
        xml_logs.extend(parse_xml_log(h / "windows_event_sysmon.xml"))
        ecar_logs.extend(parse_ecar(h / "ecar.json"))
    print(f"Loaded {len(xml_logs)} XML events, {len(ecar_logs)} eCAR events")
    print()

    # 对每个 GT 事件做 join
    for ev in events:
        print("=" * 76)
        rid = ev["record_id"]
        sid = ev.get("storyline_id", "?")
        print(f"GT record_id={rid}  storyline_id={sid}")
        print(f"  activity: {ev['activity']}")
        print(f"  time:     {ev['time']}")
        attrs = ev.get("attributes", {})
        print(f"  attributes: {json.dumps(attrs, ensure_ascii=False)}")

        xml_hits = find_xml_matches(ev, xml_logs, tolerance_s=5.0)
        ecar_hits = find_ecar_matches(ev, ecar_logs, tolerance_s=5.0)

        print(f"\n  → XML matches: {len(xml_hits)} 条")
        for h in xml_hits[:3]:
            print(f"    [{h['eid']}] {h['src']} @ {h['ts']} (score={h['score']:.0f})")
            for r in h["reasons"][:3]:
                print(f"        • {r}")
            # 显示关键字段
            for k in ("NewProcessName", "CommandLine", "DestinationIp", "DestinationPort",
                      "TargetUserName", "ProcessId"):
                if k in h["data_snippet"]:
                    val = h["data_snippet"][k][:90]
                    print(f"        {k}: {val}")

        print(f"\n  → eCAR matches: {len(ecar_hits)} 条")
        for h in ecar_hits[:3]:
            ts = h["ts_ms"]
            from datetime import datetime
            ts_str = datetime.fromtimestamp(ts / 1000).strftime("%H:%M:%S.%f")[:-3]
            print(f"    [{h['object']}/{h['action']}] {h['src']} @ {ts_str} (score={h['score']:.0f})")
            for r in h["reasons"][:3]:
                print(f"        • {r}")
            for k in ("image_path", "command_line", "dst_ip", "dst_port", "registry_key"):
                if k in h["properties"]:
                    val = str(h["properties"][k])[:90]
                    print(f"        {k}: {val}")
        print()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("output_dir", type=Path, help="output/<name> 目录")
    ap.add_argument("--ids", nargs="+", default=[], help="storyline_id 过滤")
    args = ap.parse_args()
    main(args.output_dir, args.ids)
