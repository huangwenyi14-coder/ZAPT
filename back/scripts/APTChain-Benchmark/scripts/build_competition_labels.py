#!/usr/bin/env python3
"""Build competition-style labels by joining GROUND_TRUTH.json back to logs."""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ElementTree
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

OUTPUT_DIR = Path("output")
SCENARIOS_DIR = Path("scenarios")
DEFAULT_LABEL_DIR = OUTPUT_DIR / "competition_labels"
XML_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
EVENT_START_PATTERN = re.compile(r"<Event(?:\s|>)")
EVENT_END_PATTERN = re.compile(r"</Event>")
TECHNIQUE_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")

TECHNIQUE_TACTICS = {
    "T1005": "Collection",
    "T1016": "Discovery",
    "T1027": "Defense Evasion",
    "T1036": "Defense Evasion",
    "T1036.006": "Defense Evasion",
    "T1037.004": "Persistence",
    "T1033": "Discovery",
    "T1041": "Exfiltration",
    "T1046": "Discovery",
    "T1049": "Discovery",
    "T1053.003": "Persistence",
    "T1053.005": "Persistence",
    "T1055": "Defense Evasion",
    "T1055.002": "Defense Evasion",
    "T1059.001": "Execution",
    "T1059.003": "Execution",
    "T1070.004": "Defense Evasion",
    "T1071": "Command and Control",
    "T1071.001": "Command and Control",
    "T1078": "Initial Access",
    "T1082": "Discovery",
    "T1083": "Discovery",
    "T1095": "Command and Control",
    "T1105": "Command and Control",
    "T1113": "Collection",
    "T1115": "Collection",
    "T1140": "Defense Evasion",
    "T1189": "Initial Access",
    "T1203": "Execution",
    "T1204.002": "Execution",
    "T1217": "Discovery",
    "T1218.005": "Defense Evasion",
    "T1218.007": "Defense Evasion",
    "T1218.011": "Defense Evasion",
    "T1219": "Command and Control",
    "T1497": "Defense Evasion",
    "T1497.001": "Defense Evasion",
    "T1539": "Credential Access",
    "T1547.001": "Persistence",
    "T1552.001": "Credential Access",
    "T1555.003": "Credential Access",
    "T1560": "Collection",
    "T1560.001": "Collection",
    "T1560.003": "Collection",
    "T1562.001": "Defense Evasion",
    "T1566": "Initial Access",
    "T1566.001": "Initial Access",
    "T1566.002": "Initial Access",
    "T1566.003": "Initial Access",
    "T1567.002": "Exfiltration",
    "T1568": "Command and Control",
    "T1573.001": "Command and Control",
    "T1574.002": "Persistence",
    "T1018": "Discovery",
    "T1591": "Reconnaissance",
    "T1603": "Collection",
    "T1620": "Defense Evasion",
}


@dataclass(frozen=True)
class EvidenceRef:
    source_type: str
    source_file: str
    record_ref: str
    log_id: str
    match_reason: str
    timestamp: str | None = None
    physical_record_id: str | None = None
    relative_path: str | None = None
    record_index: int | None = None
    byte_offset: int | None = None
    byte_length: int | None = None

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "source_type": self.source_type,
            "source_file": self.source_file,
            "record_ref": self.record_ref,
            "log_id": self.log_id,
            "match_reason": self.match_reason,
        }
        if self.timestamp:
            out["timestamp"] = self.timestamp
        if self.physical_record_id:
            out["physical_record_id"] = self.physical_record_id
        if self.relative_path:
            out["relative_path"] = self.relative_path
        if self.record_index is not None:
            out["record_index"] = self.record_index
        if self.byte_offset is not None:
            out["byte_offset"] = self.byte_offset
        if self.byte_length is not None:
            out["byte_length"] = self.byte_length
        return out


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create answer/label JSON files from output/*/GROUND_TRUTH.json and data/* logs."
    )
    parser.add_argument("--output-root", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--scenarios-root", type=Path, default=SCENARIOS_DIR)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_LABEL_DIR)
    parser.add_argument("--scenario", action="append", default=[])
    return parser.parse_args()


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def iso_from_epoch(seconds: float | int | None) -> str | None:
    if seconds is None:
        return None
    return datetime.fromtimestamp(float(seconds), UTC).isoformat().replace("+00:00", "Z")


def parse_duration(value: str | None) -> timedelta:
    if not value:
        return timedelta()
    compact = re.sub(r"\s+", "", value)
    parts = re.findall(r"(\d+)(ms|[smhd])", compact)
    if not parts or "".join(f"{amount}{unit}" for amount, unit in parts) != compact:
        return timedelta()
    duration = timedelta()
    for raw_amount, unit in parts:
        amount = int(raw_amount)
        if unit == "ms":
            duration += timedelta(milliseconds=amount)
        elif unit == "s":
            duration += timedelta(seconds=amount)
        elif unit == "m":
            duration += timedelta(minutes=amount)
        elif unit == "h":
            duration += timedelta(hours=amount)
        else:
            duration += timedelta(days=amount)
    return duration


def normalize_host(value: str | None) -> str:
    if not value:
        return ""
    return value.split(".", 1)[0].lower()


def source_type_for(path: Path) -> str:
    if path.name == "ecar.json":
        return "ecar"
    if path.name == "windows_event_security.xml":
        return "windows_security"
    if path.name == "windows_event_sysmon.xml":
        return "sysmon"
    if path.name == "syslog.log":
        return "syslog"
    if path.suffix == ".json":
        return f"zeek_{path.stem}"
    return path.stem


def relative_to_scenario(path: Path, scenario_dir: Path) -> str:
    return path.relative_to(scenario_dir).as_posix()


def load_scenario_yaml(scenario_name: str, scenarios_root: Path) -> dict[str, Any]:
    path = scenarios_root / scenario_name / "scenario.yaml"
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def technique_ids(techniques: Iterable[str]) -> list[str]:
    ids: list[str] = []
    for technique in techniques:
        for match in TECHNIQUE_PATTERN.findall(str(technique)):
            if match not in ids:
                ids.append(match)
    return ids


def scenario_techniques_by_storyline(scenario_yaml: dict[str, Any]) -> dict[str, list[str]]:
    by_id: dict[str, list[str]] = {}
    for step in scenario_yaml.get("storyline", []) or []:
        values: list[str] = []
        for event in step.get("events", []) or []:
            technique = event.get("technique")
            if technique:
                values.append(str(technique))
        if values:
            by_id[str(step.get("id"))] = values
    return by_id


def scenario_specs_by_storyline(scenario_yaml: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Return authored typed specs keyed by storyline ID."""
    return {
        str(step.get("id")): list(step.get("events", []) or [])
        for step in scenario_yaml.get("storyline", []) or []
    }


def enrich_ground_truth_events(
    events: list[dict[str, Any]], scenario_yaml: dict[str, Any]
) -> list[dict[str, Any]]:
    """Attach authored fields that are useful for exact evidence joins."""
    specs_by_step = scenario_specs_by_storyline(scenario_yaml)
    enriched: list[dict[str, Any]] = []
    for event in events:
        item = dict(event)
        attrs = dict(event.get("attributes", {}))
        matching_specs = [
            spec
            for spec in specs_by_step.get(str(event.get("storyline_id")), [])
            if spec.get("type") == event.get("kind")
        ]
        authored = matching_specs[0] if matching_specs else {}
        for key in (
            "hostname",
            "source_file",
            "source_process_ref",
            "terminate_source_process",
            "persistent",
        ):
            if authored.get(key) is not None:
                attrs.setdefault(key, authored[key])
        item["attributes"] = attrs
        enriched.append(item)
    return enriched


def infer_retail_technique(event: dict[str, Any]) -> str:
    activity = str(event.get("activity", "")).lower()
    cmd = str(event.get("attributes", {}).get("command_line", "")).lower()
    if "ftp" in activity and event.get("kind") == "connection":
        return "T1190 - Exploit Public-Facing Application"
    if "whoami" in cmd or cmd == "id":
        return "T1033 - System Owner/User Discovery"
    if "uname" in cmd:
        return "T1082 - System Information Discovery"
    if "passwd" in cmd or "group" in cmd or "ls -la /home" in cmd:
        return "T1087 - Account Discovery"
    if "ps aux" in cmd:
        return "T1057 - Process Discovery"
    if "netstat" in cmd or "ip addr" in cmd or "ip route" in cmd or "resolv.conf" in cmd:
        return "T1016 - System Network Configuration Discovery"
    if "find /" in cmd or "df -h" in cmd or "/etc/hosts" in cmd:
        return "T1083 - File and Directory Discovery"
    if "arp -a" in cmd or "ping -c" in cmd:
        return "T1018 - Remote System Discovery"
    if "nmap" in cmd:
        return "T1046 - Network Service Discovery"
    if "auth.log" in cmd or "history" in cmd:
        return "T1005 - Data from Local System"
    if "password" in cmd:
        return "T1552.001 - Unsecured Credentials: Credentials In Files"
    return ""


def tactic_for(technique_ids_: list[str], event_kind: str) -> str:
    for tid in technique_ids_:
        if tid in TECHNIQUE_TACTICS:
            return TECHNIQUE_TACTICS[tid]
        parent = tid.split(".", 1)[0]
        if parent in TECHNIQUE_TACTICS:
            return TECHNIQUE_TACTICS[parent]
    if event_kind == "beacon":
        return "Command and Control"
    if event_kind == "connection":
        return "Command and Control"
    if event_kind == "logon":
        return "Initial Access"
    return "Execution"


def build_step_event_map(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by_step: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        by_step[str(event["storyline_id"])].append(event)
    return by_step


def step_timestamp(events: list[dict[str, Any]]) -> str:
    if not events:
        return ""
    return min(event["time"] for event in events)


def key_entities_for(events: list[dict[str, Any]], techniques: list[str]) -> dict[str, list[str]]:
    entities: dict[str, set[str]] = defaultdict(set)
    for event in events:
        attrs = event.get("attributes", {})
        for key in (
            "dst_ip",
            "dst_port",
            "source_ip",
            "logon_id",
            "task_name",
            "uid",
            "output_file",
            "network_url",
            "query",
            "target_process",
            "source_file",
            "size_bytes",
            "orig_bytes",
        ):
            value = attrs.get(key)
            if value is not None and value != "(filtered by sensor placement)":
                entities[key].add(str(value))
        hostname = attrs.get("hostname")
        if hostname:
            entities["domain"].add(str(hostname))
        for key in ("files", "source_files"):
            for path in attrs.get(key, []) or []:
                entities["file"].add(str(path))
        process_name = attrs.get("process_name")
        if process_name:
            entities["process"].add(Path(str(process_name).replace("\\", "/")).name)
            entities["process_path"].add(str(process_name))
        command_line = attrs.get("command_line")
        if command_line:
            entities["command_line"].add(str(command_line))
        task_content = attrs.get("task_content")
        if task_content:
            for exe in re.findall(r"[\w. -]+\.exe", task_content, flags=re.IGNORECASE):
                entities["process"].add(exe.strip('"'))
    for technique in techniques:
        for tid in TECHNIQUE_PATTERN.findall(technique):
            entities["ttp"].add(tid)
    return {key: sorted(values) for key, values in sorted(entities.items())}


def event_window(event: dict[str, Any]) -> tuple[datetime, datetime]:
    start = parse_iso(event["time"])
    attrs = event.get("attributes", {})
    if event.get("kind") == "beacon":
        duration = parse_duration(attrs.get("termination")) or timedelta(hours=1)
        return start - timedelta(seconds=5), start + duration + timedelta(minutes=2)
    if event.get("kind") == "process":
        return start - timedelta(seconds=3), start + timedelta(seconds=8)
    if event.get("kind") in {"file_collection", "archive_create"}:
        completed = attrs.get("completed_at")
        end = parse_iso(completed) if completed else start
        return start - timedelta(seconds=2), end + timedelta(seconds=2)
    if event.get("kind") == "scheduled_task_created":
        return start - timedelta(seconds=10), start + timedelta(minutes=5)
    if event.get("kind") == "logon":
        return start - timedelta(seconds=10), start + timedelta(seconds=30)
    return start - timedelta(seconds=15), start + timedelta(minutes=3)


def event_matches_json_record(event: dict[str, Any], record: dict[str, Any]) -> str | None:
    attrs = event.get("attributes", {})
    uid = attrs.get("uid")
    if uid and uid != "(filtered by sensor placement)":
        record_uids = {str(record.get("uid", ""))}
        for value in record.get("conn_uids", []) or []:
            record_uids.add(str(value))
        if uid in record_uids:
            return "uid"

    timestamp = record.get("ts")
    if timestamp is None:
        return None
    record_time = datetime.fromtimestamp(float(timestamp), UTC)
    win_start, win_end = event_window(event)
    kind = event.get("kind")
    if kind in {"file_collection", "archive_create"}:
        return None

    if kind == "process":
        network_url = attrs.get("network_url")
        if not network_url:
            return None
        parsed = urlparse(str(network_url))
        event_time = parse_iso(event["time"])
        if record.get("query") == parsed.hostname and event_time - timedelta(
            seconds=45
        ) <= record_time <= event_time + timedelta(seconds=5):
            return "dns_prerequisite"
        if (
            record.get("host") == parsed.hostname
            and record.get("uri") == (parsed.path or "/")
            and event_time - timedelta(seconds=5)
            <= record_time
            <= event_time + timedelta(minutes=3)
        ):
            return "process_http_effect"
        return None

    hostname = attrs.get("hostname")
    if hostname and record.get("query") == hostname:
        event_time = parse_iso(event["time"])
        if event_time - timedelta(seconds=45) <= record_time <= event_time + timedelta(seconds=5):
            return "dns_prerequisite"
    if hostname and kind == "connection":
        subject = str(record.get("certificate.subject", ""))
        if f"CN={hostname}" in subject and win_start <= record_time <= win_end:
            return "tls_certificate"
    if not (win_start <= record_time <= win_end):
        return None

    dst_ip = attrs.get("dst_ip")
    dst_port = attrs.get("dst_port")
    if dst_ip and dst_ip == record.get("id.resp_h"):
        if dst_port is None or str(dst_port) == str(record.get("id.resp_p")):
            if event.get("kind") == "beacon":
                return "beacon_dst_time"
            return "dst_time"
    query = attrs.get("query")
    if query and query == record.get("query"):
        return "dns_query"
    return None


def extract_xml_fields(raw: str) -> tuple[dict[str, Any], datetime | None]:
    fields: dict[str, Any] = {}
    timestamp: datetime | None = None
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError:
        return fields, timestamp
    system = root.find(f"{{{XML_NS}}}System")
    if system is not None:
        for tag in ("EventID", "EventRecordID", "Computer", "Channel"):
            element = system.find(f"{{{XML_NS}}}{tag}")
            if element is not None and element.text:
                fields[tag] = element.text
        time_created = system.find(f"{{{XML_NS}}}TimeCreated")
        if time_created is not None:
            value = time_created.get("SystemTime")
            if value:
                fields["TimeCreated"] = value
                try:
                    timestamp = parse_iso(value)
                except ValueError:
                    timestamp = None
    event_data = root.find(f"{{{XML_NS}}}EventData")
    if event_data is not None:
        for data_el in event_data.findall(f"{{{XML_NS}}}Data"):
            name = data_el.get("Name")
            if name:
                fields[name] = data_el.text or ""
    return fields, timestamp


def event_matches_xml_fields(
    event: dict[str, Any], fields: dict[str, Any], ts: datetime | None
) -> str | None:
    if ts is None:
        return None
    win_start, win_end = event_window(event)
    attrs = event.get("attributes", {})
    pid = attrs.get("pid")
    pid_hex = f"0x{pid:x}" if isinstance(pid, int) else None
    cmd = attrs.get("command_line")
    process_name = attrs.get("process_name")
    logon_id = attrs.get("logon_id")
    task_name = attrs.get("task_name")
    dst_ip = attrs.get("dst_ip")
    dst_port = attrs.get("dst_port")
    query = attrs.get("query")
    hostname = attrs.get("hostname")
    kind = event.get("kind")
    event_id = str(fields.get("EventID", ""))
    pid_values = {
        str(fields.get("ProcessId", "")),
        str(fields.get("ProcessID", "")),
        str(fields.get("NewProcessId", "")),
        str(fields.get("SourceProcessId", "")),
    }
    pid_matches = pid is not None and (
        str(pid) in pid_values
        or (pid_hex is not None and pid_hex.lower() in {value.lower() for value in pid_values})
    )

    if kind == "file_collection":
        return None

    if kind == "archive_create":
        if (
            event_id == "11"
            and pid_matches
            and fields.get("TargetFilename") == attrs.get("output_file")
            and win_start <= ts <= win_end
        ):
            return "archive_output"
        return None

    if kind == "process":
        event_time = parse_iso(event["time"])
        network_url = attrs.get("network_url")
        if network_url:
            hostname = urlparse(str(network_url)).hostname
            if (
                event_id == "22"
                and fields.get("QueryName") == hostname
                and event_time - timedelta(seconds=45) <= ts <= event_time + timedelta(seconds=5)
            ):
                return "dns_prerequisite"
            if (
                event_id in {"3", "5156"}
                and pid_matches
                and event_time - timedelta(seconds=5) <= ts <= event_time + timedelta(minutes=3)
            ):
                return "process_network_effect"
        if not pid_matches:
            return None
        if win_start <= ts <= win_end and event_id in {"1", "4688"}:
            rendered_image = fields.get("Image") or fields.get("NewProcessName")
            if cmd and fields.get("CommandLine") == cmd:
                return "process_create_command"
            if process_name and rendered_image == process_name:
                return "process_create_image"
        if (
            win_start <= ts <= win_end
            and event_id == "11"
            and process_name
            and fields.get("TargetFilename") == process_name
        ):
            return "process_image_create"
        if (
            not attrs.get("persistent")
            and event_id in {"5", "4689"}
            and event_time <= ts <= event_time + timedelta(minutes=15)
        ):
            return "process_terminate"
        return None

    if kind == "connection":
        event_time = parse_iso(event["time"])
        if (
            event_id == "22"
            and hostname
            and fields.get("QueryName") == hostname
            and event_time - timedelta(seconds=45) <= ts <= event_time + timedelta(seconds=5)
        ):
            return "dns_prerequisite"
        if (
            event_id == "5156"
            and str(fields.get("DestPort")) == "53"
            and normalize_host(fields.get("Computer")) == normalize_host(event.get("system"))
            and event_time - timedelta(seconds=5) <= ts <= event_time + timedelta(seconds=1)
        ):
            return "dns_transport"
        field_dst_ip = fields.get("DestinationIp") or fields.get("DestAddress")
        field_dst_port = fields.get("DestinationPort") or fields.get("DestPort")
        process_owner_known = isinstance(pid, int) and pid > 0
        if (
            event_id in {"3", "5156"}
            and (pid_matches or not process_owner_known)
            and dst_ip
            and field_dst_ip == dst_ip
            and (dst_port is None or str(field_dst_port) == str(dst_port))
            and win_start <= ts <= win_end
        ):
            return "process_dst_tuple"
        if (
            attrs.get("process_terminated")
            and event_id in {"5", "4689"}
            and pid_matches
            and event_time <= ts <= event_time + timedelta(minutes=15)
        ):
            return "process_terminate"
        return None

    if task_name and fields.get("TaskName") == task_name:
        if win_start <= ts <= win_end:
            return "task_name_time"

    if pid is not None:
        if str(pid) in pid_values or (
            pid_hex and pid_hex.lower() in {v.lower() for v in pid_values}
        ):
            if cmd and fields.get("CommandLine") == cmd:
                return "pid_command"
            if process_name and fields.get("Image") == process_name:
                return "pid_image"
            if win_start <= ts <= win_end:
                return "pid_time"

    if cmd and fields.get("CommandLine") == cmd:
        return "command_line"

    if logon_id and logon_id.lower() in {
        str(fields.get("SubjectLogonId", "")).lower(),
        str(fields.get("TargetLogonId", "")).lower(),
        str(fields.get("LogonId", "")).lower(),
    }:
        if win_start <= ts <= win_end or event.get("kind") == "process":
            return "logon_id_time"

    if query and fields.get("QueryName") == query:
        if win_start <= ts <= win_end:
            return "dns_query_time"

    field_dst_ip = fields.get("DestinationIp") or fields.get("DestAddress")
    field_dst_port = fields.get("DestinationPort") or fields.get("DestPort")
    if dst_ip and field_dst_ip == dst_ip:
        if dst_port is None or str(field_dst_port) == str(dst_port):
            if win_start <= ts <= win_end:
                return "dst_time"
            if event.get("kind") == "beacon" and win_start <= ts <= win_end + timedelta(minutes=1):
                return "beacon_dst_time"
    return None


def event_matches_ecar_record(event: dict[str, Any], record: dict[str, Any]) -> str | None:
    ts_ms = record.get("timestamp_ms")
    if ts_ms is None:
        return None
    ts = datetime.fromtimestamp(int(ts_ms) / 1000, UTC)
    win_start, win_end = event_window(event)
    attrs = event.get("attributes", {})
    props = record.get("properties", {}) or {}
    kind = event.get("kind")
    pid = attrs.get("pid")
    pid_matches = pid is not None and record.get("pid") == pid

    if kind == "file_collection":
        if (
            pid_matches
            and record.get("object") == "FILE"
            and record.get("action") == "READ"
            and props.get("file_path") in set(attrs.get("files", []) or [])
            and win_start <= ts <= win_end
        ):
            return "collected_file_read"
        return None

    if kind == "archive_create":
        if not pid_matches or record.get("object") != "FILE" or not (win_start <= ts <= win_end):
            return None
        file_path = props.get("file_path")
        if record.get("action") == "READ" and file_path in set(attrs.get("source_files", []) or []):
            return "archive_input_read"
        if record.get("action") == "CREATE" and file_path == attrs.get("output_file"):
            return "archive_output"
        return None

    if kind == "process":
        event_time = parse_iso(event["time"])
        network_url = attrs.get("network_url")
        if (
            network_url
            and pid_matches
            and record.get("object") == "FLOW"
            and event_time - timedelta(seconds=5) <= ts <= event_time + timedelta(minutes=3)
        ):
            parsed_url = urlparse(str(network_url))
            expected_port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
            if str(props.get("dst_port")) == str(expected_port):
                return "process_network_effect"
        if not pid_matches:
            return None
        if (
            win_start <= ts <= win_end
            and record.get("object") == "PROCESS"
            and record.get("action") == "CREATE"
        ):
            if attrs.get("command_line") and props.get("command_line") == attrs.get("command_line"):
                return "process_create_command"
            if attrs.get("process_name") and props.get("image_path") == attrs.get("process_name"):
                return "process_create_image"
        if (
            win_start <= ts <= win_end
            and record.get("object") == "FILE"
            and record.get("action") == "CREATE"
            and props.get("file_path") == attrs.get("process_name")
        ):
            return "process_image_create"
        if (
            not attrs.get("persistent")
            and record.get("object") == "PROCESS"
            and record.get("action") == "TERMINATE"
            and event_time <= ts <= event_time + timedelta(minutes=15)
        ):
            return "process_terminate"
        return None

    if kind == "connection":
        event_time = parse_iso(event["time"])
        process_owner_known = isinstance(pid, int) and pid > 0
        if (
            pid_matches
            and record.get("object") == "FILE"
            and record.get("action") == "READ"
            and props.get("file_path") == attrs.get("source_file")
            and win_start <= ts <= win_end
        ):
            return "upload_source_read"
        if (
            record.get("object") == "FLOW"
            and str(props.get("dst_port")) == "53"
            and normalize_host(record.get("hostname")) == normalize_host(event.get("system"))
            and event_time - timedelta(seconds=5) <= ts <= event_time + timedelta(seconds=1)
        ):
            return "dns_transport"
        if (
            record.get("object") == "FLOW"
            and (pid_matches or not process_owner_known)
            and props.get("dst_ip") == attrs.get("dst_ip")
            and str(props.get("dst_port")) == str(attrs.get("dst_port"))
            and win_start <= ts <= win_end
        ):
            return "process_dst_tuple"
        if (
            attrs.get("process_terminated")
            and pid_matches
            and record.get("object") == "PROCESS"
            and record.get("action") == "TERMINATE"
            and event_time <= ts <= event_time + timedelta(minutes=15)
        ):
            return "process_terminate"
        return None

    logon_id = attrs.get("logon_id")
    if logon_id and str(props.get("logon_id", "")).lower() == str(logon_id).lower():
        if win_start <= ts <= win_end:
            return "logon_id_time"

    if pid is not None and record.get("pid") == pid:
        cmd = attrs.get("command_line")
        if cmd and props.get("command_line") == cmd:
            return "pid_command"
        if win_start <= ts <= win_end:
            return "pid_time"

    task_name = attrs.get("task_name")
    if task_name and task_name in json.dumps(record, ensure_ascii=False):
        if win_start <= ts <= win_end:
            return "task_name_time"

    dst_ip = attrs.get("dst_ip")
    dst_port = attrs.get("dst_port")
    if dst_ip and props.get("dst_ip") == dst_ip:
        if dst_port is None or str(props.get("dst_port")) == str(dst_port):
            if win_start <= ts <= win_end:
                return "beacon_dst_time" if event.get("kind") == "beacon" else "dst_time"
    return None


def scan_json_file(
    path: Path, scenario_dir: Path, events: list[dict[str, Any]]
) -> dict[str, list[EvidenceRef]]:
    hits: dict[str, list[EvidenceRef]] = defaultdict(list)
    source_file = relative_to_scenario(path, scenario_dir)
    source_type = source_type_for(path)
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            timestamp = iso_from_epoch(record.get("ts"))
            for event in events:
                reason = event_matches_json_record(event, record)
                if not reason:
                    continue
                uid = record.get("uid") or record.get("fuid") or f"line:{line_no}"
                hits[event["record_id"]].append(
                    EvidenceRef(
                        source_type=source_type,
                        source_file=source_file,
                        record_ref=f"line:{line_no}",
                        log_id=f"{source_file}#{uid}",
                        match_reason=reason,
                        timestamp=timestamp,
                    )
                )
    return hits


def scan_ecar_file(
    path: Path, scenario_dir: Path, events: list[dict[str, Any]]
) -> dict[str, list[EvidenceRef]]:
    hits: dict[str, list[EvidenceRef]] = defaultdict(list)
    source_file = relative_to_scenario(path, scenario_dir)
    source_type = source_type_for(path)
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            timestamp_ms = record.get("timestamp_ms")
            timestamp = None
            if timestamp_ms is not None:
                timestamp = iso_from_epoch(int(timestamp_ms) / 1000)
            for event in events:
                reason = event_matches_ecar_record(event, record)
                if not reason:
                    continue
                log_id = record.get("id") or f"{source_file}#line:{line_no}"
                hits[event["record_id"]].append(
                    EvidenceRef(
                        source_type=source_type,
                        source_file=source_file,
                        record_ref=f"line:{line_no}",
                        log_id=f"{source_file}#{log_id}",
                        match_reason=reason,
                        timestamp=timestamp,
                    )
                )
    return hits


def scan_xml_file(
    path: Path, scenario_dir: Path, events: list[dict[str, Any]]
) -> dict[str, list[EvidenceRef]]:
    hits: dict[str, list[EvidenceRef]] = defaultdict(list)
    source_file = relative_to_scenario(path, scenario_dir)
    source_type = source_type_for(path)
    in_event = False
    event_lines: list[str] = []
    start_line = 0
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not in_event and EVENT_START_PATTERN.search(line):
                in_event = True
                event_lines = [line]
                start_line = line_no
            elif in_event:
                event_lines.append(line)
            if in_event and EVENT_END_PATTERN.search(line):
                raw = "".join(event_lines)
                fields, ts = extract_xml_fields(raw)
                for event in events:
                    reason = event_matches_xml_fields(event, fields, ts)
                    if not reason:
                        continue
                    event_record_id = fields.get("EventRecordID") or f"line:{start_line}"
                    timestamp = ts.isoformat().replace("+00:00", "Z") if ts else None
                    hits[event["record_id"]].append(
                        EvidenceRef(
                            source_type=source_type,
                            source_file=source_file,
                            record_ref=f"line:{start_line}",
                            log_id=f"{source_file}#EventRecordID:{event_record_id}",
                            match_reason=reason,
                            timestamp=timestamp,
                        )
                    )
                in_event = False
                event_lines = []
    return hits


def merge_hits(target: dict[str, list[EvidenceRef]], source: dict[str, list[EvidenceRef]]) -> None:
    seen = {record_id: {ref.log_id for ref in refs} for record_id, refs in target.items()}
    for record_id, refs in source.items():
        bucket = target[record_id]
        bucket_seen = seen.setdefault(record_id, {ref.log_id for ref in bucket})
        for ref in refs:
            if ref.log_id in bucket_seen:
                continue
            bucket.append(ref)
            bucket_seen.add(ref.log_id)


def scan_logs(scenario_dir: Path, events: list[dict[str, Any]]) -> dict[str, list[EvidenceRef]]:
    hits: dict[str, list[EvidenceRef]] = defaultdict(list)
    data_dir = scenario_dir / "data"
    if not data_dir.exists():
        return hits
    for path in sorted(data_dir.rglob("*")):
        if not path.is_file() or path.name == ".DS_Store":
            continue
        if path.name == "COLLECTION_PROFILE.json":
            continue
        if path.name == "ecar.json":
            merge_hits(hits, scan_ecar_file(path, scenario_dir, events))
        elif path.suffix == ".json":
            merge_hits(hits, scan_json_file(path, scenario_dir, events))
        elif path.suffix == ".xml":
            merge_hits(hits, scan_xml_file(path, scenario_dir, events))
    for refs in hits.values():
        refs.sort(key=lambda ref: (ref.source_file, ref.record_ref, ref.log_id))
    expand_correlated_ecar_actors(scenario_dir, events, hits)
    expand_correlated_zeek_uids(scenario_dir, hits)
    expand_dns_endpoint_flows(scenario_dir, hits)
    return assign_each_log_once(events, hits)


MATCH_REASON_PRIORITY = {
    "uid": 120,
    "collected_file_read": 115,
    "archive_input_read": 115,
    "archive_output": 115,
    "upload_source_read": 115,
    "process_create_command": 110,
    "process_create_image": 108,
    "process_image_create": 106,
    "process_http_effect": 105,
    "process_network_effect": 105,
    "process_dst_tuple": 105,
    "process_terminate": 102,
    "beacon_process_owner": 101,
    "process_actor_id": 101,
    "dns_prerequisite": 100,
    "dns_transport_uid": 100,
    "dns_endpoint_tuple": 100,
    "zeek_transaction_uid": 100,
    "zeek_file_id": 100,
    "dns_transport": 99,
    "tls_certificate": 98,
    "task_name_time": 95,
    "dns_query": 95,
    "pid_command": 90,
    "pid_image": 85,
    "logon_id_time": 80,
    "pid_time": 70,
    "beacon_dst_time": 65,
    "dst_time": 60,
}


def expand_correlated_ecar_actors(
    scenario_dir: Path,
    events: list[dict[str, Any]],
    hits: dict[str, list[EvidenceRef]],
) -> None:
    """Expand exact eCAR actor links and beacon process-owner lifecycle records."""
    event_kinds = {str(event["record_id"]): str(event.get("kind")) for event in events}
    owners_by_record_id: dict[str, set[str]] = defaultdict(set)
    beacon_flows_by_record_id: dict[str, set[str]] = defaultdict(set)
    for record_id, refs in hits.items():
        for ref in refs:
            if ref.source_type != "ecar":
                continue
            ecar_record_id = ref.log_id.rsplit("#", 1)[-1]
            if ref.match_reason in {"process_create_command", "process_create_image"}:
                owners_by_record_id[ecar_record_id].add(record_id)
            if event_kinds.get(record_id) == "beacon" and ref.match_reason in {
                "beacon_dst_time",
                "dst_time",
            }:
                beacon_flows_by_record_id[ecar_record_id].add(record_id)
    if not owners_by_record_id and not beacon_flows_by_record_id:
        return

    beacon_owner_processes: list[tuple[str, int, datetime, str, str]] = []
    process_file_effects: list[tuple[str, int, datetime, str]] = []
    for path in sorted((scenario_dir / "data").rglob("ecar.json")):
        source_file = relative_to_scenario(path, scenario_dir)
        records: list[tuple[int, dict[str, Any]]] = []
        process_owners: dict[str, set[str]] = defaultdict(set)
        beacon_owners: dict[str, set[str]] = defaultdict(set)
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                records.append((line_no, record))
                record_key = str(record.get("id", ""))
                for owner in owners_by_record_id.get(record_key, set()):
                    object_id = str(record.get("objectID", ""))
                    if object_id:
                        process_owners[object_id].add(owner)
                for owner in beacon_flows_by_record_id.get(record_key, set()):
                    actor_id = str(record.get("actorID", ""))
                    if actor_id:
                        beacon_owners[actor_id].add(owner)
        for line_no, record in records:
            actor_id = str(record.get("actorID", ""))
            record_key = str(record.get("id", f"line:{line_no}"))
            timestamp = iso_from_epoch(
                int(record["timestamp_ms"]) / 1000
                if record.get("timestamp_ms") is not None
                else None
            )
            for record_id in process_owners.get(actor_id, set()):
                # Network evidence belongs to the explicit connection/beacon step.
                # A persistent process's actorID can span hours; assigning all of
                # its FLOW rows back to the process-create step hides the actual
                # C2 lifecycle and defeats one-log/one-storyline labeling.
                if record.get("object") == "FLOW":
                    continue
                hits[record_id].append(
                    EvidenceRef(
                        source_type="ecar",
                        source_file=source_file,
                        record_ref=f"line:{line_no}",
                        log_id=f"{source_file}#{record_key}",
                        match_reason="process_actor_id",
                        timestamp=timestamp,
                    )
                )
                properties = record.get("properties", {}) or {}
                file_path = str(properties.get("file_path", ""))
                if (
                    record.get("object") == "FILE"
                    and record.get("action") in {"CREATE", "WRITE"}
                    and record.get("timestamp_ms") is not None
                    and record.get("pid") is not None
                    and file_path
                ):
                    process_file_effects.append(
                        (
                            record_id,
                            int(record["pid"]),
                            datetime.fromtimestamp(int(record["timestamp_ms"]) / 1000, UTC),
                            file_path,
                        )
                    )
            object_id = str(record.get("objectID", ""))
            if (
                object_id not in beacon_owners
                or record.get("object") != "PROCESS"
                or record.get("action") != "CREATE"
                or record.get("timestamp_ms") is None
                or record.get("pid") is None
            ):
                continue
            properties = record.get("properties", {}) or {}
            created_at = datetime.fromtimestamp(int(record["timestamp_ms"]) / 1000, UTC)
            for record_id in beacon_owners[object_id]:
                hits[record_id].append(
                    EvidenceRef(
                        source_type="ecar",
                        source_file=source_file,
                        record_ref=f"line:{line_no}",
                        log_id=f"{source_file}#{record_key}",
                        match_reason="beacon_process_owner",
                        timestamp=timestamp,
                    )
                )
                beacon_owner_processes.append(
                    (
                        record_id,
                        int(record["pid"]),
                        created_at,
                        str(properties.get("image_path", "")),
                        str(properties.get("command_line", "")),
                    )
                )

    if not beacon_owner_processes and not process_file_effects:
        return
    for path in sorted((scenario_dir / "data").rglob("*.xml")):
        source_file = relative_to_scenario(path, scenario_dir)
        source_type = source_type_for(path)
        in_event = False
        event_lines: list[str] = []
        start_line = 0
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                if not in_event and EVENT_START_PATTERN.search(line):
                    in_event = True
                    event_lines = [line]
                    start_line = line_no
                elif in_event:
                    event_lines.append(line)
                if not (in_event and EVENT_END_PATTERN.search(line)):
                    continue
                fields, ts = extract_xml_fields("".join(event_lines))
                in_event = False
                event_lines = []
                if ts is None or str(fields.get("EventID")) not in {"1", "11", "4688"}:
                    continue
                if str(fields.get("EventID")) == "11":
                    for record_id, pid, effect_at, file_path in process_file_effects:
                        if (
                            str(fields.get("ProcessId")) == str(pid)
                            and fields.get("TargetFilename") == file_path
                            and abs((ts - effect_at).total_seconds()) <= 2
                        ):
                            event_record_id = fields.get("EventRecordID") or f"line:{start_line}"
                            hits[record_id].append(
                                EvidenceRef(
                                    source_type=source_type,
                                    source_file=source_file,
                                    record_ref=f"line:{start_line}",
                                    log_id=f"{source_file}#EventRecordID:{event_record_id}",
                                    match_reason="process_actor_id",
                                    timestamp=ts.isoformat().replace("+00:00", "Z"),
                                )
                            )
                    continue
                for record_id, pid, created_at, image_path, command_line in beacon_owner_processes:
                    rendered_pid = (
                        fields.get("NewProcessId")
                        if str(fields.get("EventID")) == "4688"
                        else fields.get("ProcessId")
                    )
                    expected_pids = {str(pid), f"0x{pid:x}"}
                    rendered_image = fields.get("Image") or fields.get("NewProcessName")
                    if (
                        str(rendered_pid).lower() not in {value.lower() for value in expected_pids}
                        or abs((ts - created_at).total_seconds()) > 2
                        or (image_path and rendered_image != image_path)
                        or (command_line and fields.get("CommandLine") != command_line)
                    ):
                        continue
                    event_record_id = fields.get("EventRecordID") or f"line:{start_line}"
                    hits[record_id].append(
                        EvidenceRef(
                            source_type=source_type,
                            source_file=source_file,
                            record_ref=f"line:{start_line}",
                            log_id=f"{source_file}#EventRecordID:{event_record_id}",
                            match_reason="beacon_process_owner",
                            timestamp=ts.isoformat().replace("+00:00", "Z"),
                        )
                    )


def expand_correlated_zeek_uids(scenario_dir: Path, hits: dict[str, list[EvidenceRef]]) -> None:
    """Add Zeek companion rows that share a matched transaction UID."""
    owners_by_uid: dict[str, set[str]] = defaultdict(set)
    for record_id, refs in hits.items():
        for ref in refs:
            is_beacon_http = ref.source_type == "zeek_http" and ref.match_reason in {
                "beacon_dst_time",
                "dst_time",
            }
            if not is_beacon_http and ref.match_reason not in {
                "dns_prerequisite",
                "dns_query",
                "process_http_effect",
            }:
                continue
            owners_by_uid[ref.log_id.rsplit("#", 1)[-1]].add(record_id)
    if not owners_by_uid:
        return

    data_dir = scenario_dir / "data"
    records: list[tuple[Path, int, dict[str, Any]]] = []
    owners_by_fuid: dict[str, set[str]] = defaultdict(set)
    for path in sorted(data_dir.rglob("*.json")):
        if path.name == "ecar.json":
            continue
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                records.append((path, line_no, record))
                record_uids = {str(record.get("uid", ""))}
                record_uids.update(str(uid) for uid in record.get("conn_uids", []) or [])
                owners: set[str] = set()
                for uid in record_uids:
                    owners.update(owners_by_uid.get(uid, set()))
                if not owners:
                    continue
                for fuid_key in ("resp_fuids", "orig_fuids", "cert_chain_fuids"):
                    for fuid in record.get(fuid_key, []) or []:
                        owners_by_fuid[str(fuid)].update(owners)
                fuid = record.get("fuid")
                if fuid:
                    owners_by_fuid[str(fuid)].update(owners)
                source_file = relative_to_scenario(path, scenario_dir)
                source_type = source_type_for(path)
                timestamp = iso_from_epoch(record.get("ts"))
                record_key = (
                    record.get("uid") or record.get("fuid") or record.get("id") or f"line:{line_no}"
                )
                for record_id in owners:
                    hits[record_id].append(
                        EvidenceRef(
                            source_type=source_type,
                            source_file=source_file,
                            record_ref=f"line:{line_no}",
                            log_id=f"{source_file}#{record_key}",
                            match_reason="zeek_transaction_uid",
                            timestamp=timestamp,
                        )
                    )

    for path, line_no, record in records:
        file_id = str(record.get("fuid") or record.get("id") or "")
        owners = owners_by_fuid.get(file_id, set())
        if not owners:
            continue
        source_file = relative_to_scenario(path, scenario_dir)
        source_type = source_type_for(path)
        timestamp = iso_from_epoch(record.get("ts"))
        for record_id in owners:
            hits[record_id].append(
                EvidenceRef(
                    source_type=source_type,
                    source_file=source_file,
                    record_ref=f"line:{line_no}",
                    log_id=f"{source_file}#{file_id}",
                    match_reason="zeek_file_id",
                    timestamp=timestamp,
                )
            )


def expand_dns_endpoint_flows(scenario_dir: Path, hits: dict[str, list[EvidenceRef]]) -> None:
    """Join matched Zeek DNS transactions to endpoint FLOW records by exact tuple."""
    owners_by_uid: dict[str, set[str]] = defaultdict(set)
    for record_id, refs in hits.items():
        for ref in refs:
            if ref.source_type == "zeek_dns" and ref.match_reason in {
                "dns_prerequisite",
                "dns_query",
            }:
                owners_by_uid[ref.log_id.rsplit("#", 1)[-1]].add(record_id)
    if not owners_by_uid:
        return

    dns_tuples: list[tuple[str, datetime, str, str, str, str]] = []
    for path in sorted((scenario_dir / "data").rglob("conn.json")):
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                uid = str(record.get("uid", ""))
                if uid not in owners_by_uid or str(record.get("id.resp_p")) != "53":
                    continue
                ts = datetime.fromtimestamp(float(record["ts"]), UTC)
                for record_id in owners_by_uid[uid]:
                    dns_tuples.append(
                        (
                            record_id,
                            ts,
                            str(record.get("id.orig_h", "")),
                            str(record.get("id.orig_p", "")),
                            str(record.get("id.resp_h", "")),
                            str(record.get("id.resp_p", "")),
                        )
                    )

    for path in sorted((scenario_dir / "data").rglob("ecar.json")):
        source_file = relative_to_scenario(path, scenario_dir)
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                if record.get("object") != "FLOW" or record.get("timestamp_ms") is None:
                    continue
                ts = datetime.fromtimestamp(int(record["timestamp_ms"]) / 1000, UTC)
                props = record.get("properties", {}) or {}
                for record_id, expected_ts, src_ip, src_port, dst_ip, dst_port in dns_tuples:
                    if (
                        abs((ts - expected_ts).total_seconds()) > 2
                        or str(props.get("src_ip")) != src_ip
                        or str(props.get("src_port")) != src_port
                        or str(props.get("dst_ip")) != dst_ip
                        or str(props.get("dst_port")) != dst_port
                    ):
                        continue
                    record_key = record.get("id") or f"line:{line_no}"
                    hits[record_id].append(
                        EvidenceRef(
                            source_type="ecar",
                            source_file=source_file,
                            record_ref=f"line:{line_no}",
                            log_id=f"{source_file}#{record_key}",
                            match_reason="dns_endpoint_tuple",
                            timestamp=ts.isoformat().replace("+00:00", "Z"),
                        )
                    )

    for path in sorted((scenario_dir / "data").rglob("*.xml")):
        source_file = relative_to_scenario(path, scenario_dir)
        source_type = source_type_for(path)
        in_event = False
        event_lines: list[str] = []
        start_line = 0
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                if not in_event and EVENT_START_PATTERN.search(line):
                    in_event = True
                    event_lines = [line]
                    start_line = line_no
                elif in_event:
                    event_lines.append(line)
                if not (in_event and EVENT_END_PATTERN.search(line)):
                    continue
                fields, ts = extract_xml_fields("".join(event_lines))
                in_event = False
                event_lines = []
                if ts is None or str(fields.get("EventID")) not in {"3", "5156"}:
                    continue
                field_src_ip = fields.get("SourceIp") or fields.get("SourceAddress")
                field_src_port = fields.get("SourcePort")
                field_dst_ip = fields.get("DestinationIp") or fields.get("DestAddress")
                field_dst_port = fields.get("DestinationPort") or fields.get("DestPort")
                for record_id, expected_ts, src_ip, src_port, dst_ip, dst_port in dns_tuples:
                    if (
                        abs((ts - expected_ts).total_seconds()) > 2
                        or str(field_src_ip) != src_ip
                        or str(field_src_port) != src_port
                        or str(field_dst_ip) != dst_ip
                        or str(field_dst_port) != dst_port
                    ):
                        continue
                    event_record_id = fields.get("EventRecordID") or f"line:{start_line}"
                    hits[record_id].append(
                        EvidenceRef(
                            source_type=source_type,
                            source_file=source_file,
                            record_ref=f"line:{start_line}",
                            log_id=f"{source_file}#EventRecordID:{event_record_id}",
                            match_reason="dns_endpoint_tuple",
                            timestamp=ts.isoformat().replace("+00:00", "Z"),
                        )
                    )


def assign_each_log_once(
    events: list[dict[str, Any]], hits: dict[str, list[EvidenceRef]]
) -> dict[str, list[EvidenceRef]]:
    """Assign each physical log record to its strongest storyline match."""
    events_by_id = {str(event["record_id"]): event for event in events}
    candidates: dict[str, list[tuple[str, EvidenceRef]]] = defaultdict(list)
    for record_id, refs in hits.items():
        for ref in refs:
            candidates[ref.log_id].append((record_id, ref))

    assigned: dict[str, list[EvidenceRef]] = defaultdict(list)
    for options in candidates.values():

        def rank(option: tuple[str, EvidenceRef]) -> tuple[float, float, str]:
            record_id, ref = option
            priority = float(MATCH_REASON_PRIORITY.get(ref.match_reason, 0))
            event = events_by_id.get(record_id, {})
            distance = float("inf")
            if ref.timestamp and event.get("time"):
                distance = abs(
                    (parse_iso(ref.timestamp) - parse_iso(event["time"])).total_seconds()
                )
            return priority, -distance, record_id

        record_id, ref = max(options, key=rank)
        assigned[record_id].append(ref)

    for refs in assigned.values():
        refs.sort(key=lambda ref: (ref.source_file, ref.record_ref, ref.log_id))
    return assigned


def build_predicted_storyline(
    gt: dict[str, Any],
    scenario_yaml: dict[str, Any],
    evidence_by_record: dict[str, list[EvidenceRef]],
    evidence_by_storyline: dict[str, list[EvidenceRef]] | None = None,
) -> list[dict[str, Any]]:
    events_by_step = build_step_event_map(gt.get("events", []))
    yaml_techniques = scenario_techniques_by_storyline(scenario_yaml)
    predicted: list[dict[str, Any]] = []
    for step in gt.get("storyline_steps", []):
        sid = step["storyline_id"]
        step_events = events_by_step.get(sid, [])
        techniques = yaml_techniques.get(sid, [])
        if not techniques:
            inferred = [infer_retail_technique(event) for event in step_events]
            techniques = [value for value in inferred if value]
        tids = technique_ids(techniques)
        event_type = ",".join(step.get("event_types", [])) or (
            step_events[0].get("kind") if step_events else ""
        )
        evidence_refs: list[dict[str, Any]] = []
        seen_refs: set[str] = set()
        if evidence_by_storyline is not None:
            step_refs = evidence_by_storyline.get(sid, [])
        else:
            step_refs = [
                ref
                for event in step_events
                for ref in evidence_by_record.get(event["record_id"], [])
            ]
        for ref in step_refs:
            if ref.log_id in seen_refs:
                continue
            evidence_refs.append(ref.as_dict())
            seen_refs.add(ref.log_id)
        predicted.append(
            {
                "pred_id": f"p-{step['index'] + 1:03d}",
                "storyline_id": sid,
                "event_type": event_type,
                "timestamp": step_timestamp(step_events),
                "ta": tactic_for(tids, step_events[0].get("kind", "") if step_events else ""),
                "ttp": tids,
                "actor": step.get("actor"),
                "victim": step.get("system"),
                "system": step.get("system"),
                "description": step.get("activity"),
                "key_entities": key_entities_for(step_events, techniques),
                "evidence_refs": evidence_refs,
            }
        )
    return predicted


def load_exact_record_evidence(
    scenario_dir: Path,
) -> tuple[dict[str, list[EvidenceRef]], list[dict[str, Any]]] | None:
    """Load exact malicious physical-record provenance when the final ledger exists."""
    ledger_path = scenario_dir / "RECORD_GROUND_TRUTH.jsonl"
    if not ledger_path.exists():
        return None

    by_storyline: dict[str, list[EvidenceRef]] = defaultdict(list)
    labels: list[dict[str, Any]] = []
    seen_physical_ids: set[str] = set()
    with ledger_path.open(encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                row = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON in {ledger_path} at line {line_number}: {exc}"
                ) from exc
            if row.get("label") != "malicious":
                continue

            physical_record_id = str(row.get("physical_record_id", ""))
            relative_path = str(row.get("relative_path", ""))
            record_index = row.get("record_index")
            if not physical_record_id or not relative_path or not isinstance(record_index, int):
                raise ValueError(
                    f"Malformed malicious record provenance in {ledger_path} at line {line_number}"
                )
            if physical_record_id in seen_physical_ids:
                raise ValueError(
                    f"Duplicate malicious physical_record_id {physical_record_id!r} "
                    f"in {ledger_path}"
                )
            seen_physical_ids.add(physical_record_id)

            storyline_ids = [
                str(value) for value in row.get("contributing_storyline_ids", []) if str(value)
            ]
            primary_storyline_id = str(row.get("storyline_id") or "")
            if primary_storyline_id and primary_storyline_id not in storyline_ids:
                storyline_ids.insert(0, primary_storyline_id)
            source_file = f"data/{relative_path}"
            byte_offset = row.get("byte_offset")
            byte_length = row.get("byte_length")
            ref = EvidenceRef(
                source_type=str(row.get("source_format") or source_type_for(Path(relative_path))),
                source_file=source_file,
                record_ref=f"record_index:{record_index}",
                log_id=physical_record_id,
                match_reason="generation_provenance",
                timestamp=str(row.get("observed_time") or "") or None,
                physical_record_id=physical_record_id,
                relative_path=relative_path,
                record_index=record_index,
                byte_offset=byte_offset if isinstance(byte_offset, int) else None,
                byte_length=byte_length if isinstance(byte_length, int) else None,
            )
            for storyline_id in storyline_ids:
                by_storyline[storyline_id].append(ref)

            labels.append(
                {
                    "log_id": physical_record_id,
                    "physical_record_id": physical_record_id,
                    "storyline_id": primary_storyline_id
                    or (storyline_ids[0] if storyline_ids else ""),
                    "storyline_ids": storyline_ids,
                    "record_id": str(row.get("logical_event_id") or ""),
                    "source_type": ref.source_type,
                    "source_file": source_file,
                    "relative_path": relative_path,
                    "record_index": record_index,
                    "record_ref": ref.record_ref,
                    "byte_offset": ref.byte_offset,
                    "byte_length": ref.byte_length,
                    "match_reason": ref.match_reason,
                    "label": "attack_evidence",
                    **({"timestamp": ref.timestamp} if ref.timestamp else {}),
                }
            )

    for refs in by_storyline.values():
        refs.sort(
            key=lambda ref: (
                ref.relative_path or ref.source_file,
                ref.record_index if ref.record_index is not None else -1,
                ref.log_id,
            )
        )
    labels.sort(
        key=lambda row: (
            row["relative_path"],
            row["record_index"],
            row["physical_record_id"],
        )
    )
    return dict(by_storyline), labels


def build_attack_log_labels(
    gt: dict[str, Any], evidence_by_record: dict[str, list[EvidenceRef]]
) -> list[dict[str, str]]:
    event_to_storyline = {
        event["record_id"]: event["storyline_id"] for event in gt.get("events", [])
    }
    labels: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for record_id, refs in sorted(evidence_by_record.items()):
        storyline_id = event_to_storyline.get(record_id, "")
        for ref in refs:
            key = (ref.log_id, storyline_id)
            if key in seen:
                continue
            seen.add(key)
            labels.append(
                {
                    "log_id": ref.log_id,
                    "storyline_id": storyline_id,
                    "record_id": record_id,
                    "source_type": ref.source_type,
                    "source_file": ref.source_file,
                    "record_ref": ref.record_ref,
                    "match_reason": ref.match_reason,
                    "label": "attack_evidence",
                    **({"timestamp": ref.timestamp} if ref.timestamp else {}),
                }
            )
    labels.sort(key=lambda row: (row["source_file"], row["record_ref"], row["storyline_id"]))
    return labels


def build_scenario_labels(
    scenario_dir: Path, scenarios_root: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    gt = json.loads((scenario_dir / "GROUND_TRUTH.json").read_text(encoding="utf-8"))
    scenario_name = gt["scenario_name"]
    scenario_yaml = load_scenario_yaml(scenario_name, scenarios_root)
    enriched_gt = dict(gt)
    enriched_gt["events"] = enrich_ground_truth_events(gt.get("events", []), scenario_yaml)
    exact_evidence = load_exact_record_evidence(scenario_dir)
    if exact_evidence is not None:
        evidence_by_storyline, attack_log_labels = exact_evidence
        evidence_by_record: dict[str, list[EvidenceRef]] = {}
        predicted_storyline = build_predicted_storyline(
            enriched_gt,
            scenario_yaml,
            evidence_by_record,
            evidence_by_storyline,
        )
        join_method = (
            "Exact final-write provenance from RECORD_GROUND_TRUTH.jsonl using "
            "physical_record_id, relative_path, record_index, and byte range."
        )
    else:
        evidence_by_record = scan_logs(scenario_dir, enriched_gt["events"])
        predicted_storyline = build_predicted_storyline(
            enriched_gt,
            scenario_yaml,
            evidence_by_record,
        )
        attack_log_labels = build_attack_log_labels(enriched_gt, evidence_by_record)
        join_method = (
            "Compatibility fallback: GROUND_TRUTH attributes joined by exact command/PID, "
            "actorID, logon_id, task name, file path, network tuple, Zeek UID/FUID, and "
            "bounded causal timing."
        )
    expected_visible = {
        sid: sum(source.get("visible", 0) for source in status.values())
        for sid, status in gt.get("source_evidence_status", {}).items()
    }
    found = {step["storyline_id"]: len(step["evidence_refs"]) for step in predicted_storyline}
    gaps = {
        sid: {"expected_visible": expected_count, "found_refs": found.get(sid, 0)}
        for sid, expected_count in expected_visible.items()
        if expected_count > 0 and found.get(sid, 0) == 0
    }
    labels = {
        "schema_version": 1,
        "scenario_name": scenario_name,
        "labeling_policy": {
            "positive_labels": "attack_log_labels contains logs recovered as attack evidence.",
            "negative_labels": "Any data log not listed in attack_log_labels is benign/noise for LogF1.",
            "join_method": join_method,
        },
        "predicted_storyline": predicted_storyline,
        "attack_log_labels": attack_log_labels,
    }
    summary = {
        "scenario_name": scenario_name,
        "steps": len(predicted_storyline),
        "events": len(gt.get("events", [])),
        "attack_log_labels": len(attack_log_labels),
        "expected_visible_labels": sum(expected_visible.values()),
        "manifest_delta": len(attack_log_labels) - sum(expected_visible.values()),
        "steps_without_any_evidence": [
            step["storyline_id"] for step in predicted_storyline if not step["evidence_refs"]
        ],
        "steps_without_evidence": [
            step["storyline_id"]
            for step in predicted_storyline
            if not step["evidence_refs"] and expected_visible.get(step["storyline_id"], 0) > 0
        ],
        "steps_without_expected_visible_evidence": [
            step["storyline_id"]
            for step in predicted_storyline
            if not step["evidence_refs"] and expected_visible.get(step["storyline_id"], 0) == 0
        ],
        "coverage_gaps": gaps,
        "record_ground_truth_used": exact_evidence is not None,
    }
    return labels, summary


def scenario_dirs(output_root: Path, selected: list[str]) -> list[Path]:
    selected_set = set(selected)
    dirs = [path for path in sorted(output_root.iterdir()) if path.is_dir()]
    if selected_set:
        dirs = [path for path in dirs if path.name in selected_set]
    return [path for path in dirs if (path / "GROUND_TRUTH.json").exists()]


def extracted_log_record(scenario_dir: Path, label: dict[str, str]) -> dict[str, Any] | str:
    """Read one labeled physical record into a review-friendly representation."""
    path = scenario_dir / label["source_file"]
    byte_offset = label.get("byte_offset")
    byte_length = label.get("byte_length")
    if (
        path.exists()
        and isinstance(byte_offset, int)
        and isinstance(byte_length, int)
        and byte_offset >= 0
        and byte_length >= 0
    ):
        with path.open("rb") as handle:
            handle.seek(byte_offset)
            raw_record = handle.read(byte_length).decode("utf-8", errors="replace")
        if path.suffix == ".json":
            try:
                return json.loads(raw_record)
            except json.JSONDecodeError:
                return raw_record.rstrip("\r\n")
        if path.suffix == ".xml":
            fields, _timestamp = extract_xml_fields(raw_record)
            return fields
        return raw_record.rstrip("\r\n")
    match = re.fullmatch(r"line:(\d+)", label["record_ref"])
    if not match or not path.exists():
        return ""
    line_number = int(match.group(1))
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    if line_number < 1 or line_number > len(lines):
        return ""
    if path.suffix == ".json":
        try:
            return json.loads(lines[line_number - 1])
        except json.JSONDecodeError:
            return lines[line_number - 1].rstrip("\n")
    if path.suffix == ".xml":
        raw_lines: list[str] = []
        for line in lines[line_number - 1 :]:
            raw_lines.append(line)
            if EVENT_END_PATTERN.search(line):
                break
        fields, _timestamp = extract_xml_fields("".join(raw_lines))
        return fields
    return lines[line_number - 1].rstrip("\n")


def build_extracted_attack_logs(scenario_dir: Path, labels: dict[str, Any]) -> dict[str, Any]:
    """Materialize every positive label with the underlying log record."""
    logs: list[dict[str, Any]] = []
    for label in labels["attack_log_labels"]:
        logs.append({**label, "record": extracted_log_record(scenario_dir, label)})
    return {
        "schema_version": 1,
        "scenario_name": labels["scenario_name"],
        "attack_log_count": len(logs),
        "attack_logs": logs,
    }


def main() -> None:
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    summaries: list[dict[str, Any]] = []
    for scenario_dir in scenario_dirs(args.output_root, args.scenario):
        labels, summary = build_scenario_labels(scenario_dir, args.scenarios_root)
        out_path = args.out_dir / f"{labels['scenario_name']}.labels.json"
        out_path.write_text(
            json.dumps(labels, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        extracted_path = args.out_dir / f"{labels['scenario_name']}.attack-logs.json"
        extracted_path.write_text(
            json.dumps(
                build_extracted_attack_logs(scenario_dir, labels),
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        summaries.append(summary)
        print(
            f"{labels['scenario_name']}: steps={summary['steps']} "
            f"attack_log_labels={summary['attack_log_labels']} "
            f"steps_without_evidence={len(summary['steps_without_evidence'])}"
        )
    summary_path = args.out_dir / "SUMMARY.json"
    summary_path.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "scenario_count": len(summaries),
                "summaries": summaries,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {summary_path}")


if __name__ == "__main__":
    main()
