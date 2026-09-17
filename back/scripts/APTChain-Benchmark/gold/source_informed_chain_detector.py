#!/usr/bin/env python3
"""Source-informed EvidenceForge chain detector.

Finding-only mode preserves the copied legacy detector. Record-level mode uses
the label-free Record Index, four independent discovery engines, and bounded
identity/time graph edges implemented by ``record_graph_detector``.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import statistics
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

UTC = timezone.utc  # noqa: UP017 - keep the copied detector executable on system Python 3.10


def locate_repo_root(detector_path: Path) -> Path:
    """Locate the checkout root without depending on the detector's directory depth."""
    resolved = detector_path.resolve()
    for candidate in resolved.parents:
        if (candidate / "src" / "evidenceforge").is_dir() and (
            candidate / "pyproject.toml"
        ).is_file():
            return candidate
    return resolved.parent.parent


REPO_ROOT = locate_repo_root(Path(__file__))
TICK_DEDUP_SECONDS = 8.0
SYSTEM_PORTS = {"53", "67", "68", "88", "123", "135", "137", "138", "139", "389", "445"}
PIVOT_BEFORE_SECONDS = 40 * 60
PIVOT_AFTER_SECONDS = 25 * 60
MAX_WEAK_PROCESS_PIVOTS_PER_BEACON = int(
    os.environ.get("SOURCE_INFORMED_MAX_WEAK_PROCESS_PIVOTS", "12")
)
MAX_CONNECTION_PIVOTS_PER_BEACON = int(os.environ.get("SOURCE_INFORMED_MAX_CONNECTION_PIVOTS", "8"))
MAX_PROCESS_FLOW_PIVOTS_PER_BEACON = 3
MAX_PROCESS_FLOW_BURST_PIVOTS_PER_BEACON = 3
MAX_NO_BEACON_PROCESS_FLOW_PIVOTS = 3
AGGRESSIVE_CONNECTION_MODE = os.environ.get(
    "SOURCE_INFORMED_CONNECTION_MODE", ""
).lower() == "aggressive" or os.environ.get(
    "SOURCE_INFORMED_AGGRESSIVE_CONNECTIONS", ""
).lower() in {"1", "true", "yes"}
DEFAULT_TICK_CONNECTION_PIVOTS = "3" if AGGRESSIVE_CONNECTION_MODE else "0"
MAX_TICK_CONNECTION_PIVOTS_PER_BEACON = int(
    os.environ.get("SOURCE_INFORMED_MAX_TICK_CONNECTION_PIVOTS", DEFAULT_TICK_CONNECTION_PIVOTS)
)
MIN_PROCESS_PIVOT_SCORE = float(os.environ.get("SOURCE_INFORMED_MIN_PROCESS_SCORE", "0.9"))
EMIT_PROCESS_FLOW_PIVOT = os.environ.get("SOURCE_INFORMED_EMIT_PROCESS_FLOW", "1").lower() not in {
    "0",
    "false",
    "no",
}
EMIT_DNS_PIVOT = os.environ.get("SOURCE_INFORMED_EMIT_DNS", "").lower() in {"1", "true", "yes"}
EMIT_LOGON_PIVOT = os.environ.get("SOURCE_INFORMED_EMIT_LOGON", "1").lower() not in {
    "0",
    "false",
    "no",
}
EMIT_STANDALONE_LINUX_ENUM = os.environ.get(
    "SOURCE_INFORMED_STANDALONE_LINUX_ENUM", ""
).lower() in {
    "1",
    "true",
    "yes",
}
EMIT_SHELL_PARENT_ANOMALY = os.environ.get(
    "SOURCE_INFORMED_EMIT_SHELL_PARENT_ANOMALY", "1"
).lower() not in {
    "0",
    "false",
    "no",
}
ONLY_TEST_SOURCE_LEAKAGE = os.environ.get(
    "SOURCE_INFORMED_ONLY_TEST_SOURCE_LEAKAGE", ""
).lower() in {
    "1",
    "true",
    "yes",
}
EVENT_RE = re.compile(r"<Event xmlns=.*?</Event>", re.DOTALL)

BASELINE_DNS_TAGS = {
    "background",
    "saas",
    "git",
    "storage",
    "web",
    "cdn",
    "email",
    "outlook",
    "teams",
    "onedrive",
    "dev",
    "social",
}
BASELINE_APP_CATEGORIES = {"user_app", "browser", "office", "code", "build", "query"}
CATALOG_RISKY_EXES = {
    "bitsadmin.exe",
    "certutil.exe",
    "cmd.exe",
    "curl",
    "curl.exe",
    "dnscmd.exe",
    "mshta.exe",
    "powershell.exe",
    "reg.exe",
    "rundll32.exe",
    "schtasks.exe",
    "sqlcmd.exe",
    "wget",
    "wget.exe",
    "wscript.exe",
}
BENIGN_INFRA_TOKENS = (
    "windowsupdate",
    "microsoft.com",
    "office.com",
    "office365.com",
    "office.net",
    "microsoftonline.com",
    "msftauth.net",
    "msauth.net",
    "googleapis.com",
    "gstatic.com",
    "apple.com",
    "icloud.com",
    "mozilla.com",
    "dell.com",
    "paloaltonetworks.com",
    "cisco.com",
    "github.com",
    "salesforce.com",
    "slack.com",
    "zoom.us",
    "okta.com",
    "atlassian.com",
    "workday",
)
INTERVAL_BINS = (
    (60.0, 18, "60s sleep+jitter callback"),
    (90.0, 18, "90s sleep+jitter callback"),
    (300.0, 10, "5m sleep+jitter callback"),
)

LOLBIN_RE = re.compile(r"\\(powershell|cmd|mshta|rundll32|reg|schtasks)\.exe\b", re.I)
DOWNLOAD_RE = re.compile(
    r"\b(download(file|string)|webclient|http\.open|curl\b|wget\b|bitsadmin|certutil)\b|https?://",
    re.I,
)
PAYLOAD_RE = re.compile(
    r"shellcode|rc4|xor|decrypt|loadresource|lockresource|getprocaddress|loadlibrary|"
    r"\bload\s*pe\b|inmemory|in-memory|fileloadmodule|mzh|reflective",
    re.I,
)
DISCOVERY_RE = re.compile(
    r"\b(tasklist|systeminfo|whoami|hostname|ipconfig|netstat|arp|nmap|uname|id|ps aux|"
    r"ip addr|ip route|history)\b|getcomputername|getusername|securitycenter|regqueryvalue|gdir\b",
    re.I,
)
PERSISTENCE_RE = re.compile(
    r"schtasks\b.*\b/create\b|reg\s+add\b.*\\run\b|scheduled task|periodicwork", re.I
)
USER_WRITABLE_RE = re.compile(
    r"\\(users|appdata|temp|downloads|programdata)\\|/(tmp|var/tmp|home)/|"
    r"ntuser\.dat.*\.alf|\.pdf\.exe\b|\.docx?\.lnk\b|\.bin\b|\.db,",
    re.I,
)
LINUX_ENUM_RE = re.compile(
    r"^(whoami\b|id\b|uname\b|cat /etc/(passwd|group|hosts|resolv\.conf)|ps aux|"
    r"netstat\b|ip (addr|route)|ls -la /home|find /|df -h|arp -a|history|grep -r password|"
    r"nmap\b|for i in \{1\.\.254\}.*ping)",
    re.I,
)
BROWSER_IMAGE_RE = re.compile(r"\\(chrome|msedge|firefox|opera|iexplore)\.exe\b", re.I)
DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpg|png|txt)\.lnk\b|\.(pdf|docx?|xlsx?|pptx?|jpg|png|txt)\.exe\b",
    re.I,
)
SCRIPT_DROP_RE = re.compile(
    r"\\(users|downloads|temp|appdata)\\.*\.(vbs|js|jse|hta|ps1|bat)\b", re.I
)
DLL_SIDELOAD_RE = re.compile(
    r"\.exe\s*(-|=)?[> ]+\s*[^ ]+\.dll(![a-z0-9_]+)?|\.dll![a-z0-9_]+", re.I
)
ANTI_ANALYSIS_RE = re.compile(
    r"isdebuggerpresent|checkremotedebuggerpresent|createtoolhelp32snapshot|process32(first|next)|"
    r"anti[- ]?debug|sandbox|反调试|环境检测|枚举进程",
    re.I,
)
DEFENSE_EVASION_RE = re.compile(r"amsi\s*bypass|etw\s*patch|disable.*defen|impair.*defen", re.I)
BEACON_PAYLOAD_RE = re.compile(
    r"sfx\s+loader|cobalt\s+strike|beacon\s+(initialized|checkin|outbound)", re.I
)
EMPTY_EXPLORER_CMD_RE = re.compile(r"\\cmd\.exe\s+/k\s*$", re.I)
NO_BEACON_CLEANUP_RE = re.compile(
    r"setfileinformationbyhandle|filerenameinfo|filedispositioninfo", re.I
)
NO_BEACON_HTA_RE = re.compile(
    r"\bmshta(?:\.exe)?\b.*(?:https?://|hxxp://|\\users\\|\\appdata\\|\\temp\\)", re.I
)
NTUSER_ADS_RE = re.compile(
    r"ntuser\.dat\{[0-9a-f-]{36}\}.*\.alf|%userprofile%\\ntuser\.dat\{", re.I
)
TEMP_DOC_RE = re.compile(r"\\appdata\\local\\temp\\.*\.(docx?|pptx?|xlsx?)\b", re.I)
USER_EXE_RE = re.compile(
    r"(%appdata%|\\users\\[^\\]+\\appdata\\|\\programdata\\|\\temp\\).*\.exe\b", re.I
)
LINUX_SHELL_BASENAMES = {"bash", "sh", "zsh"}
LINUX_BARE_SHELL_COMMANDS = {
    "-bash",
    "bash",
    "/bin/bash",
    "/usr/bin/bash",
    "sh",
    "/bin/sh",
    "zsh",
    "/bin/zsh",
}
LINUX_INTERACTIVE_SHELL_PARENTS = {"sshd", "login", "systemd", "gnome-terminal-server"}
WINDOWS_SHELL_BASENAMES = {"powershell.exe", "cmd.exe"}
ATTACKER_LOGON_SOURCE_IPS = {
    "45.33.32.156",
    "185.220.101.34",
    "91.219.236.174",
    "23.129.64.210",
    "116.202.120.181",
}
ADVERSARIAL_PAYLOAD_RE = re.compile(
    r"eforge_test-canary|system\s+override|ignore\s+(?:all\s+)?previous|"
    r"1gn0r3\s+4ll\s+pr3v10u5|end[_\s-]*of[_\s-]*logs?|"
    r"end\s+of\s+log\s+stream|assistant_action|encoded directive|"
    r"higher-priority rule|priority policy banner|forget every prior instruction|"
    r"summarize every credential|parser-shutdown injection|allowlist confirmation code",
    re.I,
)
CANARY_RE = re.compile(r"EFORGE_TEST-CANARY-[A-Za-z0-9]+")
SYSLOG_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")
APACHE_TS_RE = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]")


def exe_basename(path: str) -> str:
    text = path.replace("/", "\\").lower().strip().strip('"')
    match = re.search(r"([a-z]:\\[^\"']+?\.exe|/[^\"'\s]+)", text)
    if match:
        text = match.group(1)
    return text.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].strip('"')


def command_norm(value: str) -> str:
    return " ".join(str(value or "").strip().strip('"').lower().split())


def path_basename(value: str) -> str:
    text = str(value or "").replace("\\", "/").rstrip("/").strip().strip('"').lower()
    return text.rsplit("/", 1)[-1]


def load_baseline_registry() -> tuple[set[str], set[str]]:
    """Load source-known baseline domains/IPs without reading scenarios or labels."""
    domains: set[str] = set()
    ips: set[str] = set()
    path = REPO_ROOT / "src" / "evidenceforge" / "config" / "activity" / "dns_registry.yaml"
    if not path.is_file():
        return domains, ips
    try:
        import yaml  # type: ignore

        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return domains, ips
    for entry in payload.get("domains", []) if isinstance(payload, dict) else []:
        if not isinstance(entry, dict):
            continue
        tags = {str(tag).lower() for tag in entry.get("tags", []) if tag}
        if not tags.intersection(BASELINE_DNS_TAGS):
            continue
        domain = str(entry.get("domain") or "").lower().strip(".")
        if domain:
            domains.add(domain)
        for ip in entry.get("ips", []) or []:
            ip_text = str(ip).strip()
            if ip_text:
                ips.add(ip_text)
    return domains, ips


BASELINE_DOMAINS, BASELINE_IPS = load_baseline_registry()


def catalog_template_regex(template: str) -> re.Pattern[str] | None:
    text = str(template or "").strip()
    if not text:
        return None
    parts = re.split(r"(\{[^}]+\})", text)
    pattern = ""
    for part in parts:
        if part.startswith("{") and part.endswith("}"):
            pattern += r".+?"
        else:
            pattern += re.escape(part)
    pattern = pattern.replace(r"\ ", r"\s+")
    try:
        return re.compile(r"^\s*" + pattern + r"\s*$", re.I)
    except re.error:
        return None


def load_baseline_application_catalog() -> tuple[set[str], set[str], list[re.Pattern[str]]]:
    exes: set[str] = set()
    path_tokens: set[str] = set()
    command_patterns: list[re.Pattern[str]] = []
    path = REPO_ROOT / "src" / "evidenceforge" / "config" / "activity" / "application_catalog.yaml"
    if not path.is_file():
        return exes, path_tokens, command_patterns
    try:
        import yaml  # type: ignore

        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return exes, path_tokens, command_patterns

    def add_catalog_path(raw_value: str) -> None:
        raw_path = str(raw_value or "").lower().replace("/", "\\")
        if not raw_path:
            return
        basename = exe_basename(raw_path)
        if basename in CATALOG_RISKY_EXES:
            return
        exes.add(basename)
        normalized = raw_path.replace("{username}", "")
        parent = normalized.rsplit("\\", 1)[0]
        if parent and not parent.startswith("c:\\windows\\system32"):
            path_tokens.add(parent)

    def add_command_template(raw_value: str) -> None:
        regex = catalog_template_regex(str(raw_value or ""))
        if regex is not None:
            command_patterns.append(regex)

    for app in payload.get("applications", []) if isinstance(payload, dict) else []:
        if not isinstance(app, dict):
            continue
        categories = {str(cat).lower() for cat in app.get("categories", []) if cat}
        if categories and not categories.intersection(BASELINE_APP_CATEGORIES):
            continue
        for platform in (app.get("platforms") or {}).values():
            if not isinstance(platform, dict):
                continue
            add_catalog_path(str(platform.get("image_path") or ""))
            for command_template in platform.get("command_templates", []) or []:
                add_command_template(str(command_template))
            for child_command in platform.get("children", []) or []:
                add_catalog_path(str(child_command))
                add_command_template(str(child_command))
    return exes, path_tokens, command_patterns


BASELINE_APP_EXES, BASELINE_APP_PATH_TOKENS, BASELINE_APP_COMMAND_PATTERNS = (
    load_baseline_application_catalog()
)


def load_source_behavior_catalog() -> tuple[set[str], set[str], set[str]]:
    baseline_bash: set[str] = set()
    shell_parents: set[str] = set()
    system_exes: set[str] = set()
    activity_dir = REPO_ROOT / "src" / "evidenceforge" / "config" / "activity"
    try:
        import yaml  # type: ignore
    except Exception:
        return baseline_bash, shell_parents, system_exes

    bash_path = activity_dir / "bash_commands.yaml"
    try:
        bash_payload = yaml.safe_load(bash_path.read_text(encoding="utf-8")) or {}
    except Exception:
        bash_payload = {}
    if isinstance(bash_payload, dict):
        for value in bash_payload.values():
            if isinstance(value, list):
                baseline_bash.update(str(item).strip() for item in value if isinstance(item, str))

    spawn_path = activity_dir / "spawn_rules.yaml"
    try:
        spawn_payload = yaml.safe_load(spawn_path.read_text(encoding="utf-8")) or {}
    except Exception:
        spawn_payload = {}
    for platform_rules in (
        (spawn_payload.get("windows", {}), spawn_payload.get("linux", {}))
        if isinstance(spawn_payload, dict)
        else ()
    ):
        if not isinstance(platform_rules, dict):
            continue
        for parent, parent_data in platform_rules.items():
            parent_name = str(parent).lower()
            children = parent_data.get("children", []) if isinstance(parent_data, dict) else []
            child_names = {str(child).lower() for child in children if child}
            if parent_name in {
                "cmd.exe",
                "powershell.exe",
                "pwsh.exe",
                "bash",
                "sh",
                "zsh",
            } or child_names.intersection(
                {
                    "cmd.exe",
                    "powershell.exe",
                    "pwsh.exe",
                    "mshta.exe",
                    "rundll32.exe",
                    "schtasks.exe",
                }
            ):
                shell_parents.add(parent_name)

    system_path = activity_dir / "system_processes.yaml"
    try:
        system_payload = yaml.safe_load(system_path.read_text(encoding="utf-8")) or {}
    except Exception:
        system_payload = {}

    def collect_system_exes(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"exe", "image", "path"}:
                    basename = exe_basename(str(item or ""))
                    if basename:
                        system_exes.add(basename)
                collect_system_exes(item)
        elif isinstance(value, list):
            for item in value:
                collect_system_exes(item)

    collect_system_exes(system_payload)
    return baseline_bash, shell_parents, system_exes


SOURCE_BASELINE_BASH_COMMANDS, SOURCE_SHELL_PARENT_EXES, SOURCE_SYSTEM_EXES = (
    load_source_behavior_catalog()
)


def parse_iso(value: str | None) -> float | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    text = re.sub(r"(\.\d{6})\d+(?=[+-]\d\d:\d\d$)", r"\1", text)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).timestamp()


def parse_apache_ts(line: str) -> float | None:
    match = APACHE_TS_RE.search(line)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC).timestamp()
    except ValueError:
        return None


def epoch_to_iso(ts: float) -> str:
    return (
        datetime.fromtimestamp(ts, tz=UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def is_private_or_local(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    a, b = nums[0], nums[1]
    return (
        a == 10
        or a == 127
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or (a == 169 and b == 254)
    )


def flow_key(src: str, dst: str, dport: str, proto: str) -> tuple[str, str, str, str] | None:
    if not src or not dst or not dport:
        return None
    proto = (proto or "tcp").lower()
    dport = str(dport)
    if dport in SYSTEM_PORTS:
        return None
    if is_private_or_local(dst):
        return None
    return (src, dst, dport, proto)


def benign_hostname(hostname: str) -> bool:
    host = hostname.lower().strip(".")
    if host in BASELINE_DOMAINS:
        return True
    if any(host.endswith("." + domain) for domain in BASELINE_DOMAINS):
        return True
    return any(token in host for token in BENIGN_INFRA_TOKENS)


def benign_destination(dst_ip: str, hostnames: set[str]) -> bool:
    if dst_ip in BASELINE_IPS:
        return True
    return any(benign_hostname(hostname) for hostname in hostnames)


def ecar_text(rec: dict[str, Any]) -> str:
    props = rec.get("properties") or {}
    chunks = [str(rec.get("object") or ""), str(rec.get("action") or "")]
    if isinstance(props, dict):
        chunks.extend(str(value) for value in props.values())
    return " ".join(chunks)


def xml_local_text(elem: ET.Element, local_name: str) -> str:
    for child in elem.iter():
        if child.tag.rsplit("}", 1)[-1] == local_name:
            return (child.text or "").strip()
    return ""


def xml_data_fields(elem: ET.Element) -> dict[str, str]:
    fields: dict[str, str] = {}
    for child in elem.iter():
        if child.tag.rsplit("}", 1)[-1] != "Data":
            continue
        name = child.get("Name")
        if name:
            fields[name] = (child.text or "").strip()
    return fields


def read_case(
    data_dir: Path,
) -> tuple[
    dict[tuple[str, str, str, str], list[dict[str, Any]]],
    dict[str, set[str]],
    list[dict[str, Any]],
]:
    flow_groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    dst_hostnames: dict[str, set[str]] = defaultdict(set)
    ecar_events: list[dict[str, Any]] = []

    for path in sorted(data_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = str(path.relative_to(data_dir))
        name = path.name.lower()
        if name == "ecar.json":
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line_no, line in enumerate(handle, start=1):
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    try:
                        ts = float(rec.get("timestamp_ms")) / 1000.0
                    except Exception:
                        continue
                    event = {
                        "ts": ts,
                        "file": rel,
                        "line": line_no,
                        "host": str(rec.get("hostname") or ""),
                        "object": str(rec.get("object") or "").upper(),
                        "action": str(rec.get("action") or "").upper(),
                        "pid": str(rec.get("pid") or ""),
                        "ppid": str(rec.get("ppid") or ""),
                        "actor_id": str(rec.get("actorID") or ""),
                        "object_id": str(rec.get("objectID") or ""),
                        "principal": str(rec.get("principal") or ""),
                        "props": rec.get("properties") or {},
                        "text": ecar_text(rec),
                    }
                    ecar_events.append(event)
                    if event["object"] != "FLOW":
                        continue
                    props = event["props"]
                    if not isinstance(props, dict):
                        continue
                    key = flow_key(
                        str(props.get("src_ip") or ""),
                        str(props.get("dst_ip") or ""),
                        str(props.get("dst_port") or ""),
                        str(props.get("protocol") or ""),
                    )
                    if key is None:
                        continue
                    flow_groups[key].append(
                        {
                            "ts": ts,
                            "file": rel,
                            "line": line_no,
                            "source": "ecar",
                            "host": event["host"],
                            "props": props,
                        }
                    )
        elif name in {"conn.json", "dns.json", "ssl.json", "http.json"}:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line_no, line in enumerate(handle, start=1):
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if name == "conn.json":
                        try:
                            ts = float(rec.get("ts"))
                        except Exception:
                            continue
                        props = {
                            "src_ip": str(rec.get("id.orig_h") or ""),
                            "src_port": str(rec.get("id.orig_p") or ""),
                            "dst_ip": str(rec.get("id.resp_h") or ""),
                            "dst_port": str(rec.get("id.resp_p") or ""),
                            "protocol": str(rec.get("proto") or ""),
                            "service": str(rec.get("service") or ""),
                            "duration": str(rec.get("duration") or ""),
                            "orig_bytes": str(rec.get("orig_bytes") or ""),
                            "resp_bytes": str(rec.get("resp_bytes") or ""),
                            "uid": str(rec.get("uid") or ""),
                            "conn_state": str(rec.get("conn_state") or ""),
                        }
                        ecar_events.append(
                            {
                                "ts": ts,
                                "file": rel,
                                "line": line_no,
                                "host": "",
                                "object": "FLOW",
                                "action": "CONNECT",
                                "pid": "",
                                "ppid": "",
                                "actor_id": "",
                                "object_id": "",
                                "principal": "",
                                "props": props,
                                "text": json.dumps(rec, ensure_ascii=False),
                            }
                        )
                    elif name == "dns.json":
                        query = str(rec.get("query") or "")
                        answers = rec.get("answers") or []
                        if query and isinstance(answers, list):
                            for answer in answers:
                                if isinstance(answer, str) and answer.count(".") == 3:
                                    dst_hostnames[answer].add(query)
                        try:
                            ts = float(rec.get("ts"))
                        except Exception:
                            ts = None
                        if ts is not None:
                            ecar_events.append(
                                {
                                    "ts": ts,
                                    "file": rel,
                                    "line": line_no,
                                    "host": str(rec.get("id.orig_h") or ""),
                                    "object": "DNS_QUERY",
                                    "action": "QUERY",
                                    "pid": "",
                                    "ppid": "",
                                    "actor_id": "",
                                    "object_id": "",
                                    "principal": "",
                                    "props": {
                                        "src_ip": str(rec.get("id.orig_h") or ""),
                                        "query": query,
                                        "qtype": str(
                                            rec.get("qtype_name") or rec.get("qtype") or ""
                                        ),
                                        "rcode": str(
                                            rec.get("rcode_name") or rec.get("rcode") or ""
                                        ),
                                        "answers": answers,
                                    },
                                    "text": json.dumps(rec, ensure_ascii=False),
                                }
                            )
                    else:
                        dst = str(rec.get("id.resp_h") or "")
                        host = str(rec.get("server_name") or rec.get("host") or "")
                        if dst and host:
                            dst_hostnames[dst].add(host)
                        if name == "http.json":
                            try:
                                ts = float(rec.get("ts"))
                            except Exception:
                                ts = None
                            if ts is not None:
                                props = {
                                    "src_ip": str(rec.get("id.orig_h") or ""),
                                    "dst_ip": str(rec.get("id.resp_h") or ""),
                                    "dst_port": str(rec.get("id.resp_p") or ""),
                                    "host": host,
                                    "uri": str(rec.get("uri") or ""),
                                    "user_agent": str(rec.get("user_agent") or ""),
                                    "referrer": str(rec.get("referrer") or ""),
                                }
                                text = json.dumps(rec, ensure_ascii=False)
                                if ADVERSARIAL_PAYLOAD_RE.search(text):
                                    ecar_events.append(
                                        {
                                            "ts": ts,
                                            "file": rel,
                                            "line": line_no,
                                            "host": host.split(".", 1)[0]
                                            if host
                                            else str(rec.get("id.orig_h") or ""),
                                            "object": "TEXT",
                                            "action": "OBSERVE",
                                            "pid": "",
                                            "ppid": "",
                                            "actor_id": "",
                                            "object_id": "",
                                            "principal": "",
                                            "props": props,
                                            "text": text,
                                        }
                                    )
        elif name in {"syslog.log", "web_access.log", "proxy_access.log"}:
            host = path.parent.name.split(".", 1)[0]
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line_no, line in enumerate(handle, start=1):
                    if not ADVERSARIAL_PAYLOAD_RE.search(line):
                        continue
                    ts: float | None = None
                    if name == "syslog.log":
                        match = SYSLOG_TS_RE.search(line)
                        ts = parse_iso(match.group(0)) if match else None
                    else:
                        ts = parse_apache_ts(line)
                    if ts is None:
                        continue
                    ecar_events.append(
                        {
                            "ts": ts,
                            "file": rel,
                            "line": line_no,
                            "host": host,
                            "object": "TEXT",
                            "action": "OBSERVE",
                            "pid": "",
                            "ppid": "",
                            "actor_id": "",
                            "object_id": "",
                            "principal": "",
                            "props": {"log_format": name},
                            "text": line.strip(),
                        }
                    )
        elif name.startswith("windows_event_") and name.endswith(".xml"):
            content = path.read_text(encoding="utf-8", errors="replace")
            for match in EVENT_RE.finditer(content):
                try:
                    elem = ET.fromstring(match.group(0))
                except ET.ParseError:
                    continue
                event_id = xml_local_text(elem, "EventID")
                if event_id != "4698":
                    continue
                system_time = ""
                for child in elem.iter():
                    if child.tag.rsplit("}", 1)[-1] == "TimeCreated":
                        system_time = child.get("SystemTime", "")
                        break
                ts = parse_iso(system_time)
                if ts is None:
                    continue
                fields = xml_data_fields(elem)
                text = " ".join(fields.values())
                ecar_events.append(
                    {
                        "ts": ts,
                        "file": rel,
                        "line": content.count("\n", 0, match.start()) + 1,
                        "host": xml_local_text(elem, "Computer").split(".", 1)[0],
                        "object": "SCHEDULED_TASK",
                        "action": "CREATE",
                        "pid": str(fields.get("ClientProcessId") or fields.get("ProcessId") or ""),
                        "ppid": "",
                        "actor_id": "",
                        "object_id": "",
                        "principal": str(fields.get("SubjectUserName") or ""),
                        "props": fields,
                        "text": text,
                    }
                )
    ecar_events.sort(key=lambda item: item["ts"])
    return flow_groups, dst_hostnames, ecar_events


def cluster_ticks(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ticks: list[dict[str, Any]] = []
    for row in sorted(rows, key=lambda item: item["ts"]):
        if ticks and row["ts"] - ticks[-1]["ts"] <= TICK_DEDUP_SECONDS:
            ticks[-1]["evidence"].append(row)
            continue
        ticks.append({"ts": row["ts"], "evidence": [row]})
    return ticks


def find_periodic_window(ticks: list[dict[str, Any]]) -> dict[str, Any] | None:
    if len(ticks) < 4:
        return None
    best: dict[str, Any] | None = None
    times = [tick["ts"] for tick in ticks]
    for interval, min_ticks, label in INTERVAL_BINS:
        low = interval * 0.55
        high = interval * 1.45
        for start in range(len(times)):
            run = [start]
            for idx in range(start + 1, len(times)):
                delta = times[idx] - times[run[-1]]
                if low <= delta <= high:
                    run.append(idx)
                elif delta > high:
                    break
            if len(run) < min_ticks:
                continue
            intervals = [times[run[i]] - times[run[i - 1]] for i in range(1, len(run))]
            mean = statistics.mean(intervals)
            cv = statistics.pstdev(intervals) / mean if mean else 99.0
            if cv > 0.38:
                continue
            candidate = {
                "start_index": run[0],
                "end_index": run[-1],
                "tick_count": len(run),
                "median": statistics.median(intervals),
                "cv": cv,
                "label": label,
            }
            if best is None or (candidate["tick_count"], -candidate["cv"]) > (
                best["tick_count"],
                -best["cv"],
            ):
                best = candidate
    return best


def finding(
    case_id: str,
    seq: int,
    category: str,
    severity: str,
    host: str,
    ts: float,
    score: float,
    summary: str,
    evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "finding_id": f"{case_id}:F{seq:04d}",
        "category": category,
        "severity": severity,
        "host": host,
        "timestamp": epoch_to_iso(ts),
        "score": round(score, 4),
        "summary": summary,
        "evidence": evidence,
    }


def evidence(ev: dict[str, Any], detail: str) -> dict[str, Any]:
    return {"file": ev["file"], "line": ev["line"], "detail": detail}


def suspicious_process_score(ev: dict[str, Any]) -> tuple[float, str]:
    if ev["object"] != "PROCESS" or ev["action"] != "CREATE":
        return 0.0, ""
    props = ev["props"] if isinstance(ev["props"], dict) else {}
    command = str(props.get("command_line") or "")
    image = str(props.get("image_path") or "")
    score = 0.0
    reasons: list[str] = []
    is_browser = bool(BROWSER_IMAGE_RE.search(image))
    if LOLBIN_RE.search(image) or LOLBIN_RE.search(command):
        score += 0.9
        reasons.append("LOLBIN/script host")
    if DOWNLOAD_RE.search(command) and not is_browser:
        score += 1.1
        reasons.append("download/network command")
    if PAYLOAD_RE.search(command):
        score += 1.2
        reasons.append("payload/decrypt/load primitive")
    if BEACON_PAYLOAD_RE.search(command):
        score += 1.3
        reasons.append("beacon payload text")
    if DEFENSE_EVASION_RE.search(command):
        score += 1.3
        reasons.append("defense evasion text")
    if ANTI_ANALYSIS_RE.search(command):
        score += 1.2
        reasons.append("anti-analysis behavior")
    if DLL_SIDELOAD_RE.search(command) or DLL_SIDELOAD_RE.search(image):
        score += 1.1
        reasons.append("DLL side-load/export shape")
    if DOUBLE_EXT_RE.search(command) or DOUBLE_EXT_RE.search(image):
        score += 1.2
        reasons.append("double-extension lure")
    if SCRIPT_DROP_RE.search(command) and re.search(
        r"(wscript|cscript|mshta|explorer|cmd|powershell)\.exe", command + " " + image, re.I
    ):
        score += 1.1
        reasons.append("script from user/download path")
    if DISCOVERY_RE.search(command):
        score += 0.8
        reasons.append("discovery primitive")
    if PERSISTENCE_RE.search(command):
        score += 1.1
        reasons.append("persistence command")
    if USER_WRITABLE_RE.search(command) or USER_WRITABLE_RE.search(image):
        score += 0.9
        reasons.append("user-writable or masqueraded path")
    if LINUX_ENUM_RE.search(command.strip()):
        score += 1.0
        reasons.append("Linux enumeration command")
    return score, ", ".join(reasons)


def low_signal_baseline_process(ev: dict[str, Any], score: float, reason: str) -> bool:
    if score >= 1.0:
        return False
    props = ev["props"] if isinstance(ev["props"], dict) else {}
    command = str(props.get("command_line") or "")
    image = str(props.get("image_path") or "")
    parent = str(props.get("parent_image_path") or "")
    text = f"{image} {command}".lower().replace("/", "\\")
    basename = exe_basename(image or command)
    catalog_known = basename in BASELINE_APP_EXES or any(
        token and token in text for token in BASELINE_APP_PATH_TOKENS
    )
    if reason == "user-writable or masqueraded path" and catalog_known:
        return True
    if (
        reason == "LOLBIN/script host"
        and EMPTY_EXPLORER_CMD_RE.search(command)
        and parent.lower().endswith("\\explorer.exe")
    ):
        return True
    return False


def catalog_baseline_process(ev: dict[str, Any]) -> bool:
    props = ev["props"] if isinstance(ev["props"], dict) else {}
    command = str(props.get("command_line") or "")
    image = str(props.get("image_path") or "")
    parent = str(props.get("parent_image_path") or "")
    text = f"{image} {command}".lower().replace("/", "\\")
    basename = exe_basename(image or command)
    parent_basename = path_basename(parent)
    command_clean = command_norm(command)
    image_norm = image.strip().strip('"').lower().replace("/", "\\")
    command_image_norm = command.strip().strip('"').lower().replace("/", "\\")
    if basename in LINUX_SHELL_BASENAMES and command_clean in LINUX_BARE_SHELL_COMMANDS:
        if command_clean == "-bash" and parent_basename in LINUX_INTERACTIVE_SHELL_PARENTS:
            return True
    if basename in BASELINE_APP_EXES:
        return True
    if any(token and token in text for token in BASELINE_APP_PATH_TOKENS):
        return True
    command_compact = " ".join(command.strip().split())
    if command_compact:
        if any(pattern.search(command_compact) for pattern in BASELINE_APP_COMMAND_PATTERNS):
            return True
    if basename in WINDOWS_SHELL_BASENAMES and command_image_norm in {basename, image_norm}:
        return True
    return False


def flow_tuple(ev: dict[str, Any]) -> tuple[str, str, str]:
    props = ev["props"] if isinstance(ev["props"], dict) else {}
    return (
        str(props.get("src_ip") or ""),
        str(props.get("dst_ip") or ""),
        str(props.get("dst_port") or ""),
    )


def c2_flow_seeds(
    anchor: dict[str, Any],
    events: list[dict[str, Any]],
    start: float,
    end: float,
) -> tuple[set[str], set[str], dict[str, list[float]]]:
    pids: set[str] = set()
    actor_ids: set[str] = set()
    host_flow_times: dict[str, list[float]] = defaultdict(list)
    for ev in events:
        if ev["object"] != "FLOW" or not (start <= ev["ts"] <= end):
            continue
        src_ip, dst_ip, _dport = flow_tuple(ev)
        if dst_ip != anchor["dst_ip"]:
            continue
        host_flow_times[str(ev.get("host") or src_ip)].append(float(ev["ts"]))
        if src_ip == anchor["src_ip"]:
            pid = str(ev.get("pid") or "")
            actor_id = str(ev.get("actor_id") or "")
            if pid:
                pids.add(pid)
            if actor_id:
                actor_ids.add(actor_id)
    return pids, actor_ids, host_flow_times


def associated_c2_flow_time(
    ev: dict[str, Any], flow_times: dict[str, list[float]], max_delta: float = 15 * 60
) -> float | None:
    times = flow_times.get(str(ev.get("host") or ""), [])
    if not times:
        return None
    ts = float(ev["ts"])
    nearest = min(times, key=lambda item: abs(item - ts))
    if abs(nearest - ts) <= max_delta:
        return nearest
    return None


def process_association_reasons(
    ev: dict[str, Any],
    seed_pids: set[str],
    seed_actor_ids: set[str],
    selected_pids: set[str],
    c2_flow_times: dict[str, list[float]],
) -> list[str]:
    reasons: list[str] = []
    pid = str(ev.get("pid") or "")
    ppid = str(ev.get("ppid") or "")
    actor_id = str(ev.get("actor_id") or "")
    object_id = str(ev.get("object_id") or "")
    if pid and pid in seed_pids:
        reasons.append("same pid as beacon C2 flow")
    if object_id and object_id in seed_actor_ids:
        reasons.append("process objectID is beacon C2 flow actorID")
    elif actor_id and actor_id in seed_actor_ids:
        reasons.append("same actorID as beacon C2 flow")
    if ppid and ppid in selected_pids:
        reasons.append("child of selected beacon-chain process")
    if associated_c2_flow_time(ev, c2_flow_times) is not None:
        if str(ev.get("host") or ""):
            reasons.append("host has same C2 flow near process")
    return reasons


def strong_process_association(associations: list[str]) -> bool:
    return any(
        reason.startswith("same pid")
        or reason.startswith("same actorID")
        or reason.startswith("process objectID")
        or reason.startswith("child of selected")
        for reason in associations
    )


def source_shell_parent_anomaly_reason(ev: dict[str, Any]) -> str:
    """Very narrow source-informed shell anomaly; not a general shell detector."""
    if ev["object"] != "PROCESS" or ev["action"] != "CREATE":
        return ""
    props = ev["props"] if isinstance(ev["props"], dict) else {}
    command = str(props.get("command_line") or "")
    image = str(props.get("image_path") or "")
    parent = str(props.get("parent_image_path") or "")
    basename = exe_basename(image or command)
    parent_text = parent.lower().replace("/", "\\")
    parent_basename = path_basename(parent)
    command_clean = command_norm(command)
    if basename not in LINUX_SHELL_BASENAMES or command_clean not in LINUX_BARE_SHELL_COMMANDS:
        return ""
    if command_clean == "-bash" and parent_basename in LINUX_INTERACTIVE_SHELL_PARENTS:
        return ""
    if re.search(r"(^[a-z]:\\|\\windows\\|\.exe$)", parent_text):
        return "cross-OS Linux shell launched by Windows parent"
    return ""


def process_candidate_sort_key(
    item: tuple[float, dict[str, Any], str, list[str]], anchor_ts: float
) -> tuple[int, float, float]:
    score, ev, _reason, associations = item
    strong_rank = 0 if strong_process_association(associations) else 1
    return (strong_rank, abs(float(ev["ts"]) - anchor_ts), -score)


def sampled_items(items: list[Any], limit: int) -> list[Any]:
    if limit <= 0 or not items:
        return []
    if len(items) <= limit:
        return list(items)
    if limit == 1:
        return [items[0]]
    indexes = {round(idx * (len(items) - 1) / (limit - 1)) for idx in range(limit)}
    return [items[idx] for idx in sorted(indexes)]


def find_beacons(
    case_id: str,
    flow_groups: dict[tuple[str, str, str, str], list[dict[str, Any]]],
    dst_hostnames: dict[str, set[str]],
    seq: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    findings: list[dict[str, Any]] = []
    anchors: list[dict[str, Any]] = []
    for key, rows in flow_groups.items():
        src, dst, dport, proto = key
        hostnames = dst_hostnames.get(dst, set())
        if benign_destination(dst, hostnames):
            continue
        ticks = cluster_ticks(rows)
        window = find_periodic_window(ticks)
        if window is None:
            continue
        first_tick = ticks[window["start_index"]]
        first_ev = first_tick["evidence"][0]
        evs = []
        for tick_index in range(
            window["start_index"],
            min(window["start_index"] + 4, window["end_index"] + 1),
        ):
            tick_ev = ticks[tick_index]["evidence"][0]
            evs.append(
                evidence(tick_ev, f"{tick_ev['source']} tick for periodic {proto}/{dport} flow")
            )
        seq += 1
        host_context = ""
        if hostnames:
            shown_hosts = ", ".join(sorted(hostnames)[:3])
            host_context = f", names={shown_hosts}"
        findings.append(
            finding(
                case_id,
                seq,
                "source_informed_periodic_beacon",
                "high",
                src,
                first_tick["ts"],
                max(0.1, 1.0 - window["cv"]),
                (
                    f"{window['label']} {src}->{dst}:{dport}, ticks={window['tick_count']}, "
                    f"median={window['median']:.1f}s, cv={window['cv']:.2f}{host_context}"
                ),
                evs,
            )
        )
        anchors.append(
            {
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": dport,
                "proto": proto,
                "host": first_ev.get("host") or src,
                "ts": first_tick["ts"],
                "tick_times": {
                    round(tick["ts"])
                    for tick in ticks[window["start_index"] : window["end_index"] + 1]
                },
                "tick_events": [
                    tick["evidence"][0]
                    for tick in ticks[window["start_index"] : window["end_index"] + 1]
                ],
            }
        )
    return findings, anchors, seq


def pivot_from_anchor(
    case_id: str,
    anchor: dict[str, Any],
    events: list[dict[str, Any]],
    seq: int,
) -> tuple[list[dict[str, Any]], int]:
    out: list[dict[str, Any]] = []
    host = str(anchor["host"])
    start = float(anchor["ts"]) - PIVOT_BEFORE_SECONDS
    end = float(anchor["ts"]) + PIVOT_AFTER_SECONDS
    seen: set[tuple[str, str, int]] = set()
    seed_pids, seed_actor_ids, c2_flow_times = c2_flow_seeds(anchor, events, start, end)

    proc_candidates: list[tuple[float, dict[str, Any], str, list[str]]] = []
    for ev in events:
        if ev["object"] != "PROCESS" or ev["action"] != "CREATE" or not (start <= ev["ts"] <= end):
            continue
        score, reason = suspicious_process_score(ev)
        if not reason:
            continue
        associations = process_association_reasons(
            ev, seed_pids, seed_actor_ids, set(), c2_flow_times
        )
        same_host = ev["host"] == host
        c2_near = "host has same C2 flow near process" in associations
        if not same_host and not c2_near:
            continue
        if low_signal_baseline_process(ev, score, reason):
            continue
        if catalog_baseline_process(ev) and not strong_process_association(associations):
            continue
        if (
            score >= MIN_PROCESS_PIVOT_SCORE
            or (strong_process_association(associations) and score >= 0.5)
            or (c2_near and score >= 1.2)
        ):
            assoc_bonus = 0.25 * len(associations)
            proc_candidates.append((score + assoc_bonus, ev, reason, associations))

    selected_pids = {
        str(ev.get("pid") or "")
        for _score, ev, _reason, assoc in proc_candidates
        if strong_process_association(assoc)
    }
    selected_pids.discard("")
    for ev in events:
        if ev["object"] != "PROCESS" or ev["action"] != "CREATE" or not (start <= ev["ts"] <= end):
            continue
        if ev["host"] != host:
            continue
        score, reason = suspicious_process_score(ev)
        if not reason or score < 0.5 or low_signal_baseline_process(ev, score, reason):
            continue
        associations = process_association_reasons(
            ev, seed_pids, seed_actor_ids, selected_pids, c2_flow_times
        )
        if not strong_process_association(associations):
            continue
        if catalog_baseline_process(ev):
            continue
        key = (str(ev.get("pid") or ""), str(ev.get("ppid") or ""), int(ev["ts"]))
        if any(
            key
            == (
                str(existing.get("pid") or ""),
                str(existing.get("ppid") or ""),
                int(existing["ts"]),
            )
            for _s, existing, _r, _a in proc_candidates
        ):
            continue
        proc_candidates.append((score + 0.25 * len(associations), ev, reason, associations))

    proc_candidates.sort(key=lambda item: process_candidate_sort_key(item, float(anchor["ts"])))
    strong_candidates = [
        item for item in proc_candidates if strong_process_association(item[3]) or item[0] >= 1.8
    ]
    weak_candidates = [item for item in proc_candidates if item not in strong_candidates]
    selected_process_candidates = (
        strong_candidates + weak_candidates[:MAX_WEAK_PROCESS_PIVOTS_PER_BEACON]
    )
    for score, ev, reason, associations in selected_process_candidates:
        key = ("process", ev["pid"], int(ev["ts"]))
        if key in seen:
            continue
        seen.add(key)
        reason_text = reason
        if associations:
            reason_text = f"{reason}; " + "; ".join(associations)
        seq += 1
        out.append(
            finding(
                case_id,
                seq,
                "beacon_pivot_process",
                "medium",
                ev["host"],
                ev["ts"],
                min(0.95, 0.45 + score / 4.0),
                f"process near source-informed beacon: {reason_text}",
                [
                    evidence(ev, reason_text),
                    {"file": "", "line": 0, "detail": "pivoted from periodic beacon/C2 chain"},
                ],
            )
        )

    selected_process_pids = {
        str(ev["pid"])
        for _score, ev, _reason, _associations in selected_process_candidates
        if str(ev.get("pid") or "")
    }
    conn_count = 0
    for ev in events:
        if ev["host"] != host or ev["object"] != "FLOW" or not (start <= ev["ts"] <= end):
            continue
        props = ev["props"] if isinstance(ev["props"], dict) else {}
        dst_ip = str(props.get("dst_ip") or "")
        src_ip = str(props.get("src_ip") or "")
        if src_ip != anchor["src_ip"] or dst_ip != anchor["dst_ip"]:
            continue
        if round(ev["ts"]) in anchor["tick_times"]:
            continue
        if conn_count >= MAX_CONNECTION_PIVOTS_PER_BEACON:
            break
        conn_count += 1
        seq += 1
        out.append(
            finding(
                case_id,
                seq,
                "beacon_pivot_connection",
                "medium",
                ev["host"],
                ev["ts"],
                0.72,
                f"non-periodic flow to beacon destination {dst_ip} near callback chain",
                [evidence(ev, "same destination as detected beacon")],
            )
        )

    for ev in sampled_items(
        list(anchor.get("tick_events") or []), MAX_TICK_CONNECTION_PIVOTS_PER_BEACON
    ):
        if str(ev.get("host") or "") != host:
            continue
        if not (start <= float(ev["ts"]) <= end):
            continue
        key = ("connection_tick", str(ev.get("line") or ""), int(ev["ts"]))
        if key in seen:
            continue
        seen.add(key)
        seq += 1
        out.append(
            finding(
                case_id,
                seq,
                "aggressive_beacon_tick_connection",
                "medium",
                ev["host"],
                ev["ts"],
                0.78,
                f"sampled periodic beacon flow to confirmed destination {anchor['dst_ip']}",
                [evidence(ev, "periodic tick from confirmed source-informed beacon")],
            )
        )

    if EMIT_PROCESS_FLOW_PIVOT:
        process_flow_count = 0
        process_flow_seeds: list[dict[str, Any]] = []
        for ev in events:
            if ev["host"] != host or ev["object"] != "FLOW" or not (start <= ev["ts"] <= end):
                continue
            if process_flow_count >= MAX_PROCESS_FLOW_PIVOTS_PER_BEACON:
                break
            if str(ev.get("pid") or "") not in selected_process_pids:
                continue
            props = ev["props"] if isinstance(ev["props"], dict) else {}
            src_ip = str(props.get("src_ip") or "")
            dst_ip = str(props.get("dst_ip") or "")
            dport = str(props.get("dst_port") or "")
            if src_ip != anchor["src_ip"] or not dst_ip or dport in SYSTEM_PORTS:
                continue
            if dst_ip == anchor["dst_ip"] or round(ev["ts"]) in anchor["tick_times"]:
                continue
            if benign_destination(dst_ip, set()):
                continue
            process_flow_count += 1
            process_flow_seeds.append(ev)
            seq += 1
            out.append(
                finding(
                    case_id,
                    seq,
                    "beacon_pivot_process_flow",
                    "medium",
                    ev["host"],
                    ev["ts"],
                    0.76,
                    f"non-baseline flow from suspicious process pid {ev['pid']} near beacon chain",
                    [evidence(ev, "FLOW keeps process pid from a selected beacon-pivot process")],
                )
            )
        burst_count = 0
        for seed in process_flow_seeds:
            seed_props = seed["props"] if isinstance(seed["props"], dict) else {}
            seed_src = str(seed_props.get("src_ip") or "")
            seed_dst = str(seed_props.get("dst_ip") or "")
            seed_port = str(seed_props.get("dst_port") or "")
            if not seed_src or not seed_dst or not seed_port:
                continue
            for ev in events:
                if burst_count >= MAX_PROCESS_FLOW_BURST_PIVOTS_PER_BEACON:
                    break
                if ev["host"] != host or ev["object"] != "FLOW":
                    continue
                if not (float(seed["ts"]) <= ev["ts"] <= float(seed["ts"]) + 10 * 60):
                    continue
                props = ev["props"] if isinstance(ev["props"], dict) else {}
                if str(props.get("src_ip") or "") != seed_src:
                    continue
                if (
                    str(props.get("dst_ip") or "") != seed_dst
                    or str(props.get("dst_port") or "") != seed_port
                ):
                    continue
                if ev["file"] == seed["file"] and ev["line"] == seed["line"]:
                    continue
                key = ("process_flow_burst", seed_dst, seed_port, int(ev["ts"]))
                if key in seen:
                    continue
                seen.add(key)
                burst_count += 1
                seq += 1
                out.append(
                    finding(
                        case_id,
                        seq,
                        "beacon_pivot_process_flow",
                        "medium",
                        ev["host"],
                        ev["ts"],
                        0.74,
                        f"same-destination burst after suspicious process flow to {seed_dst}:{seed_port}",
                        [
                            evidence(
                                ev, "same host/destination shortly after selected process-pid flow"
                            )
                        ],
                    )
                )

    if EMIT_DNS_PIVOT:
        for ev in events:
            if ev["object"] != "DNS_QUERY" or not (
                float(anchor["ts"]) - 120 <= ev["ts"] <= float(anchor["ts"]) + 120
            ):
                continue
            props = ev["props"] if isinstance(ev["props"], dict) else {}
            if str(props.get("src_ip") or "") != anchor["src_ip"]:
                continue
            answers = props.get("answers") if isinstance(props.get("answers"), list) else []
            if anchor["dst_ip"] not in {str(answer) for answer in answers}:
                continue
            seq += 1
            out.append(
                finding(
                    case_id,
                    seq,
                    "beacon_pivot_dns_query",
                    "medium",
                    host,
                    ev["ts"],
                    0.78,
                    f"DNS answer resolves beacon destination {anchor['dst_ip']}",
                    [evidence(ev, "DNS answer contains detected beacon destination")],
                )
            )
            break

    if EMIT_LOGON_PIVOT:
        logon_candidates: list[dict[str, Any]] = []
        for ev in events:
            if ev["host"] != host or ev["object"] != "USER_SESSION" or ev["action"] != "LOGIN":
                continue
            if not (float(anchor["ts"]) - 75 * 60 <= ev["ts"] <= float(anchor["ts"]) + 60):
                continue
            principal = ev["principal"].lower()
            props = ev["props"] if isinstance(ev["props"], dict) else {}
            src_ip = str(props.get("src_ip") or "")
            if principal.endswith("$") or principal in {
                "system",
                "local service",
                "network service",
            }:
                continue
            if src_ip and not is_private_or_local(src_ip):
                logon_candidates.append(ev)
        if logon_candidates:
            ev = min(logon_candidates, key=lambda item: item["ts"])
            seq += 1
            out.append(
                finding(
                    case_id,
                    seq,
                    "beacon_pivot_logon",
                    "low",
                    ev["host"],
                    ev["ts"],
                    0.55,
                    "earliest external login context before beacon chain",
                    [evidence(ev, "external source login on beacon host")],
                )
            )

    for ev in events:
        if ev["host"] != host or ev["action"] != "CREATE":
            continue
        if not (start <= ev["ts"] <= end):
            continue
        if ev["object"] == "SCHEDULED_TASK":
            seq += 1
            out.append(
                finding(
                    case_id,
                    seq,
                    "beacon_pivot_scheduled_task",
                    "medium",
                    ev["host"],
                    ev["ts"],
                    0.82,
                    "Windows 4698 scheduled task creation in beacon chain",
                    [evidence(ev, "4698 scheduled task creation near beacon")],
                )
            )
            break
        if ev["object"] != "PROCESS":
            continue
        command = str(
            (ev["props"] if isinstance(ev["props"], dict) else {}).get("command_line") or ""
        )
        if not re.search(r"schtasks\b.*\b/create\b", command, re.I):
            continue
        seq += 1
        out.append(
            finding(
                case_id,
                seq,
                "beacon_pivot_scheduled_task",
                "medium",
                ev["host"],
                ev["ts"],
                0.74,
                "scheduled-task persistence command in beacon chain",
                [evidence(ev, "schtasks/periodic-work persistence near beacon")],
            )
        )
        break

    return out, seq


def no_beacon_lure_marker_score(ev: dict[str, Any]) -> float:
    if ev["object"] != "PROCESS" or ev["action"] != "CREATE":
        return 0.0
    props = ev["props"] if isinstance(ev["props"], dict) else {}
    command = str(props.get("command_line") or "")
    image = str(props.get("image_path") or "")
    text = f"{image} {command}".lower()
    score = 0.0
    if PAYLOAD_RE.search(text) or "shellcode" in text or " rc4 " in f" {text} ":
        score += 3.0
    if DOUBLE_EXT_RE.search(text):
        score += 2.5
    if NO_BEACON_HTA_RE.search(text):
        score += 2.0
    if NTUSER_ADS_RE.search(text) and ("mshta" in text or "cmd" in text):
        score += 3.0
    if NO_BEACON_CLEANUP_RE.search(text) and ("rundll32" in text or "powershell" in text):
        score += 2.0
    if DEFENSE_EVASION_RE.search(text) or ANTI_ANALYSIS_RE.search(text):
        score += 1.5
    return score


def source_lure_followon_reason(ev: dict[str, Any]) -> str:
    if ev["object"] != "PROCESS" or ev["action"] != "CREATE":
        return ""
    props = ev["props"] if isinstance(ev["props"], dict) else {}
    command = str(props.get("command_line") or "")
    image = str(props.get("image_path") or "")
    text = f"{image} {command}".lower().replace("/", "\\")
    basename = exe_basename(image or command)
    if NTUSER_ADS_RE.search(text) and ("mshta" in text or "cmd" in text):
        return "NTUSER.DAT ADS/HTA lure execution"
    if "winword" in text and TEMP_DOC_RE.search(command):
        return "Office decoy document opened from user temp after lure"
    if (
        USER_EXE_RE.search(command)
        and basename not in BASELINE_APP_EXES
        and basename not in SOURCE_SYSTEM_EXES
    ):
        return "user-writable executable launched after lure"
    if (
        image.lower().replace("/", "\\").startswith("c:\\windows\\system32\\")
        and basename.endswith(".exe")
        and basename not in SOURCE_SYSTEM_EXES
        and basename not in BASELINE_APP_EXES
        and basename not in CATALOG_RISKY_EXES
    ):
        return "non-baseline System32 executable in lure actor chain"
    return ""


def source_lure_process_chain_findings(
    case_id: str,
    events: list[dict[str, Any]],
    seq: int,
    *,
    category: str,
    summary_prefix: str,
) -> tuple[list[dict[str, Any]], int]:
    out: list[dict[str, Any]] = []
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        if ev["object"] == "PROCESS" and ev["action"] == "CREATE" and ev["host"]:
            by_host[ev["host"]].append(ev)

    for _host, host_events in by_host.items():
        host_events.sort(key=lambda item: item["ts"])
        markers = [(no_beacon_lure_marker_score(ev), ev) for ev in host_events]
        markers = [(score, ev) for score, ev in markers if score >= 2.0]
        strong_markers = [
            (score, ev)
            for score, ev in markers
            if NTUSER_ADS_RE.search(str(ev.get("text") or ""))
            and (
                "mshta" in str(ev.get("text") or "").lower()
                or "cmd" in str(ev.get("text") or "").lower()
            )
        ]
        if not strong_markers:
            continue
        best_window: list[tuple[float, dict[str, Any]]] = []
        best_sum = 0.0
        for idx, (_score, first) in enumerate(strong_markers):
            window = [
                (score, ev)
                for score, ev in strong_markers[idx:]
                if ev["ts"] - first["ts"] <= 60 * 60
            ]
            window_sum = sum(score for score, _ev in window)
            if window_sum > best_sum:
                best_window = window
                best_sum = window_sum
        if best_sum < 3.0 or not best_window:
            continue

        marker_pids = {
            str(ev.get("pid") or "") for _score, ev in best_window if str(ev.get("pid") or "")
        }
        marker_parent_pids = {
            str(ev.get("ppid") or "") for _score, ev in best_window if str(ev.get("ppid") or "")
        }
        marker_actor_ids = {
            value
            for _score, ev in best_window
            for value in (str(ev.get("object_id") or ""), str(ev.get("actor_id") or ""))
            if value
        }
        start = min(ev["ts"] for _score, ev in best_window) - 15 * 60
        end = max(ev["ts"] for _score, ev in best_window) + 15 * 60
        candidates: list[tuple[float, dict[str, Any], str]] = []
        for ev in host_events:
            if not (start <= ev["ts"] <= end):
                continue
            score, reason = suspicious_process_score(ev)
            marker_score = no_beacon_lure_marker_score(ev)
            ppid = str(ev.get("ppid") or "")
            actor_id = str(ev.get("actor_id") or "")
            props = ev["props"] if isinstance(ev["props"], dict) else {}
            command = str(props.get("command_line") or "")
            command_norm = command.strip()
            actor_link = (ppid and (ppid in marker_pids or ppid in marker_parent_pids)) or (
                actor_id and actor_id in marker_actor_ids
            )
            followon_reason = source_lure_followon_reason(ev)
            if low_signal_baseline_process(ev, score, reason) and not followon_reason:
                continue
            if catalog_baseline_process(ev) and not actor_link:
                continue
            keep = bool(followon_reason and (marker_score >= 2.0 or actor_link))
            if not keep:
                continue
            if command_norm in SOURCE_BASELINE_BASH_COMMANDS and not marker_score:
                continue
            detail = reason or followon_reason or "source-generated lure process chain"
            if followon_reason and followon_reason not in detail:
                detail = f"{detail}; {followon_reason}"
            if marker_score >= 2.0:
                detail = f"{detail}; source-generated lure marker"
            if actor_link:
                detail = f"{detail}; actor/parent linked to lure marker"
            candidates.append((score + marker_score + (0.5 if actor_link else 0.0), ev, detail))

        candidates.sort(key=lambda item: (abs(item[1]["ts"] - best_window[0][1]["ts"]), -item[0]))
        seen: set[tuple[str, int]] = set()
        for score, ev, detail in candidates[:8]:
            key = (str(ev.get("pid") or ""), int(ev["ts"]))
            if key in seen:
                continue
            seen.add(key)
            seq += 1
            out.append(
                finding(
                    case_id,
                    seq,
                    category,
                    "medium",
                    ev["host"],
                    ev["ts"],
                    min(0.94, 0.55 + score / 8.0),
                    f"{summary_prefix}: {detail}",
                    [evidence(ev, detail)],
                )
            )
        break
    return out, seq


def no_beacon_anchor_findings(
    case_id: str, events: list[dict[str, Any]], seq: int
) -> tuple[list[dict[str, Any]], int]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()

    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        if ev["object"] == "PROCESS" and ev["action"] == "CREATE" and ev["host"]:
            by_host[ev["host"]].append(ev)

    for host, host_events in by_host.items():
        host_events.sort(key=lambda item: item["ts"])
        markers = [(no_beacon_lure_marker_score(ev), ev) for ev in host_events]
        markers = [(score, ev) for score, ev in markers if score >= 2.0]
        if len(markers) < 2:
            continue
        best_window: list[tuple[float, dict[str, Any]]] = []
        best_sum = 0.0
        for idx, (_score, first) in enumerate(markers):
            window = [
                (score, ev) for score, ev in markers[idx:] if ev["ts"] - first["ts"] <= 60 * 60
            ]
            window_sum = sum(score for score, _ev in window)
            if len(window) >= 2 and window_sum > best_sum:
                best_window = window
                best_sum = window_sum
        if best_sum < 4.0 or not best_window:
            continue
        start = min(ev["ts"] for _score, ev in best_window) - 15 * 60
        end = max(ev["ts"] for _score, ev in best_window) + 15 * 60
        candidates: list[tuple[float, dict[str, Any], str]] = []
        for ev in host_events:
            if not (start <= ev["ts"] <= end):
                continue
            score, reason = suspicious_process_score(ev)
            marker_score = no_beacon_lure_marker_score(ev)
            if not reason and marker_score <= 0:
                continue
            if low_signal_baseline_process(ev, score, reason):
                continue
            props = ev["props"] if isinstance(ev["props"], dict) else {}
            parent = str(props.get("parent_image_path") or "").lower()
            command = str(props.get("command_line") or "")
            image = str(props.get("image_path") or "")
            text = f"{image} {command}".lower()
            keep = (
                marker_score >= 2.0
                or score >= 1.8
                or (
                    score >= 0.9
                    and ("powershell" in text or "mshta" in text or "rundll32" in text)
                    and parent.endswith("\\explorer.exe")
                )
            )
            if keep:
                detail = reason or "source-informed no-beacon lure marker"
                if marker_score >= 2.0:
                    detail = f"{detail}; no-beacon lure marker"
                candidates.append((score + marker_score, ev, detail))
        candidates.sort(key=lambda item: (abs(item[1]["ts"] - best_window[0][1]["ts"]), -item[0]))
        for score, ev, detail in candidates[:8]:
            key = ("lure", ev.get("pid", ""), int(ev["ts"]))
            if key in seen:
                continue
            seen.add(key)
            seq += 1
            out.append(
                finding(
                    case_id,
                    seq,
                    "source_informed_no_beacon_lure_process",
                    "medium",
                    ev["host"],
                    ev["ts"],
                    min(0.94, 0.55 + score / 8.0),
                    f"no-beacon source-informed lure/process chain: {detail}",
                    [evidence(ev, detail)],
                )
            )
        first_chain_ts = min(
            (ev["ts"] for _score, ev, _detail in candidates),
            default=min(ev["ts"] for _score, ev in best_window),
        )
        logon_candidates: list[dict[str, Any]] = []
        for ev in events:
            if ev["host"] != host or ev["object"] != "USER_SESSION" or ev["action"] != "LOGIN":
                continue
            if not (first_chain_ts - 15 * 60 <= ev["ts"] <= first_chain_ts + 5 * 60):
                continue
            principal = ev["principal"].lower()
            props = ev["props"] if isinstance(ev["props"], dict) else {}
            src_ip = str(props.get("src_ip") or "")
            if principal.endswith("$") or principal in {
                "system",
                "local service",
                "network service",
            }:
                continue
            if principal == "attacker" or (
                src_ip and src_ip != "-" and not is_private_or_local(src_ip)
            ):
                logon_candidates.append(ev)
        if logon_candidates:
            ev = min(logon_candidates, key=lambda item: abs(item["ts"] - first_chain_ts))
            key = ("logon", ev.get("host", ""), int(ev["ts"]))
            if key not in seen:
                seen.add(key)
                seq += 1
                out.append(
                    finding(
                        case_id,
                        seq,
                        "source_informed_no_beacon_logon_context",
                        "low",
                        ev["host"],
                        ev["ts"],
                        0.68,
                        "no-beacon lure-chain login context",
                        [
                            evidence(
                                ev, "login tightly adjacent to strong no-beacon lure/process chain"
                            )
                        ],
                    )
                )
        selected_pids = {
            str(ev.get("pid") or "")
            for _score, ev, _detail in candidates
            if str(ev.get("pid") or "")
        }
        selected_actor_ids = {
            value
            for _score, ev, _detail in candidates
            for value in (str(ev.get("object_id") or ""), str(ev.get("actor_id") or ""))
            if value
        }
        flow_count = 0
        for ev in events:
            if flow_count >= MAX_NO_BEACON_PROCESS_FLOW_PIVOTS:
                break
            if ev["host"] != host or ev["object"] != "FLOW" or not (start <= ev["ts"] <= end):
                continue
            pid = str(ev.get("pid") or "")
            actor_id = str(ev.get("actor_id") or "")
            if not (
                (pid and pid in selected_pids) or (actor_id and actor_id in selected_actor_ids)
            ):
                continue
            props = ev["props"] if isinstance(ev["props"], dict) else {}
            dst_ip = str(props.get("dst_ip") or "")
            dst_port = str(props.get("dst_port") or "")
            if not dst_ip or dst_port in SYSTEM_PORTS:
                continue
            if benign_destination(dst_ip, set()):
                continue
            key = ("flow", dst_ip, dst_port, int(ev["ts"]))
            if key in seen:
                continue
            seen.add(key)
            flow_count += 1
            seq += 1
            out.append(
                finding(
                    case_id,
                    seq,
                    "source_informed_no_beacon_process_flow",
                    "medium",
                    ev["host"],
                    ev["ts"],
                    0.76,
                    f"no-beacon lure-chain process flow to {dst_ip}:{dst_port}",
                    [
                        evidence(
                            ev, "FLOW pid/actorID belongs to selected no-beacon lure process chain"
                        )
                    ],
                )
            )
        break

    for ev in events:
        if ev["object"] != "SCHEDULED_TASK" or ev["action"] != "CREATE":
            continue
        key = ("sched", ev.get("host", ""), int(ev["ts"]))
        if key in seen:
            continue
        seen.add(key)
        seq += 1
        out.append(
            finding(
                case_id,
                seq,
                "source_informed_no_beacon_scheduled_task",
                "medium",
                ev["host"],
                ev["ts"],
                0.82,
                "no-beacon scheduled task creation anchor",
                [evidence(ev, "4698 scheduled task creation in no-beacon case")],
            )
        )

    for ev in events:
        if ev["object"] != "FLOW":
            continue
        props = ev["props"] if isinstance(ev["props"], dict) else {}
        src_ip = str(props.get("src_ip") or "")
        dst_ip = str(props.get("dst_ip") or "")
        dst_port = str(props.get("dst_port") or "")
        service = str(props.get("service") or "").lower()
        if dst_port != "21" and service != "ftp":
            continue
        if not src_ip or not dst_ip:
            continue
        inbound_to_private = not is_private_or_local(src_ip) and is_private_or_local(dst_ip)
        outbound_to_external = is_private_or_local(src_ip) and not is_private_or_local(dst_ip)
        if not (inbound_to_private or outbound_to_external):
            continue
        seq += 1
        out.append(
            finding(
                case_id,
                seq,
                "source_informed_no_beacon_ftp_connection",
                "high",
                "",
                ev["ts"],
                0.86,
                f"no-beacon FTP/RCE-like flow {src_ip}->{dst_ip}:{dst_port}",
                [evidence(ev, "Zeek FTP flow in no-beacon case")],
            )
        )
        break

    return out, seq


def source_leakage_only_test_findings(
    case_id: str,
    events: list[dict[str, Any]],
    seq: int,
) -> tuple[list[dict[str, Any]], int]:
    """Intentionally source-leaky rules for measuring the ceiling, never default."""
    out: list[dict[str, Any]] = []
    seen_payloads: set[str] = set()

    for ev in events:
        if ev["object"] == "USER_SESSION" and ev["action"] == "LOGIN":
            props = ev["props"] if isinstance(ev["props"], dict) else {}
            src_ip = str(props.get("src_ip") or props.get("source_ip") or "")
            outcome = str(props.get("outcome") or "").lower()
            if src_ip in ATTACKER_LOGON_SOURCE_IPS and outcome in {"", "success", "succeeded"}:
                seq += 1
                out.append(
                    finding(
                        case_id,
                        seq,
                        "only_test_source_leakage_logon_ip",
                        "high",
                        ev["host"],
                        ev["ts"],
                        0.99,
                        f"only-test source-leakage logon IP from storyline.py attacker pool: {src_ip}",
                        [evidence(ev, "hardcoded attacker source IP pool in framework source")],
                    )
                )
            continue

        if ev["object"] != "TEXT" or ev["action"] != "OBSERVE":
            continue
        text = str(ev.get("text") or "")
        if not ADVERSARIAL_PAYLOAD_RE.search(text):
            continue
        token_match = CANARY_RE.search(text)
        payload_key = (
            token_match.group(0)
            if token_match
            else hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()
        )
        if payload_key in seen_payloads:
            continue
        seen_payloads.add(payload_key)
        seq += 1
        out.append(
            finding(
                case_id,
                seq,
                "only_test_source_leakage_adversarial_payload",
                "high",
                ev["host"],
                ev["ts"],
                0.97,
                "only-test source-derived prompt/log injection payload marker",
                [evidence(ev, "source-derived adversarial payload text marker")],
            )
        )

    return out, seq


def shell_parent_anomaly_findings(
    case_id: str,
    events: list[dict[str, Any]],
    seq: int,
) -> tuple[list[dict[str, Any]], int]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    per_host: Counter[str] = Counter()
    for ev in events:
        reason = source_shell_parent_anomaly_reason(ev)
        if not reason:
            continue
        host = str(ev.get("host") or "")
        if per_host[host] >= 2:
            continue
        key = (host, str(ev.get("pid") or ""), int(ev["ts"]))
        if key in seen:
            continue
        seen.add(key)
        per_host[host] += 1
        seq += 1
        out.append(
            finding(
                case_id,
                seq,
                "source_informed_shell_parent_anomaly",
                "medium",
                host,
                ev["ts"],
                0.7,
                f"source-informed shell parent anomaly: {reason}",
                [evidence(ev, reason)],
            )
        )
    return out, seq


def global_chain_findings(
    case_id: str,
    events: list[dict[str, Any]],
    seq: int,
    anchored_hosts: set[str],
) -> tuple[list[dict[str, Any]], int]:
    out: list[dict[str, Any]] = []
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        if ev["object"] == "PROCESS" and ev["action"] == "CREATE":
            by_host[ev["host"]].append(ev)

    for host, host_events in by_host.items():
        if not EMIT_STANDALONE_LINUX_ENUM and host not in anchored_hosts:
            continue
        linux_enum = [
            ev
            for ev in host_events
            if LINUX_ENUM_RE.search(
                str(
                    (ev["props"] if isinstance(ev["props"], dict) else {}).get("command_line") or ""
                ).strip()
            )
        ]
        for start_idx, first in enumerate(linux_enum):
            window = [ev for ev in linux_enum[start_idx:] if ev["ts"] - first["ts"] <= 75 * 60]
            if len(window) < 6:
                continue
            for ev in window[:18]:
                command = str(
                    (ev["props"] if isinstance(ev["props"], dict) else {}).get("command_line") or ""
                )
                seq += 1
                out.append(
                    finding(
                        case_id,
                        seq,
                        "source_informed_linux_enum_chain",
                        "medium",
                        ev["host"],
                        ev["ts"],
                        0.78,
                        "Linux post-exploitation enumeration sequence",
                        [evidence(ev, f"enumeration command in dense chain: {command[:80]}")],
                    )
                )
            break

    return out, seq


def detect_case(case_id: str, data_dir: Path, seq: int) -> tuple[list[dict[str, Any]], int]:
    flow_groups, dst_hostnames, events = read_case(data_dir)
    findings, anchors, seq = find_beacons(case_id, flow_groups, dst_hostnames, seq)
    for anchor in anchors:
        pivot_findings, seq = pivot_from_anchor(case_id, anchor, events, seq)
        findings.extend(pivot_findings)
    if anchors:
        lure_findings, seq = source_lure_process_chain_findings(
            case_id,
            events,
            seq,
            category="source_informed_lure_process_chain",
            summary_prefix="source-generated lure/process chain",
        )
        findings.extend(lure_findings)
    if not anchors:
        no_beacon_findings, seq = no_beacon_anchor_findings(case_id, events, seq)
        findings.extend(no_beacon_findings)
    if ONLY_TEST_SOURCE_LEAKAGE:
        leakage_findings, seq = source_leakage_only_test_findings(case_id, events, seq)
        findings.extend(leakage_findings)
    if EMIT_SHELL_PARENT_ANOMALY:
        shell_findings, seq = shell_parent_anomaly_findings(case_id, events, seq)
        findings.extend(shell_findings)
    strong_anchor_hosts = {
        str(item.get("host") or "")
        for item in findings
        if item.get("category") != "source_informed_linux_enum_chain"
        and str(item.get("host") or "")
    }
    chain_findings, seq = global_chain_findings(case_id, events, seq, strong_anchor_hosts)
    findings.extend(chain_findings)
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str, int]] = set()
    for item in findings:
        first_ev = (item.get("evidence") or [{}])[0]
        key = (
            str(item.get("case_id") or ""),
            str(item.get("category") or ""),
            str(item.get("host") or ""),
            str(item.get("timestamp") or ""),
            str(first_ev.get("file") or ""),
            int(first_ev.get("line") or 0),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped, seq


PRIVATE_INDEX_KEYS = {
    "attribution_status",
    "causal_parentage_status",
    "contributing_event_types",
    "contributing_logical_event_ids",
    "contributing_storyline_ids",
    "detectability_class",
    "detectability_reason",
    "event_type",
    "label",
    "logical_event_id",
    "mapping_method",
    "parent_logical_event_ids",
    "provenance_kind",
    "required_anchor_types",
    "storyline_id",
}
REQUIRED_INDEX_FIELDS = {
    "byte_length",
    "byte_offset",
    "correlation_features",
    "observed_time",
    "physical_record_id",
    "record_index",
    "record_sha256",
    "relative_path",
    "source_format",
    "source_instance",
}


def private_index_key_paths(value: Any, prefix: str = "$") -> list[str]:
    """Find private label/provenance keys anywhere in a supposedly blind index row."""
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            child_path = f"{prefix}.{key_text}"
            if key_text.lower() in PRIVATE_INDEX_KEYS:
                found.append(child_path)
            found.extend(private_index_key_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(private_index_key_paths(child, f"{prefix}[{index}]"))
    return found


def validate_record_index_files(records: list[dict[str, Any]], data_dir: Path) -> None:
    """Verify index locators and hashes against the exact blind data files."""
    root = data_dir.expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"record-index data directory does not exist: {root}")
    payloads: dict[str, bytes] = {}
    indexes_by_path: dict[str, set[int]] = defaultdict(set)
    for row_number, record in enumerate(records, start=1):
        relative_path = str(record["relative_path"])
        candidate = (root / relative_path).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ValueError(
                f"record index row {row_number} escapes data directory: {relative_path}"
            ) from exc
        if not candidate.is_file():
            raise ValueError(
                f"record index row {row_number} references missing file: {relative_path}"
            )
        if relative_path not in payloads:
            payloads[relative_path] = candidate.read_bytes()
        payload = payloads[relative_path]
        offset = record["byte_offset"]
        length = record["byte_length"]
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or isinstance(length, bool)
            or not isinstance(length, int)
            or offset < 0
            or length <= 0
            or offset + length > len(payload)
        ):
            raise ValueError(f"record index row {row_number} has invalid byte range")
        actual_hash = hashlib.sha256(payload[offset : offset + length]).hexdigest()
        expected_hash = str(record["record_sha256"]).lower()
        if actual_hash != expected_hash:
            raise ValueError(f"record index row {row_number} hash mismatch for {relative_path}")
        indexes_by_path[relative_path].add(int(record["record_index"]))
    for relative_path, indexes in indexes_by_path.items():
        if indexes != set(range(len(indexes))):
            raise ValueError(f"record indexes are not contiguous for {relative_path}")


def load_record_index(path: Path, *, data_dir: Path | None = None) -> list[dict[str, Any]]:
    """Load and validate a label-free RECORD_INDEX.jsonl file."""
    records: list[dict[str, Any]] = []
    seen_physical_ids: set[str] = set()
    seen_locators: set[tuple[str, int]] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid record index at {path}:{line_number}: {exc}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"record index row {line_number} is not an object")
            private_paths = private_index_key_paths(record)
            if private_paths:
                raise ValueError(f"record index contains private keys: {private_paths}")
            missing = REQUIRED_INDEX_FIELDS.difference(record)
            if missing:
                raise ValueError(
                    f"record index row {line_number} missing fields: {sorted(missing)}"
                )
            physical_id = str(record.get("physical_record_id") or "")
            if not re.fullmatch(r"pr-[0-9a-f]{24}", physical_id):
                raise ValueError(f"record index row {line_number} has invalid physical_record_id")
            record_index = record.get("record_index")
            if (
                isinstance(record_index, bool)
                or not isinstance(record_index, int)
                or record_index < 0
            ):
                raise ValueError(f"record index row {line_number} has invalid record_index")
            relative_path = str(record.get("relative_path") or "")
            if not relative_path or Path(relative_path).is_absolute():
                raise ValueError(f"record index row {line_number} has invalid relative_path")
            locator = (relative_path, record_index)
            if physical_id in seen_physical_ids:
                raise ValueError(f"duplicate physical_record_id in record index: {physical_id}")
            if locator in seen_locators:
                raise ValueError(f"duplicate record locator in record index: {locator}")
            seen_physical_ids.add(physical_id)
            seen_locators.add(locator)
            records.append(record)
    if data_dir is not None:
        validate_record_index_files(records, data_dir)
    return records


def flattened_record_text(record: dict[str, Any]) -> str:
    chunks: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                chunks.append(str(key))
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
        elif value is not None:
            chunks.append(str(value))

    visit(record.get("correlation_features") or {})
    visit(record.get("native_record_id") or {})
    chunks.extend(
        [
            str(record.get("source_format") or ""),
            str(record.get("source_instance") or ""),
            str(record.get("relative_path") or ""),
        ]
    )
    return " ".join(chunks)


def record_timestamp(record: dict[str, Any], default_year: int) -> float | None:
    value = str(record.get("observed_time") or "").strip()
    parsed = parse_iso(value)
    if parsed is not None:
        return parsed
    for pattern in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
        try:
            parsed_dt = datetime.strptime(value, pattern).replace(year=default_year, tzinfo=UTC)
        except ValueError:
            continue
        return parsed_dt.timestamp()
    return None


def scalar_values(value: Any, keys: set[str]) -> set[str]:
    values: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in keys and not isinstance(child, dict | list):
                text = str(child).strip()
                if text:
                    values.add(text.lower())
            values.update(scalar_values(child, keys))
    elif isinstance(value, list):
        for child in value:
            values.update(scalar_values(child, keys))
    return values


def nested_scalar_values(value: Any) -> set[str]:
    values: set[str] = set()
    if isinstance(value, dict):
        for child in value.values():
            values.update(nested_scalar_values(child))
    elif isinstance(value, list):
        for child in value:
            values.update(nested_scalar_values(child))
    elif value is not None:
        text = str(value).strip().lower()
        if text:
            values.add(text)
    return values


def field_values(value: Any, keys: set[str]) -> set[str]:
    """Collect scalar values below explicitly named fields, including list-valued fields."""
    values: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in keys:
                values.update(nested_scalar_values(child))
            values.update(field_values(child, keys))
    elif isinstance(value, list):
        for child in value:
            values.update(field_values(child, keys))
    return values


SOURCE_IP_KEYS = {"id.orig_h", "sourceip", "src_ip"}
DESTINATION_IP_KEYS = {
    "answers",
    "destinationip",
    "dst_ip",
    "id.resp_h",
    "resolved_ips",
}
DOMAIN_KEYS = {"host", "query", "queryname", "server_name", "sni"}


def reverse_pointer(ip_value: str) -> str:
    try:
        return ipaddress.ip_address(ip_value).reverse_pointer.lower().rstrip(".")
    except ValueError:
        return ""


def record_matches_endpoint(record: dict[str, Any], hosts: set[str]) -> bool:
    if record_matches_host(record, hosts):
        return True
    expected_ips = {
        alias for host in hosts for alias in host_aliases(host) if _is_ip_literal(alias)
    }
    source_ips = field_values(record.get("correlation_features") or {}, SOURCE_IP_KEYS)
    return bool(expected_ips.intersection(source_ips))


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def normalized_process_ids(value: Any, keys: set[str]) -> set[str]:
    """Return comparable decimal process IDs without treating logon IDs as PIDs."""
    normalized: set[str] = set()
    for raw_value in scalar_values(value, keys):
        try:
            normalized.add(str(int(raw_value, 0)))
        except ValueError:
            normalized.add(raw_value.lower())
    return normalized


def host_aliases(value: str) -> set[str]:
    """Return exact IP aliases or full/short DNS host aliases without truncating IPv4."""
    text = str(value or "").strip().lower().rstrip(".")
    if not text:
        return set()
    try:
        return {ipaddress.ip_address(text).compressed}
    except ValueError:
        return {text, text.split(".", 1)[0]}


def record_host_tokens(record: dict[str, Any]) -> set[str]:
    values = scalar_values(
        record.get("correlation_features") or {},
        {"hostname", "computer", "host", "source_instance"},
    )
    instance = str(record.get("source_instance") or "")
    if instance:
        values.add(instance)
    aliases: set[str] = set()
    for value in values:
        aliases.update(host_aliases(value))
    return aliases


def record_host_scope(record: dict[str, Any]) -> str:
    """Choose one stable host scope for PID and source-native identity matching."""
    instance = str(record.get("source_instance") or "").strip()
    if instance:
        aliases = host_aliases(instance)
        if aliases:
            return min(aliases, key=lambda item: ("." in item, len(item), item))
    tokens = record_host_tokens(record)
    return min(tokens, key=lambda item: ("." in item, len(item), item), default="")


ScopedIdentity = tuple[str, str]


class ProcessIdentityRoles:
    """Role-aware process identities scoped to one host."""

    def __init__(self) -> None:
        self.process_pids: set[ScopedIdentity] = set()
        self.process_stable_ids: set[ScopedIdentity] = set()
        self.actor_pids: set[ScopedIdentity] = set()
        self.actor_stable_ids: set[ScopedIdentity] = set()
        self.object_ids: set[ScopedIdentity] = set()


def _scoped(scope: str, values: set[str]) -> set[ScopedIdentity]:
    if not scope:
        return set()
    return {(scope, value) for value in values if value}


def process_identities(record: dict[str, Any]) -> ProcessIdentityRoles:
    """Extract role-aware identities without conflating actors, objects, or logon sessions."""
    features = record.get("correlation_features") or {}
    source_format = str(record.get("source_format") or "")
    event_id = str(features.get("event_id") or "")
    object_type = str(features.get("object") or "").upper()
    action = str(features.get("action") or "").upper()
    scope = record_host_scope(record)
    roles = ProcessIdentityRoles()
    if source_format == "ecar":
        roles.process_pids.update(_scoped(scope, normalized_process_ids(features, {"pid"})))
        actor_ids = _scoped(scope, scalar_values(features, {"actorid"}))
        object_ids = _scoped(scope, scalar_values(features, {"objectid"}))
        if object_type == "PROCESS":
            roles.process_stable_ids.update(object_ids)
            if action == "CREATE":
                roles.actor_stable_ids.update(actor_ids)
            else:
                roles.process_stable_ids.update(actor_ids)
        else:
            # FLOW/FILE/MODULE actorID is the process responsible for the observation;
            # objectID identifies the flow, file, or module and must not join the process set.
            roles.process_stable_ids.update(actor_ids)
            roles.object_ids.update(object_ids)
    elif source_format == "windows_event_sysmon":
        roles.process_pids.update(_scoped(scope, normalized_process_ids(features, {"processid"})))
        roles.process_stable_ids.update(_scoped(scope, scalar_values(features, {"processguid"})))
    elif source_format == "windows_event_security":
        if event_id == "4688":
            roles.process_pids.update(
                _scoped(scope, normalized_process_ids(features, {"newprocessid"}))
            )
            roles.actor_pids.update(_scoped(scope, normalized_process_ids(features, {"processid"})))
        else:
            roles.process_pids.update(
                _scoped(scope, normalized_process_ids(features, {"processid"}))
            )
    return roles


def is_process_chain_record(record: dict[str, Any]) -> bool:
    """Limit process expansion to record families that can represent the attack chain."""
    features = record.get("correlation_features") or {}
    source_format = str(record.get("source_format") or "")
    event_id = str(features.get("event_id") or "")
    object_type = str(features.get("object") or "").upper()
    if source_format == "ecar":
        return object_type in {"PROCESS", "FILE", "MODULE"}
    if source_format == "windows_event_security":
        return event_id in {"4688", "4689"}
    if source_format == "windows_event_sysmon":
        return event_id in {"1", "5", "7", "11"}
    return False


def record_matches_host(record: dict[str, Any], hosts: set[str]) -> bool:
    normalized: set[str] = set()
    for host in hosts:
        normalized.update(host_aliases(host))
    return bool(normalized.intersection(record_host_tokens(record)))


def infer_index_year(records: list[dict[str, Any]]) -> int:
    for record in records:
        value = str(record.get("observed_time") or "")
        match = re.match(r"(\d{4})-", value)
        if match:
            return int(match.group(1))
    return datetime.now(tz=UTC).year


def evidence_locator_keys(
    findings: list[dict[str, Any]], data_dir: Path | None = None
) -> set[tuple[str, int]]:
    keys: set[tuple[str, int]] = set()
    xml_line_indexes: dict[str, dict[int, int]] = {}
    for item in findings:
        for ref in item.get("evidence", []):
            relative_path = str(ref.get("file") or "")
            line_number = int(ref.get("line") or 0)
            if not relative_path or line_number <= 0:
                continue
            if relative_path.lower().endswith((".json", ".log", ".bash_history")):
                keys.add((relative_path, line_number - 1))
            elif data_dir is not None and relative_path.lower().endswith(".xml"):
                if relative_path not in xml_line_indexes:
                    xml_path = data_dir / relative_path
                    line_indexes: dict[int, int] = {}
                    if xml_path.is_file():
                        content = xml_path.read_text(encoding="utf-8", errors="replace")
                        current_line = 1
                        previous_start = 0
                        for record_index, match in enumerate(EVENT_RE.finditer(content)):
                            current_line += content.count("\n", previous_start, match.start())
                            line_indexes[current_line] = record_index
                            previous_start = match.start()
                    xml_line_indexes[relative_path] = line_indexes
                record_index = xml_line_indexes[relative_path].get(line_number)
                if record_index is not None:
                    keys.add((relative_path, record_index))
    return keys


def finding_context(
    data_dir: Path,
    findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[str], float, float]:
    flow_groups, dst_hostnames, _events = read_case(data_dir)
    _beacon_findings, anchors, _seq = find_beacons(
        "record-expansion", flow_groups, dst_hostnames, 0
    )
    hosts = {str(item.get("host") or "") for item in findings if item.get("host")}
    timestamps = [
        parsed
        for item in findings
        if (parsed := parse_iso(str(item.get("timestamp") or ""))) is not None
    ]
    for anchor in anchors:
        hosts.add(str(anchor.get("host") or ""))
        hosts.add(str(anchor.get("src_ip") or ""))
        timestamps.extend(float(value) for value in anchor.get("tick_times", set()))
    if not timestamps:
        raise ValueError("source-informed detector produced no timestamped attack context")
    return anchors, hosts, min(timestamps), max(timestamps)


def record_level_predictions(
    *,
    data_dir: Path,
    record_index: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Expand source-informed findings to exact physical-record predictions."""
    if not findings:
        return {
            "analysis_summary": (
                "source-informed detector produced no findings and expanded 0 physical records"
            ),
            "predictions": [],
        }
    anchors, detected_hosts, chain_start, chain_end = finding_context(data_dir, findings)
    default_year = infer_index_year(record_index)
    rows: list[dict[str, Any]] = []
    for record in record_index:
        row = dict(record)
        row["_text"] = flattened_record_text(record)
        row["_text_lower"] = row["_text"].lower()
        row["_ts"] = record_timestamp(record, default_year)
        row["_matches_detected_host"] = record_matches_host(row, detected_hosts)
        row["_matches_detected_endpoint"] = record_matches_endpoint(row, detected_hosts)
        rows.append(row)

    anchor_dst_ips = {str(anchor.get("dst_ip") or "") for anchor in anchors}
    direct_locators = evidence_locator_keys(findings, data_dir)
    finding_times = {
        parsed
        for item in findings
        if (parsed := parse_iso(str(item.get("timestamp") or ""))) is not None
    }

    c2_domains: set[str] = set()
    for row in rows:
        features = row.get("correlation_features") or {}
        destination_ips = field_values(features, DESTINATION_IP_KEYS)
        if destination_ips.intersection(ip.lower() for ip in anchor_dst_ips):
            c2_domains.update(field_values(features, DOMAIN_KEYS))
    c2_domains = {
        domain.rstrip(".")
        for domain in c2_domains
        if "." in domain and not re.fullmatch(r"\d+(?:\.\d+){3}", domain)
    }
    c2_reverse_names = {pointer for ip in anchor_dst_ips if (pointer := reverse_pointer(ip))}

    selected: dict[str, tuple[dict[str, Any], str, float, str]] = {}

    def add(
        row: dict[str, Any],
        reason: str,
        confidence: float = 0.99,
        association_strength: str = "direct",
    ) -> None:
        physical_id = str(row.get("physical_record_id") or "")
        if not physical_id:
            return
        current = selected.get(physical_id)
        if current is None or confidence > current[2]:
            selected[physical_id] = (row, reason, confidence, association_strength)

    for row in rows:
        locator = (str(row.get("relative_path") or ""), int(row.get("record_index") or 0))
        if locator in direct_locators:
            add(row, "direct source-informed finding evidence", 0.995)

    strong_endpoint_re = re.compile(
        r"chromedo\.vbs|\.pdf\.lnk|bandizip\.exe|ark\.x64\.dll|cobalt\s+strike|"
        r"beacon\s+initialized|amsi\s*bypass|etw\s*patch|反调试|环境检测|sfx\s+loader",
        re.I,
    )
    email_re = re.compile(r"\\outlook\.exe\b|\boutlook\.exe\b", re.I)
    first_execution = min(
        (
            float(row["_ts"])
            for row in rows
            if row["_ts"] is not None
            and row["_matches_detected_host"]
            and strong_endpoint_re.search(row["_text"])
        ),
        default=chain_start,
    )
    email_candidates = [
        row
        for row in rows
        if row["_ts"] is not None
        and row["_matches_detected_host"]
        and email_re.search(row["_text"])
        and first_execution - 30 * 60 <= float(row["_ts"]) <= first_execution
    ]
    latest_email_time = max((float(row["_ts"]) for row in email_candidates), default=None)

    strong_pids: set[ScopedIdentity] = set()
    strong_stable_ids: set[ScopedIdentity] = set()
    for row in rows:
        ts = row["_ts"]
        if ts is None or not row["_matches_detected_host"]:
            continue
        text = row["_text"]
        locator = (str(row.get("relative_path") or ""), int(row.get("record_index") or 0))
        is_direct_seed = locator in direct_locators
        is_token_seed = bool(strong_endpoint_re.search(text))
        is_mail_seed = bool(
            latest_email_time is not None
            and abs(float(ts) - latest_email_time) <= 12
            and email_re.search(text)
        )
        if is_token_seed:
            add(row, "high-signal endpoint chain token", 0.995)
        if is_mail_seed:
            add(
                row, "mail-client activity immediately preceding the detected execution chain", 0.93
            )
        if is_direct_seed or is_token_seed or is_mail_seed:
            identities = process_identities(row)
            strong_pids.update(identities.process_pids)
            strong_stable_ids.update(identities.process_stable_ids)

    # Expand once from immutable, high-confidence process seeds. Do not propagate identities from
    # companions: that would turn a shared logon session or parent PID into a transitive flood.
    for row in rows:
        ts = row["_ts"]
        if ts is None or not is_process_chain_record(row):
            continue
        if not row["_matches_detected_host"]:
            continue
        if not (chain_start - 30 * 60 <= float(ts) <= chain_end + 15 * 60):
            continue
        identities = process_identities(row)
        if identities.process_pids.intersection(
            strong_pids
        ) or identities.process_stable_ids.intersection(strong_stable_ids):
            add(
                row,
                "same host-scoped process identity as detected endpoint chain",
                0.97,
                "exact_identity",
            )

    dns_rows: list[dict[str, Any]] = []
    for row in rows:
        ts = row["_ts"]
        if ts is None:
            continue
        features = row.get("correlation_features") or {}
        row_ips = field_values(features, DESTINATION_IP_KEYS)
        row_domains = {value.rstrip(".") for value in field_values(features, DOMAIN_KEYS)}
        has_c2_ip = bool(row_ips.intersection(ip.lower() for ip in anchor_dst_ips))
        has_c2_domain = bool(row_domains.intersection(c2_domains | c2_reverse_names))
        if has_c2_ip or has_c2_domain:
            if chain_start - 5 * 60 <= float(ts) <= chain_end + 60:
                add(row, "record contains detected C2 IP/domain/SNI", 0.995)
                if row.get("source_format") == "zeek_dns":
                    dns_rows.append(row)

    dns_times: list[tuple[float, set[str], set[str]]] = []
    for row in dns_rows:
        ts = float(row["_ts"])
        features = row.get("correlation_features") or {}
        ports = scalar_values(
            features,
            {"id.orig_p", "src_port", "sourceport"},
        )
        dns_times.append((ts, ports, field_values(features, SOURCE_IP_KEYS)))

    for row in rows:
        ts = row["_ts"]
        if ts is None:
            continue
        source_format = str(row.get("source_format") or "")
        features = row.get("correlation_features") or {}
        values = scalar_values(
            features,
            {"id.orig_p", "src_port", "sourceport", "destinationport", "dst_port"},
        )
        event_ids = scalar_values(features, {"event_id"})
        query_names = {value.rstrip(".") for value in field_values(features, DOMAIN_KEYS)}
        for dns_ts, dns_ports, _dns_clients in dns_times:
            explicit_dns_transport = row["_matches_detected_endpoint"] and (
                bool(values.intersection({"53"})) or bool(values.intersection(dns_ports))
            )
            same_tick_sysmon_dns = (
                source_format == "windows_event_sysmon"
                and "22" in event_ids
                and row["_matches_detected_host"]
                and abs(float(ts) - dns_ts) <= 0.5
            )
            same_tick_zeek_dns = (
                source_format == "zeek_dns"
                and row["_matches_detected_endpoint"]
                and abs(float(ts) - dns_ts) <= 0.5
            )
            if abs(float(ts) - dns_ts) <= 2.6 and explicit_dns_transport:
                if source_format in {
                    "ecar",
                    "windows_event_security",
                    "windows_event_sysmon",
                    "zeek_conn",
                    "zeek_dns",
                }:
                    add(
                        row,
                        "host-scoped DNS transport companion for detected C2 resolution",
                        0.985,
                        "tuple_and_time",
                    )
                    break
            if same_tick_sysmon_dns:
                if query_names.intersection(c2_domains | c2_reverse_names):
                    add(
                        row,
                        "Sysmon DNS query matches detected C2 domain or reverse pointer",
                        0.985,
                        "ioc_and_time",
                    )
                else:
                    add(
                        row,
                        "time-only Sysmon DNS companion; retained below scoring threshold",
                        0.35,
                        "time_only_inferred",
                    )
                break
            if same_tick_zeek_dns:
                if query_names.intersection(c2_domains | c2_reverse_names):
                    add(
                        row,
                        "Zeek DNS query matches detected C2 domain or reverse pointer",
                        0.985,
                        "ioc_and_time",
                    )
                else:
                    add(
                        row,
                        "time-only Zeek DNS companion; retained below scoring threshold",
                        0.35,
                        "time_only_inferred",
                    )
                break

    selected_dns_uids: dict[str, tuple[float, str]] = {}
    for selected_row, _reason, confidence, strength in selected.values():
        if selected_row.get("source_format") != "zeek_dns":
            continue
        for uid in field_values(selected_row.get("correlation_features") or {}, {"uid"}):
            current = selected_dns_uids.get(uid)
            if current is None or confidence > current[0]:
                selected_dns_uids[uid] = (confidence, strength)
    for row in rows:
        if row.get("source_format") != "zeek_conn":
            continue
        row_uids = field_values(row.get("correlation_features") or {}, {"uid"})
        matches = [selected_dns_uids[uid] for uid in row_uids if uid in selected_dns_uids]
        if not matches:
            continue
        confidence, strength = max(matches, key=lambda item: item[0])
        add(row, "same Zeek UID as selected DNS observation", confidence, strength)

    # Security 5156 may retain only a source port, omitting the destination IP. Correlate it with
    # already-confirmed C2/DNS observations rather than guessing from a shared logon session.
    confirmed_network_ticks: list[tuple[float, set[str]]] = []
    for selected_row, _reason, _confidence, _strength in selected.values():
        selected_ts = selected_row["_ts"]
        if selected_ts is None or selected_row.get("source_format") == "windows_event_security":
            continue
        ports = scalar_values(
            selected_row.get("correlation_features") or {},
            {"id.orig_p", "src_port", "sourceport"},
        )
        confirmed_network_ticks.append((float(selected_ts), ports))

    for row in rows:
        if row.get("source_format") != "windows_event_security" or row["_ts"] is None:
            continue
        event_ids = scalar_values(row.get("correlation_features") or {}, {"event_id"})
        if "5156" not in event_ids:
            continue
        source_ports = scalar_values(
            row.get("correlation_features") or {}, {"sourceport", "src_port"}
        )
        same_endpoint_flow = row["_matches_detected_host"] and any(
            abs(float(row["_ts"]) - tick) <= 0.5 and bool(source_ports.intersection(ports))
            for tick, ports in confirmed_network_ticks
        )
        is_dc_observation = str(row.get("source_instance") or "").lower().startswith("dc-")
        dc_dns_companion = is_dc_observation and any(
            abs(float(row["_ts"]) - dns_ts) <= 0.5 for dns_ts, _ports, _clients in dns_times
        )
        if same_endpoint_flow:
            add(
                row,
                "Security 5156 host/port/time companion for confirmed C2/DNS flow",
                0.99,
                "tuple_and_time",
            )
        elif dc_dns_companion:
            add(
                row,
                "time-only DC Security 5156 companion; retained below scoring threshold",
                0.35,
                "time_only_inferred",
            )

    # ASA translation messages omit the tuple in this format. Require the expected adjacent
    # 302013/302014 C2 record; retain a time-only fallback below the scoring threshold.
    selected_asa_rows = {
        (str(row.get("relative_path") or ""), int(row.get("record_index") or 0)): row
        for row, _reason, _confidence, _strength in selected.values()
        if row.get("source_format") == "cisco_asa" and row["_ts"] is not None
    }
    expected_asa_pair = {"305011": "302013", "305012": "302014"}
    for row in rows:
        if row.get("source_format") != "cisco_asa" or row["_ts"] is None:
            continue
        msg_ids = scalar_values(row.get("correlation_features") or {}, {"msg_id", "message_id"})
        nat_msg_ids = msg_ids.intersection(expected_asa_pair)
        if not nat_msg_ids:
            continue
        locator = (str(row.get("relative_path") or ""), int(row.get("record_index") or 0) - 1)
        adjacent = selected_asa_rows.get(locator)
        adjacent_msg_ids = (
            scalar_values(adjacent.get("correlation_features") or {}, {"msg_id", "message_id"})
            if adjacent is not None
            else set()
        )
        exact_adjacent_pair = (
            any(expected_asa_pair[msg_id] in adjacent_msg_ids for msg_id in nat_msg_ids)
            and abs(float(row["_ts"]) - float(adjacent["_ts"])) <= 1.1
        )
        if exact_adjacent_pair:
            add(
                row,
                "adjacent ASA NAT companion for detected C2 connection",
                0.985,
                "adjacent_native_pair",
            )
        elif any(
            abs(float(row["_ts"]) - float(candidate["_ts"])) <= 1.1
            for candidate in selected_asa_rows.values()
        ):
            add(
                row,
                "time-only ASA NAT companion; retained below scoring threshold",
                0.35,
                "time_only_inferred",
            )

    selected_logon_ids: set[ScopedIdentity] = set()
    for selected_row, _reason, _confidence, _strength in selected.values():
        features = selected_row.get("correlation_features") or {}
        if (
            selected_row.get("source_format") == "ecar"
            and str(features.get("object") or "").upper() == "USER_SESSION"
        ):
            selected_logon_ids.update(
                _scoped(
                    record_host_scope(selected_row),
                    field_values(features, {"logon_id", "targetlogonid"}),
                )
            )

    # Prefer exact host-scoped LogonId. Time-only identity/persistence companions remain visible
    # for audit but stay below the default scoring threshold.
    for row in rows:
        ts = row["_ts"]
        if ts is None or not row["_matches_detected_host"]:
            continue
        if any(abs(float(ts) - finding_ts) <= 1.5 for finding_ts in finding_times):
            features = row.get("correlation_features") or {}
            source_format = str(row.get("source_format") or "")
            event_ids = scalar_values(features, {"event_id"})
            object_type = str(features.get("object") or "").upper()
            row_logon_ids = _scoped(
                record_host_scope(row), field_values(features, {"targetlogonid"})
            )
            exact_security_logon = (
                source_format == "windows_event_security"
                and "4624" in event_ids
                and bool(row_logon_ids.intersection(selected_logon_ids))
            )
            is_ecar_identity = source_format == "ecar" and object_type == "USER_SESSION"
            if exact_security_logon:
                add(
                    row,
                    "same host-scoped LogonId as detected login",
                    0.98,
                    "exact_identity",
                )
            elif is_ecar_identity:
                add(row, "direct ECAR identity finding", 0.96, "direct")
            elif source_format == "windows_event_security" and event_ids.intersection(
                {"4624", "4698"}
            ):
                add(
                    row,
                    "time-only identity/persistence companion; retained below scoring threshold",
                    0.35,
                    "time_only_inferred",
                )

    predictions = []
    for physical_id, (row, reason, confidence, association_strength) in sorted(
        selected.items(),
        key=lambda item: (
            str(item[1][0].get("relative_path") or ""),
            int(item[1][0].get("record_index") or 0),
        ),
    ):
        predictions.append(
            {
                "physical_record_id": physical_id,
                "relative_path": str(row.get("relative_path") or ""),
                "record_index": int(row.get("record_index") or 0),
                "label": "malicious",
                "confidence": confidence,
                "reason": reason,
                "association_strength": association_strength,
            }
        )
    return {
        "analysis_summary": (
            f"source-informed detector expanded {len(findings)} findings across "
            f"{len(anchors)} periodic-beacon anchor(s) to {len(predictions)} physical records"
        ),
        "predictions": predictions,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input")
    parser.add_argument("--data-dir")
    parser.add_argument("--record-index")
    parser.add_argument("--output", required=True)
    parser.add_argument("--findings-output")
    parser.add_argument(
        "--predict-storyline-tactics",
        action="store_true",
        help=(
            "Optionally emit evidence-scoped ATT&CK tactic predictions for hidden "
            "storyline-level evaluation (record-level --data-dir mode only)."
        ),
    )
    parser.add_argument(
        "--only-test-source-leakage",
        action="store_true",
        help="Enable intentionally source-leaky rules for ceiling tests.",
    )
    args = parser.parse_args()
    global ONLY_TEST_SOURCE_LEAKAGE
    ONLY_TEST_SOURCE_LEAKAGE = ONLY_TEST_SOURCE_LEAKAGE or args.only_test_source_leakage

    if bool(args.input) == bool(args.data_dir):
        parser.error("provide exactly one of --input or --data-dir")
    if args.record_index and not args.data_dir:
        parser.error("--record-index requires --data-dir")
    if args.data_dir and not args.record_index:
        parser.error("record-level --data-dir mode requires --record-index")
    if args.predict_storyline_tactics and not args.record_index:
        parser.error("--predict-storyline-tactics requires record-level --record-index mode")

    if args.input:
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    else:
        data_dir = Path(args.data_dir).expanduser().resolve()
        case_id = (
            data_dir.parent.parent.name if data_dir.parent.name == "blind" else data_dir.parent.name
        )
        payload = {
            "cases": [
                {
                    "case_id": case_id or "record-case",
                    "data_dir": str(data_dir),
                }
            ]
        }
    if args.record_index:
        if len(payload.get("cases", [])) != 1:
            parser.error("record-level mode accepts exactly one case")
        case = payload["cases"][0]
        case_data_dir = Path(case["data_dir"])
        try:
            from record_graph_detector import detect_record_graph
        except ModuleNotFoundError:  # Imported as gold.source_informed_chain_detector.
            from gold.record_graph_detector import detect_record_graph
        output, finding_output = detect_record_graph(
            case_id=str(case["case_id"]),
            rows=load_record_index(Path(args.record_index), data_dir=case_data_dir),
            baseline_domains=BASELINE_DOMAINS,
            baseline_ips=BASELINE_IPS,
            benign_tokens=BENIGN_INFRA_TOKENS,
            predict_storyline_tactics=args.predict_storyline_tactics,
        )
    else:
        findings: list[dict[str, Any]] = []
        seq = 0
        for case in payload.get("cases", []):
            case_findings, seq = detect_case(case["case_id"], Path(case["data_dir"]), seq)
            findings.extend(case_findings)
        finding_output = {
            "schema_version": 1,
            "detector": "source_informed_chain_detector",
            "findings": findings,
        }
        output = finding_output
    if args.findings_output:
        findings_path = Path(args.findings_output)
        findings_path.parent.mkdir(parents=True, exist_ok=True)
        findings_path.write_text(
            json.dumps(finding_output, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
