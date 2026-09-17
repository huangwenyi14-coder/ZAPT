#!/usr/bin/env python3
"""Convert APT-report JSON scripts to EvidenceForge scenario.yaml + GROUND_TRUTH.md.

DEPRECATED for APT-report inputs. Use ``scripts/regenerate_apt_scenarios.py``
instead — it applies a kill-chain phase reorder, realistic-name substitution,
C2 server node injection, ATT&CK ID validation, and real parameter extraction
that the legacy script does not. See
``docs/worklog/2026-07-06-apt-scenario-rebuild.md`` for the quality rules and
the SOP for mapping new reports.

Input format (per 10 篇):
  - meta: { report_name, source_file, source_type, description, "APT group",
            "target country", "target industry", malware_families,
            vulnerabilities, references }
  - scene_nodes: [ { id, name, os, role } ]   (always 3 fixed entries)
  - steps: [ { step_id, order, name, action_type, scene_tag, src, end, os,
               description, notes, params: { attack_mapping, iocs, ... } } ]

Output: a directory under scenarios/ with:
  - scenario.yaml    (EvidenceForge scenario)
  - GROUND_TRUTH.md  (analyst-facing narrative derived from steps)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import OrderedDict
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML required. Run: uv add pyyaml", file=sys.stderr)
    raise


# ---------------------------------------------------------------------------
# scene_tag normalization
# ---------------------------------------------------------------------------

# Map (scene_tag, action_type) -> (event_type, requires_network)
# When the same scene_tag appears with different action_types, prefer the
# network-aware one for socket/file_transfer actions.
TAG_TO_EVENT: dict[str, tuple[str, str]] = {
    # Phishing / delivery (no direct email event) -> process (client download)
    "phishing_attachment": ("process", "phish"),
    "spearphishing_attachment": ("process", "phish"),
    "phishing_attachment_delivery": ("process", "phish"),
    "phishing_lnk_delivery": ("process", "phish"),
    "phishing_desktop_loader": ("process", "phish"),
    "phishing_document_delivery": ("process", "phish"),
    "phishing_delivery": ("process", "phish"),
    "spearphishing_via_social_media": ("process", "phish"),
    "social_engineering_identity": ("process", "phish"),
    "watering_hole_chrome_0day": ("process", "phish"),
    "malicious_app_distribution": ("process", "phish"),
    # Execution / dropper (mostly process)
    "exploit_execution": ("process", "exec"),
    "malware_execution": ("process", "exec"),
    "dropper_execution": ("process", "exec"),
    "dropper_release": ("process", "exec"),
    "dropper_drop_payload": ("process", "exec"),
    "payload_execution_infostealer": ("process", "exec"),
    "malicious_build_event_execution": ("process", "exec"),
    "mshta_hta_execution": ("process", "exec"),
    "decoy_document_open": ("process", "exec"),
    "decoy_document_download": ("connection", "download"),  # one-shot fetch
    "white_binary_launch": ("process", "exec"),
    "ioc_summary": ("__skip__", ""),  # meta only
    # Network delivery (file_transfer / socket)
    "payload_download": ("connection", "download"),
    "payload_download_execute": ("process", "exec"),
    "payload_delivery": ("connection", "download"),
    "payload_decrypt_and_drop": ("process", "exec"),
    "plugin_download": ("connection", "download"),
    "plugin_list_download": ("connection", "download"),
    "plugin_load_execution": ("process", "exec"),
    "periodic_plugin_scheduler": ("process", "exec"),
    "c2_file_transfer": ("connection", "download"),
    "network_connectivity_check": ("connection", "check"),
    # C2 (beacon = recurring; one-shot checkins = connection)
    "c2_beacon": ("beacon", "c2"),
    "c2_beacon_https": ("beacon", "c2"),
    "c2_beacon_registration": ("beacon", "c2"),
    "c2_beacon_fingerprint": ("beacon", "c2"),
    "c2_checkin": ("connection", "c2"),
    "c2_command_fetch": ("connection", "c2"),
    "c2_command_poll": ("connection", "c2"),
    "c2_health_check": ("connection", "c2"),
    "c2_system_info_exfil": ("connection", "c2"),
    "c2_task_complete": ("connection", "c2"),
    "c2_retrieval_via_referrer": ("connection", "c2"),
    "c2_retrieval_via_firebase": ("connection", "c2"),
    "c2_csharp_backdoor": ("beacon", "c2"),
    "c2_dns_resolution": ("dns_query", "c2"),
    # Persistence
    "persistence": ("scheduled_task_created", "persist"),
    "persistence_scheduled_task": ("scheduled_task_created", "persist"),
    "scheduled_task_persistence": ("scheduled_task_created", "persist"),
    "persistence_service": ("service_installed", "persist"),
    "service_installation": ("service_installed", "persist"),
    "registry_run_persistence": ("process", "persist"),
    "registry_run_key_persistence": ("process", "persist"),
    "persistence_registry_run": ("process", "persist"),
    "c2_decrypt_and_persistence": ("process", "persist"),
    # Recon / host cli
    "host_recon": ("process", "recon"),
    "directory_enumeration": ("process", "recon"),
    "remote_command_execution": ("process", "exec"),
    "screen_capture": ("process", "exec"),
    "host_cli": ("process", "exec"),
    # Defense evasion
    "anti_analysis": ("process", "evade"),
    "anti_debug_anti_vm": ("process", "evade"),
    "sandbox_evasion_and_recon": ("process", "evade"),
    "av_detection_evasion": ("process", "evade"),
    "defense_evasion": ("process", "evade"),
    "self_deletion": ("process", "evade"),
    "traffic_obfuscation": ("process", "evade"),
    "hardcoded_c2": ("process", "evade"),
    "dropper_drop_payload": ("process", "exec"),
    # In-memory / reflective
    "reflective_load_remcos": ("process", "exec"),
    "in_memory_pe_load": ("process", "exec"),
    "shellcode_load_dll": ("process", "exec"),
    "shellcode_decrypt": ("process", "exec"),
    # Theft / collection
    "credential_theft_chrome": ("process", "theft"),
    "credential_theft_firefox": ("process", "theft"),
    "browser_history_theft": ("process", "theft"),
    "clipboard_theft": ("process", "theft"),
    "document_filename_collection": ("process", "theft"),
    "data_exfiltration": ("connection", "exfil"),
    "data_exfiltration_cloud": ("connection", "exfil"),
    "collection_exfiltration": ("connection", "exfil"),
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

CHINESE_FILENAME = re.compile(r"[一-鿿]")
SAFE_SLUG_RE = re.compile(r"[^a-z0-9_-]+")


def slugify(name: str, meta: dict | None = None) -> str:
    """ASCII-safe kebab slug for a scenario name.

    Strategy:
      1. Try to use meta['APT group'] as the primary slug component
         (e.g. 'Lazarus', 'APT-C-48 (CNC)' -> 'apt-c-48-cnc').
      2. Prepend a date prefix derived from the filename when one is present.
      3. Avoid duplicating the date when the filename already contains it.
    """
    # Date extraction
    m = re.match(r"^(\d{4})(\d{2})(\d{2})", name)
    if not m:
        m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", name)
    if m:
        date = f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    else:
        date = ""

    # APT-group-driven slug
    apt_raw = ""
    if meta:
        apt_raw = (meta.get("APT group") or "").strip()
    if apt_raw:
        slug_core = re.sub(r"[^A-Za-z0-9]+", "-", apt_raw).strip("-").lower()
        if slug_core:
            return f"{date}-{slug_core}" if date else slug_core

    # Filename-based fallback
    base = name.lower().replace(".json", "")
    # If filename starts with the date, strip it (avoid date duplication)
    if date and base.startswith(date):
        base = base[len(date):].lstrip("-_ ")
    if not base:
        return date or "scenario"
    slug_core = re.sub(r"[^a-z0-9-]+", "-", base).strip("-")
    if not slug_core:
        return date or "scenario"
    return f"{date}-{slug_core}" if date else slug_core


def parse_date_from_filename(path: Path) -> str:
    """Pull an ISO date from common filename patterns."""
    name = path.stem
    m = re.match(r"^(\d{4})(\d{2})(\d{2})", name)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}T10:00:00Z"
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", name)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}T10:00:00Z"
    return "2024-01-01T10:00:00Z"


def technique_label(am: dict) -> str:
    if not isinstance(am, dict):
        return ""
    tid = am.get("technique_id", "")
    tname = am.get("technique", "")
    if tid and tname:
        return f"{tid} - {tname}"
    return tid or tname or ""


def technique_id_only(am: dict) -> str:
    if not isinstance(am, dict):
        return ""
    return am.get("technique_id", "")


def filter_nonempty(d: dict) -> dict:
    """Drop None, empty string, empty list, empty dict values."""
    out = {}
    for k, v in d.items():
        if v is None:
            continue
        if isinstance(v, str) and not v.strip():
            continue
        if isinstance(v, (list, dict)) and len(v) == 0:
            continue
        out[k] = v
    return out


# ---------------------------------------------------------------------------
# scene_node -> environment mapping
# ---------------------------------------------------------------------------

# Hardcoded mapping (per 10 篇 analysis): id 142/145/143 are stable.
NODE_ID_TO_HOSTNAME = {
    142: "ATK-LNX-01",  # linux_attack_server
    145: "WS-VICTIM-01",  # win10_victim
    143: "LNX-VICTIM-01",  # linux_victim
}
NODE_ID_TO_USER = {
    142: "attacker",
    145: "victim.user",
    143: "victim.lnx",
}
NODE_ID_TO_OS = {
    142: "linux",
    145: "windows",
    143: "linux",
}
NODE_ID_TO_IP = {
    142: "10.10.10.10",
    145: "10.10.20.20",
    143: "10.10.30.30",
}
NODE_ID_TO_TYPE = {
    142: "server",
    145: "workstation",
    143: "server",
}


def build_environment(scene_nodes: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    users: list[dict] = []
    systems: list[dict] = []
    identities: list[dict] = []

    used_hostnames: set[str] = set()
    used_usernames: set[str] = set()

    for n in scene_nodes:
        nid = n.get("id")
        hostname = NODE_ID_TO_HOSTNAME.get(nid, f"NODE-{nid}")
        username = NODE_ID_TO_USER.get(nid, f"user{nid}")
        os_cat = NODE_ID_TO_OS.get(nid, n.get("os", "linux"))
        ip = NODE_ID_TO_IP.get(nid, f"10.10.{nid % 250}.{nid % 250}")
        stype = NODE_ID_TO_TYPE.get(nid, "workstation")

        # Dedup collision-safe
        suffix = 2
        base_host = hostname
        while hostname in used_hostnames:
            hostname = f"{base_host}-{suffix}"
            suffix += 1
        used_hostnames.add(hostname)

        suffix = 2
        base_user = username
        while username in used_usernames:
            username = f"{base_user}{suffix}"
            suffix += 1
        used_usernames.add(username)

        os_label = "Windows 10" if os_cat == "windows" else "Ubuntu 22.04 LTS"
        services: list[str] = []
        roles: list[str] = []
        if stype == "workstation":
            services = ["rdp", "smb-client"]
        if os_cat == "linux":
            services = ["ssh"]
        if "attacker" in n.get("role", ""):
            roles = ["linux_admin_target"]

        users.append(
            filter_nonempty(
                {
                    "username": username,
                    "full_name": username.replace(".", " ").title(),
                    "email": f"{username}@example.local",
                    "persona": "sysadmin" if "attacker" in n.get("role", "") else "developer",
                    "primary_system": hostname,
                    "enabled": True,
                }
            )
        )
        systems.append(
            filter_nonempty(
                {
                    "hostname": hostname,
                    "ip": ip,
                    "os": os_label,
                    "type": stype,
                    "assigned_user": username,
                    "services": services,
                    "roles": roles,
                }
            )
        )

    return users, systems, identities


# ---------------------------------------------------------------------------
# iocs -> network_identities extraction (one identity per unique C2 domain)
# ---------------------------------------------------------------------------

def collect_identities(all_steps: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for s in all_steps:
        iocs = s.get("params", {}).get("iocs", {})
        for d in iocs.get("domains", []) or []:
            if not d or d in seen:
                continue
            seen.add(d)
            # Try to find an associated IP
            ip = None
            for other in all_steps:
                oi = other.get("params", {}).get("iocs", {})
                if d in (oi.get("domains") or []):
                    ips = oi.get("ips") or []
                    if ips:
                        ip = ips[0]
                        break
            entry = {"id": d.replace(".", "_"), "hosts": [d], "tags": ["c2"]}
            if ip:
                entry["ips"] = [ip]
            out.append(entry)
    return out


# ---------------------------------------------------------------------------
# step -> storyline event
# ---------------------------------------------------------------------------

INTERPRETER_TO_PROCESS = {
    "powershell": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "powershell.exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "cmd": r"C:\Windows\System32\cmd.exe",
    "cmd.exe": r"C:\Windows\System32\cmd.exe",
    "mshta.exe": r"C:\Windows\System32\mshta.exe",
    "rundll32.exe": r"C:\Windows\System32\rundll32.exe",
    "reg.exe": r"C:\Windows\System32\reg.exe",
    "schtasks.exe": r"C:\Windows\System32\schtasks.exe",
    "sc.exe": r"C:\Windows\System32\scvars.exe",
    "wmic.exe": r"C:\Windows\System32\wbem\wmic.exe",
    "tasklist": r"C:\Windows\System32\tasklist.exe",
    "systeminfo": r"C:\Windows\System32\systeminfo.exe",
    "shellcode": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "windows_api": r"C:\Windows\System32\rundll32.exe",
    "windows_pe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "windows_com": r"C:\Windows\System32\schtasks.exe",
    "csharp": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "native": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "rundll32": r"C:\Windows\System32\rundll32.exe",
    "VBA macro": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    "android_java": "/system/bin/sh",
    "bash": "/bin/bash",
    "sh": "/bin/sh",
    "crontab": "/usr/bin/crontab",
}


def process_for_interpreter(interp: str, os_cat: str) -> str:
    if not interp:
        return ""
    key = interp.strip().lower()
    if os_cat == "linux":
        if key in ("cmd", "cmd.exe"):
            return ""
        if key in ("powershell", "powershell.exe", "mshta.exe", "rundll32.exe",
                   "reg.exe", "schtasks.exe", "windows_api", "windows_pe",
                   "windows_com", "csharp", "native", "shellcode", "rundll32"):
            return ""
        if "bash" in key or "sh" in key:
            return "/bin/bash"
        return ""
    if key in INTERPRETER_TO_PROCESS:
        return INTERPRETER_TO_PROCESS[key]
    # Bare names
    if key in ("bash", "sh"):
        return r"C:\Windows\System32\cmd.exe"
    if key in ("crontab",):
        return r"C:\Windows\System32\schtasks.exe"
    return ""


def pick_actor_for_src(src_id: int) -> str:
    return NODE_ID_TO_USER.get(src_id, "attacker")


def pick_system_for_step(step: dict) -> str:
    """Pick the target system hostname based on the step's OS field and src.

    Per the analysis of the 10 篇:
      - src=142 (attacker, linux) + os=windows  -> still a Windows step but
        logically the attacker hosts. The first phishing step sometimes uses
        src=142 end=145 (attacker -> victim). For these "outbound" steps we
        keep the attacker's host (they originate from there).
      - src=145 (windows victim) + os=windows  -> windows victim host
      - src=143 (linux victim)  + os=linux     -> linux victim host
      - src=142 + os=linux = rare (C2 on attacker host)
    """
    src = step.get("src", 0)
    os_cat = (step.get("os") or "").lower()
    if src == 145:
        return NODE_ID_TO_HOSTNAME[145]  # WS-VICTIM-01
    if src == 143:
        return NODE_ID_TO_HOSTNAME[143]  # LNX-VICTIM-01
    if src == 142:
        # Attacker-originated step. If end != 0 it's outbound to a victim.
        end = step.get("end", 0)
        if end in (145,):
            if os_cat == "android":
                return NODE_ID_TO_HOSTNAME[143]
            if os_cat == "linux":
                return NODE_ID_TO_HOSTNAME[143]
            return NODE_ID_TO_HOSTNAME[145]
        # Self-loop on attacker host
        return NODE_ID_TO_HOSTNAME[142]
    return NODE_ID_TO_HOSTNAME.get(145, "WS-VICTIM-01")


def os_to_os_category(os_field: str) -> str:
    o = (os_field or "").lower()
    if o == "android":
        return "linux"
    return o or "windows"


def step_time(stage: int, total: int) -> str:
    """Convert step order into a relative time offset.

    Spreads steps across `total` evenly into a 1-hour window for compact
    scenarios; longer ones get an extra hour.
    """
    if total <= 0:
        return "+5m"
    base_minutes = max(1, 60 // max(total, 1))  # step interval in minutes
    minutes = (stage - 1) * max(2, base_minutes)
    if minutes < 60:
        return f"+{minutes}m"
    h, m = divmod(minutes, 60)
    return f"+{h}h{m}m" if m else f"+{h}h"


def _resolve_host_from_iocs(step: dict) -> str:
    iocs = step.get("params", {}).get("iocs", {})
    doms = iocs.get("domains") or []
    if doms:
        return doms[0]
    net = step.get("params", {}).get("network", {})
    if isinstance(net, dict):
        h = net.get("host")
        if h:
            return h
    return ""


def _resolve_ip_from_iocs(step: dict) -> str:
    iocs = step.get("params", {}).get("iocs", {})
    ips = iocs.get("ips") or []
    if ips:
        return ips[0]
    net = step.get("params", {}).get("network", {})
    if isinstance(net, dict):
        ip = net.get("ip")
        if ip:
            return ip
    # fallback synthetic IP for domains that don't have one
    return "203.0.113.10"


def _build_connection_event(step: dict, kind: str) -> dict:
    iocs = step.get("params", {}).get("iocs", {})
    net = step.get("params", {}).get("network", {}) or {}
    doms = iocs.get("domains") or []
    ips = iocs.get("ips") or []
    urls = iocs.get("urls") or []
    host = ""
    if isinstance(net, dict):
        host = net.get("host", "") or ""
    if not host and doms:
        host = doms[0]
    port = 443
    method = "GET"
    uri = ""
    if isinstance(net, dict):
        p = net.get("port")
        if p:
            port = p
        m = net.get("method")
        if m:
            method = m
        u = net.get("uri")
        if u:
            uri = u
    if not uri and urls:
        # Extract path from first URL
        first = urls[0]
        if "://" in first:
            tail = first.split("://", 1)[1]
            if "/" in tail:
                uri = "/" + tail.split("/", 1)[1]
    if ips:
        dst_ip = ips[0]
    else:
        dst_ip = "203.0.113.10"
    service = "ssl" if port == 443 else (net.get("protocol", "tcp") if isinstance(net, dict) else "tcp")
    evt: dict = {
        "type": "connection",
        "dst_ip": dst_ip,
        "dst_port": port,
        "service": service,
    }
    if host:
        evt["hostname"] = host
    if method:
        evt["method"] = method
    if uri:
        evt["uri"] = uri
    am = step.get("params", {}).get("attack_mapping", {})
    if am:
        evt["technique"] = technique_label(am)
    if step.get("description"):
        evt["description"] = step["description"]
    if kind == "exfil":
        # Use POST for exfil by default
        if "method" not in evt:
            evt["method"] = "POST"
    return filter_nonempty(evt)


def _build_beacon_event(step: dict) -> dict:
    """Recurring C2 beacon."""
    evt = _build_connection_event(step, kind="c2")
    evt["type"] = "beacon"
    # Reasonable defaults: 5m interval, 1h duration, 20% jitter
    evt["interval"] = "5m"
    evt["duration"] = "1h"
    evt["jitter"] = 0.2
    evt["action"] = "allow"
    return filter_nonempty(evt)


def _build_process_event(step: dict) -> dict:
    params = step.get("params", {}) or {}
    proc = params.get("process", {}) or {}
    cmd = params.get("command", {}) or {}
    am = params.get("attack_mapping", {}) or {}
    os_cat = os_to_os_category(step.get("os", ""))

    # Decide process image path
    if isinstance(proc, dict):
        target = proc.get("target_process", "")
    else:
        target = ""
    interp = cmd.get("interpreter", "") if isinstance(cmd, dict) else ""
    img = ""
    if target and os_cat == "windows" and "\\" not in target and "/" not in target:
        img = process_for_interpreter(target, os_cat)
    if not img:
        img = process_for_interpreter(interp, os_cat)
    if not img:
        if os_cat == "linux":
            img = "/bin/bash"
        else:
            img = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

    # If `target` looks like a full path, use it
    if isinstance(proc, dict) and proc.get("target_process") and (
        "\\" in proc.get("target_process", "") or "/" in proc.get("target_process", "")
    ):
        img = proc["target_process"]

    command_line = cmd.get("command_line", "") if isinstance(cmd, dict) else ""
    if not command_line and target:
        command_line = target

    evt: dict = {"type": "process", "process_name": img}
    if command_line:
        evt["command_line"] = command_line
    if am:
        evt["technique"] = technique_label(am)
    if step.get("description"):
        evt["description"] = step["description"]
    return filter_nonempty(evt)


def _build_scheduled_task_event(step: dict) -> dict:
    params = step.get("params", {}) or {}
    persist = params.get("persistence", {}) or {}
    proc = params.get("process", {}) or {}
    am = params.get("attack_mapping", {}) or {}

    # Derive task name from persistence details or fall back to a slug
    details = ""
    if isinstance(persist, dict):
        details = persist.get("details", "") or ""
    task_name = ""
    m = re.search(r"计划任务[：:]?\s*([\w\-_./]+)", details)
    if m:
        task_name = m.group(1)
    if not task_name and isinstance(proc, dict):
        task_name = proc.get("target_process", "BackgroundTask")
    if not task_name:
        task_name = "BackgroundTask"

    # If there are two tasks (透明部落 pattern), keep just the first.
    # Strip ".exe" from task name and ensure it starts with letter
    task_name = re.sub(r"[^A-Za-z0-9_\-]", "_", task_name)[:60] or "BackgroundTask"

    target = ""
    if isinstance(proc, dict):
        target = proc.get("target_process", "")

    evt: dict = {
        "type": "scheduled_task_created",
        "task_name": task_name,
    }
    if target:
        # task_content describes what the task runs
        evt["task_content"] = f'"{target}"' if not target.startswith('"') else target
    if am:
        evt["technique"] = technique_label(am)
    if step.get("description"):
        evt["description"] = step["description"]
    return filter_nonempty(evt)


def _build_service_event(step: dict) -> dict:
    params = step.get("params", {}) or {}
    am = params.get("attack_mapping", {}) or {}
    target = ""
    if isinstance(params.get("process"), dict):
        target = params["process"].get("target_process", "")
    evt: dict = {
        "type": "service_installed",
        "service_name": (target or "BackgroundSvc")[:60],
        "service_file_name": (target or r"C:\Windows\System32\svchost.exe"),
    }
    if am:
        evt["technique"] = technique_label(am)
    if step.get("description"):
        evt["description"] = step["description"]
    return filter_nonempty(evt)


def _build_dns_query_event(step: dict) -> dict:
    host = _resolve_host_from_iocs(step)
    evt: dict = {
        "type": "dns_query",
        "query": host or "example.invalid",
        "qtype": "A",
        "rcode": "NOERROR",
        "answer": _resolve_ip_from_iocs(step),
    }
    am = step.get("params", {}).get("attack_mapping", {})
    if am:
        evt["technique"] = technique_label(am)
    if step.get("description"):
        evt["description"] = step["description"]
    return filter_nonempty(evt)


def build_step_event(step: dict) -> dict | None:
    tag = step.get("scene_tag", "")
    mapping = TAG_TO_EVENT.get(tag)
    if mapping is None:
        # Unknown tag — fall back to process to keep the step visible
        evt_type = "process"
        kind = "exec"
    else:
        evt_type, kind = mapping
    if evt_type == "__skip__":
        return None
    if evt_type == "process":
        return _build_process_event(step)
    if evt_type == "connection":
        return _build_connection_event(step, kind=kind)
    if evt_type == "beacon":
        return _build_beacon_event(step)
    if evt_type == "scheduled_task_created":
        return _build_scheduled_task_event(step)
    if evt_type == "service_installed":
        return _build_service_event(step)
    if evt_type == "dns_query":
        return _build_dns_query_event(step)
    return _build_process_event(step)


# ---------------------------------------------------------------------------
# YAML emission (preserve key order)
# ---------------------------------------------------------------------------

def make_yaml() -> "yaml.SafeDumper":
    """Custom YAML dumper that emits UTF-8, sorts keys=False, no anchors."""
    class _Dumper(yaml.SafeDumper):
        pass

    def _repr_ordereddict(dumper, data):
        return dumper.represent_mapping(
            "tag:yaml.org,2002:map", list(data.items())
        )

    _Dumper.add_representer(str, lambda d, v: d.represent_scalar(
        "tag:yaml.org,2002:str", v, style="|" if "\n" in v else None,
    ))
    _Dumper.add_representer(OrderedDict, _repr_ordereddict)
    return _Dumper


def dump_yaml(obj, stream) -> None:
    yaml.dump(obj, stream, Dumper=make_yaml(), allow_unicode=True, sort_keys=False, width=100)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def convert(json_path: Path, out_root: Path) -> Path:
    raw = json.loads(json_path.read_text(encoding="utf-8"))
    meta = raw.get("meta", {})
    scene_nodes = raw.get("scene_nodes", [])
    steps = raw.get("steps", [])

    name = slugify(json_path.stem, meta=meta)
    scenario_dir = out_root / name
    scenario_dir.mkdir(parents=True, exist_ok=True)

    users, systems, _ = build_environment(scene_nodes)
    identities = collect_identities(steps)

    # Build network segments
    segments: list[dict] = []
    for s in systems:
        host = s["hostname"]
        ip = s["ip"]
        # Derive a /24 segment per host (simple)
        parts = ip.split(".")
        cidr = ".".join(parts[:3]) + ".0/24"
        seg_name = f"seg_{host.lower().replace('-', '_')}"
        segments.append(
            {
                "name": seg_name,
                "cidr": cidr,
                "exposure": "internal",
                "systems": [host],
            }
        )

    # Build storyline
    storyline: list[dict] = []
    ground_truth_rows: list[tuple[str, str, str, str]] = []
    total = len(steps)
    skipped = 0

    # Track (actor, system) -> first process index. If the first event for a
    # victim (actor, system) is a process, we'll prepend a synthetic logon to
    # avoid the "no prior logon" validation warning.
    first_process_actor_system: tuple[str, str] | None = None
    seen_actor_system: set[tuple[str, str]] = set()

    for idx, step in enumerate(steps, start=1):
        event = build_step_event(step)
        if event is None:
            skipped += 1
            continue
        actor = pick_actor_for_src(step.get("src", 145))
        system_host = pick_system_for_step(step)
        rel_time = step_time(idx - skipped, total)
        evt_id = f"evt-{name[:8].replace('_', '-')}-{idx:02d}"
        storyline_entry: dict = OrderedDict()
        storyline_entry["id"] = evt_id
        storyline_entry["time"] = rel_time
        storyline_entry["actor"] = actor
        storyline_entry["system"] = system_host
        storyline_entry["activity"] = step.get("name", "") or step.get("description", "")
        storyline_entry["events"] = [event]
        storyline.append(storyline_entry)
        am = step.get("params", {}).get("attack_mapping", {}) or {}
        tid = technique_id_only(am)
        tactic = am.get("tactic", "") if isinstance(am, dict) else ""
        ground_truth_rows.append(
            (evt_id, rel_time, step.get("name", ""), f"{tid} ({tactic})" if tid else tactic)
        )
        # Record first time a victim (actor, system) shows a process event
        if (
            event.get("type") in ("process", "beacon", "connection", "dns_query")
            and (actor, system_host) not in seen_actor_system
        ):
            seen_actor_system.add((actor, system_host))
            if first_process_actor_system is None and actor != "attacker":
                first_process_actor_system = (actor, system_host)

    # Prepend a synthetic logon event for the first victim (actor, system)
    # so subsequent process events have a valid session context. This
    # suppresses the "no prior logon" validation warnings on Windows victims.
    if first_process_actor_system is not None:
        actor, system_host = first_process_actor_system
        os_label = "Windows 10" if system_host.startswith("WS-") else "Ubuntu 22.04 LTS"
        logon_entry: dict = OrderedDict()
        logon_entry["id"] = f"evt-{name[:8].replace('_', '-')}-logon"
        logon_entry["time"] = "+0m"
        logon_entry["actor"] = actor
        logon_entry["system"] = system_host
        logon_entry["activity"] = f"{actor} 登录到 {system_host}（构造受害者交互登入）"
        logon_evt: dict = {
            "type": "logon",
            "logon_type": 2 if os_label.startswith("Windows") else 10,
        }
        logon_entry["events"] = [logon_evt]
        storyline.insert(0, logon_entry)

    description = meta.get("description", "").strip() or meta.get("report_name", "")

    env: dict = OrderedDict()
    env["description"] = meta.get("report_name", name)
    env["timezone"] = {"default": "UTC"}
    if users:
        env["users"] = users
    if systems:
        env["systems"] = systems
    if identities:
        env["network_identities"] = identities

    network: dict = OrderedDict()
    if segments:
        network["segments"] = segments
    if network:
        env["network"] = network

    # Domain (default)
    env_block: dict = OrderedDict()
    env_block["description"] = env["description"]
    env_block["timezone"] = env["timezone"]
    if users:
        env_block["users"] = users
    if systems:
        env_block["systems"] = systems
    if identities:
        env_block["network_identities"] = identities
    if network:
        env_block["network"] = network

    scenario: dict = OrderedDict()
    scenario["version"] = "1.0"
    scenario["name"] = name
    scenario["description"] = description or name
    scenario["environment"] = env_block

    time_window: dict = OrderedDict()
    time_window["start"] = parse_date_from_filename(json_path)
    time_window["duration"] = "8h"
    time_window["warmup"] = "4h"
    scenario["time_window"] = time_window

    baseline: dict = OrderedDict()
    baseline["description"] = "Standard office activity. APT report scripts intentionally omit baseline detail; EvidenceForge will synthesize plausible background noise."
    baseline["intensity"] = "medium"
    baseline["variation"] = "medium"
    scenario["baseline_activity"] = baseline

    output: dict = OrderedDict()
    output["logs"] = [
        {"format": "windows"},
        {"format": "syslog"},
        {"format": "ecar"},
    ]
    output["destination"] = f"output/{name}"
    output["compression"] = False
    scenario["output"] = output

    if storyline:
        scenario["storyline"] = storyline

    yaml_path = scenario_dir / "scenario.yaml"
    with yaml_path.open("w", encoding="utf-8") as f:
        dump_yaml(scenario, f)

    # GROUND_TRUTH.md
    gt_lines = [
        f"# GROUND_TRUTH — {name}",
        "",
        f"**Source report:** {meta.get('report_name', '')}",
        f"**APT group:** {meta.get('APT group', '')}",
        f"**Target country:** {', '.join(meta.get('target country') or [])}",
        f"**Target industry:** {', '.join(meta.get('target industry') or [])}",
        f"**Malware families:** {', '.join(meta.get('malware_families') or []) or '_(none disclosed)_'}",
        f"**Vulnerabilities:** {', '.join(meta.get('vulnerabilities') or []) or '_(none disclosed)_'}",
        f"**References:**",
    ]
    for ref in meta.get("references") or []:
        gt_lines.append(f"  - {ref}")
    gt_lines += [
        "",
        f"**Description:** {description}",
        "",
        "## Attack Timeline",
        "",
        "| # | Event ID | Time | Activity | MITRE Technique |",
        "|---|----------|------|----------|-----------------|",
    ]
    for i, (eid, t, name_, mitre) in enumerate(ground_truth_rows, start=1):
        # Escape pipe chars in cells
        def esc(s: str) -> str:
            return s.replace("|", "\\|")
        gt_lines.append(f"| {i} | `{esc(eid)}` | `{esc(t)}` | {esc(name_)} | {esc(mitre)} |")

    gt_lines += [
        "",
        "## Source Mapping Notes",
        "",
        "- Each story step was mapped from a source JSON `steps[].scene_tag` to an EvidenceForge typed event. See `scenario.yaml` for the exact conversion.",
        "- Empty fields in the source (`user_agent`, `hash`, `ip`, `sender`, etc.) were intentionally omitted so the engine can synthesize them deterministically.",
        "- Field names with spaces (e.g. `APT group`, `target country`) were preserved as `APT group` for narrative fidelity.",
        "",
    ]
    gt_path = scenario_dir / "GROUND_TRUTH.md"
    gt_path.write_text("\n".join(gt_lines), encoding="utf-8")

    return scenario_dir


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("inputs", nargs="+", type=Path, help="Input JSON files")
    p.add_argument(
        "--out",
        type=Path,
        default=Path("scenarios"),
        help="Output directory (default: scenarios/)",
    )
    args = p.parse_args()

    out_root: Path = args.out
    out_root.mkdir(parents=True, exist_ok=True)

    for inp in args.inputs:
        if not inp.exists():
            print(f"!! not found: {inp}", file=sys.stderr)
            continue
        scenario_dir = convert(inp, out_root)
        print(f"  -> {scenario_dir}/scenario.yaml")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
