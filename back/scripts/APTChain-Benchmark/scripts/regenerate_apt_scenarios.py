#!/usr/bin/env python3
"""Rebuild EvidenceForge scenario source files from APT-report JSON scripts.

This script supersedes ``convert_apt_json.py`` for APT-report derived inputs.
It does NOT generate log data; use ``uv run eforge generate`` for that. Existing
scenario directories are protected unless ``--overwrite-existing`` is passed.
It encodes a kill-chain-aware quality rule set:

  1. Re-orders steps by MITRE ATT&CK tactic phase so prerequisites come before
     effects (e.g., persistence after RAT execution, exfil after C2 setup).
  2. Resolves every observable step onto a victim-side system. External
     attackers and C2 infrastructure are modeled through event source/destination
     fields and network identities, never as baseline-enabled enterprise hosts.
  3. Replaces generic ``attacker`` / ``victim.user`` actor names with realistic
     first.last handles (marcus.chen, priya.patel, etc.) drawn from a pool that
     aligns with the target country/industry implied by the APT report.
  4. Extracts real parameters from the source JSON (MD5, SHA256, URLs, domains,
     IPs, command lines, registry keys, mutexes, scheduled-task names, ports,
     PDB paths, encryption keys) and pushes them into typed event fields rather
     than leaving them only in the description text.
  5. Keeps attacker/C2 infrastructure outside the enterprise topology and
     models those endpoints only as external network identities.
  6. Normalizes legacy IDs to bundled Enterprise ATT&CK v19.1 and never
     presents Mobile/ICS identifiers as Enterprise labels.
  7. Skips meta-only steps (e.g., ``ioc_summary``) and rejects thin reports
     instead of padding them into bogus scenarios.
  8. Adds a deterministic 8-72 hour visible benign prelude before the attack
     while keeping the report attack anchor at the same absolute time.
  9. Compiles only natively supported Windows/Linux endpoint steps; unsupported
     platform branches are omitted and pure unsupported-platform reports fail
     the quality gate.

Usage:
    uv run python scripts/regenerate_apt_scenarios.py \\
        "/path/to/A.json" "/path/to/B.json" ... \\
        --out scenarios-v2

Run with ``--help`` for all options.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from evidenceforge.events.gold_labels import load_enterprise_attack_mapping

try:
    import yaml
except ImportError:  # pragma: no cover - dependency must be present
    print("PyYAML required. Run: uv add pyyaml", file=sys.stderr)
    raise


WINDOWS_TARGET_HOST = "WKS-ENG-021"
LINUX_TARGET_HOST = "APP-LNX-02"
ATTACK_START_PADDING_MINUTES = 15
MIN_VISIBLE_PRELUDE_HOURS = 8
MAX_VISIBLE_PRELUDE_HOURS = 72
SUPPORTED_SOURCE_OPERATING_SYSTEMS = {"", "linux", "windows"}


def stable_int(seed: str, lower: int, upper: int) -> int:
    """Return a deterministic integer in the inclusive ``[lower, upper]`` range."""
    if lower > upper:
        raise ValueError("lower must not exceed upper")
    digest = hashlib.sha256(seed.encode("utf-8", "replace")).digest()
    return lower + int.from_bytes(digest[:8], "big") % (upper - lower + 1)


def synthetic_external_ip(hostname: str) -> str:
    """Return a stable RFC 5737 address for a source-reported hostname.

    A domain-only report still needs an IP for connection rendering. This
    mapping supplies only that simulation-layer DNS answer; it never invents
    a hostname or replaces a redacted/absent report indicator.
    """
    prefixes = ("192.0.2", "198.51.100", "203.0.113")
    prefix = prefixes[stable_int(f"external-prefix:{hostname}", 0, len(prefixes) - 1)]
    last_octet = stable_int(f"external-host:{hostname}", 10, 249)
    return f"{prefix}.{last_octet}"


def visible_prelude_hours(scenario_name: str) -> int:
    """Choose 8-72 visible benign hours reproducibly for one scenario."""
    return stable_int(
        f"visible-prelude:{scenario_name}",
        MIN_VISIBLE_PRELUDE_HOURS,
        MAX_VISIBLE_PRELUDE_HOURS,
    )


# ---------------------------------------------------------------------------
# Quality rule 1: kill-chain phase ordering
# ---------------------------------------------------------------------------

PHASE_ORDER = [
    "recon",
    "initial_access",
    "execution",
    "defense_evasion",
    "discovery",
    "persistence",
    "c2_setup",
    "c2_communication",
    "collection",
    "exfiltration",
    "cleanup",
]

PHASE_BY_TAG: dict[str, str] = {
    # initial access / supply chain
    "phishing_attachment": "initial_access",
    "phishing_lnk_delivery": "initial_access",
    "phishing_delivery": "initial_access",
    "spearphishing_attachment": "initial_access",
    "spearphishing_via_social_media": "initial_access",
    "social_engineering_identity": "recon",
    "watering_hole_chrome_0day": "initial_access",
    "malicious_app_distribution": "initial_access",
    "phishing_attachment_delivery": "initial_access",
    "phishing_desktop_loader": "initial_access",
    # execution / droppers
    "exploit_execution": "execution",
    "malware_execution": "execution",
    "dropper_execution": "execution",
    "dropper_release": "execution",
    "dropper_drop_payload": "execution",
    "payload_execution_infostealer": "execution",
    "malicious_build_event_execution": "execution",
    "mshta_hta_execution": "execution",
    "decoy_document_open": "execution",
    "decoy_document_download": "execution",
    "white_binary_launch": "execution",
    "reflective_load_remcos": "execution",
    "in_memory_pe_load": "execution",
    "shellcode_load_dll": "execution",
    "shellcode_decrypt": "execution",
    "powershell_havoc_loader": "execution",
    "plugin_load_execution": "execution",
    "periodic_plugin_scheduler": "execution",
    # defense evasion
    "anti_analysis": "defense_evasion",
    "anti_debug_anti_vm": "defense_evasion",
    "sandbox_evasion_and_recon": "defense_evasion",
    "av_detection_evasion": "defense_evasion",
    "defense_evasion": "defense_evasion",
    "self_deletion": "cleanup",
    "traffic_obfuscation": "defense_evasion",
    "hardcoded_c2": "defense_evasion",
    # discovery
    "host_recon": "discovery",
    "bios_registry_query": "discovery",
    "registry_query": "discovery",
    "registry_read": "discovery",
    "directory_enumeration": "c2_communication",
    "host_cli": "execution",
    "remote_command_execution": "c2_communication",
    "screen_capture": "c2_communication",
    "network_connectivity_check": "discovery",
    # persistence
    "persistence": "persistence",
    "persistence_scheduled_task": "persistence",
    "scheduled_task_persistence": "persistence",
    "persistence_service": "persistence",
    "service_installation": "persistence",
    "registry_run_persistence": "persistence",
    "registry_run_key_persistence": "persistence",
    "persistence_registry_run": "persistence",
    "registry_set": "defense_evasion",
    "registry_write": "defense_evasion",
    "c2_decrypt_and_persistence": "persistence",
    # payload transfer / delivery
    "payload_download": "execution",
    "payload_download_execute": "execution",
    "payload_delivery": "execution",
    "payload_decrypt_and_drop": "execution",
    "plugin_download": "execution",
    "plugin_list_download": "c2_communication",
    "c2_file_transfer": "exfiltration",
    # C2
    "c2_dns_resolution": "c2_setup",
    "c2_checkin": "c2_setup",
    "c2_beacon": "c2_communication",
    "c2_beacon_https": "c2_communication",
    "c2_beacon_registration": "c2_communication",
    "c2_beacon_fingerprint": "c2_communication",
    "c2_command_fetch": "c2_communication",
    "c2_command_poll": "c2_communication",
    "c2_health_check": "c2_communication",
    "c2_system_info_exfil": "collection",
    "c2_task_complete": "c2_communication",
    "c2_retrieval_via_referrer": "c2_communication",
    "c2_retrieval_via_firebase": "c2_communication",
    "c2_csharp_backdoor": "c2_communication",
    # collection / theft
    "credential_theft_chrome": "collection",
    "credential_theft_firefox": "collection",
    "browser_history_theft": "collection",
    "clipboard_theft": "collection",
    "document_filename_collection": "collection",
    "data_exfiltration": "exfiltration",
    "data_exfiltration_cloud": "exfiltration",
    "collection_exfiltration": "exfiltration",
    # meta
    "ioc_summary": "__skip__",
}

PHASE_BY_TACTIC: dict[str, str] = {
    "reconnaissance": "recon",
    "resource development": "recon",
    "initial access": "initial_access",
    "execution": "execution",
    "privilege escalation": "execution",
    "defense evasion": "defense_evasion",
    "discovery": "discovery",
    "persistence": "persistence",
    "command and control": "c2_communication",
    "collection": "collection",
    "credential access": "collection",
    "lateral movement": "c2_communication",
    "exfiltration": "exfiltration",
    "impact": "cleanup",
}

PHASE_BY_GENERIC_TAG: dict[str, str] = {
    "reconnaissance": "recon",
    "resource_development": "recon",
    "initial_access": "initial_access",
    "execution": "execution",
    "privilege_escalation": "execution",
    "defense_evasion": "defense_evasion",
    "discovery": "discovery",
    "persistence": "persistence",
    "command_and_control": "c2_communication",
    "c2_establishment": "c2_setup",
    "c2_communication": "c2_communication",
    "collection": "collection",
    "credential_access": "collection",
    "lateral_movement": "c2_communication",
    "exfiltration": "exfiltration",
    "impact": "cleanup",
    "actions_on_objectives": "cleanup",
}

INITIAL_ACCESS_TAGS = {
    "phishing_attachment",
    "phishing_lnk_delivery",
    "phishing_delivery",
    "spearphishing_attachment",
    "spearphishing_via_social_media",
    "watering_hole_chrome_0day",
    "malicious_app_distribution",
    "phishing_attachment_delivery",
    "phishing_desktop_loader",
}


def phase_for_step(step: dict) -> str:
    """Resolve a kill-chain phase from a specific tag, generic tag, or ATT&CK tactic."""
    tag = str(step.get("scene_tag") or "").strip().lower()
    explicit = PHASE_BY_TAG.get(tag)
    if explicit is not None:
        return explicit
    generic = PHASE_BY_GENERIC_TAG.get(tag)
    if generic is not None:
        return generic
    attack_mapping = fix_technique_id(
        str(step.get("scene_tag") or "").strip().lower(),
        _am_dict(step),
    )
    tactic = str(attack_mapping.get("tactic") or attack_mapping.get("tactic_name") or "").strip()
    return PHASE_BY_TACTIC.get(tactic.lower(), "execution")


def is_c2_step(step: dict) -> bool:
    """Return whether a report step is command-and-control rather than lateral movement."""
    tag = str(step.get("scene_tag") or "").strip().lower()
    if tag in C2_TRAFFIC_TAGS or tag in {
        "command_and_control",
        "c2_establishment",
        "c2_communication",
    }:
        return True
    attack_mapping = _am_dict(step)
    tactic = str(attack_mapping.get("tactic") or attack_mapping.get("tactic_name") or "").strip()
    return tactic.lower() == "command and control"


def is_lateral_movement_step(step: dict) -> bool:
    """Return whether a report step describes movement between victim-side systems."""
    tag = str(step.get("scene_tag") or "").strip().lower()
    if tag == "lateral_movement":
        return True
    attack_mapping = _am_dict(step)
    tactic = str(attack_mapping.get("tactic") or attack_mapping.get("tactic_name") or "").strip()
    return tactic.lower() == "lateral movement"


C2_TRAFFIC_TAGS = {
    "c2_dns_resolution",
    "c2_checkin",
    "c2_beacon",
    "c2_beacon_https",
    "c2_beacon_registration",
    "c2_beacon_fingerprint",
    "c2_command_fetch",
    "c2_command_poll",
    "c2_health_check",
    "c2_system_info_exfil",
    "c2_task_complete",
    "c2_retrieval_via_referrer",
    "c2_retrieval_via_firebase",
    "c2_csharp_backdoor",
    "c2_file_transfer",
    "data_exfiltration",
    "data_exfiltration_cloud",
    "collection_exfiltration",
    "plugin_list_download",
}

EXECUTION_TAGS = {
    "exploit_execution",
    "malware_execution",
    "dropper_execution",
    "dropper_release",
    "dropper_drop_payload",
    "payload_execution_infostealer",
    "malicious_build_event_execution",
    "mshta_hta_execution",
    "decoy_document_open",
    "decoy_document_download",
    "white_binary_launch",
    "reflective_load_remcos",
    "in_memory_pe_load",
    "shellcode_load_dll",
    "shellcode_decrypt",
    "powershell_havoc_loader",
    "plugin_load_execution",
    "periodic_plugin_scheduler",
    "host_cli",
}


# ---------------------------------------------------------------------------
# Quality rule 2: realistic user names by region
# ---------------------------------------------------------------------------

NAMES_BY_REGION: dict[str, list[str]] = {
    "CN": [
        "wei.zhang",
        "fang.li",
        "jing.wang",
        "bo.liu",
        "min.chen",
        "hao.yang",
        "lei.huang",
        "yan.zhao",
        "qian.wu",
        "yan.zhou",
        "ting.xu",
        "jun.sun",
    ],
    "GLOBAL": [
        "marcus.chen",
        "priya.patel",
        "sarah.oconnell",
        "diego.ramirez",
        "aisha.johnson",
        "lucas.martinez",
        "fatima.ali",
        "raj.kapoor",
        "emma.thompson",
        "kenji.tanaka",
        "olga.petrova",
        "noah.smith",
        "amelia.kim",
        "felix.mueller",
    ],
    "IN": [
        "raj.kapoor",
        "priya.patel",
        "amit.sharma",
        "neha.gupta",
        "vikram.singh",
        "anjali.menon",
        "arjun.reddy",
        "kavya.iyer",
    ],
    "RU": [
        "olga.petrova",
        "ivan.smirnov",
        "dmitri.volkov",
        "natalia.sokolova",
    ],
    "JP": [
        "kenji.tanaka",
        "haruto.sato",
        "yuki.suzuki",
        "akiko.watanabe",
    ],
}


def pick_name_pool(meta: dict) -> list[str]:
    """Pick a name pool based on the target country in the meta block."""
    countries = meta.get("target country") or []
    # Attackers are typically not from the target country, so pick a global
    # pool for attacker; victim pool is target country.
    if any("中国" in c or "China" in c for c in countries):
        return NAMES_BY_REGION["CN"]
    if any("印度" in c or "India" in c for c in countries):
        return NAMES_BY_REGION["IN"]
    if any("俄罗斯" in c or "Russia" in c for c in countries):
        return NAMES_BY_REGION["RU"]
    if any("日本" in c or "Japan" in c for c in countries):
        return NAMES_BY_REGION["JP"]
    return NAMES_BY_REGION["GLOBAL"]


# ---------------------------------------------------------------------------
# Quality rule 3: ATT&CK technique_id validation
# ---------------------------------------------------------------------------

ENTERPRISE_TECHNIQUE_ALIASES: dict[str, tuple[str, str]] = {
    # ATT&CK v19.1 folds the former DLL Side-Loading sub-technique into DLL.
    "T1574.002": ("T1574.001", "Hijack Execution Flow: DLL"),
}

TECHNIQUE_TACTIC_OVERRIDES: dict[tuple[str, str], str] = {
    # (scene_tag, technique_id) -> correct technique_id
    ("c2_beacon", "T1071.001"): "T1071",  # raw TCP beacon without HTTP semantics
}


def _am_dict(step: dict) -> dict:
    """Coerce ``params.attack_mapping`` into a dict. The 10 篇 corpus modeled
    it as a single dict, but the broader corpus sometimes uses a list of
    dicts (one per step variant) or a string description. We pick the first
    useful dict entry."""
    am = (step.get("params") or {}).get("attack_mapping")
    if isinstance(am, dict):
        return am
    if isinstance(am, list):
        for entry in am:
            if isinstance(entry, dict):
                return entry
        return {}
    if isinstance(am, str):
        # Bare description with no IDs — let the caller fall through to the
        # ``__skip__``/empty path.
        return {}
    return {}


def fix_technique_id(scene_tag: str, am: dict) -> dict:
    """Normalize one source mapping to bundled Enterprise ATT&CK v19.1.

    Mobile and ICS technique IDs are valid in their own ATT&CK domains, but
    must not be presented as Enterprise ATT&CK labels. Unsupported IDs are
    therefore omitted while their source-provided human-readable technique
    names remain available as documentation.
    """
    normalized = dict(am)
    tid = str(normalized.get("technique_id") or "").upper()
    if not tid:
        return normalized

    alias = ENTERPRISE_TECHNIQUE_ALIASES.get(tid)
    if alias is not None:
        tid, technique_name = alias
        normalized["technique_id"] = tid
        normalized["technique"] = technique_name

    key = (scene_tag, tid)
    if key in TECHNIQUE_TACTIC_OVERRIDES:
        tid = TECHNIQUE_TACTIC_OVERRIDES[key]
        normalized["technique_id"] = tid

    known_ids = load_enterprise_attack_mapping()["technique_to_tactics"]
    if tid not in known_ids:
        normalized.pop("technique_id", None)
    return normalized


def is_supported_source_step(step: dict) -> bool:
    """Return whether the deterministic renderer supports the step platform."""
    os_name = str(step.get("os") or "").strip().lower()
    return os_name in SUPPORTED_SOURCE_OPERATING_SYSTEMS


# ---------------------------------------------------------------------------
# Quality rule 4: process image paths (interpreter → real path)
# ---------------------------------------------------------------------------

# Mirrors scripts/convert_apt_json.py with expansions for real APT samples.
INTERPRETER_TO_PROCESS_WIN: dict[str, str] = {
    "powershell": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "powershell.exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "cmd": r"C:\Windows\System32\cmd.exe",
    "cmd.exe": r"C:\Windows\System32\cmd.exe",
    "mshta.exe": r"C:\Windows\System32\mshta.exe",
    "rundll32.exe": r"C:\Windows\System32\rundll32.exe",
    "reg.exe": r"C:\Windows\System32\reg.exe",
    "schtasks.exe": r"C:\Windows\System32\schtasks.exe",
    "sc.exe": r"C:\Windows\System32\sc.exe",
    "wmic.exe": r"C:\Windows\System32\wbem\wmic.exe",
    "tasklist": r"C:\Windows\System32\tasklist.exe",
    "systeminfo": r"C:\Windows\System32\systeminfo.exe",
    "net.exe": r"C:\Windows\System32\net.exe",
    "net1.exe": r"C:\Windows\System32\net1.exe",
    "wevtutil.exe": r"C:\Windows\System32\wevtutil.exe",
    "taskkill.exe": r"C:\Windows\System32\taskkill.exe",
    "rundll32": r"C:\Windows\System32\rundll32.exe",
    "vba macro": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    "ole": r"C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE",
    "vbscript": r"C:\Windows\System32\wscript.exe",
    "wscript": r"C:\Windows\System32\wscript.exe",
}


def process_for_interpreter(interp: str, os_cat: str) -> str:
    if not interp:
        return ""
    key = interp.strip().lower()
    if os_cat == "linux":
        if key in ("bash", "sh"):
            return "/bin/bash"
        if key in ("crontab",):
            return "/usr/bin/crontab"
        return ""
    if key in INTERPRETER_TO_PROCESS_WIN:
        return INTERPRETER_TO_PROCESS_WIN[key]
    return ""


# ---------------------------------------------------------------------------
# Quality rule 5: scene_nodes → environment mapping
# ---------------------------------------------------------------------------

DEFAULT_NODES = [
    {
        "id": 145,
        "name": "win10_victim",
        "os": "windows",
        "role": "victim",
        "hostname": WINDOWS_TARGET_HOST,
        "ip": "10.20.20.21",
        "os_label": "Windows 11 Enterprise",
        "type": "workstation",
        "services": ["rdp", "smb-client"],
        "roles": ["user_workstation"],
        "persona": "developer",
    },
    {
        "id": 143,
        "name": "linux_victim",
        "os": "linux",
        "role": "victim",
        "hostname": LINUX_TARGET_HOST,
        "ip": "10.20.30.12",
        "os_label": "Ubuntu 22.04 LTS",
        "type": "server",
        "services": ["ssh"],
        "roles": ["application_server"],
        "persona": "developer",
    },
    {
        "id": 1001,
        "name": "finance_workstation",
        "os": "windows",
        "role": "victim",
        "hostname": "WKS-FIN-014",
        "ip": "10.20.20.14",
        "os_label": "Windows 11 Enterprise",
        "type": "workstation",
        "services": ["rdp", "smb-client"],
        "roles": ["user_workstation"],
        "persona": "accountant",
    },
    {
        "id": 1002,
        "name": "hr_workstation",
        "os": "windows",
        "role": "victim",
        "hostname": "WKS-HR-009",
        "ip": "10.20.20.9",
        "os_label": "Windows 10 Enterprise",
        "type": "workstation",
        "services": ["rdp", "smb-client"],
        "roles": ["user_workstation"],
        "persona": "hr",
    },
    {
        "id": 1003,
        "name": "domain_controller",
        "os": "windows",
        "role": "victim",
        "hostname": "DC-01",
        "ip": "10.20.10.10",
        "os_label": "Windows Server 2022",
        "type": "domain_controller",
        "services": ["dns", "kerberos", "ldap"],
        "roles": ["domain_controller", "dns_server"],
        "persona": "sysadmin",
    },
    {
        "id": 1004,
        "name": "file_server",
        "os": "windows",
        "role": "victim",
        "hostname": "FS-01",
        "ip": "10.20.40.10",
        "os_label": "Windows Server 2022",
        "type": "server",
        "services": ["smb", "dfs"],
        "roles": ["file_server"],
    },
    {
        "id": 1005,
        "name": "web_server",
        "os": "linux",
        "role": "victim",
        "hostname": "WEB-01",
        "ip": "10.20.50.10",
        "os_label": "Ubuntu 22.04 LTS",
        "type": "server",
        "services": ["nginx", "https"],
        "roles": ["web_server"],
    },
    {
        "id": 1006,
        "name": "database_server",
        "os": "linux",
        "role": "victim",
        "hostname": "DB-01",
        "ip": "10.20.60.10",
        "os_label": "Ubuntu 22.04 LTS",
        "type": "server",
        "services": ["postgresql"],
        "roles": ["database"],
    },
]


def build_scene_index(scene_nodes: list[dict]) -> dict[int, dict]:
    """Index scene_nodes by id, merging in the default node definitions."""
    by_id: dict[int, dict] = {}
    for d in DEFAULT_NODES:
        by_id[d["id"]] = dict(d)
    for n in scene_nodes:
        nid = n.get("id")
        if nid is None:
            continue
        existing = by_id.get(nid, {})
        merged = {**existing, **n}
        # Ensure hostname/ip fall back to defaults
        merged.setdefault("hostname", existing.get("hostname", f"NODE-{nid}"))
        merged.setdefault("ip", existing.get("ip", f"10.10.{nid % 250}.{nid % 250}"))
        merged.setdefault("os_label", existing.get("os_label", "Ubuntu 22.04 LTS"))
        merged.setdefault("type", existing.get("type", "workstation"))
        merged.setdefault("services", existing.get("services", []))
        by_id[nid] = merged
    return by_id


def ensure_c2_server_node(scene_index: dict[int, dict], steps: list[dict]) -> dict:
    """Compatibility no-op: C2 is external identity data, not an enterprise node.

    Older versions injected ``C2-SERVER-01`` into ``environment.systems`` and
    therefore let the baseline engine treat it as an internal managed server.
    Keep the function for CLI compatibility, but intentionally do not mutate
    the scene index. ``collect_network_identities`` owns C2 domains and IPs.
    """
    del steps
    return scene_index


def collect_c2_hosts(steps: list[dict]) -> set[str]:
    hosts: set[str] = set()
    for s in steps:
        iocs = (s.get("params") or {}).get("iocs") or {}
        for d in iocs.get("domains") or []:
            if d:
                hosts.add(d)
        net = (s.get("params") or {}).get("network") or {}
        if isinstance(net, dict):
            h = net.get("host")
            if h:
                hosts.add(h)
    return hosts


# ---------------------------------------------------------------------------
# Quality rule 6: actor / system / end resolution
# ---------------------------------------------------------------------------


def pick_actor_system_end(
    step: dict,
    scene_index: dict[int, dict],
    name_pool: list[str],
    attacker_name: str,
    victim_name: str,
    linux_victim_name: str,
    campaign_network: dict | None = None,
) -> tuple[str, str, str]:
    """Return (actor, system_hostname, c2_hostname_or_empty)."""
    src = step.get("src", 145)
    end = step.get("end")
    os_field = (step.get("os") or "windows").lower()
    os_cat = "linux" if os_field == "android" else os_field
    tag = step.get("scene_tag", "")
    targets_linux = os_cat == "linux" and (src == 143 or end == 143)

    # Initial-access (phishing / watering hole / supply chain) events are
    # captured from the **victim's** endpoint: SOCs see the user opening the
    # attachment, not the attacker's outbound SMTP. Phishing is therefore
    # attributed to the victim user on the affected endpoint.
    if tag in INITIAL_ACCESS_TAGS or tag == "social_engineering_identity":
        if targets_linux:
            return linux_victim_name, LINUX_TARGET_HOST, ""
        return victim_name, WINDOWS_TARGET_HOST, ""

    # C2-traffic steps run on the victim system but talk to a C2 host.
    if is_c2_step(step):
        victim_host = LINUX_TARGET_HOST if targets_linux else WINDOWS_TARGET_HOST
        c2_host = _resolve_c2_host(scene_index, step, campaign_network)
        victim_actor = linux_victim_name if targets_linux else victim_name
        return victim_actor, victim_host, c2_host

    # Linux-only execution steps on the linux victim host
    if targets_linux:
        return linux_victim_name, LINUX_TARGET_HOST, ""

    # Android -> use linux victim as the closest existing host
    if os_field == "android":
        return linux_victim_name, LINUX_TARGET_HOST, ""

    # Default: victim user on the Windows victim host
    return victim_name, WINDOWS_TARGET_HOST, ""


def _resolve_c2_host(
    scene_index: dict[int, dict],
    step: dict,
    campaign_network: dict | None = None,
) -> str:
    """Pick the most appropriate C2 host for a C2-traffic step.

    Uses only a per-step or campaign-wide source-reported domain. An absent or
    redacted hostname stays absent instead of becoming a synthetic C2 label.
    """
    net = (step.get("params") or {}).get("network") or {}
    host_in_step = ""
    if isinstance(net, dict):
        host_in_step = (net.get("host") or "").strip()
    if not host_in_step or not is_valid_hostname(host_in_step):
        iocs = (step.get("params") or {}).get("iocs") or {}
        domains = [d for d in (iocs.get("domains") or []) if is_valid_hostname(d)]
        if domains:
            host_in_step = domains[0]
    if host_in_step and is_valid_hostname(host_in_step):
        return host_in_step
    campaign_host = str((campaign_network or {}).get("hostname") or "")
    return campaign_host if is_valid_hostname(campaign_host) else ""


# ---------------------------------------------------------------------------
# Quality rule 7: real parameter extraction
# ---------------------------------------------------------------------------


def _cmd_str(step: dict) -> str:
    """Return params.command as a raw string regardless of whether the source
    JSON modeled it as a string or a dict. The new JSON corpus uses a string
    (a free-text command description) while the legacy 10 篇 corpus uses a
    dict with ``command_line``/``interpreter`` keys."""
    cmd = (step.get("params") or {}).get("command")
    if cmd is None:
        return ""
    if isinstance(cmd, str):
        return cmd.strip()
    if isinstance(cmd, dict):
        return (cmd.get("command_line") or "").strip()
    return str(cmd).strip()


def _cmd_dict(cmd: object) -> dict:
    """Coerce params.command into a dict shape regardless of source schema.

    The legacy schema is already a dict with ``command_line`` / ``interpreter``
    keys. The new schema is a free-text string, in which case we treat the
    whole string as ``command_line`` and leave ``interpreter`` empty so that
    downstream regex extraction (e.g., for ``rundll32.exe``) still works."""
    if isinstance(cmd, dict):
        return cmd
    if isinstance(cmd, str):
        return {"command_line": cmd.strip(), "interpreter": ""}
    return {}


def _iocs_list(step: dict, key: str) -> list[str]:
    """Return params.iocs.<key> as a list of strings, tolerating None/strings
    that the source JSON may have written as a single value."""
    iocs = (step.get("params") or {}).get("iocs") or {}
    if not isinstance(iocs, dict):
        return []
    raw = iocs.get(key)
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x) for x in raw if x]
    if isinstance(raw, str):
        return [raw] if raw else []
    return [str(raw)]


# Conservative hostname validator. The engine's regex is stricter, so we
# pre-screen before emitting into scenario.yaml.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$")
_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def is_valid_hostname(name: str) -> bool:
    """Return True only for fully-qualified hostnames that pass a basic
    RFC-1123 style check (label.label.tld)."""
    if not name or not isinstance(name, str):
        return False
    if "***" in name or "*" in name:
        return False
    if any(ord(c) > 127 for c in name):
        return False
    return bool(_HOSTNAME_RE.match(name))


def normalize_ip(raw: str) -> str:
    """Strip ``host:port`` suffixes, ``xx.xxx`` redactions, and validate the
    remaining IPv4 dotted-quad. Returns the cleaned IP, or ``""`` if invalid."""
    if not raw or not isinstance(raw, str):
        return ""
    candidate = raw.strip()
    if ":" in candidate:
        candidate = candidate.split(":", 1)[0]
    m = _IPV4_RE.match(candidate)
    if not m:
        return ""
    octets = [int(g) for g in m.groups()]
    if any(o > 255 for o in octets):
        return ""
    # Reject "xx.xxx" style redactions (any octet is non-numeric word, but the
    # regex already rules that out). Also drop obviously-bogus 0.x and 255.x
    # broadcast addresses that show up in some redacted corpora.
    if any(o in (0,) for o in octets):
        return ""
    return ".".join(str(o) for o in octets)


def extract_real_command(step: dict, os_cat: str) -> str:
    cmd = _cmd_str(step)
    if cmd:
        return cmd
    # Fall back to assembling from process + parent
    proc = (step.get("params") or {}).get("process") or {}
    files = (step.get("params") or {}).get("files") or []
    target = (proc.get("target_process") or "").strip()
    if not target and files:
        # Use the first file's basename when there's no explicit command
        target = (files[0].get("file_name") or "").strip()
    if not target:
        return ""
    if os_cat == "linux":
        return f"./{target}" if not target.startswith("/") else target
    if "\\" in target or "/" in target:
        return target
    return target


def extract_process_image(step: dict, os_cat: str) -> str:
    """Pick a realistic process image path."""
    proc = (step.get("params") or {}).get("process") or {}
    cmd = _cmd_dict((step.get("params") or {}).get("command"))
    target = (proc.get("target_process") or "").strip()
    interp = (cmd.get("interpreter") or "").strip()
    files = (step.get("params") or {}).get("files") or []

    # If the target is a full path, use it directly
    if target and ("\\" in target or "/" in target):
        return target

    # If the target looks like a real malware/sample filename (no spaces, has
    # extension), prefer the file_path from the params.files entry.
    if target and "." in target and " " not in target:
        for f in files:
            name = (f.get("file_name") or "").strip()
            path = (f.get("file_path") or "").strip()
            if name == target and path:
                return path
            if name == target and os_cat == "windows":
                return f"C:\\Windows\\Temp\\{name}"
            if name == target and os_cat == "linux":
                return f"/tmp/{name}"

    # If the interpreter is one of the well-known Win32 tools, use it
    mapped = process_for_interpreter(interp or target, os_cat)
    if mapped:
        return mapped
    if target:
        # Treat the target as a literal executable name
        if os_cat == "windows":
            return target if target.lower().endswith(".exe") else f"{target}.exe"
        return f"/usr/local/bin/{target}" if not target.startswith("/") else target

    # Missing ownership is handled later as an explicitly marked degradation.
    # Returning a familiar shell here used to turn absence into a false report fact.
    return ""


def _hostname_from_url(raw_url: str) -> str:
    """Return a valid source hostname from an HTTP(S)/hxxp(s) URL."""
    match = re.match(r"^h(?:tt|xx)ps?://([^/:?#]+)", raw_url.strip(), flags=re.IGNORECASE)
    if not match:
        return ""
    hostname = match.group(1)
    return hostname if is_valid_hostname(hostname) else ""


def extract_network(step: dict) -> dict:
    """Extract a source-backed network tuple from one report step.

    A valid reported hostname receives a stable RFC 5737 simulation address
    when the report omits its historical DNS answer. No hostname is invented.
    """
    net = (step.get("params") or {}).get("network") or {}
    iocs = (step.get("params") or {}).get("iocs") or {}
    out: dict = {}
    if not isinstance(net, dict):
        net = {}
    if not isinstance(iocs, dict):
        iocs = {}
    host = str(net.get("host") or net.get("hostname") or "").strip()
    ip = normalize_ip(str(net.get("ip") or net.get("dst_ip") or ""))
    port = net.get("port")
    method = str(net.get("method") or "").strip()
    uri = str(net.get("uri") or "").strip()
    protocol = str(net.get("protocol") or "").strip().lower()
    urls = _iocs_list(step, "urls")

    # Drop redacted / Chinese placeholder hostnames so we don't poison the
    # engine's hostname validator.
    if not is_valid_hostname(host):
        host = ""
    if not host:
        domains = [domain for domain in _iocs_list(step, "domains") if is_valid_hostname(domain)]
        if domains:
            host = domains[0]
    if not host:
        for raw_url in urls:
            host = _hostname_from_url(raw_url)
            if host:
                break
    if not ip:
        for raw in _iocs_list(step, "ips"):
            cleaned = normalize_ip(raw)
            if cleaned:
                ip = cleaned
                break
    if host and not ip:
        ip = synthetic_external_ip(host)
    if host:
        out["hostname"] = host
    if ip:
        out["dst_ip"] = ip
    if port:
        port_match = re.search(r"\d+", str(port))
        if port_match and 0 < int(port_match.group()) <= 65535:
            out["dst_port"] = int(port_match.group())
    if method:
        out["method"] = method.upper()
    if uri:
        out["uri"] = uri
    if protocol:
        out["service"] = "ssl" if protocol in ("https", "tls") else protocol
    # URL → method/uri fallback
    if not uri:
        for raw_url in urls:
            if "://" not in raw_url:
                continue
            tail = raw_url.split("://", 1)[1]
            if "/" in tail:
                out["uri"] = "/" + tail.split("/", 1)[1]
            if not method:
                out["method"] = "GET"
            break
    return out


def collect_campaign_network_context(steps: list[dict]) -> dict:
    """Choose one source-backed endpoint tuple for underspecified network steps.

    HTTP method, URI and protocol/service describe one behavior rather than the
    campaign as a whole, so they are intentionally excluded from this context.
    """
    candidates: list[tuple[int, int, dict]] = []
    for index, step in enumerate(steps):
        network = extract_network(step)
        if not network.get("dst_ip"):
            continue
        phase = phase_for_step(step)
        priority = 0 if is_c2_step(step) or phase == "exfiltration" else 1
        candidates.append((priority, index, network))
    if not candidates:
        return {}
    _, _, selected = min(candidates, key=lambda item: (item[0], item[1]))
    return {key: selected[key] for key in ("hostname", "dst_ip", "dst_port") if key in selected}


def _has_process_or_file_facts(step: dict, *, include_files: bool = True) -> bool:
    """Return whether a step has native host facts suitable for endpoint evidence."""
    params = step.get("params") or {}
    if not isinstance(params, dict):
        return False
    if _cmd_str(step):
        return True
    process = params.get("process") or {}
    if isinstance(process, dict) and any(process.get(key) for key in ("target_process", "parent")):
        return True
    return include_files and bool(extract_file_metadata(step))


def _merge_network_context(step_network: dict, campaign_network: dict | None) -> dict:
    """Fill only a compatible endpoint tuple from campaign-level context.

    URI, method and service are behavior-bound and never cross step boundaries.
    If the current step names another host/IP, no fields from the campaign
    endpoint are mixed into it.
    """
    merged = dict(step_network)
    campaign = campaign_network or {}
    step_host = str(step_network.get("hostname") or "")
    step_ip = str(step_network.get("dst_ip") or "")
    campaign_host = str(campaign.get("hostname") or "")
    campaign_ip = str(campaign.get("dst_ip") or "")
    has_step_endpoint = bool(step_host or step_ip)
    same_endpoint = bool(
        (step_host and campaign_host and step_host == campaign_host)
        or (step_ip and campaign_ip and step_ip == campaign_ip)
    )
    if has_step_endpoint and not same_endpoint:
        return merged
    for key in ("hostname", "dst_ip", "dst_port"):
        if key not in merged and key in campaign:
            merged[key] = campaign[key]
    return merged


def extract_persistence(step: dict) -> dict:
    """Extract scheduled task name, service name, registry path, etc."""
    persist = (step.get("params") or {}).get("persistence") or {}
    cl = _cmd_str(step)
    registry = (step.get("params") or {}).get("registry") or {}
    out: dict = {}
    details = (persist.get("details") or "") if isinstance(persist, dict) else ""

    # Scheduled task name
    m = re.search(r"/tn\s+([^\s/]+)", cl)
    if m:
        out["task_name"] = m.group(1)
    if "task_name" not in out:
        m = re.search(r"计划任务[：:]?\s*([\w\-_./]+)", details)
        if m:
            out["task_name"] = m.group(1)

    # Service name
    m = re.search(r"sc\s+create\s+([^\s]+)", cl)
    if m:
        out["service_name"] = m.group(1)
    if "service_name" not in out:
        m = re.search(r"服务名[：:]?\s*([\w\-_./]+)", details)
        if m:
            out["service_name"] = m.group(1)

    # Registry path / value
    if isinstance(registry, dict):
        key = (registry.get("key") or "").strip()
        value_name = (registry.get("value_name") or "").strip()
        if key:
            out["registry_key"] = key
        if value_name:
            out["registry_value"] = value_name

    # Binary path used by the persistence mechanism
    m = re.search(r"/tr\s+(.+?)(?:\s*&&|$)", cl)
    if m:
        out["task_content"] = m.group(1).strip()
    if "task_content" not in out and isinstance(persist, dict):
        d = (persist.get("binary") or persist.get("command") or "").strip()
        if d:
            out["task_content"] = d
    return out


def extract_file_metadata(step: dict) -> dict:
    """Pick the most informative file from the step's files[] list."""
    files = (step.get("params") or {}).get("files") or []
    if not files:
        return {}
    files = [f for f in files if isinstance(f, dict)]
    if not files:
        return {}
    # Prefer a file that has an md5/sha256/path
    files.sort(key=lambda f: -bool(f.get("md5")) - bool(f.get("sha256")) - bool(f.get("file_path")))
    chosen = files[0]
    return {
        "file_name": chosen.get("file_name") or "",
        "file_path": chosen.get("file_path") or "",
        "md5": chosen.get("md5") or "",
        "sha256": chosen.get("sha256") or "",
        "description": chosen.get("description") or "",
    }


# ---------------------------------------------------------------------------
# Quality rule 8: event-type selection and field assembly
# ---------------------------------------------------------------------------


def build_event(
    step: dict,
    actor: str,
    system: str,
    c2_host: str,
    os_cat: str,
    campaign_network: dict | None = None,
) -> dict | list[dict] | None:
    tag = str(step.get("scene_tag") or "").strip().lower()
    phase = phase_for_step(step)
    action_type = str(step.get("action_type") or "").strip().lower()
    if phase == "__skip__":
        return None

    am = fix_technique_id(tag, _am_dict(step))
    technique_str = ""
    if am:
        tid = am.get("technique_id") or ""
        tname = am.get("technique") or am.get("technique_name") or ""
        technique_str = f"{tid} - {tname}" if tid and tname else (tid or tname)

    description = step.get("description") or ""
    file_meta = extract_file_metadata(step)
    step_network = extract_network(step)
    net = _merge_network_context(step_network, campaign_network)
    persist = extract_persistence(step)
    registry = (step.get("params") or {}).get("registry") or {}
    has_registry_key = isinstance(registry, dict) and bool(registry.get("key"))
    technique_id = str(am.get("technique_id") or "")
    searchable_text = " ".join(
        [
            tag,
            str(step.get("name") or ""),
            description,
            technique_id,
        ]
    ).lower()

    def process_fallback(*, include_files: bool = False) -> dict | None:
        if not _has_process_or_file_facts(step, include_files=include_files):
            return None
        return _build_process_event(step, os_cat, technique_str, description, file_meta)

    # Decide event type
    if tag in INITIAL_ACCESS_TAGS or (phase == "initial_access" and action_type == "email"):
        email = (step.get("params") or {}).get("email") or {}
        has_email_facts = isinstance(email, dict) and any(
            str(email.get(key) or "").strip()
            for key in ("sender", "recipient", "subject", "delivery_method")
        )
        if (
            not has_email_facts
            and not file_meta
            and not _has_process_or_file_facts(
                step,
                include_files=False,
            )
        ):
            return None
        return _build_phishing_event(step, system, technique_str, description, file_meta, os_cat)
    if is_lateral_movement_step(step):
        if technique_id.startswith("T1021.001"):
            return _build_remote_session_event("rdp_session", technique_str, description)
        if technique_id.startswith("T1021.004") or ("ssh" in searchable_text):
            return _build_remote_session_event("ssh_session", technique_str, description)
        return _build_process_event(step, os_cat, technique_str, description, file_meta)
    if is_c2_step(step):
        if tag == "c2_dns_resolution" or action_type == "dns":
            if not net.get("hostname"):
                return process_fallback()
            return _build_dns_event(net, technique_str, description)
        if tag in {
            "c2_beacon",
            "c2_beacon_https",
            "c2_beacon_registration",
            "c2_beacon_fingerprint",
            "c2_csharp_backdoor",
        } or any(token in searchable_text for token in ("beacon", "heartbeat", "check-in")):
            if not net.get("dst_ip"):
                return process_fallback()
            return _build_beacon_event(net, technique_str, description)
        if (
            tag
            in {
                "c2_file_transfer",
                "data_exfiltration",
                "data_exfiltration_cloud",
                "collection_exfiltration",
            }
            or phase == "exfiltration"
        ):
            if not net.get("dst_ip"):
                return process_fallback()
            return _build_exfil_event(step, net, technique_str, description)
        if not net.get("dst_ip"):
            return process_fallback()
        return _build_c2_event(net, technique_str, description)
    if phase == "exfiltration":
        if not net.get("dst_ip"):
            return process_fallback()
        return _build_exfil_event(step, net, technique_str, description)
    if tag in {
        "persistence",
        "persistence_scheduled_task",
        "scheduled_task_persistence",
        "c2_decrypt_and_persistence",
    } or (phase == "persistence" and technique_id.startswith("T1053")):
        if not persist.get("task_name") or not persist.get("task_content"):
            return process_fallback(include_files=True)
        return _build_persistence_event(persist, step, technique_str, description)
    if tag in {"persistence_service", "service_installation"} or (
        phase == "persistence" and technique_id.startswith("T1543")
    ):
        if not persist.get("service_name") or not persist.get("task_content"):
            return process_fallback(include_files=True)
        return _build_service_install_event(persist, step, technique_str, description)
    if tag in {
        "registry_run_persistence",
        "registry_run_key_persistence",
        "persistence_registry_run",
    } or (
        phase == "persistence"
        and (technique_id.startswith("T1547.001") or bool(persist.get("registry_key")))
    ):
        if (
            not persist.get("registry_key")
            or not persist.get("registry_value")
            or not persist.get("task_content")
        ):
            return process_fallback(include_files=True) or _inferred_owner_process(step, os_cat)
        return _build_registry_run_event(persist, step, technique_str, description)
    if phase == "persistence":
        event = process_fallback(include_files=True)
        if event is None and has_registry_key:
            return _inferred_owner_process(step, os_cat)
        return event
    if tag == "network_connectivity_check":
        if not step_network.get("dst_ip"):
            return process_fallback()
        return _build_connectivity_event(step_network, technique_str, description)
    if tag in {
        "payload_download",
        "payload_download_execute",
        "plugin_download",
        "payload_delivery",
        "payload_decrypt_and_drop",
        "dropper_drop_payload",
    } or (
        action_type == "file_transfer"
        and phase in {"initial_access", "execution", "c2_setup", "c2_communication"}
    ):
        if not net.get("dst_ip"):
            return process_fallback()
        return _build_payload_download_event(step, net, file_meta, technique_str, description)
    if tag == "plugin_list_download":
        if not net.get("dst_ip"):
            return process_fallback()
        return _build_plugin_list_event(step, net, technique_str, description)
    if action_type == "dns":
        if not net.get("hostname"):
            return process_fallback()
        return _build_dns_event(net, technique_str, description)
    if action_type in {"socket", "website", "pcap"} and phase in {
        "initial_access",
        "recon",
        "execution",
    }:
        if not net.get("dst_ip"):
            return process_fallback()
        return _build_c2_event(net, technique_str, description)
    if has_registry_key:
        return process_fallback(include_files=True) or _inferred_owner_process(step, os_cat)
    return process_fallback(include_files=True)


def _build_phishing_event(
    step: dict,
    system: str,
    technique: str,
    description: str,
    file_meta: dict,
    os_cat: str,
) -> list[dict]:
    """Build victim-side Outlook evidence for a reported phishing event.

    Only source-reported sender, recipient, subject, delivery, attachment, and
    hash facts are included. Follow-on document or script execution belongs to
    its own report step; this function does not invent that process chain.
    """
    email = (step.get("params") or {}).get("email") or {}
    if not isinstance(email, dict):
        email = {}
    sender = (email.get("sender") or "").strip()
    recipient = (email.get("recipient") or "").strip()
    subject = (email.get("subject") or "").strip()
    delivery = (email.get("delivery_method") or "").strip()
    file_name = file_meta.get("file_name") or ""
    md5 = file_meta.get("md5") or ""
    sha256 = file_meta.get("sha256") or ""

    outlook = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"

    reported_facts: list[str] = []
    if sender:
        reported_facts.append(f"From=<{sender}>")
    if recipient:
        reported_facts.append(f"To=<{recipient}>")
    if subject:
        reported_facts.append(f'Subject="{subject}"')
    if delivery:
        reported_facts.append(f"Delivery={delivery}")
    if file_name:
        reported_facts.append(f"attachment={file_name}")
    if md5:
        reported_facts.append(f"md5={md5}")
    if sha256:
        reported_facts.append(f"sha256={sha256}")

    command_line = f'"{outlook}" /c ipm.note'
    if subject:
        command_line += f' /m "{subject}"'
    if file_name:
        command_line += f' /a "{file_name}"'

    event_description = "Outlook processes the reported phishing message on the endpoint."
    if reported_facts:
        event_description += " Source-reported facts: " + " ".join(reported_facts) + "."
    if description:
        event_description += f" Report narrative: {description}"

    chain: list[dict] = [
        {
            "type": "process",
            "process_name": outlook,
            "command_line": command_line,
            "description": event_description,
        }
    ]

    if technique:
        for evt in chain:
            evt["technique"] = technique
    return chain


def _build_process_event(
    step: dict,
    os_cat: str,
    technique: str,
    description: str,
    file_meta: dict,
) -> dict:
    proc_img = extract_process_image(step, os_cat)
    cmd = extract_real_command(step, os_cat)
    if proc_img:
        evt = {"type": "process", "process_name": proc_img}
    else:
        evt = _inferred_owner_process(step, os_cat)
    if cmd:
        evt["command_line"] = cmd
    if technique:
        evt["technique"] = technique
    if description:
        existing_description = str(evt.get("description") or "").strip()
        evt["description"] = (
            f"{existing_description} Report narrative: {description}".strip()
            if existing_description
            else description
        )
    if file_meta.get("file_name"):
        evt["description"] = (evt.get("description") or "") + f" [binary={file_meta['file_name']}]"
    return evt


def _build_persistence_event(
    persist: dict,
    step: dict,
    technique: str,
    description: str,
) -> dict:
    task_name = persist["task_name"]
    task_content = persist["task_content"]
    evt = {
        "type": "scheduled_task_created",
        "task_name": task_name[:60],
        "task_content": task_content,
        "description": description or f"Scheduled task created: {task_name}",
    }
    if technique:
        evt["technique"] = technique
    return evt


def _build_service_install_event(
    persist: dict,
    step: dict,
    technique: str,
    description: str,
) -> dict:
    svc = persist["service_name"]
    binary = persist["task_content"]
    evt = {
        "type": "service_installed",
        "service_name": svc[:60],
        "service_file_name": binary,
        "description": description or f"Service installed: {svc}",
    }
    if technique:
        evt["technique"] = technique
    return evt


def _build_registry_run_event(
    persist: dict,
    step: dict,
    technique: str,
    description: str,
) -> dict:
    """Registry Run-key persistence is modeled as a process invoking reg.exe."""
    reg_key = persist["registry_key"]
    value_name = persist["registry_value"]
    binary = persist["task_content"]
    cmd = f'reg.exe add "{reg_key}" /v "{value_name}" /t REG_SZ /d "{binary}" /f'
    evt = {
        "type": "process",
        "process_name": r"C:\Windows\System32\reg.exe",
        "command_line": cmd,
        "description": (description or f"Registry Run-key persistence under {reg_key}"),
    }
    if technique:
        evt["technique"] = technique
    return evt


def _build_remote_session_event(
    event_type: str,
    technique: str,
    description: str,
) -> dict:
    """Build a victim-side remote-session observation from another enterprise host."""
    evt = {
        "type": event_type,
        "source_ip": "10.20.20.14",
    }
    if technique:
        evt["technique"] = technique
    if description:
        evt["description"] = description
    return evt


def _build_dns_event(net: dict, technique: str, description: str) -> dict:
    evt = {
        "type": "dns_query",
        "query": net["hostname"],
        "qtype": "A",
        "rcode": "NOERROR",
        "answer": net["dst_ip"],
    }
    if technique:
        evt["technique"] = technique
    if description:
        evt["description"] = description
    return evt


def _build_beacon_event(net: dict, technique: str, description: str) -> dict:
    """Recurring C2 beacon."""
    evt = {
        "type": "beacon",
        "dst_ip": net["dst_ip"],
        "dst_port": net.get("dst_port") or 443,
        "interval": "5m",
        "duration": "1h",
        "jitter": 0.2,
        "action": "allow",
    }
    if net.get("hostname"):
        evt["hostname"] = net["hostname"]
    if net.get("service"):
        evt["service"] = net["service"]
    else:
        evt["service"] = "ssl" if evt["dst_port"] == 443 else "tcp"
    if technique:
        evt["technique"] = technique
    if description:
        evt["description"] = description
    return evt


def _build_c2_event(net: dict, technique: str, description: str) -> dict:
    """One-shot C2 traffic (checkin, command poll, etc.)."""
    evt = {
        "type": "connection",
        "dst_ip": net["dst_ip"],
        "dst_port": net.get("dst_port") or 443,
        "service": net.get("service") or "ssl",
    }
    if net.get("hostname"):
        evt["hostname"] = net["hostname"]
    if net.get("method"):
        evt["method"] = net["method"]
    if net.get("uri"):
        evt["uri"] = net["uri"]
    if technique:
        evt["technique"] = technique
    if description:
        evt["description"] = description
    return evt


def _build_exfil_event(
    step: dict,
    net: dict,
    technique: str,
    description: str,
) -> dict:
    """Data exfiltration connection — POST to a remote endpoint."""
    evt = {
        "type": "connection",
        "dst_ip": net["dst_ip"],
        "dst_port": net.get("dst_port") or 443,
        "service": net.get("service") or "ssl",
        "method": net.get("method") or "POST",
    }
    if net.get("hostname"):
        evt["hostname"] = net["hostname"]
    if net.get("uri"):
        evt["uri"] = net["uri"]
    if technique:
        evt["technique"] = technique
    if description:
        evt["description"] = description
    return evt


def _build_connectivity_event(net: dict, technique: str, description: str) -> dict:
    """One-shot connectivity check to the source-reported endpoint."""
    evt = {
        "type": "connection",
        "dst_ip": net["dst_ip"],
        "dst_port": net.get("dst_port") or 443,
        "service": net.get("service") or "ssl",
    }
    if net.get("hostname"):
        evt["hostname"] = net["hostname"]
    if net.get("method"):
        evt["method"] = net["method"]
    if net.get("uri"):
        evt["uri"] = net["uri"]
    if technique:
        evt["technique"] = technique
    if description:
        evt["description"] = description
    return evt


def _build_payload_download_event(
    step: dict,
    net: dict,
    file_meta: dict,
    technique: str,
    description: str,
) -> dict:
    """A HTTP connection that downloads a payload to disk."""
    evt = {
        "type": "connection",
        "dst_ip": net["dst_ip"],
        "dst_port": net.get("dst_port") or 443,
        "service": net.get("service") or "ssl",
        "method": net.get("method") or "GET",
    }
    if net.get("hostname"):
        evt["hostname"] = net["hostname"]
    if net.get("uri"):
        evt["uri"] = net["uri"]
    else:
        # Derive a sensible URI from the file name if present
        if file_meta.get("file_name"):
            evt["uri"] = "/" + file_meta["file_name"]
    if file_meta.get("md5") or file_meta.get("sha256") or file_meta.get("file_name"):
        bits = []
        if file_meta.get("file_name"):
            bits.append(f"file={file_meta['file_name']}")
        if file_meta.get("md5"):
            bits.append(f"md5={file_meta['md5']}")
        if file_meta.get("sha256"):
            bits.append(f"sha256={file_meta['sha256']}")
        evt["description"] = " ".join(bits) + " " + (description or "")
    elif description:
        evt["description"] = description
    if technique:
        evt["technique"] = technique
    return evt


def _build_plugin_list_event(
    step: dict,
    net: dict,
    technique: str,
    description: str,
) -> dict:
    """C2 fetches a plugin manifest."""
    evt = {
        "type": "connection",
        "dst_ip": net["dst_ip"],
        "dst_port": net.get("dst_port") or 443,
        "service": net.get("service") or "ssl",
        "method": net.get("method") or "GET",
    }
    if net.get("hostname"):
        evt["hostname"] = net["hostname"]
    if net.get("uri"):
        evt["uri"] = net["uri"]
    if technique:
        evt["technique"] = technique
    if description:
        evt["description"] = description
    return evt


_PROCESS_OWNED_EVENT_FIELDS: dict[str, str] = {
    "connection": "source_process_ref",
    "beacon": "source_process_ref",
    "scheduled_task_created": "source_process_ref",
    "file_create": "process_ref",
    "file_delete": "process_ref",
    "registry_set": "process_ref",
    "registry_query": "process_ref",
    "image_load": "process_ref",
    "file_collection": "process_ref",
    "archive_create": "process_ref",
}


def _safe_ref_token(value: object) -> str:
    token = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(value or "")).strip("-").lower()
    return token[:40] or "step"


def _reported_file_paths(step: dict, os_cat: str) -> list[str]:
    """Return usable local paths from report file facts without preserving wildcards."""
    params = step.get("params") or {}
    raw_files = params.get("files") or []
    if isinstance(raw_files, dict):
        raw_files = [raw_files]
    paths: list[str] = []
    for raw_file in raw_files:
        if not isinstance(raw_file, dict):
            continue
        raw_path = str(raw_file.get("file_path") or "").strip()
        raw_name = str(raw_file.get("file_name") or "").strip()
        candidate = raw_path or raw_name
        if not candidate or "://" in candidate:
            continue
        basename = re.split(r"[\\/]", candidate)[-1]
        basename = re.sub(r"[^A-Za-z0-9._() -]+", "_", basename).strip(" ._")
        if not basename:
            continue
        if os_cat == "linux":
            path = candidate if candidate.startswith("/") else f"/tmp/{basename}"
            if re.match(r"^[A-Za-z]:\\", path):
                path = f"/tmp/{basename}"
        else:
            path = (
                candidate if re.match(r"^[A-Za-z]:\\", candidate) else rf"C:\ProgramData\{basename}"
            )
            if path.startswith("/"):
                path = rf"C:\ProgramData\{basename}"
        if "*" in path or path in paths:
            continue
        paths.append(path)
    return paths[:10]


def _inferred_owner_process(step: dict, os_cat: str) -> dict:
    """Create a clearly marked minimal anchor when the report omits ownership."""
    reported_process = extract_process_image(step, os_cat)
    process_name = reported_process or (
        "/usr/local/bin/report-unspecified" if os_cat == "linux" else "report-unspecified.exe"
    )
    if reported_process:
        degradation = (
            "[LEGACY_CONVERSION_DEGRADED] Same-step report process used as a synthetic "
            "ownership anchor because the legacy input has no explicit process-to-behavior relation."
        )
    else:
        degradation = (
            "[LEGACY_CONVERSION_DEGRADED] Synthetic victim-side process anchor: "
            "the legacy report step did not identify the owning process. This placeholder "
            "is simulation scaffolding and is not a report-disclosed executable or IOC."
        )
    event = {
        "type": "process",
        "process_name": process_name,
        "description": degradation,
    }
    command_line = extract_real_command(step, os_cat)
    if command_line:
        event["command_line"] = command_line
    return event


def _registry_operation(step: dict, registry: dict) -> str | None:
    """Classify an explicit same-step registry read/write operation."""
    tag = str(step.get("scene_tag") or "").strip().lower()
    if tag in {"bios_registry_query", "registry_query", "registry_read"}:
        return "query"
    if tag in {
        "registry_set",
        "registry_write",
        "registry_run_persistence",
        "registry_run_key_persistence",
        "persistence_registry_run",
    }:
        return "set"

    action_text = (
        " ".join(
            str(registry.get(key) or "") for key in ("operation", "action", "access", "access_type")
        )
        .strip()
        .lower()
    )
    command = extract_real_command(step, "windows").lower()
    text = f"{action_text} {command}".strip()
    read_match = bool(
        re.search(r"\b(query|read|get|enum|enumerate|inspect|check)\b", text)
        or any(token in text for token in ("查询", "读取", "枚举", "检查"))
    )
    write_match = bool(
        re.search(r"\b(set|write|add|create|modify|update)\b", text)
        or any(token in text for token in ("写入", "设置", "添加", "创建", "修改", "更新"))
    )
    if read_match == write_match:
        if "value_data" in registry and registry.get("value_data") is not None:
            return "set"
        return None
    return "query" if read_match else "set"


def _mark_legacy_degradation(events: list[dict], message: str) -> None:
    """Persist a conversion limitation in emitted data instead of hiding it."""
    if not events:
        return
    target = next((event for event in events if event.get("type") == "process"), events[0])
    marker = f"[LEGACY_CONVERSION_DEGRADED] {message}"
    existing = str(target.get("description") or "").strip()
    target["description"] = f"{existing} {marker}".strip()


def enrich_storyline_events(
    events: list[dict],
    step: dict,
    *,
    sequence: int,
    actor: str,
    system: str,
    os_cat: str,
    latest_process_by_system: dict[str, str],
    process_owners: dict[str, tuple[str, str]],
    referenced_processes: set[str],
) -> list[dict]:
    """Add process ownership and source-backed atomic evidence to one report step."""
    del latest_process_by_system
    enriched = [dict(event) for event in events]
    step_ref = _safe_ref_token(step.get("step_id") or step.get("name") or sequence)

    current_process_ref: str | None = None
    process_index = 0
    for event in enriched:
        if event.get("type") != "process":
            continue
        process_index += 1
        process_ref = event.get("process_ref") or f"proc-{sequence:03d}-{step_ref}-{process_index}"
        event["process_ref"] = process_ref
        process_owners[process_ref] = (actor, system)
        current_process_ref = process_ref

    needs_process_owner = any(
        event.get("type") in _PROCESS_OWNED_EVENT_FIELDS for event in enriched
    )
    if current_process_ref is None and needs_process_owner:
        owner = _inferred_owner_process(step, os_cat)
        current_process_ref = f"proc-{sequence:03d}-{step_ref}-owner"
        owner["process_ref"] = current_process_ref
        process_owners[current_process_ref] = (actor, system)
        enriched.insert(0, owner)

    if current_process_ref is not None:
        for event in enriched:
            field = _PROCESS_OWNED_EVENT_FIELDS.get(str(event.get("type") or ""))
            if field and not event.get(field):
                event[field] = current_process_ref
                referenced_processes.add(current_process_ref)

    phase = phase_for_step(step)
    action_type = str(step.get("action_type") or "").strip().lower()
    attack_mapping = _am_dict(step)
    technique_id = str(attack_mapping.get("technique_id") or "")
    searchable_text = " ".join(
        [
            str(step.get("scene_tag") or ""),
            str(step.get("name") or ""),
            str(step.get("description") or ""),
            technique_id,
        ]
    ).lower()
    file_paths = _reported_file_paths(step, os_cat)

    if current_process_ref is not None and file_paths:
        if phase == "collection":
            enriched.append(
                {
                    "type": "file_collection",
                    "process_ref": current_process_ref,
                    "files": file_paths,
                    "description": "Files explicitly listed by the report for this collection step.",
                }
            )
            referenced_processes.add(current_process_ref)
        elif action_type in {"email", "file_transfer"} or phase == "initial_access":
            for path in file_paths[:3]:
                enriched.append(
                    {
                        "type": "file_create",
                        "process_ref": current_process_ref,
                        "path": path,
                        "description": (
                            "Victim-side artifact materialized from a file fact in the source report."
                        ),
                    }
                )
            referenced_processes.add(current_process_ref)

        if technique_id.startswith("T1560") or any(
            token in searchable_text for token in ("archive", "compress", "zip", "rar")
        ):
            archive_path = next(
                (
                    path
                    for path in file_paths
                    if path.lower().endswith((".zip", ".rar", ".7z", ".tar", ".tar.gz", ".tgz"))
                ),
                None,
            )
            source_files = [path for path in file_paths if path != archive_path]
            if archive_path and source_files:
                enriched.append(
                    {
                        "type": "archive_create",
                        "process_ref": current_process_ref,
                        "source_files": source_files,
                        "archive_path": archive_path,
                        "size_bytes": stable_int(
                            f"archive-size:{sequence}:{step_ref}",
                            262_144,
                            8_388_608,
                        ),
                        "description": (
                            "Archive boundary built only from source-reported file paths."
                        ),
                    }
                )
                referenced_processes.add(current_process_ref)

        if technique_id.startswith("T1070.004") or any(
            token in searchable_text for token in ("self-delete", "self delete", "delete file")
        ):
            enriched.append(
                {
                    "type": "file_delete",
                    "process_ref": current_process_ref,
                    "path": file_paths[0],
                    "description": "File deletion explicitly described by the source report.",
                }
            )
            referenced_processes.add(current_process_ref)

        dll_path = next((path for path in file_paths if path.lower().endswith(".dll")), None)
        if dll_path and (
            technique_id.startswith(("T1574", "T1129", "T1620"))
            or any(token in searchable_text for token in ("dll", "module load", "sideload"))
        ):
            enriched.append(
                {
                    "type": "image_load",
                    "process_ref": current_process_ref,
                    "image_loaded": dll_path,
                    "signed": False,
                    "signature_status": "Unavailable",
                    "description": "Module load derived from the source report's DLL execution fact.",
                }
            )
            referenced_processes.add(current_process_ref)

    registry = (step.get("params") or {}).get("registry") or {}
    if current_process_ref is not None and isinstance(registry, dict) and registry.get("key"):
        operation = _registry_operation(step, registry)
        if operation == "query":
            query_event = {
                "type": "registry_query",
                "process_ref": current_process_ref,
                "key": str(registry["key"]),
                "description": "Registry read materialized from fields in the source report.",
            }
            value_name = str(registry.get("value_name") or registry.get("value") or "").strip()
            if value_name:
                query_event["value_name"] = value_name
            enriched.append(query_event)
            referenced_processes.add(current_process_ref)
        elif operation == "set":
            enriched.append(
                {
                    "type": "registry_set",
                    "process_ref": current_process_ref,
                    "key": str(registry["key"]),
                    "value_name": str(
                        registry.get("value_name") or registry.get("value") or "(Default)"
                    ),
                    "value_data": str(
                        registry.get("value_data")
                        or registry.get("description")
                        or extract_real_command(step, os_cat)
                        or ""
                    ),
                    "description": "Registry write materialized from fields in the source report.",
                }
            )
            referenced_processes.add(current_process_ref)
        else:
            _mark_legacy_degradation(
                enriched,
                "The registry key was reported without unambiguous read/write semantics; "
                "no precise registry event was emitted.",
            )

    return enriched


def finalize_process_lifecycles(
    storyline: list[dict],
    process_owners: dict[str, tuple[str, str]],
    referenced_processes: set[str],
) -> None:
    """Keep referenced processes alive and close each one after the final attack step."""
    if not referenced_processes:
        return

    for entry in storyline:
        for event in entry.get("events") or []:
            process_ref = event.get("process_ref")
            if event.get("type") == "process" and process_ref in referenced_processes:
                event["persistent"] = True
                event["supplementary"] = "none"

    last_minutes = max(
        (_relative_minutes(entry.get("time")) for entry in storyline),
        default=ATTACK_START_PADDING_MINUTES,
    )
    grouped: OrderedDict[tuple[str, str], list[str]] = OrderedDict()
    for process_ref in sorted(referenced_processes):
        owner = process_owners.get(process_ref)
        if owner is not None:
            grouped.setdefault(owner, []).append(process_ref)

    for group_index, ((actor, system), refs) in enumerate(grouped.items(), start=1):
        storyline.append(
            {
                "id": f"evt-lifecycle-close-{group_index:02d}",
                "time": _fmt_duration(last_minutes + group_index),
                "actor": actor,
                "on_behalf_of": actor,
                "system": system,
                "activity": "Close report-correlated process lifecycles",
                "events": [
                    {
                        "type": "process_terminate",
                        "process_ref": process_ref,
                        "description": "Close the final observable lifetime of this attack process.",
                    }
                    for process_ref in refs
                ],
            }
        )


# ---------------------------------------------------------------------------
# Quality rule 9: timeline (time offsets)
# ---------------------------------------------------------------------------


def step_time(stage: int, total: int, *, prelude_minutes: int = 0) -> str:
    """Spread steps across a realistic timeline — early steps close together,
    later steps spread out as the attacker takes more deliberate actions."""
    if total <= 0:
        return _fmt_duration(prelude_minutes + ATTACK_START_PADDING_MINUTES)
    # First attack step follows the visible benign prelude by 15 minutes, then
    # uses ~6 minute cadence for the first hour and ~30 minute cadence later.
    # ~30 minute cadence thereafter.
    minutes_offsets: list[int] = []
    t = prelude_minutes + ATTACK_START_PADDING_MINUTES
    attack_start = t
    for _ in range(total):
        minutes_offsets.append(t)
        t += 6 if t - attack_start < 60 else 30
    return _fmt_duration(minutes_offsets[stage - 1] if 1 <= stage <= total else t)


def _fmt_duration(minutes: int) -> str:
    if minutes < 60:
        return f"+{minutes}m"
    h, m = divmod(minutes, 60)
    return f"+{h}h{m}m" if m else f"+{h}h"


def _relative_minutes(value: object) -> int:
    """Parse a relative duration such as ``+2h15m`` into integer minutes."""
    if not isinstance(value, str) or not value.startswith("+"):
        raise ValueError(f"expected relative time, got {value!r}")
    body = value[1:]
    matches = re.findall(r"(\d+)([dhms])", body)
    if not matches or "".join(f"{amount}{unit}" for amount, unit in matches) != body:
        raise ValueError(f"invalid relative time: {value!r}")
    seconds = 0
    for amount, unit in matches:
        seconds += int(amount) * {"d": 86_400, "h": 3_600, "m": 60, "s": 1}[unit]
    return math.ceil(seconds / 60)


# ---------------------------------------------------------------------------
# Quality rule 10: scenario YAML emission
# ---------------------------------------------------------------------------


def filter_nonempty(d: dict) -> dict:
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


def slugify(name: str, meta: dict | None = None) -> str:
    m = re.match(r"^(\d{4})(\d{2})(\d{2})", name)
    if not m:
        m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", name)
    date = f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else ""
    apt_raw = (meta or {}).get("APT group") or ""
    if apt_raw:
        slug_core = re.sub(r"[^A-Za-z0-9]+", "-", apt_raw).strip("-").lower()
        if slug_core:
            return f"{date}-{slug_core}" if date else slug_core
    base = name.lower().replace(".json", "")
    if date and base.startswith(date):
        base = base[len(date) :].lstrip("-_ ")
    if not base:
        return date or "scenario"
    slug_core = re.sub(r"[^a-z0-9-]+", "-", base).strip("-")
    return f"{date}-{slug_core}" if date else slug_core


def disambiguate_slug(slug: str, json_path: Path, used: set[str]) -> str:
    """If the computed slug is already in use, append a short discriminator
    drawn from the JSON filename (e.g. ``-v2``, ``-mst-en``)."""
    if slug not in used:
        return slug
    stem = json_path.stem.lower()
    # Try to find a v1/v2 or part1/part2 marker in the filename. Use look-
    # arounds that tolerate the surrounding underscores / hyphens.
    mv = re.search(r"(?:^|[_\-])(v\d+|part\d+)(?:[_\-]|$)", stem)
    if mv:
        candidate = f"{slug}-{mv.group(1)}"
        if candidate not in used:
            return candidate
    # Try to find a Chinese/ASCII "v1/v2"-style suffix
    mv = re.search(r"(?:^|[_\-])([a-z]{1,4}\d{0,2})(?:[_\-]|$)", stem)
    if mv and len(mv.group(1)) >= 2:
        candidate = f"{slug}-{mv.group(1)}"
        if candidate not in used:
            return candidate
    # Fall back to a 4-char fingerprint of the path
    import hashlib

    h = hashlib.md5(str(json_path).encode("utf-8")).hexdigest()[:4]
    candidate = f"{slug}-{h}"
    return candidate


def parse_date_from_filename(path: Path) -> str:
    name = path.stem
    m = re.match(r"^(\d{4})(\d{2})(\d{2})", name)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}T10:00:00Z"
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", name)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}T10:00:00Z"
    return "2024-01-01T10:00:00Z"


def shift_time_window_start(attack_anchor: str, prelude_hours: int) -> str:
    """Move the visible window earlier while preserving the attack's absolute anchor."""
    anchor = datetime.fromisoformat(attack_anchor.replace("Z", "+00:00"))
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=UTC)
    shifted = anchor - timedelta(hours=prelude_hours)
    return shifted.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _yaml_dumper():
    class _Dumper(yaml.SafeDumper):
        pass

    def _repr_ordereddict(dumper, data):
        return dumper.represent_mapping("tag:yaml.org,2002:map", list(data.items()))

    _Dumper.add_representer(
        str,
        lambda d, v: d.represent_scalar(
            "tag:yaml.org,2002:str",
            v,
            style="|" if "\n" in v else None,
        ),
    )
    _Dumper.add_representer(OrderedDict, _repr_ordereddict)
    return _Dumper


def dump_yaml(obj, stream) -> None:
    yaml.dump(obj, stream, Dumper=_yaml_dumper(), allow_unicode=True, sort_keys=False, width=100)


def assess_source_quality(raw: dict, *, minimum_steps: int = 5) -> dict:
    """Assess whether report JSON has enough facts for honest deterministic compilation."""
    raw_steps = [step for step in (raw.get("steps") or []) if isinstance(step, dict)]
    unsupported_platform_steps = [step for step in raw_steps if not is_supported_source_step(step)]
    steps = [
        step
        for step in raw_steps
        if is_supported_source_step(step) and phase_for_step(step) != "__skip__"
    ]
    phase_names = {phase_for_step(step) for step in steps}
    normalized_mappings = [
        fix_technique_id(
            str(step.get("scene_tag") or "").strip().lower(),
            _am_dict(step),
        )
        for step in steps
    ]
    technique_count = sum(bool(mapping.get("technique_id")) for mapping in normalized_mappings)
    unsupported_technique_ids = sorted(
        {
            str(raw_mapping.get("technique_id") or "").upper()
            for step, raw_mapping, normalized_mapping in zip(
                steps,
                (_am_dict(step) for step in steps),
                normalized_mappings,
                strict=True,
            )
            if raw_mapping.get("technique_id") and not normalized_mapping.get("technique_id")
        }
    )
    parameterized_steps = 0
    observable_fact_count = 0
    campaign_network = collect_campaign_network_context(steps)
    renderable_steps: list[dict] = []

    for step in steps:
        os_cat = (
            "linux"
            if str(step.get("os") or "").lower() == "android"
            else str(step.get("os") or "windows").lower()
        )
        event = build_event(
            step,
            "quality.audit",
            WINDOWS_TARGET_HOST,
            "",
            os_cat,
            campaign_network,
        )
        if event:
            renderable_steps.append(step)
    renderable_phase_names = {phase_for_step(step) for step in renderable_steps}

    observable_keys = {
        "command",
        "commands",
        "email",
        "evidence",
        "files",
        "network",
        "persistence",
        "registry",
    }
    for step in steps:
        params = step.get("params") or {}
        if not isinstance(params, dict):
            continue
        has_observable_fact = any(params.get(key) for key in observable_keys)
        iocs = params.get("iocs") or {}
        has_ioc = isinstance(iocs, dict) and any(
            iocs.get(key) for key in ("domains", "hashes", "ips", "malware_names", "urls")
        )
        if has_observable_fact or has_ioc:
            parameterized_steps += 1
        observable_fact_count += sum(bool(params.get(key)) for key in observable_keys)
        observable_fact_count += int(has_ioc)

    step_count = len(steps)
    required_parameterized_steps = max(3, math.ceil(step_count * 0.4))
    technique_coverage = technique_count / step_count if step_count else 0.0
    reasons: list[str] = []
    if step_count < minimum_steps:
        reasons.append(f"only {step_count} report steps; minimum is {minimum_steps}")
    if len(phase_names) < 3:
        reasons.append(f"only {len(phase_names)} distinct kill-chain phases; minimum is 3")
    if len(renderable_steps) < minimum_steps:
        reasons.append(
            f"only {len(renderable_steps)} source-backed renderable steps; "
            f"minimum is {minimum_steps}"
        )
    if len(renderable_phase_names) < 3:
        reasons.append(
            f"only {len(renderable_phase_names)} renderable kill-chain phases; minimum is 3"
        )
    if technique_coverage < 0.75:
        reasons.append(f"ATT&CK technique coverage is {technique_coverage:.0%}; minimum is 75%")
    if parameterized_steps < required_parameterized_steps:
        reasons.append(
            f"only {parameterized_steps}/{step_count} steps contain observable facts; "
            f"minimum is {required_parameterized_steps}"
        )
    if observable_fact_count == 0:
        reasons.append("report has no command, file, network, registry, email, or IOC facts")
    if unsupported_platform_steps and not steps:
        platforms = sorted(
            {
                str(step.get("os") or "").strip().lower() or "(unspecified)"
                for step in unsupported_platform_steps
            }
        )
        reasons.append(
            "all report steps target unsupported endpoint platforms: " + ", ".join(platforms)
        )

    return {
        "eligible": not reasons,
        "reasons": reasons,
        "metrics": {
            "step_count": step_count,
            "phase_count": len(phase_names),
            "phases": sorted(phase_names),
            "technique_count": technique_count,
            "technique_coverage": round(technique_coverage, 4),
            "parameterized_steps": parameterized_steps,
            "required_parameterized_steps": required_parameterized_steps,
            "observable_fact_count": observable_fact_count,
            "renderable_step_count": len(renderable_steps),
            "renderable_phase_count": len(renderable_phase_names),
            "renderable_phases": sorted(renderable_phase_names),
            "campaign_network_source_available": bool(campaign_network),
            "unsupported_platform_step_count": len(unsupported_platform_steps),
            "unsupported_platforms": sorted(
                {
                    str(step.get("os") or "").strip().lower() or "(unspecified)"
                    for step in unsupported_platform_steps
                }
            ),
            "unsupported_enterprise_technique_ids": unsupported_technique_ids,
        },
    }


# ---------------------------------------------------------------------------
# Main convert function
# ---------------------------------------------------------------------------


def reorder_steps(steps: list[dict]) -> list[dict]:
    """Stable sort by phase index, then by original order."""
    decorated = []
    for idx, s in enumerate(steps):
        phase = phase_for_step(s)
        # __skip__ items bubble to the end but stay removable
        phase_idx = len(PHASE_ORDER) if phase == "__skip__" else PHASE_ORDER.index(phase)
        decorated.append((phase_idx, idx, s))
    decorated.sort()
    return [s for _, _, s in decorated]


def build_users_and_systems(
    meta: dict,
    scene_index: dict[int, dict],
    name_pool: list[str],
) -> tuple[list[dict], list[dict]]:
    """Build the environment.users and environment.systems blocks."""
    del meta
    expanded_names = list(dict.fromkeys([*name_pool, *NAMES_BY_REGION["GLOBAL"]]))
    while len(expanded_names) < 8:
        expanded_names.append(f"employee.{len(expanded_names) + 1:02d}")

    # Index 0 is reserved for external report narration. The next two names
    # must stay aligned with ``convert()`` and ``pick_actor_system_end()``.
    victim_name = expanded_names[1]
    linux_victim_name = expanded_names[2]
    extra_name_iter = iter(expanded_names[3:])

    users: list[dict] = []
    systems: list[dict] = []

    for _nid, n in scene_index.items():
        hostname = n["hostname"]
        role = n.get("role") or ("attacker" if "attacker" in (n.get("name") or "") else "victim")
        hostname_role_hint = re.search(r"(^|[-_.])(atk|attacker|c2)([-_.]|$)", hostname, re.I)
        if (
            role
            in {
                "attacker",
                "external_attacker",
                "c2",
                "c2_server",
                "c2_infra",
                "external",
            }
            or hostname_role_hint
        ):
            # ``environment.systems`` is the collected victim organization.
            # External infrastructure belongs in network_identities and event
            # source/destination fields; otherwise it receives baseline users,
            # domain auth, DNS registration, and legitimate admin traffic.
            continue

        assigned_actor: str | None = None
        if hostname == WINDOWS_TARGET_HOST:
            assigned_actor = victim_name
        elif hostname == LINUX_TARGET_HOST:
            assigned_actor = linux_victim_name
        elif n.get("type") == "workstation" or n.get("type") == "domain_controller":
            assigned_actor = next(extra_name_iter, None)

        if assigned_actor is not None:
            persona = str(n.get("persona") or "developer")
            users.append(
                filter_nonempty(
                    {
                        "username": assigned_actor,
                        "full_name": assigned_actor.replace(".", " ").title(),
                        "email": f"{assigned_actor}@example.local",
                        "persona": persona,
                        "primary_system": hostname,
                        "enabled": True,
                    }
                )
            )

        if hostname == LINUX_TARGET_HOST:
            actor = linux_victim_name
        elif hostname == WINDOWS_TARGET_HOST:
            actor = victim_name
        else:
            actor = assigned_actor
        systems.append(
            filter_nonempty(
                {
                    "hostname": hostname,
                    "ip": n["ip"],
                    "os": n["os_label"],
                    "type": n["type"],
                    "assigned_user": actor,
                    "services": n.get("services") or [],
                    "roles": n.get("roles") or [],
                }
            )
        )

    # Deduplicate users defensively if a source node reuses a generated actor.
    seen: set[str] = set()
    deduped: list[dict] = []
    for u in users:
        if u["username"] in seen:
            continue
        seen.add(u["username"])
        deduped.append(u)
    return deduped, systems


def collect_network_identities(steps: list[dict]) -> list[dict]:
    """One entry per unique source-reported external hostname.

    If a domain resolves to an IP that is also used by another domain in the
    same scenario, omit the IP from all but the first entry to avoid the
    "shared IP across identities" validator warning. The shared-IP case is
    legitimate when modeling virtual hosting/CDN, but for APT scenarios the
    safer default is one identity per IP.
    """
    host_ips: OrderedDict[str, str] = OrderedDict()
    for step in steps:
        network = extract_network(step)
        hostname = str(network.get("hostname") or "")
        ip = str(network.get("dst_ip") or "")
        if not hostname or not ip:
            continue
        existing_ip = host_ips.get(hostname)
        if existing_ip is None or (
            existing_ip == synthetic_external_ip(hostname) and ip != existing_ip
        ):
            host_ips[hostname] = ip

    out: list[dict] = []
    used_ips: set[str] = set()
    for hostname, ip in host_ips.items():
        entry: dict = {
            "id": hostname.replace(".", "_").replace("-", "_"),
            "hosts": [hostname],
            "tags": ["external"],
        }
        if ip not in used_ips:
            entry["ips"] = [ip]
            used_ips.add(ip)
        out.append(entry)
    return out


def build_segments(systems: list[dict]) -> list[dict]:
    """Derive one internal segment per unique /24 without duplicate CIDRs."""
    systems_by_cidr: OrderedDict[str, list[str]] = OrderedDict()
    for s in systems:
        ip = s["ip"]
        parts = ip.split(".")
        cidr = ".".join(parts[:3]) + ".0/24"
        systems_by_cidr.setdefault(cidr, []).append(s["hostname"])

    segments: list[dict] = []
    for cidr, hostnames in systems_by_cidr.items():
        cidr_prefix = cidr.split("/")[0].replace(".", "_")
        segments.append(
            {
                "name": f"seg_{cidr_prefix}",
                "cidr": cidr,
                "exposure": "internal",
                "systems": hostnames,
            }
        )
    return segments


def build_synthetic_logon_step(
    name: str,
    victim_name: str,
    system: str,
    time: str,
    os_cat: str,
) -> dict:
    """Prepend a synthetic interactive logon to anchor subsequent process events."""
    del os_cat
    logon_type = 2 if system == WINDOWS_TARGET_HOST else 10
    evt: dict = {
        "id": f"evt-{name[:8].replace('_', '-')}-logon",
        "time": time,
        "actor": victim_name,
        "on_behalf_of": victim_name,
        "system": system,
        "activity": f"{victim_name} opens an interactive session on {system}",
        "events": [{"type": "logon", "logon_type": logon_type}],
    }
    return evt


def convert(
    json_path: Path,
    out_root: Path,
    forced_name: str | None = None,
    auto_c2_server: bool = False,
    overwrite_existing: bool = False,
) -> Path:
    raw = json.loads(json_path.read_text(encoding="utf-8"))
    meta = raw.get("meta", {})
    scene_nodes = raw.get("scene_nodes", [])
    steps = [
        step
        for step in raw.get("steps", [])
        if isinstance(step, dict) and is_supported_source_step(step)
    ]

    name = forced_name or slugify(json_path.stem, meta=meta)
    prelude_hours = visible_prelude_hours(name)
    prelude_minutes = prelude_hours * 60
    scenario_dir = out_root / name
    if scenario_dir.exists() and any(scenario_dir.iterdir()) and not overwrite_existing:
        raise FileExistsError(
            f"{scenario_dir} already exists and is not empty; write to a staging "
            "directory or pass --overwrite-existing after reviewing the diff"
        )
    scenario_dir.mkdir(parents=True, exist_ok=True)

    name_pool = pick_name_pool(meta)
    scene_index = build_scene_index(scene_nodes)
    if auto_c2_server:
        scene_index = ensure_c2_server_node(scene_index, steps)
    users, systems = build_users_and_systems(meta, scene_index, name_pool)
    identities = collect_network_identities(steps)
    campaign_network = collect_campaign_network_context(steps)
    segments = build_segments(systems)
    # Minimal Zeek sensor so Zeek logs are actually generated
    has_linux = any(
        any(token in (s.get("os") or "").lower() for token in ("linux", "ubuntu", "debian"))
        for s in systems
    )
    sensor_block: dict = OrderedDict()
    sensor_block["sensors"] = [
        {
            "name": "network-sensor-01",
            "type": "network",
            "log_formats": ["zeek"],
            "monitoring_segments": [seg["name"] for seg in segments],
            "hostname": "SENSOR-NET-01",
        },
    ]

    # Resolve actor names for the roles we care about
    expanded_names = list(dict.fromkeys([*name_pool, *NAMES_BY_REGION["GLOBAL"]]))
    pool_iter = iter(expanded_names)
    attacker_name = next(pool_iter, "operator.alpha")
    victim_name = next(pool_iter, "victim.user")
    linux_victim_name = next(pool_iter, "victim.lnx")

    # ---- reorder steps by phase ----
    ordered = reorder_steps(steps)

    # ---- skip meta-only steps ----
    storyline: list[dict] = []
    ground_truth_rows: list[tuple[str, str, str, str]] = []
    latest_process_by_system: dict[str, str] = {}
    process_owners: dict[str, tuple[str, str]] = {}
    referenced_processes: set[str] = set()
    real_count = 0
    total = sum(1 for source_step in ordered if phase_for_step(source_step) != "__skip__")

    for step in ordered:
        if phase_for_step(step) == "__skip__":
            continue
        actor, system, c2_host = pick_actor_system_end(
            step,
            scene_index,
            name_pool,
            attacker_name,
            victim_name,
            linux_victim_name,
            campaign_network,
        )
        os_cat = (step.get("os") or "windows").lower()
        events = build_event(
            step,
            actor,
            system,
            c2_host,
            os_cat,
            campaign_network,
        )
        if events is None:
            continue
        if isinstance(events, dict):
            events = [events]
        if not events:
            continue
        real_count += 1
        events = enrich_storyline_events(
            events,
            step,
            sequence=real_count,
            actor=actor,
            system=system,
            os_cat=os_cat,
            latest_process_by_system=latest_process_by_system,
            process_owners=process_owners,
            referenced_processes=referenced_processes,
        )
        rel_time = step_time(real_count, total, prelude_minutes=prelude_minutes)
        evt_id = f"evt-{name[:8].replace('_', '-')}-{real_count:02d}"
        storyline_entry: dict = OrderedDict()
        storyline_entry["id"] = evt_id
        storyline_entry["time"] = rel_time
        storyline_entry["actor"] = actor
        # on_behalf_of defaults to actor; SYSTEM-owned processes (services,
        # scheduled tasks) can be overridden in YAML to disambiguate the
        # business actor from the process owner.
        storyline_entry["on_behalf_of"] = actor
        storyline_entry["system"] = system
        if c2_host and c2_host != system:
            # Annotate C2 traffic with the C2 endpoint; the system field stays
            # as the host where the action originated (the validator only
            # accepts registered system hostnames there).
            activity = step.get("name") or step.get("description") or ""
            storyline_entry["activity"] = f"{activity} → {c2_host}"
        else:
            storyline_entry["activity"] = step.get("name") or step.get("description") or ""
        storyline_entry["events"] = events
        storyline.append(storyline_entry)
        am = fix_technique_id(
            str(step.get("scene_tag") or "").strip().lower(),
            _am_dict(step),
        )
        tid = am.get("technique_id") or ""
        tactic = am.get("tactic") or am.get("tactic_name") or ""
        gt_label = f"{tid} ({tactic})" if tid else tactic
        ground_truth_rows.append((evt_id, rel_time, step.get("name") or "", gt_label))

    # Prepend synthetic logon only if the first story event is execution-related
    # and would otherwise lack a session anchor.
    needs_logon = (
        bool(storyline)
        and storyline[0]["events"][0]["type"]
        in {
            "process",
            "connection",
            "beacon",
            "dns_query",
        }
        and not any(e.get("type") == "logon" for e in storyline[0]["events"])
    )
    if needs_logon:
        first_system = storyline[0]["system"]
        first_actor = storyline[0]["actor"]
        logon = build_synthetic_logon_step(
            name,
            first_actor,
            first_system,
            _fmt_duration(prelude_minutes + 10),
            "windows" if first_system.startswith("WS-") else "linux",
        )
        storyline.insert(0, logon)

    finalize_process_lifecycles(storyline, process_owners, referenced_processes)

    description = (meta.get("description") or "").strip() or meta.get("report_name") or name

    env_block: dict = OrderedDict()
    env_block["description"] = meta.get("report_name") or name
    env_block["timezone"] = {"default": "UTC"}
    if users:
        env_block["users"] = users
    if systems:
        env_block["systems"] = systems
    if identities:
        env_block["network_identities"] = identities
    if segments:
        env_block["network"] = {"segments": segments, **sensor_block}

    scenario: dict = OrderedDict()
    scenario["version"] = "1.0"
    scenario["name"] = name
    scenario["description"] = description
    scenario["environment"] = env_block

    time_window: dict = OrderedDict()
    attack_anchor = parse_date_from_filename(json_path)
    time_window["start"] = shift_time_window_start(attack_anchor, prelude_hours)
    last_storyline_minute = max(
        (_relative_minutes(entry["time"]) for entry in storyline),
        default=prelude_minutes + ATTACK_START_PADDING_MINUTES,
    )
    post_prelude_hours = max(
        8,
        math.ceil((last_storyline_minute - prelude_minutes) / 60) + 2,
    )
    time_window["duration"] = f"{prelude_hours + post_prelude_hours}h"
    time_window["warmup"] = "4h"
    scenario["time_window"] = time_window

    baseline: dict = OrderedDict()
    baseline["description"] = (
        "Standard office activity for the target organization. EvidenceForge "
        "will synthesize plausible background noise across HTTP browsing, "
        "email, file shares, and service traffic. The attack storyline is "
        "modeled alongside this baseline and is correlated with the user, "
        "victim-side system, and external network identities defined in the "
        "environment block. The visible pre-attack baseline lasts "
        f"{prelude_hours} hours."
    )
    # The standard topology has eight assets and visible windows up to 72
    # hours. Low hourly density keeps the long baseline realistic and bounded;
    # corpus volume comes from duration and cross-host depth, not event floods.
    baseline["intensity"] = "low"
    baseline["variation"] = "medium"
    scenario["baseline_activity"] = baseline

    output: dict = OrderedDict()
    output_logs: list[dict] = [
        {"format": "windows"},
        {"format": "syslog"},
        {"format": "ecar"},
        {"format": "web_access"},
        {"format": "zeek"},
    ]
    if has_linux:
        output_logs.append({"format": "bash_history"})
    output["logs"] = output_logs
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
        f"**Source report:** {meta.get('report_name') or ''}",
        f"**APT group:** {meta.get('APT group') or ''}",
        f"**Target country:** {', '.join(meta.get('target country') or [])}",
        f"**Target industry:** {', '.join(meta.get('target industry') or [])}",
        f"**Malware families:** {', '.join(meta.get('malware_families') or []) or '_(none disclosed)_'}",
        f"**Vulnerabilities:** {', '.join(meta.get('vulnerabilities') or []) or '_(none disclosed)_'}",
        "**References:**",
    ]
    for ref in meta.get("references") or []:
        gt_lines.append(f"  - {ref}")
    gt_lines += [
        "",
        f"**Description:** {description}",
        "",
        "## Quality Notes",
        "",
        "- Storyline events are reordered by MITRE ATT&CK kill-chain phase "
        "(recon → initial access → execution → defense evasion → discovery → "
        "persistence → C2 setup → C2 communication → collection → "
        "exfiltration → cleanup) so prerequisites precede their effects.",
        "- Actor and system fields use realistic first.last handles aligned to "
        "the target country, not generic `attacker` / `victim.user`.",
        "- C2-traffic steps use only source-reported campaign domains or IPs. "
        "A reported domain without a historical DNS answer receives a stable "
        "RFC 5737 simulation address; missing/redacted domains are not replaced "
        "with invented C2 names.",
        "- Real parameters from the source JSON (MD5, SHA256, URLs, registry "
        "paths, scheduled task names, command lines) are pushed into typed "
        "event fields rather than left in the description text.",
        "",
        "## Attack Timeline",
        "",
        "| # | Event ID | Time | Activity | MITRE Technique |",
        "|---|----------|------|----------|-----------------|",
    ]
    for i, (eid, t, name_, mitre) in enumerate(ground_truth_rows, start=1):

        def esc(s: str) -> str:
            return s.replace("|", "\\|")

        gt_lines.append(f"| {i} | `{esc(eid)}` | `{esc(t)}` | {esc(name_)} | {esc(mitre)} |")
    gt_lines += [
        "",
        "## Source Mapping Notes",
        "",
        "- Each story step was mapped from a source JSON `steps[].scene_tag` to an "
        "EvidenceForge typed event. The full mapping rules are documented in "
        "`scripts/regenerate_apt_scenarios.py` and `docs/worklog/`.",
        "- Empty source fields (`sender`, `subject`, attachment, destination, "
        "etc.) remain absent. A step that cannot produce source-backed host or "
        "network evidence is omitted instead of receiving placeholder IOCs.",
        f"- Source steps compiled into typed attack entries: {real_count}/{total}.",
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
        default=Path("scenarios-v2"),
        help="Output directory (default: scenarios-v2/)",
    )
    p.add_argument(
        "--auto-c2-server",
        action="store_true",
        default=False,
        help=(
            "Deprecated compatibility option. C2 infrastructure is always "
            "modeled as external network identities and is never injected "
            "into the victim organization's systems or baseline."
        ),
    )
    p.add_argument(
        "--overwrite-existing",
        action="store_true",
        default=False,
        help=(
            "Allow replacement of files in an existing scenario directory. "
            "Off by default to protect manually curated scenarios."
        ),
    )
    p.add_argument(
        "--minimum-source-steps",
        type=int,
        default=5,
        help="Discard reports with fewer than this many source steps (default: 5).",
    )
    p.add_argument(
        "--no-quality-gate",
        action="store_true",
        default=False,
        help="Compile reports even when source-fact quality gates fail.",
    )
    p.add_argument(
        "--exclude-name",
        action="append",
        default=[],
        help="Do not compile this resolved scenario slug. Repeatable.",
    )
    p.add_argument(
        "--quality-report",
        type=Path,
        default=None,
        help="Quality decision JSON path (default: <out>/SOURCE_QUALITY_REPORT.json).",
    )
    args = p.parse_args()

    out_root: Path = args.out
    out_root.mkdir(parents=True, exist_ok=True)

    # Pre-compute slugs and disambiguate across the whole batch so two reports
    # with the same date+APT group do not overwrite each other.
    used_slugs: set[str] = set()
    plan: list[tuple[Path, str]] = []
    quality_rows: list[dict] = []
    excluded_names = set(args.exclude_name)
    failed = False
    for inp in args.inputs:
        if not inp.exists():
            print(f"!! not found: {inp}", file=sys.stderr)
            failed = True
            continue
        try:
            raw = json.loads(inp.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"!! invalid JSON {inp}: {e}", file=sys.stderr)
            failed = True
            continue
        if not isinstance(raw, dict) or "steps" not in raw:
            print(f"!! skipping {inp} (no steps[])", file=sys.stderr)
            failed = True
            continue
        slug = slugify(inp.stem, meta=raw.get("meta", {}))
        slug = disambiguate_slug(slug, inp, used_slugs)
        used_slugs.add(slug)
        assessment = assess_source_quality(raw, minimum_steps=args.minimum_source_steps)
        source_eligible = bool(assessment["eligible"])
        quality_row = {
            "scenario": slug,
            "source": str(inp),
            "source_eligible": source_eligible,
            **assessment,
        }
        if slug in excluded_names:
            quality_row["eligible"] = False
            quality_row["decision"] = "protected_curated"
            quality_row["reasons"] = [
                *quality_row["reasons"],
                "excluded because a manually curated scenario with this name is protected",
            ]
        elif source_eligible or args.no_quality_gate:
            quality_row["decision"] = "accepted"
        else:
            quality_row["decision"] = "rejected_source_quality"
        quality_rows.append(quality_row)
        if slug in excluded_names or (not quality_row["eligible"] and not args.no_quality_gate):
            reason_text = "; ".join(quality_row["reasons"])
            print(f"  xx discarded {slug}: {reason_text}")
            continue
        plan.append((inp, slug))

    for inp, slug in plan:
        try:
            scenario_dir = convert(
                inp,
                out_root,
                forced_name=slug,
                auto_c2_server=args.auto_c2_server,
                overwrite_existing=args.overwrite_existing,
            )
        except Exception as e:
            print(f"!! failed on {inp}: {e}", file=sys.stderr)
            failed = True
            continue
        print(f"  -> {scenario_dir}/scenario.yaml")

    quality_report = args.quality_report or out_root / "SOURCE_QUALITY_REPORT.json"
    quality_report.parent.mkdir(parents=True, exist_ok=True)
    quality_report.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "minimum_source_steps": args.minimum_source_steps,
                "quality_gate_enabled": not args.no_quality_gate,
                "input_count": len(quality_rows),
                "accepted_count": sum(row["decision"] == "accepted" for row in quality_rows),
                "protected_curated_count": sum(
                    row["decision"] == "protected_curated" for row in quality_rows
                ),
                "rejected_source_quality_count": sum(
                    row["decision"] == "rejected_source_quality" for row in quality_rows
                ),
                "scenarios": quality_rows,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"  quality report: {quality_report}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
