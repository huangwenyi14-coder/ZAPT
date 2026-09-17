#!/usr/bin/env python3
"""Record-index-native detector with independent discovery and bounded expansion.

The detector consumes only an explicit allowlist from the public, label-free
``RECORD_INDEX.jsonl``.  Discovery engines run independently and contribute
anchors to a graph whose edges all have an identity and/or a time boundary.
It intentionally never propagates by PID alone or by a host-wide time window.
"""

from __future__ import annotations

import ipaddress
import math
import re
import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote_plus, urlsplit

UTC = timezone.utc  # noqa: UP017 - detector remains executable on system Python 3.10

DETECTOR_VERSION = "1.5"
DETECTOR_NAME = "record_index_bounded_graph_detector"

TICK_DEDUP_SECONDS = 8.0
MIN_PERIOD_SECONDS = 20.0
MAX_PERIOD_SECONDS = 4 * 60 * 60.0
TUPLE_TIME_SECONDS = 3.0
DNS_TO_CONNECT_SECONDS = 120.0
PROXY_BRIDGE_SECONDS = 5.0
PROXY_DNS_SECONDS = 30.0
PROCESS_TERMINATION_EMITTER_SKEW_SECONDS = 5.0
PROCESS_INITIAL_MODULE_WINDOW_SECONDS = 5.0
PROCESS_FALLBACK_LIFETIME_SECONDS = 8 * 60 * 60.0
ARTIFACT_TO_EXECUTION_SECONDS = 4 * 60 * 60.0
ARTIFACT_EMISSION_SECONDS = 5 * 60.0
IDENTITY_FANOUT_SECONDS = 5.0
RDP_TO_LATERAL_SECONDS = 2 * 60 * 60.0
ONE_SHOT_PROCESS_WINDOW_SECONDS = 60 * 60.0
ACTIVE_CONTENT_FOLLOWUP_SECONDS = 10 * 60.0
TACTIC_PROCESS_CONTEXT_SECONDS = 10 * 60.0
TACTIC_NETWORK_TRANSACTION_SECONDS = 30.0
PROXY_PORTS = {3128, 8000, 8080, 8888}

# Public fields that may be consumed by the detector.  Unknown fields are
# discarded before feature extraction so future sidecar additions cannot
# silently become labels or unreviewed correlation shortcuts.
SOURCE_FIELD_ALLOWLIST: dict[str, frozenset[str]] = {
    "ecar": frozenset(
        {
            "action",
            "actorID",
            "hostname",
            "id",
            "object",
            "objectID",
            "pid",
            "ppid",
            "principal",
            "properties",
            "tid",
        }
    ),
    "windows_event_sysmon": frozenset(
        {"channel", "computer", "event_data", "event_id", "event_record_id", "provider"}
    ),
    "windows_event_security": frozenset(
        {"channel", "computer", "event_data", "event_id", "event_record_id", "provider"}
    ),
    "zeek_conn": frozenset(
        {
            "conn_state",
            "id.orig_h",
            "id.orig_p",
            "id.resp_h",
            "id.resp_p",
            "proto",
            "service",
            "uid",
        }
    ),
    "zeek_dns": frozenset(
        {
            "answers",
            "id.orig_h",
            "id.orig_p",
            "id.resp_h",
            "id.resp_p",
            "proto",
            "qtype_name",
            "query",
            "rcode_name",
            "trans_id",
            "uid",
        }
    ),
    "zeek_http": frozenset(
        {
            "host",
            "id.orig_h",
            "id.orig_p",
            "id.resp_h",
            "id.resp_p",
            "method",
            "resp_fuids",
            "status_code",
            "trans_depth",
            "uid",
            "uri",
            "user_agent",
        }
    ),
    "zeek_ssl": frozenset(
        {
            "cert_chain_fuids",
            "id.orig_h",
            "id.orig_p",
            "id.resp_h",
            "id.resp_p",
            "server_name",
            "uid",
        }
    ),
    "zeek_files": frozenset(
        {
            "conn_uids",
            "filename",
            "fuid",
            "md5",
            "mime_type",
            "rx_hosts",
            "sha1",
            "sha256",
            "tx_hosts",
        }
    ),
    "zeek_x509": frozenset(
        {"certificate.issuer", "certificate.serial", "certificate.subject", "fingerprint", "id"}
    ),
    "zeek_ocsp": frozenset(
        {"hashAlgorithm", "id", "issuerKeyHash", "issuerNameHash", "serialNumber"}
    ),
    "zeek_pe": frozenset({"compile_ts", "id", "machine"}),
    "zeek_dhcp": frozenset({"client_addr", "domain", "host_name", "mac", "server_addr"}),
    "zeek_ntp": frozenset(
        {"id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "mode", "ref_id", "stratum", "uid"}
    ),
    "cisco_asa": frozenset(
        {
            "connection_id",
            "dst_ip",
            "dst_port",
            "hostname",
            "msg_id",
            "pri",
            "severity",
            "src_ip",
            "src_port",
            "timestamp",
        }
    ),
    "proxy_access": frozenset(
        {
            "bytes_sent",
            "client_ip",
            "method",
            "protocol",
            "status_code",
            "target",
            "timestamp",
            "username",
        }
    ),
    "web_access": frozenset(
        {"bytes_sent", "client_ip", "method", "protocol", "status_code", "target", "timestamp"}
    ),
    "snort_alert": frozenset(
        {"dst_ip", "dst_port", "gid", "protocol", "rev", "sid", "src_ip", "src_port", "timestamp"}
    ),
    "bash_history": frozenset({"command", "history_timestamp", "hostname", "username"}),
    "syslog": frozenset({"app_name", "hostname", "pri", "procid", "timestamp"}),
}

NESTED_FIELD_ALLOWLIST: dict[tuple[str, str], frozenset[str]] = {
    ("ecar", "properties"): frozenset(
        {
            "command_line",
            "dst_ip",
            "dst_port",
            "file_path",
            "file_hash",
            "hashes",
            "image_path",
            "logon_id",
            "module_path",
            "parent_image_path",
            "protocol",
            "session_id",
            "signature",
            "signature_status",
            "signed",
            "src_ip",
            "src_pid",
            "src_port",
            "source_image_path",
            "target_pid",
            "target_image_path",
            "target_process_uuid",
        }
    ),
    ("windows_event_sysmon", "event_data"): frozenset(
        {
            "CommandLine",
            "Company",
            "Description",
            "DestinationIp",
            "DestinationPort",
            "FileVersion",
            "GrantedAccess",
            "Hashes",
            "Image",
            "ImageLoaded",
            "LogonGuid",
            "LogonId",
            "OriginalFileName",
            "ParentCommandLine",
            "ParentImage",
            "ParentProcessGuid",
            "ParentProcessId",
            "ProcessGuid",
            "ProcessId",
            "Protocol",
            "QueryName",
            "QueryResults",
            "Signature",
            "SignatureStatus",
            "Signed",
            "SourceIp",
            "SourceImage",
            "SourcePort",
            "SourceProcessGuid",
            "SourceProcessId",
            "TargetFilename",
            "TargetObject",
            "Details",
            "TargetImage",
            "TargetProcessGuid",
            "TargetProcessId",
            "User",
        }
    ),
    ("windows_event_security", "event_data"): frozenset(
        {
            "AuthenticationPackageName",
            "Application",
            "ClientProcessId",
            "CommandLine",
            "CreatorProcessName",
            "DestAddress",
            "DestPort",
            "Direction",
            "FQDN",
            "FilterRTID",
            "IpAddress",
            "IpPort",
            "LayerName",
            "LayerRTID",
            "LogonGuid",
            "LogonType",
            "MandatoryLabel",
            "NewProcessId",
            "NewProcessName",
            "ParentProcessId",
            "ParentProcessName",
            "ProcessID",
            "ProcessId",
            "ProcessName",
            "Protocol",
            "RemoteMachineID",
            "RemoteUserID",
            "RpcCallClientLocality",
            "SourceAddress",
            "SourceIp",
            "SourcePort",
            "DestinationAddress",
            "DestinationIp",
            "DestinationPort",
            "SubjectDomainName",
            "SubjectLogonId",
            "SubjectUserName",
            "SubjectUserSid",
            "TargetDomainName",
            "TargetLogonId",
            "TargetUserName",
            "TargetUserSid",
            "TaskContent",
            "TaskName",
            "TokenElevationType",
            "WorkstationName",
        }
    ),
}

# Canonical Security audit roles keyed by EventID.  These aliases prevent the
# overloaded Windows field names from being interpreted generically: in 4688
# ``ProcessId`` is the creator/parent while ``NewProcessId`` is the new child;
# in 5156 the process field is spelled ``ProcessID`` and the destination fields
# are ``DestAddress``/``DestPort``.
SECURITY_EVENT_FIELD_MAP: dict[int, dict[str, tuple[str, ...]]] = {
    4624: {
        "process_id": ("ProcessId",),
        "image": ("ProcessName",),
        "source_ip": ("IpAddress",),
        "source_port": ("IpPort",),
    },
    4688: {
        "process_id": ("NewProcessId",),
        "parent_process_id": ("ProcessId",),
        "image": ("NewProcessName",),
        "parent_image": ("ParentProcessName", "CreatorProcessName"),
        "command": ("CommandLine",),
    },
    4689: {
        "process_id": ("ProcessId",),
        "image": ("ProcessName",),
    },
    4698: {
        "task_name": ("TaskName",),
        "task_content": ("TaskContent",),
        "process_id": ("ClientProcessId",),
        "parent_process_id": ("ParentProcessId",),
    },
    5156: {
        "process_id": ("ProcessID",),
        "image": ("Application",),
        "direction": ("Direction",),
        "source_ip": ("SourceAddress",),
        "source_port": ("SourcePort",),
        "destination_ip": ("DestAddress",),
        "destination_port": ("DestPort",),
        "protocol": ("Protocol",),
    },
}

NETWORK_SENSOR_FORMATS = {
    "cisco_asa",
    "snort_alert",
    "zeek_conn",
    "zeek_dns",
    "zeek_files",
    "zeek_http",
    "zeek_ntp",
    "zeek_ocsp",
    "zeek_pe",
    "zeek_ssl",
    "zeek_x509",
}

SYSTEM_PORTS = {53, 67, 68, 88, 123, 135, 137, 138, 139, 389, 445}
PRIVATE_KEYS = {
    "label",
    "labels",
    "ground_truth",
    "groundtruth",
    "storyline_id",
    "logical_event_id",
    "malicious",
    "is_malicious",
    "attack_step",
    "attack_id",
    "mitre_attack",
}

WEB_EXPLOIT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "GeoServer WFS property-name expression execution",
        re.compile(
            r"(?:valueReference|propertyName)\s*=.*?exec\s*\(\s*(?:java\.lang\.)?Runtime\.getRuntime\s*\(",
            re.I,
        ),
    ),
    ("JNDI lookup exploit request", re.compile(r"\$\{jndi:(?:ldap|rmi|dns|iiop):", re.I)),
    (
        "template expression command execution",
        re.compile(r"(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\()", re.I),
    ),
)

TERMINAL_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "MSHTA remote script execution",
        re.compile(r"\bmshta(?:\.exe)?\b.*https?://", re.I),
    ),
    (
        "rundll32 loads a payload from a user-writable path",
        re.compile(
            r"\brundll32(?:\.exe)?\b.*(?:\\Users\\|\\ProgramData\\|"
            r"\\Windows\\(?:Temp|Tasks)\\).+\.(?:dll|ocx|cpl|db|bin)\b",
            re.I,
        ),
    ),
    (
        "PowerShell hidden or bypassed launch of a LOLBin payload",
        re.compile(
            r"\bpowershell(?:\.exe)?\b"
            r"(?=.*(?:-w(?:indowstyle)?\s+hidden|-executionpolicy\s+bypass|-ep\s+bypass))"
            r"(?=.*(?:rundll32|regsvr32|mshta|wscript|cscript))",
            re.I,
        ),
    ),
    (
        "silent MSI installation from a user-writable path",
        re.compile(
            r"\bmsiexec(?:\.exe)?\b(?=.*(?:/i|-i)\s+[^\r\n]+(?:\\Downloads\\|\\Temp\\))"
            r"(?=.*(?:/q(?:n|uiet)?\b|-q(?:n|uiet)?\b))",
            re.I,
        ),
    ),
    (
        "credential hive export",
        re.compile(r"\breg(?:\.exe)?\s+save\s+(?:hklm\\)?(?:sam|system|security)\b", re.I),
    ),
    (
        "LSASS MiniDump through comsvcs",
        re.compile(r"\brundll32(?:\.exe)?\b.*\bcomsvcs(?:\.dll)?\b.*\bMiniDump\b", re.I),
    ),
    ("NTDS IFM export", re.compile(r"\bntdsutil(?:\.exe)?\b.*\bifm\b.*\bcreate\s+full\b", re.I)),
    (
        "portproxy persistence",
        re.compile(r"\bnetsh(?:\.exe)?\b.*\binterface\s+portproxy\s+add\b", re.I),
    ),
    (
        "browser credential database copy",
        re.compile(r"\bcopy\b.*\\(?:Chrome|Edge|Opera).*\\Login Data\b", re.I),
    ),
    (
        "certutil remote transfer",
        re.compile(r"\bcertutil(?:\.exe)?\b.*(?:-urlcache|-verifyctl).*https?://", re.I),
    ),
    (
        "certutil decode in writable directory",
        re.compile(
            r"\bcertutil(?:\.exe)?\b.*-decode\b.*(?:\\Users\\|\\ProgramData\\|"
            r"\\Windows\\Tasks\\|\\Temp\\|/tmp/)",
            re.I,
        ),
    ),
    (
        "PowerShell hidden network execution",
        re.compile(
            r"\bpowershell(?:\.exe)?\b(?=.*(?:-w(?:indowstyle)?\s+hidden|-nop\b))(?=.*(?:https?://|download(?:file|string)|invoke-webrequest|webclient))",
            re.I,
        ),
    ),
    (
        "PowerShell host reconnaissance chain",
        re.compile(r"\bpowershell(?:\.exe)?\b.*\bwhoami\b.*\bGet-ComputerInfo\b", re.I),
    ),
    (
        "scheduled task from writable directory",
        re.compile(
            r"\bschtasks(?:\.exe)?\b.*(?:^|\s)/create\b.*"
            r"(?:\\ProgramData\\|\\AppData\\|\\Windows\\Tasks\\|\\Temp\\|\\Users\\)",
            re.I,
        ),
    ),
    (
        "service from writable directory",
        re.compile(
            r"\bsc(?:\.exe)?\s+create\b.*(?:\\ProgramData\\|\\AppData\\|\\Temp\\|\\Users\\)", re.I
        ),
    ),
    (
        "script host from download or removable media",
        re.compile(
            r"\bwscript(?:\.exe)?\b.*(?:\\Downloads\\|[D-Z]:\\).+\.(?:vbs|js|jse|wsf)\b", re.I
        ),
    ),
    (
        "sensitive material archive",
        re.compile(r"\b(?:7z|rar|tar)(?:\.exe)?\b.*(?:ntds\.dit|\\SAM\b|KeePass|password)", re.I),
    ),
    (
        "OneDrive command-line archive exfiltration",
        re.compile(
            r"(?:^|[\\/\s\"'])One(?:\.exe)?\b"
            r"(?=.*(?:-c|--config)\s+\S*auth\.json\b)"
            r"(?=.*(?:-s|--source)\s+\S+\.rar\b)",
            re.I,
        ),
    ),
    ("removable-media SCIL compilation", re.compile(r"\bscilc(?:\.exe)?\b.*\s-f\s+[D-Z]:\\", re.I)),
)

TERMINAL_SEQUENCE_RULES: tuple[tuple[str, float, tuple[re.Pattern[str], ...]], ...] = (
    (
        "bounded Windows domain discovery sequence",
        10 * 60.0,
        (
            re.compile(r"\bwhoami(?:\.exe)?\b.*\s/all\b", re.I),
            re.compile(r"\bnet(?:\.exe)?\b.*\bgroup\b.*\bDomain Admins\b", re.I),
            re.compile(r"\bwmic(?:\.exe)?\b", re.I),
        ),
    ),
    (
        "bounded persistence cleanup sequence",
        10 * 60.0,
        (
            re.compile(r"\breg(?:\.exe)?\s+delete\b.*\\CLSID\\", re.I),
            re.compile(r"\btaskkill(?:\.exe)?\b.*\bexplorer(?:\.exe)?\b", re.I),
            re.compile(r"\b(?:del|erase|Remove-Item)\b.*\.bat\b", re.I),
        ),
    ),
    (
        "bounded certutil decode and archive extraction sequence",
        5 * 60.0,
        (
            re.compile(r"\bcertutil(?:\.exe)?\b.*-decode\b", re.I),
            re.compile(r"\b(?:tar|7z|rar)(?:\.exe)?\b.*(?:-x|-xf|\bx\b)", re.I),
        ),
    ),
)

IOC_PATTERN = re.compile(
    r"(?:^|[\\/\s\"'])(?:caddywiper|mimikatz|nanodump|rubeus|sharphound|secretsdump|"
    r"laZagne|procdump64|pwdump|gsecdump|winpeas)(?:64)?(?:\.exe)?(?:$|[\s\"'])",
    re.I,
)

ENDPOINT_COMMAND_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "bulk database export to a staged file",
        re.compile(
            r"\b(?:sqluldr|sqlplus)(?:\.exe)?\b"
            r"(?=.*\b(?:query\s*=|select\b))"
            r"(?=.*\bfile\s*=\s*\S+\.(?:csv|dat|txt))"
            r"(?=.*\b(?:rows\s*=\s*\d{6,}|text\s*=\s*csv|head\s*=\s*yes))",
            re.I,
        ),
    ),
    (
        "PowerShell password-store collection and archive",
        re.compile(
            r"\bpowershell(?:\.exe)?\b"
            r"(?=.*(?:PasswordVault|KeePass|Login Data))"
            r"(?=.*(?:-Archive\b|\.zip\b|Compress-Archive\b))",
            re.I,
        ),
    ),
    (
        "batch execution from removable media",
        re.compile(r"\bcmd(?:\.exe)?\b.*(?:/c|/k)\s+[\"']?[d-z]:\\.+\.(?:bat|cmd)\b", re.I),
    ),
    (
        "writable-directory batch loads a DLL or executable",
        re.compile(
            r"\bcmd(?:\.exe)?\b"
            r"(?=.*(?:\\ProgramData\\|\\Windows\\Tasks\\).+\.(?:bat|cmd)\b)"
            r"(?=.*(?:\\ProgramData\\|\\Windows\\Tasks\\).+\.(?:dll|exe)\b)",
            re.I,
        ),
    ),
    (
        "downloaded artifact copied into Windows Tasks",
        re.compile(r"\bcopy\b.*\\Downloads\\.*\\Windows\\Tasks\\", re.I),
    ),
    (
        "staged data archived by a writable-directory archiver",
        re.compile(
            r"(?:^|[\\/\s\"'])(?:[a-z]:\\(?:ProgramData|Windows\\Temp)\\[^\s\"']*\\)?"
            r"(?:rar|7z|tar)(?:\.exe)?\b"
            r"(?=.*\\(?:staging|temp)\\)"
            r"(?=.*\.(?:csv|db|sql|dat|txt)\b)",
            re.I,
        ),
    ),
    (
        "forced cleanup of staged data and its archive",
        re.compile(
            r"\bcmd(?:\.exe)?\b.*\b(?:del|erase)\b(?=.*(?:/f|/q))"
            r"(?=.*\.(?:csv|db|sql|dat|txt)\b)(?=.*\.(?:rar|7z|zip)\b)",
            re.I,
        ),
    ),
)

WEB_SHELL_TASKING_RE = re.compile(
    r"/(?:manager|upload|temp|admin|images?)/[^?\s]+\.(?:aspx|ashx|jsp|php)(?:[?\s]|$)",
    re.I,
)
ARCHIVE_COMMAND_RE = re.compile(r"\b(?:rar|7z|tar)(?:\.exe)?\b", re.I)
HIGH_RISK_ARTIFACT_PRODUCER_RE = re.compile(
    r"(?:\bntdsutil(?:\.exe)?\b.*\bcreate\s+full\b|"
    r"\breg(?:\.exe)?\s+save\s+(?:hklm\\)?(?:sam|system|security)\b|"
    r"\b(?:sqluldr|sqlplus)(?:\.exe)?\b.*\bfile\s*=)",
    re.I,
)

SHARED_CLIENT_PROCESS_RE = re.compile(
    r"\\(?:firefox|chrome|msedge|iexplore|outlook|teams|slack)\.exe$", re.I
)

STORYLINE_TACTIC_NAMES = frozenset(
    {
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact",
    }
)


def _canonical_host(value: Any) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    if not text:
        return ""
    try:
        ipaddress.ip_address(text)
        return text
    except ValueError:
        return text.split(".", 1)[0]


def _scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value).lower()
    return str(value).strip()


def _values(value: Any) -> set[str]:
    if isinstance(value, (list, tuple, set)):
        return {_scalar(item) for item in value if _scalar(item)}
    item = _scalar(value)
    return {item} if item else set()


def _int_text(value: Any) -> str:
    text = _scalar(value)
    if not text:
        return ""
    try:
        return str(int(text, 0))
    except (ValueError, TypeError):
        try:
            return str(int(float(text)))
        except (ValueError, TypeError):
            return text.lower()


def _bool_value(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = _scalar(value).lower()
    if text in {"true", "yes", "1"}:
        return True
    if text in {"false", "no", "0"}:
        return False
    return None


def _security_event_semantics(
    event_id: int | None, event_data: Mapping[str, Any]
) -> dict[str, str]:
    """Map one Security EventID's native fields to unambiguous public roles."""
    if event_id is None:
        return {}
    mapping = SECURITY_EVENT_FIELD_MAP.get(event_id, {})
    result: dict[str, str] = {}
    for role, field_names in mapping.items():
        for field_name in field_names:
            value = _scalar(event_data.get(field_name))
            if value:
                result[role] = value
                break
    return result


def _canonical_path(value: Any) -> str:
    return _scalar(value).strip("\"'").replace("/", "\\").rstrip(".,;)").lower()


def _path_basename(value: str) -> str:
    return _canonical_path(value).rsplit("\\", 1)[-1]


WRITABLE_EXECUTABLE_RE = re.compile(
    r"(?:\\windows\\(?:temp|tasks)\\|\\programdata\\|"
    r"\\users\\[^\\]+\\(?:downloads|appdata\\(?:local|roaming)(?:\\temp)?)\\|^[d-z]:\\)",
    re.I,
)
SERVICE_PARENT_RE = re.compile(r"\\services(?:\.exe)?$", re.I)
EXPLORER_PARENT_RE = re.compile(r"\\explorer(?:\.exe)?$", re.I)
OFFICE_PARENT_RE = re.compile(
    r"\\(?:winword|excel|powerpnt|outlook|msaccess|onenote)(?:\.exe)?$", re.I
)
LOLBIN_BASENAME_RE = re.compile(
    r"^(?:cmd|cscript|mshta|powershell|pwsh|regsvr32|rundll32|wscript)(?:\.exe)?$", re.I
)
SUSPICIOUS_LAUNCH_PARENT_RE = re.compile(
    r"\\(?:cmd|cscript|flashplayerplugin_[^\\]+|mshta|msiexec|powershell|pwsh|"
    r"regsvr32|rundll32|wscript)(?:\.exe)?$",
    re.I,
)
SYSTEM_LOOKALIKE_BASENAMES = {
    "csrss.exe",
    "dllhost.exe",
    "dwm.exe",
    "lsass.exe",
    "msfeedsync.exe",
    "services.exe",
    "sihost.exe",
    "smss.exe",
    "spoolsv.exe",
    "svchost.exe",
    "taskhostw.exe",
    "wininit.exe",
    "winlogon.exe",
}
DOUBLE_EXTENSION_RE = re.compile(
    r"\.(?:docm?|docx|gif|jpeg|jpg|pdf|png|pptm?|pptx|rtf|txt|xlsm?|xlsx|zip)"
    r"\.(?:bat|cmd|com|exe|hta|js|jse|scr|vbs|vbe|wsf)$",
    re.I,
)
DOWNLOAD_LURE_TOKEN_RE = re.compile(
    r"\b(?:agenda|application|brief|configuration|document|invoice|notice|read[ -]?me|"
    r"report|resume|settings)\b",
    re.I,
)
LEGACY_FLASH_HANDLER_RE = re.compile(r"^flashplayer(?:plugin)?(?:_[0-9_]+)?\.exe$", re.I)
CONNECTIVITY_PROBE_RE = re.compile(
    r"(?:^|\.)(?:wikipedia\.org|msftconnecttest\.com|connectivitycheck\.gstatic\.com|"
    r"captive\.apple\.com|detectportal\.firefox\.com|icanhazip\.com|ifconfig\.me|"
    r"api\.ipify\.org|checkip\.amazonaws\.com)$|/generate_204(?:\?|$)",
    re.I,
)
CREDENTIAL_MATERIAL_RE = re.compile(
    r"(?:\bcredential|password store|login data|\blsass\b|\bntds(?:\.dit)?\b|"
    r"hklm\\sam|secretsdump|mimikatz)",
    re.I,
)
RISKY_LOLBIN_ARGUMENT_RE = re.compile(
    r"(?:https?://|javascript:|vbscript:|(?:\\Users\\|\\ProgramData\\|"
    r"\\Windows\\(?:Temp|Tasks)\\).+\.(?:dll|ocx|cpl|hta|js|jse|vbs|vbe|wsf|db|bin)\b|"
    r"-enc(?:odedcommand)?\b|-executionpolicy\s+bypass|-w(?:indowstyle)?\s+hidden)",
    re.I,
)
COMMON_MODULE_BASENAMES = {
    "advapi32.dll",
    "bcrypt.dll",
    "combase.dll",
    "gdi32.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "msvcp_win.dll",
    "msvcrt.dll",
    "ntdll.dll",
    "ole32.dll",
    "rpcrt4.dll",
    "sechost.dll",
    "ucrtbase.dll",
    "user32.dll",
    "vcruntime140.dll",
    "win32u.dll",
}
QUOTED_WINDOWS_PATH_RE = re.compile(r"[\"']([a-z]:\\[^\"']+)[\"']", re.I)
UNQUOTED_WINDOWS_PATH_RE = re.compile(r"(?<![\w])([a-z]:\\[^\s\"'=,;|&<>]+)", re.I)


def _windows_paths(value: str) -> set[str]:
    paths = {
        _canonical_path(match.group(1))
        for pattern in (QUOTED_WINDOWS_PATH_RE, UNQUOTED_WINDOWS_PATH_RE)
        for match in pattern.finditer(value or "")
    }
    return {path for path in paths if path and "\\" in path}


def _command_output_paths(command: str) -> set[str]:
    """Return explicit output/materialization paths from selected commands."""
    if not command:
        return set()
    paths: set[str] = set()
    value_pattern = r"(?:\"([^\"]+)\"|'([^']+)'|([a-z]:\\[^\s\"']+))"
    marker_patterns = (
        rf"(?:\s-o\s|--output\s+|-outfile\s+){value_pattern}",
        rf"\bbinpath\s*=\s*{value_pattern}",
        rf"\bfile\s*=\s*{value_pattern}",
        rf"\bcreate\s+full\s+{value_pattern}",
    )
    for pattern in marker_patterns:
        for match in re.finditer(pattern, command, re.I):
            value = next((item for item in match.groups() if item), "")
            if value:
                paths.add(_canonical_path(value))
    if re.search(r"\bcopy\b", command, re.I):
        command_paths = list(_windows_paths(command))
        if command_paths:
            # Copy destination is the final path in EvidenceForge command
            # templates. Keep only it; the input is not a materialization.
            ordered = sorted(command_paths, key=lambda path: command.lower().rfind(path.lower()))
            paths.add(ordered[-1])
    return {path for path in paths if path}


def _is_writable_executable(path: str) -> bool:
    canonical = _canonical_path(path)
    return bool(
        canonical
        and WRITABLE_EXECUTABLE_RE.search(canonical)
        and "\\microsoft\\windows defender\\" not in canonical
    )


def _has_double_extension(path: str) -> bool:
    return bool(DOUBLE_EXTENSION_RE.search(_canonical_path(path)))


def _looks_like_download_lure(path: str) -> bool:
    canonical = _canonical_path(path)
    if "\\downloads\\" not in canonical:
        return False
    basename = _path_basename(canonical).rsplit(".", 1)[0]
    words = re.findall(r"[a-z0-9]+", basename, re.I)
    return len(words) >= 5 and bool(DOWNLOAD_LURE_TOKEN_RE.search(basename))


def _active_content_lure_kind(image: str, command: str) -> str:
    """Return a narrow legacy active-content lure kind from public command fields."""
    image_basename = _path_basename(image)
    for path in _windows_paths(command):
        if "\\users\\" not in path or not any(
            marker in path
            for marker in ("\\downloads\\", "\\desktop\\", "\\appdata\\local\\temp\\")
        ):
            continue
        if path.endswith(".swf") and LEGACY_FLASH_HANDLER_RE.fullmatch(image_basename):
            return "swf"
        if path.endswith(".rtf") and image_basename in {"winword", "winword.exe"}:
            return "rtf"
    return ""


def _task_exec_parts(task_content: str) -> tuple[str, str]:
    command_match = re.search(r"<Command>\s*(.*?)\s*</Command>", task_content, re.I | re.S)
    arguments_match = re.search(r"<Arguments>\s*(.*?)\s*</Arguments>", task_content, re.I | re.S)
    return (
        _scalar(command_match.group(1)) if command_match else "",
        _scalar(arguments_match.group(1)) if arguments_match else "",
    )


def _short_task_repetition(task_content: str) -> bool:
    match = re.search(r"<Interval>PT(\d+)M</Interval>", task_content, re.I)
    return bool(match and 0 < int(match.group(1)) <= 30)


def _is_bare_execution(image: str, command: str) -> bool:
    canonical_image = _canonical_path(image)
    canonical_command = _canonical_path(command)
    return bool(
        canonical_image
        and canonical_command
        in {
            canonical_image,
            _path_basename(canonical_image),
        }
    )


def allowlisted_features(row: Mapping[str, Any]) -> dict[str, Any]:
    """Return a detached, shallow public view of a Record Index row."""
    source_format = str(row.get("source_format") or "")
    source = row.get("correlation_features")
    if not isinstance(source, Mapping):
        return {}
    result: dict[str, Any] = {}
    for key in SOURCE_FIELD_ALLOWLIST.get(source_format, frozenset()):
        if key not in source:
            continue
        value = source[key]
        nested_allowlist = NESTED_FIELD_ALLOWLIST.get((source_format, key))
        if nested_allowlist is not None:
            if isinstance(value, Mapping):
                result[key] = {
                    nested_key: value[nested_key]
                    for nested_key in nested_allowlist
                    if nested_key in value
                }
        elif isinstance(value, (str, int, float, bool, list, tuple)) or value is None:
            result[key] = value
    return result


def _parse_time(value: Any, year_hint: int) -> float | None:
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10**12:
            number /= 1000.0
        return number
    text = _scalar(value)
    if not text:
        return None
    try:
        # Windows event timestamps use 100 ns precision (seven fractional
        # digits), while Python 3.10 accepts at most microseconds.
        iso_text = re.sub(r"(\.\d{6})\d+(?=Z|[+-]\d\d:\d\d|$)", r"\1", text)
        parsed = datetime.fromisoformat(iso_text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.timestamp()
    except ValueError:
        pass
    for template in ("%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S", "%m/%d-%H:%M:%S.%f"):
        try:
            parsed = datetime.strptime(text, template)
            if "%Y" not in template:
                parsed = parsed.replace(year=year_hint)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.timestamp()
        except ValueError:
            continue
    return None


def _case_year(rows: Sequence[Mapping[str, Any]]) -> int:
    for row in rows:
        value = _scalar(row.get("observed_time"))
        match = re.search(r"\b(20\d\d)\b", value)
        if match:
            return int(match.group(1))
    return 1970


def _network_tuple(
    features: Mapping[str, Any], nested: Mapping[str, Any]
) -> tuple[str, int, str, int, str] | None:
    src = _scalar(
        features.get("id.orig_h")
        or features.get("src_ip")
        or nested.get("SourceIp")
        or nested.get("SourceAddress")
        or nested.get("src_ip")
    )
    dst = _scalar(
        features.get("id.resp_h")
        or features.get("dst_ip")
        or nested.get("DestinationIp")
        or nested.get("DestinationAddress")
        or nested.get("dst_ip")
    )
    src_port = _int_text(
        features.get("id.orig_p")
        or features.get("src_port")
        or nested.get("SourcePort")
        or nested.get("src_port")
    )
    dst_port = _int_text(
        features.get("id.resp_p")
        or features.get("dst_port")
        or nested.get("DestinationPort")
        or nested.get("dst_port")
    )
    proto = _scalar(
        features.get("proto")
        or features.get("protocol")
        or nested.get("Protocol")
        or nested.get("protocol")
    ).lower()
    if not (src and dst and src_port and dst_port):
        return None
    try:
        return (src, int(src_port), dst, int(dst_port), proto)
    except ValueError:
        return None


@dataclass
class Record:
    row: Mapping[str, Any]
    features: dict[str, Any]
    ts: float | None
    fmt: str
    physical_id: str
    host: str = ""
    event_id: int | None = None
    action: str = ""
    object_type: str = ""
    image: str = ""
    parent_image: str = ""
    target_image: str = ""
    command: str = ""
    text: str = ""
    file_path: str = ""
    module_path: str = ""
    hashes: set[str] = field(default_factory=set)
    signed: bool | None = None
    signature: str = ""
    signature_status: str = ""
    principal: str = ""
    source_ip: str = ""
    source_port: str = ""
    logon_ids: set[str] = field(default_factory=set)
    pid: str = ""
    parent_pid: str = ""
    stable_id: str = ""
    parent_stable_id: str = ""
    actor_stable_id: str = ""
    network: tuple[str, int, str, int, str] | None = None
    uids: set[str] = field(default_factory=set)
    fuids: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    dns_answers: set[str] = field(default_factory=set)
    asa_connection_ids: set[str] = field(default_factory=set)
    target_host: str = ""
    target_uri: str = ""
    application: str = ""
    direction: str = ""
    task_name: str = ""
    task_content: str = ""

    @property
    def is_process_create(self) -> bool:
        return (
            (self.fmt == "ecar" and self.object_type == "PROCESS" and self.action == "CREATE")
            or (self.fmt == "windows_event_sysmon" and self.event_id == 1)
            or (self.fmt == "windows_event_security" and self.event_id == 4688)
        )

    @property
    def is_process_terminate(self) -> bool:
        return (
            (self.fmt == "ecar" and self.object_type == "PROCESS" and self.action == "TERMINATE")
            or (self.fmt == "windows_event_sysmon" and self.event_id == 5)
            or (self.fmt == "windows_event_security" and self.event_id == 4689)
        )

    @property
    def is_file_write(self) -> bool:
        return (
            self.fmt == "ecar"
            and self.object_type == "FILE"
            and self.action in {"CREATE", "MODIFY"}
        ) or (self.fmt == "windows_event_sysmon" and self.event_id in {11, 15})

    @property
    def is_module_load(self) -> bool:
        return (self.fmt == "ecar" and self.object_type == "MODULE" and self.action == "LOAD") or (
            self.fmt == "windows_event_sysmon" and self.event_id == 7
        )

    @property
    def is_remote_thread(self) -> bool:
        return (
            self.fmt == "ecar" and self.object_type == "THREAD" and self.action == "CREATE"
        ) or (self.fmt == "windows_event_sysmon" and self.event_id == 8)

    @property
    def is_process_related(self) -> bool:
        if self.fmt == "ecar":
            return self.object_type in {"PROCESS", "FILE", "MODULE", "REGISTRY", "THREAD"}
        if self.fmt == "windows_event_sysmon":
            return self.event_id not in {3, 22}
        if self.fmt == "windows_event_security":
            return self.event_id in {4688, 4689, 4698}
        return self.fmt == "bash_history"


def normalize_records(rows: Sequence[Mapping[str, Any]]) -> list[Record]:
    year_hint = _case_year(rows)
    normalized: list[Record] = []
    for row in rows:
        fmt = _scalar(row.get("source_format"))
        features = allowlisted_features(row)
        nested_name = "properties" if fmt == "ecar" else "event_data"
        nested = features.get(nested_name)
        if not isinstance(nested, Mapping):
            nested = {}
        ts = _parse_time(row.get("observed_time"), year_hint)
        if ts is None:
            ts = _parse_time(
                features.get("timestamp") or features.get("history_timestamp"), year_hint
            )
        event_id_text = _int_text(features.get("event_id"))
        event_id = int(event_id_text) if event_id_text.isdigit() else None
        security_semantics = (
            _security_event_semantics(event_id, nested) if fmt == "windows_event_security" else {}
        )

        host = ""
        if fmt not in NETWORK_SENSOR_FORMATS:
            host = _canonical_host(
                features.get("hostname") or features.get("computer") or row.get("source_instance")
            )
        elif fmt in {"web_access", "proxy_access"}:
            host = _canonical_host(row.get("source_instance"))

        action = _scalar(features.get("action")).upper()
        object_type = _scalar(features.get("object")).upper()
        image = _scalar(
            security_semantics.get("image")
            or nested.get("image_path")
            or nested.get("Image")
            or nested.get("NewProcessName")
            or nested.get("SourceImage")
            or nested.get("source_image_path")
        )
        parent_image = _scalar(
            security_semantics.get("parent_image")
            or nested.get("parent_image_path")
            or nested.get("ParentImage")
        )
        target_image = _scalar(nested.get("target_image_path") or nested.get("TargetImage"))
        command = _scalar(
            security_semantics.get("command")
            or features.get("command")
            or nested.get("command_line")
            or nested.get("CommandLine")
        )
        file_path = _scalar(nested.get("file_path") or nested.get("TargetFilename"))
        module_path = _scalar(nested.get("module_path") or nested.get("ImageLoaded"))
        if object_type == "MODULE" and not module_path:
            module_path = file_path
        hash_values: set[str] = set()
        for hash_source in (
            nested.get("Hashes"),
            nested.get("hashes"),
            nested.get("file_hash"),
        ):
            for token in re.split(r"[,\s]+", _scalar(hash_source)):
                if token:
                    hash_values.add(token.lower())
        signed = _bool_value(nested.get("signed") if "signed" in nested else nested.get("Signed"))
        signature = _scalar(nested.get("signature") or nested.get("Signature"))
        signature_status = _scalar(nested.get("signature_status") or nested.get("SignatureStatus"))
        principal = _scalar(
            features.get("principal")
            or nested.get("TargetUserName")
            or nested.get("User")
            or nested.get("SubjectUserName")
        ).lower()

        pid = ""
        parent_pid = ""
        stable_id = ""
        parent_stable_id = ""
        actor_stable_id = ""
        if fmt == "ecar":
            pid = _int_text(features.get("pid"))
            parent_pid = _int_text(features.get("ppid"))
            if object_type == "PROCESS":
                stable_id = _scalar(features.get("objectID")).lower()
                actor_stable_id = _scalar(features.get("actorID")).lower()
                parent_stable_id = actor_stable_id if action == "CREATE" else ""
            else:
                stable_id = _scalar(features.get("actorID")).lower()
                actor_stable_id = stable_id
        elif fmt == "windows_event_sysmon":
            if event_id == 1:
                pid = _int_text(nested.get("ProcessId"))
                stable_id = _scalar(nested.get("ProcessGuid")).lower()
                parent_pid = _int_text(nested.get("ParentProcessId"))
                parent_stable_id = _scalar(nested.get("ParentProcessGuid")).lower()
            elif event_id in {3, 22}:
                pid = _int_text(nested.get("ProcessId") or nested.get("SourceProcessId"))
                stable_id = _scalar(
                    nested.get("ProcessGuid") or nested.get("SourceProcessGuid")
                ).lower()
            elif event_id == 10:
                pid = _int_text(nested.get("SourceProcessId"))
                stable_id = _scalar(nested.get("SourceProcessGuid")).lower()
            else:
                pid = _int_text(
                    nested.get("ProcessId")
                    or nested.get("SourceProcessId")
                    or nested.get("TargetProcessId")
                )
                stable_id = _scalar(
                    nested.get("ProcessGuid")
                    or nested.get("SourceProcessGuid")
                    or nested.get("TargetProcessGuid")
                ).lower()
        elif fmt == "windows_event_security":
            pid = _int_text(security_semantics.get("process_id"))
            parent_pid = _int_text(security_semantics.get("parent_process_id"))

        network_nested = dict(nested)
        if security_semantics:
            semantic_network_aliases = {
                "SourceIp": security_semantics.get("source_ip"),
                "SourcePort": security_semantics.get("source_port"),
                "DestinationIp": security_semantics.get("destination_ip"),
                "DestinationPort": security_semantics.get("destination_port"),
                "Protocol": security_semantics.get("protocol"),
            }
            for key, value in semantic_network_aliases.items():
                if value:
                    network_nested[key] = value
        network = _network_tuple(features, network_nested)
        source_ip = _scalar(
            security_semantics.get("source_ip")
            or nested.get("src_ip")
            or nested.get("SourceIp")
            or nested.get("SourceAddress")
            or nested.get("IpAddress")
        )
        source_port = _int_text(
            security_semantics.get("source_port")
            or nested.get("src_port")
            or nested.get("SourcePort")
            or nested.get("IpPort")
        )
        if network is not None:
            source_ip = source_ip or network[0]
            source_port = source_port or str(network[1])
        logon_ids = {
            _int_text(nested.get(key))
            for key in ("logon_id", "LogonId", "TargetLogonId", "SubjectLogonId")
            if _int_text(nested.get(key))
        }
        uids = set()
        for key in ("uid", "conn_uids"):
            uids.update(_values(features.get(key)))
        fuids = set()
        fuid_keys = ["fuid", "resp_fuids", "cert_chain_fuids"]
        if fmt in {"zeek_x509", "zeek_ocsp", "zeek_pe"}:
            fuid_keys.append("id")
        for key in fuid_keys:
            fuids.update(_values(features.get(key)))
        domains = {
            value.lower().rstrip(".")
            for key in ("query", "server_name", "host")
            for value in _values(features.get(key))
            if value
        }
        dns_answers = {value for value in _values(features.get("answers")) if _is_ip(value)}
        asa_connection_ids = _values(features.get("connection_id"))
        target_host, target_uri = _parse_target(_scalar(features.get("target")))
        application = _scalar(nested.get("Application"))
        direction = _scalar(security_semantics.get("direction") or nested.get("Direction"))
        task_name = _scalar(security_semantics.get("task_name") or nested.get("TaskName"))
        task_content = _scalar(security_semantics.get("task_content") or nested.get("TaskContent"))
        registry_target = _scalar(nested.get("TargetObject"))
        registry_details = _scalar(nested.get("Details"))
        if target_host:
            domains.add(target_host)

        text_parts: list[str] = [
            image,
            parent_image,
            target_image,
            command,
            file_path,
            module_path,
            application,
            direction,
            task_name,
            task_content,
            registry_target,
            registry_details,
            signature,
            signature_status,
        ]
        for key in ("target", "uri", "host", "query", "server_name", "filename", "app_name"):
            text_parts.extend(sorted(_values(features.get(key))))
        text = " ".join(part for part in text_parts if part)
        normalized.append(
            Record(
                row=row,
                features=features,
                ts=ts,
                fmt=fmt,
                physical_id=_scalar(row.get("physical_record_id")),
                host=host,
                event_id=event_id,
                action=action,
                object_type=object_type,
                image=image,
                parent_image=parent_image,
                target_image=target_image,
                command=command,
                text=text,
                file_path=file_path,
                module_path=module_path,
                hashes=hash_values,
                signed=signed,
                signature=signature,
                signature_status=signature_status,
                principal=principal,
                source_ip=source_ip,
                source_port=source_port,
                logon_ids=logon_ids,
                pid=pid,
                parent_pid=parent_pid,
                stable_id=stable_id,
                parent_stable_id=parent_stable_id,
                actor_stable_id=actor_stable_id,
                network=network,
                uids=uids,
                fuids=fuids,
                domains=domains,
                dns_answers=dns_answers,
                asa_connection_ids=asa_connection_ids,
                target_host=target_host,
                target_uri=target_uri,
                application=application,
                direction=direction,
                task_name=task_name,
                task_content=task_content,
            )
        )
    return normalized


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _parse_target(value: str) -> tuple[str, str]:
    if not value:
        return "", ""
    candidate = value if "://" in value else "//" + value
    parsed = urlsplit(candidate)
    host = (parsed.hostname or "").lower().rstrip(".")
    path = parsed.path or "/"
    return host, path


def _is_private_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        # ``ipaddress.is_private`` also classifies documentation ranges such
        # as 198.51.100.0/24 as non-global. EvidenceForge intentionally uses
        # those ranges as simulated Internet infrastructure, so only exclude
        # actual endpoint/internal ranges here.
        internal = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
            ipaddress.ip_network("fc00::/7"),
            ipaddress.ip_network("fe80::/10"),
            ipaddress.ip_network("::1/128"),
        )
        return any(address in network for network in internal if address.version == network.version)
    except ValueError:
        return False


def _domain_is_baseline(
    domain: str, baseline_domains: set[str], benign_tokens: Sequence[str]
) -> bool:
    lowered = domain.lower().rstrip(".")
    return (
        lowered in baseline_domains
        or any(lowered.endswith("." + item) for item in baseline_domains)
        or any(token.lower() in lowered for token in benign_tokens)
    )


def _dedup_times(records: Sequence[Record]) -> list[tuple[float, list[Record]]]:
    ticks: list[tuple[float, list[Record]]] = []
    for record in sorted(
        (item for item in records if item.ts is not None), key=lambda item: float(item.ts)
    ):
        timestamp = float(record.ts)
        if ticks and timestamp - ticks[-1][0] <= TICK_DEDUP_SECONDS:
            ticks[-1][1].append(record)
        else:
            ticks.append((timestamp, [record]))
    return ticks


def _robust_period(intervals: Sequence[float]) -> tuple[float, float, int] | None:
    """Fit one period against the complete deduplicated interval sequence.

    A missing callback may turn an interval into a small integer multiple of
    the base period, but every observed interval must still fit that same base
    period.  This prevents cherry-picking two or three convenient gaps from an
    otherwise irregular sequence and then labelling the whole destination.
    """
    observed = [float(item) for item in intervals if item >= MIN_PERIOD_SECONDS]
    if len(observed) < 4:
        return None

    candidates: set[float] = set()
    for interval in observed:
        max_multiple = min(64, max(1, int(interval // MIN_PERIOD_SECONDS)))
        for multiple in range(1, max_multiple + 1):
            candidate = interval / multiple
            if MIN_PERIOD_SECONDS <= candidate <= MAX_PERIOD_SECONDS:
                candidates.add(candidate)

    best: tuple[float, float, int, float] | None = None
    for candidate in candidates:
        minimum_intervals = 8 if candidate < 30 * 60 else 4
        if len(observed) < minimum_intervals:
            continue
        tolerance = 0.18 if candidate < 30 * 60 else 0.10
        normalized: list[float] = []
        direct_intervals = 0
        valid = True
        for interval in observed:
            multiple = max(1, round(interval / candidate))
            if multiple > 64:
                valid = False
                break
            expected = candidate * multiple
            if abs(interval - expected) > expected * tolerance:
                valid = False
                break
            normalized.append(interval / multiple)
            if multiple == 1:
                direct_intervals += 1
        if not valid or direct_intervals / len(observed) < 0.75:
            continue
        period = statistics.median(normalized)
        mean = statistics.mean(normalized)
        cv = statistics.pstdev(normalized) / mean if mean else math.inf
        max_cv = 0.18 if period < 30 * 60 else 0.10
        if cv > max_cv:
            continue
        direct_ratio = direct_intervals / len(observed)
        score = (cv, -direct_ratio, -len(observed), period)
        if best is None or score < (best[1], -best[3], -best[2], best[0]):
            best = (period, cv, len(observed), direct_ratio)
    if best is None:
        return None
    return best[0], best[1], best[2]


def discover_periodic(
    records: Sequence[Record],
    *,
    baseline_domains: set[str],
    baseline_ips: set[str],
    benign_tokens: Sequence[str],
) -> list[tuple[Record, str, float, str]]:
    groups: dict[tuple[str, str, int, str], list[Record]] = defaultdict(list)
    domain_by_endpoint: dict[tuple[str, str], set[str]] = defaultdict(set)
    for record in records:
        if record.network is None or record.fmt not in {"ecar", "zeek_conn"}:
            continue
        src, _src_port, dst, dst_port, proto = record.network
        if dst_port in SYSTEM_PORTS or _is_private_ip(dst) or dst in baseline_ips:
            continue
        groups[(src, dst, dst_port, proto)].append(record)
    for record in records:
        if record.fmt != "proxy_access" or not record.target_host:
            continue
        client_ip = _scalar(record.features.get("client_ip"))
        target_text = _scalar(record.features.get("target"))
        parsed = urlsplit(target_text if "://" in target_text else "//" + target_text)
        try:
            target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            continue
        groups[(client_ip, record.target_host, target_port, "proxy")].append(record)
    for record in records:
        if record.network is None:
            continue
        src, _sp, dst, _dp, _proto = record.network
        domain_by_endpoint[(src, dst)].update(record.domains)

    anchors: list[tuple[Record, str, float, str]] = []
    for key, members in groups.items():
        ticks = _dedup_times(members)
        if len(ticks) < 5:
            continue
        intervals = [ticks[index + 1][0] - ticks[index][0] for index in range(len(ticks) - 1)]
        fit = _robust_period(intervals)
        if fit is None:
            continue
        median, cv, inlier_count = fit
        src, dst, dst_port, proto = key
        domains = {dst} if proto == "proxy" else domain_by_endpoint.get((src, dst), set())
        if any(_domain_is_baseline(domain, baseline_domains, benign_tokens) for domain in domains):
            continue
        stability = 1.0 - min(cv, 1.0)
        confidence = min(0.995, 0.91 + 0.006 * min(inlier_count + 1, 12) + 0.03 * stability)
        context = f"adaptive beacon {median:.1f}s median, full-sequence CV={cv:.3f}, {inlier_count + 1} coherent callbacks/{len(ticks)} observed ticks, dst={dst}:{dst_port}/{proto}"
        if domains:
            context += ", name=" + ",".join(sorted(domains)[:3])
        if proto == "proxy":
            uri_shapes = sorted({member.target_uri for member in members if member.target_uri})
            if uri_shapes:
                context += ", URI=" + ",".join(uri_shapes[:3])
        for _timestamp, tick_members in ticks:
            for member in tick_members:
                anchors.append((member, context, confidence, "periodic_anchor"))
    return anchors


def discover_terminal(records: Sequence[Record]) -> list[tuple[Record, str, float, str]]:
    anchors_by_id: dict[str, tuple[Record, str, float, str]] = {}
    for record in records:
        if not (record.is_process_create or record.fmt == "bash_history"):
            continue
        text = unquote_plus(record.text)
        for name, pattern in TERMINAL_RULES:
            if pattern.search(text):
                anchors_by_id[record.physical_id] = (
                    record,
                    name,
                    0.995,
                    "terminal_anchor",
                )
                break

    by_host: dict[str, list[Record]] = defaultdict(list)
    for record in records:
        if (
            (record.is_process_create or record.fmt == "bash_history")
            and record.host
            and record.ts is not None
        ):
            by_host[record.host].append(record)
    for host_records in by_host.values():
        ordered = sorted(host_records, key=lambda item: float(item.ts or 0.0))
        for name, window_seconds, patterns in TERMINAL_SEQUENCE_RULES:
            for start_index, start_record in enumerate(ordered):
                if not patterns[0].search(unquote_plus(start_record.text)):
                    continue
                matched = [start_record]
                cursor = start_index + 1
                deadline = float(start_record.ts or 0.0) + window_seconds
                for pattern in patterns[1:]:
                    found: Record | None = None
                    while cursor < len(ordered):
                        candidate = ordered[cursor]
                        cursor += 1
                        if float(candidate.ts or 0.0) > deadline:
                            break
                        if pattern.search(unquote_plus(candidate.text)):
                            found = candidate
                            break
                    if found is None:
                        break
                    matched.append(found)
                if len(matched) != len(patterns):
                    continue
                for record in matched:
                    anchors_by_id.setdefault(
                        record.physical_id,
                        (record, name, 0.985, "terminal_sequence_anchor"),
                    )
    return list(anchors_by_id.values())


def discover_web(records: Sequence[Record]) -> list[tuple[Record, str, float, str]]:
    anchors: list[tuple[Record, str, float, str]] = []
    for record in records:
        if record.fmt not in {"web_access", "proxy_access", "zeek_http"}:
            continue
        text = unquote_plus(record.text)
        for name, pattern in WEB_EXPLOIT_PATTERNS:
            if pattern.search(text):
                anchors.append((record, name, 0.999, "web_exploit_anchor"))
                break
    return anchors


def discover_ioc(records: Sequence[Record]) -> list[tuple[Record, str, float, str]]:
    return [
        (record, "high-confidence tool or destructive payload IOC", 0.998, "ioc_anchor")
        for record in records
        if not record.is_process_terminate and IOC_PATTERN.search(record.text)
    ]


def discover_endpoint_behavior(
    records: Sequence[Record],
) -> list[tuple[Record, str, float, str]]:
    """Find high-confidence endpoint actions without relying on named payload IOCs."""
    anchors: list[tuple[Record, str, float, str]] = []
    for record in records:
        if not (record.is_process_create or record.fmt == "bash_history"):
            continue
        text = unquote_plus(record.text)
        for name, pattern in ENDPOINT_COMMAND_RULES:
            if pattern.search(text):
                anchors.append((record, name, 0.995, "endpoint_behavior_anchor"))
                break
    return anchors


def discover_process_anomaly(
    records: Sequence[Record],
) -> list[tuple[Record, str, float, str]]:
    """Use bounded process combinations, never a generic writable-path rule."""
    image_counts = Counter(
        _canonical_path(record.image)
        for record in records
        if record.is_process_create and record.image
    )
    activity_by_stable: dict[tuple[str, str], list[Record]] = defaultdict(list)
    activity_by_pid: dict[tuple[str, str], list[Record]] = defaultdict(list)
    for record in records:
        if record.host and record.stable_id:
            activity_by_stable[(record.host, record.stable_id)].append(record)
        if record.host and record.pid:
            activity_by_pid[(record.host, record.pid)].append(record)

    def has_rtf_exploit_followup(process: Record) -> bool:
        candidates: list[Record] = []
        if process.host and process.stable_id:
            candidates.extend(activity_by_stable[(process.host, process.stable_id)])
        if process.host and process.pid:
            candidates.extend(activity_by_pid[(process.host, process.pid)])
        for candidate in candidates:
            if (
                candidate.ts is None
                or process.ts is None
                or not 0.0
                < float(candidate.ts) - float(process.ts)
                <= ACTIVE_CONTENT_FOLLOWUP_SECONDS
                or not candidate.is_file_write
                or not candidate.file_path
            ):
                continue
            path = _canonical_path(candidate.file_path)
            same_image = bool(
                not process.image
                or not candidate.image
                or _canonical_path(process.image) == _canonical_path(candidate.image)
            )
            if (
                same_image
                and _is_writable_executable(path)
                and path.endswith((".dll", ".exe", ".com", ".scr"))
            ):
                return True
        return False

    anchors: list[tuple[Record, str, float, str]] = []
    for record in records:
        if not record.is_process_create or not record.image:
            continue
        image = _canonical_path(record.image)
        if not image.endswith((".exe", ".com", ".scr")):
            continue
        image_basename = _path_basename(image)
        rare = image_counts[image] <= 3
        writable = _is_writable_executable(image)
        bare = _is_bare_execution(record.image, record.command)
        service_parent = bool(SERVICE_PARENT_RE.search(record.parent_image))
        explorer_parent = bool(EXPLORER_PARENT_RE.search(record.parent_image))
        explorer_path_ok = bool(re.search(r"\\(?:programdata|windows\\tasks)\\", image, re.I))
        office_lolbin = bool(
            OFFICE_PARENT_RE.search(record.parent_image)
            and LOLBIN_BASENAME_RE.fullmatch(image_basename)
            and RISKY_LOLBIN_ARGUMENT_RE.search(record.command)
        )
        suspicious_parent = bool(SUSPICIOUS_LAUNCH_PARENT_RE.search(record.parent_image))
        active_content = (
            _active_content_lure_kind(record.image, record.command) if explorer_parent else ""
        )

        if active_content == "swf":
            anchors.append(
                (
                    record,
                    "legacy Flash handler opened an SWF lure from a user-writable directory",
                    0.995,
                    "active_content_swf_lure_anchor",
                )
            )
        elif active_content == "rtf" and has_rtf_exploit_followup(record):
            anchors.append(
                (
                    record,
                    "Word opened an RTF lure followed by an exact-process writable payload drop",
                    0.995,
                    "active_content_rtf_exploit_anchor",
                )
            )
        elif _has_double_extension(image):
            anchors.append(
                (
                    record,
                    "executable uses a document/archive double extension",
                    0.998,
                    "double_extension_process_anchor",
                )
            )
        elif office_lolbin:
            anchors.append(
                (
                    record,
                    "Office application launched a LOLBin with a remote or writable-path payload",
                    0.998,
                    "office_lolbin_process_anchor",
                )
            )
        elif rare and bare and explorer_parent and _looks_like_download_lure(image):
            anchors.append(
                (
                    record,
                    "rare long lure-like executable launched directly from Downloads",
                    0.985,
                    "download_lure_process_anchor",
                )
            )
        elif rare and writable and bare and image_basename in SYSTEM_LOOKALIKE_BASENAMES:
            anchors.append(
                (
                    record,
                    "rare system-lookalike executable launched from a user-writable path",
                    0.995,
                    "writable_system_lookalike_anchor",
                )
            )
        elif rare and writable and bare and suspicious_parent:
            anchors.append(
                (
                    record,
                    "rare bare writable-path executable launched by a LOLBin or installer",
                    0.985,
                    "writable_child_process_anchor",
                )
            )
        elif (
            rare
            and writable
            and bare
            and (service_parent or (explorer_parent and explorer_path_ok))
        ):
            parent_kind = "service" if service_parent else "interactive shell"
            anchors.append(
                (
                    record,
                    "rare bare executable from a writable path launched by " + parent_kind,
                    0.965,
                    "composite_process_anomaly_anchor",
                )
            )
    return anchors


def discover_scheduled_task(
    records: Sequence[Record],
) -> list[tuple[Record, str, float, str]]:
    """Detect Security 4698 tasks whose action and trigger form a strong signal."""
    anchors: list[tuple[Record, str, float, str]] = []
    user_task_path_re = re.compile(
        r"\\Users\\[^\\]+\\(?:Downloads|AppData\\(?:Local|Roaming)(?:\\Temp)?)\\|"
        r"\\Windows\\(?:Temp|Tasks)\\",
        re.I,
    )
    for record in records:
        if (
            record.fmt != "windows_event_security"
            or record.event_id != 4698
            or not record.task_content
        ):
            continue
        command, arguments = _task_exec_parts(record.task_content)
        action_text = f"{command} {arguments}".strip()
        command_path = _canonical_path(command)
        command_basename = _path_basename(command_path)
        user_writable = bool(user_task_path_re.search(action_text))
        lolbin_payload = bool(
            LOLBIN_BASENAME_RE.fullmatch(command_basename)
            and RISKY_LOLBIN_ARGUMENT_RE.search(action_text)
        )
        programdata_periodic = bool(
            "\\programdata\\" in _canonical_path(action_text)
            and _short_task_repetition(record.task_content)
        )
        if not (
            user_writable
            or lolbin_payload
            or programdata_periodic
            or _has_double_extension(command)
        ):
            continue
        reasons = []
        if user_writable:
            reasons.append("user-writable task action")
        if lolbin_payload:
            reasons.append("LOLBin task action")
        if programdata_periodic:
            reasons.append("short-period ProgramData action")
        if _has_double_extension(command):
            reasons.append("double-extension task action")
        anchors.append(
            (
                record,
                "suspicious Security 4698 scheduled task: " + ", ".join(reasons),
                0.995,
                "scheduled_task_action_anchor",
            )
        )
    return anchors


def discover_module_behavior(
    records: Sequence[Record],
) -> list[tuple[Record, str, float, str]]:
    """Detect explicit, public module-load evidence with conservative predicates."""
    suspicious_processes = {
        (record.host, record.stable_id, record.pid)
        for record, _reason, _confidence, _edge in discover_process_anomaly(records)
    }
    anchors: list[tuple[Record, str, float, str]] = []
    for record in records:
        if record.is_remote_thread:
            owner_is_suspicious = (
                record.host,
                record.stable_id,
                record.pid,
            ) in suspicious_processes
            if owner_is_suspicious or _is_writable_executable(record.image):
                anchors.append(
                    (
                        record,
                        "remote thread created by a composite-anomalous process instance",
                        0.995,
                        "remote_thread_anchor",
                    )
                )
            continue
        if not record.is_module_load or not record.module_path:
            continue
        module = _canonical_path(record.module_path)
        image = _canonical_path(record.image)
        module_basename = _path_basename(module)
        same_directory = bool(
            image
            and "\\" in image
            and "\\" in module
            and image.rsplit("\\", 1)[0] == module.rsplit("\\", 1)[0]
        )
        invalid_signature = record.signed is False or (
            bool(record.signature_status)
            and record.signature_status.lower() not in {"valid", "trusted"}
        )
        suspicious_side_load = (
            (record.host, record.stable_id, record.pid) in suspicious_processes
            and same_directory
            and _is_writable_executable(image)
            and module_basename not in COMMON_MODULE_BASENAMES
        )
        if (invalid_signature and _is_writable_executable(module)) or suspicious_side_load:
            reason = (
                "invalid or unsigned module loaded from a writable path"
                if invalid_signature
                else "non-system module side-loaded beside a writable-path executable"
            )
            anchors.append((record, reason, 0.995, "module_load_anchor"))
    return anchors


def discover_one_shot_network(
    records: Sequence[Record],
) -> list[tuple[Record, str, float, str]]:
    """Detect high-signal single transactions that do not have a beacon period."""
    anchors: list[tuple[Record, str, float, str]] = []
    for record in records:
        if record.fmt not in {"web_access", "proxy_access", "zeek_http"}:
            continue
        method = _scalar(record.features.get("method")).upper()
        target = _scalar(record.features.get("target") or record.features.get("uri"))
        if method == "POST" and WEB_SHELL_TASKING_RE.search(unquote_plus(target)):
            anchors.append(
                (
                    record,
                    "POST tasking to a script endpoint in a high-risk server directory",
                    0.99,
                    "one_shot_webshell_anchor",
                )
            )

    high_risk_processes: dict[str, Record] = {}
    for discovery in (
        discover_terminal(records),
        discover_endpoint_behavior(records),
        discover_process_anomaly(records),
    ):
        for process, _reason, _confidence, _edge in discovery:
            if process.is_process_create:
                high_risk_processes[process.physical_id] = process

    stable_instances = {
        (process.host, process.stable_id): process
        for process in high_risk_processes.values()
        if process.host and process.stable_id
    }
    pid_instances: dict[tuple[str, str], list[Record]] = defaultdict(list)
    for process in high_risk_processes.values():
        if process.host and process.pid and process.ts is not None:
            pid_instances[(process.host, process.pid)].append(process)

    candidate_flows = [
        record
        for record in records
        if record.network is not None
        and record.ts is not None
        and record.fmt in {"ecar", "windows_event_security", "windows_event_sysmon"}
        and not record.is_process_create
    ]
    group_counts = Counter(
        (
            record.host,
            record.stable_id or record.pid,
            record.network[2],
            record.network[3],
            record.network[4],
        )
        for record in candidate_flows
        if record.network is not None
    )
    for record in candidate_flows:
        if record.network is None:
            continue
        owner: Record | None = None
        if record.stable_id:
            owner = stable_instances.get((record.host, record.stable_id))
        if owner is None and record.pid:
            owner = next(
                (
                    process
                    for process in pid_instances.get((record.host, record.pid), ())
                    if process.ts is not None
                    and 0.0
                    <= float(record.ts) - float(process.ts)
                    <= ONE_SHOT_PROCESS_WINDOW_SECONDS
                ),
                None,
            )
        key = (
            record.host,
            record.stable_id or record.pid,
            record.network[2],
            record.network[3],
            record.network[4],
        )
        if owner is None or group_counts[key] > 2:
            continue
        anchors.append(
            (
                record,
                "one-shot network transaction owned by a high-confidence suspicious process",
                0.99,
                "one_shot_suspicious_process_flow_anchor",
            )
        )
    return anchors


def discover_auth_anomaly(
    records: Sequence[Record],
) -> list[tuple[Record, str, float, str]]:
    """Detect successful inbound RDP and its tightly joined lateral-auth continuation."""
    anchors_by_id: dict[str, tuple[Record, str, float, str]] = {}
    inbound = []
    for record in records:
        if record.network is None or record.ts is None:
            continue
        src, _src_port, dst, dst_port, _proto = record.network
        conn_state = _scalar(record.features.get("conn_state")).upper()
        if (
            dst_port == 3389
            and not _is_private_ip(src)
            and _is_private_ip(dst)
            and conn_state not in {"S0", "REJ", "RSTOS0"}
        ):
            inbound.append(record)
            anchors_by_id[record.physical_id] = (
                record,
                "successful inbound RDP from an external address",
                0.995,
                "external_rdp_anchor",
            )

    ecar_logins = [
        record
        for record in records
        if record.fmt == "ecar"
        and record.object_type == "USER_SESSION"
        and record.action == "LOGIN"
        and record.ts is not None
    ]
    network_records = [
        record for record in records if record.network is not None and record.ts is not None
    ]
    for rdp in inbound:
        if rdp.fmt != "ecar" or rdp.network is None or rdp.ts is None:
            continue
        external_ip, external_port, jump_ip, _rdp_port, _proto = rdp.network
        initial_logins = [
            login
            for login in ecar_logins
            if login.host == rdp.host
            and login.source_ip == external_ip
            and login.source_port == str(external_port)
            and abs(float(login.ts) - float(rdp.ts)) <= IDENTITY_FANOUT_SECONDS
        ]
        for initial in initial_logins:
            anchors_by_id[initial.physical_id] = (
                initial,
                "login session paired with external RDP tuple and time",
                0.995,
                "external_rdp_login_anchor",
            )
            if not initial.principal:
                continue
            for later in ecar_logins:
                if (
                    later.host == initial.host
                    or later.principal != initial.principal
                    or later.source_ip != jump_ip
                    or not 0 < float(later.ts) - float(initial.ts) <= RDP_TO_LATERAL_SECONDS
                ):
                    continue
                supporting = [
                    network
                    for network in network_records
                    if network.network is not None
                    and network.network[0] == jump_ip
                    and network.network[3] in {3389, 445}
                    and network.host == later.host
                    and abs(float(network.ts) - float(later.ts)) <= IDENTITY_FANOUT_SECONDS
                ]
                if not supporting:
                    continue
                anchors_by_id[later.physical_id] = (
                    later,
                    "same principal moved from external RDP host to a second internal host",
                    0.985,
                    "rdp_to_lateral_login_anchor",
                )
                for network in supporting:
                    anchors_by_id[network.physical_id] = (
                        network,
                        "network session supporting external-RDP-to-lateral-login chain",
                        0.985,
                        "rdp_to_lateral_network_anchor",
                    )
    return list(anchors_by_id.values())


def discover_artifact_sequence(
    records: Sequence[Record],
) -> list[tuple[Record, str, float, str]]:
    """Find strong producer-to-archive sequences joined by exact artifact paths."""
    producers = [
        record
        for record in records
        if record.is_process_create
        and record.ts is not None
        and HIGH_RISK_ARTIFACT_PRODUCER_RE.search(record.command)
    ]
    anchors_by_id: dict[str, tuple[Record, str, float, str]] = {}
    for producer in producers:
        output_paths = _command_output_paths(producer.command)
        if not output_paths:
            continue
        for consumer in records:
            if (
                not consumer.is_process_create
                or consumer.ts is None
                or consumer.host != producer.host
                or not 0 < float(consumer.ts) - float(producer.ts) <= ARTIFACT_TO_EXECUTION_SECONDS
                or not ARCHIVE_COMMAND_RE.search(consumer.command)
            ):
                continue
            command = _canonical_path(consumer.command)
            matched = next((path for path in output_paths if path in command), "")
            if not matched:
                continue
            anchors_by_id[consumer.physical_id] = (
                consumer,
                f"archive consumes exact high-risk output path {matched}",
                0.99,
                "artifact_producer_to_archive_anchor",
            )
    return list(anchors_by_id.values())


@dataclass(frozen=True)
class Selection:
    reason: str
    confidence: float
    edge: str
    anchor_engine: str


def _same_process_instance(left: Record, right: Record, *, window: float) -> bool:
    if not left.host or left.host != right.host or left.ts is None or right.ts is None:
        return False
    if abs(float(left.ts) - float(right.ts)) > window:
        return False
    if left.stable_id and right.stable_id and left.stable_id == right.stable_id:
        return True
    return bool(
        left.pid
        and left.pid == right.pid
        and (
            not left.image
            or not right.image
            or _canonical_path(left.image) == _canonical_path(right.image)
        )
    )


class TacticEvidenceContext:
    """Provide bounded cross-record semantics without exposing private labels."""

    def __init__(
        self,
        records: Sequence[Record],
        selections: Mapping[str, Selection],
    ) -> None:
        self.records = list(records)
        self.selections = selections
        self.selected = [record for record in self.records if record.physical_id in self.selections]
        self.network_by_tuple: dict[tuple[str, int, str, int], list[Record]] = defaultdict(list)
        for record in self.records:
            if record.network is None:
                continue
            src, src_port, dst, dst_port, _proto = record.network
            self.network_by_tuple[(src, src_port, dst, dst_port)].append(record)

        self.credential_reads = [
            record
            for record in self.selected
            if record.object_type == "FILE"
            and record.action == "READ"
            and CREDENTIAL_MATERIAL_RE.search(record.text)
        ]
        self.credential_staging_ids: set[str] = set()
        self.credential_staged_paths: set[tuple[str, str]] = set()
        for write in self.selected:
            if not write.is_file_write or not write.host or not write.file_path:
                continue
            if write.image and _canonical_path(write.file_path) == _canonical_path(write.image):
                # Some emitters report creation of the process image beside the
                # process-create event.  That is lifecycle materialization, not
                # output staged by the running process.
                continue
            if any(
                _same_process_instance(
                    write,
                    credential_read,
                    window=TACTIC_PROCESS_CONTEXT_SECONDS,
                )
                for credential_read in self.credential_reads
            ):
                self.credential_staging_ids.add(write.physical_id)
                self.credential_staged_paths.add((write.host, _canonical_path(write.file_path)))

        self.rtf_anchors = [
            record
            for record in self.selected
            if record.is_process_create
            and self.selections[record.physical_id].edge == "active_content_rtf_exploit_anchor"
        ]

    def network_peers(self, record: Record) -> list[Record]:
        if record.network is None or record.ts is None:
            return []
        src, src_port, dst, dst_port, _proto = record.network
        return [
            peer
            for peer in self.network_by_tuple[(src, src_port, dst, dst_port)]
            if peer.ts is not None
            and abs(float(peer.ts) - float(record.ts)) <= TACTIC_NETWORK_TRANSACTION_SECONDS
        ]

    def related_process_records(self, record: Record) -> list[Record]:
        owners = self.network_peers(record) if record.network is not None else [record]
        return [
            candidate
            for candidate in self.selected
            if any(
                _same_process_instance(
                    owner,
                    candidate,
                    window=TACTIC_PROCESS_CONTEXT_SECONDS,
                )
                for owner in owners
                if owner.host and (owner.stable_id or owner.pid)
            )
        ]

    def is_connectivity_probe(self, record: Record) -> bool:
        for peer in self.network_peers(record):
            values = set(peer.domains)
            values.update({peer.target_host, peer.target_uri, peer.text})
            if any(CONNECTIVITY_PROBE_RE.search(value) for value in values if value):
                return True
        return False

    def is_credential_activity(self, record: Record) -> bool:
        if CREDENTIAL_MATERIAL_RE.search(record.text):
            return True
        if not record.is_process_create:
            return False
        return any(
            credential_read.ts is not None
            and record.ts is not None
            and 0.0
            <= float(credential_read.ts) - float(record.ts)
            <= TACTIC_PROCESS_CONTEXT_SECONDS
            and _same_process_instance(
                record,
                credential_read,
                window=TACTIC_PROCESS_CONTEXT_SECONDS,
            )
            for credential_read in self.credential_reads
        )

    def is_credential_staging(self, record: Record) -> bool:
        return record.physical_id in self.credential_staging_ids

    def is_staged_read(self, record: Record) -> bool:
        return bool(
            record.object_type == "FILE"
            and record.action == "READ"
            and record.host
            and record.file_path
            and (record.host, _canonical_path(record.file_path)) in self.credential_staged_paths
        )

    def is_exfiltration(self, record: Record) -> bool:
        if self.is_staged_read(record):
            return any(
                candidate.network is not None
                and candidate.ts is not None
                and record.ts is not None
                and 0.0 <= float(candidate.ts) - float(record.ts) <= 60.0
                and _same_process_instance(record, candidate, window=60.0)
                for candidate in self.selected
            )
        if record.network is None or record.ts is None:
            return False
        return any(
            self.is_staged_read(candidate)
            and candidate.ts is not None
            and -2.0 <= float(record.ts) - float(candidate.ts) <= 60.0
            for candidate in self.related_process_records(record)
        )

    def is_download_materialization(self, record: Record) -> bool:
        if not record.is_file_write or not record.host or not record.file_path or record.ts is None:
            return False
        path = _canonical_path(record.file_path)
        if not path.endswith((".dll", ".exe", ".com", ".scr")):
            return False
        prior_network = any(
            candidate.network is not None
            and candidate.ts is not None
            and 0.0 <= float(record.ts) - float(candidate.ts) <= 5 * 60.0
            and _same_process_instance(record, candidate, window=5 * 60.0)
            for candidate in self.selected
        )
        if not prior_network:
            return False
        return any(
            candidate.host == record.host
            and candidate.ts is not None
            and 0.0 < float(candidate.ts) - float(record.ts) <= ARTIFACT_TO_EXECUTION_SECONDS
            and (
                (
                    candidate.is_process_create
                    and (
                        _canonical_path(candidate.image) == path
                        or path in _canonical_path(candidate.command)
                    )
                )
                or (candidate.is_module_load and _canonical_path(candidate.module_path) == path)
            )
            for candidate in self.records
        )

    def is_archive_extraction_materialization(self, record: Record) -> bool:
        """Recognize an executable emitted after an exact same-process archive write."""
        if not record.is_file_write or not record.host or not record.file_path or record.ts is None:
            return False
        output_path = _canonical_path(record.file_path)
        if not output_path.endswith((".dll", ".exe", ".com", ".scr")):
            return False
        return any(
            candidate.is_file_write
            and candidate.file_path
            and _canonical_path(candidate.file_path).endswith(
                (".zip", ".rar", ".7z", ".cab", ".tar", ".gz", ".tgz")
            )
            and candidate.ts is not None
            and 0.0 < float(record.ts) - float(candidate.ts) <= TACTIC_PROCESS_CONTEXT_SECONDS
            and _same_process_instance(
                record,
                candidate,
                window=TACTIC_PROCESS_CONTEXT_SECONDS,
            )
            for candidate in self.selected
        )

    def is_proxy_payload_materialization(self, record: Record) -> bool:
        """Join an unusual payload file to a later exact-path LOLBin invocation."""
        if not record.is_file_write or not record.host or not record.file_path or record.ts is None:
            return False
        payload_path = _canonical_path(record.file_path)
        if not payload_path.endswith((".bin", ".dat", ".db")):
            return False
        return any(
            candidate.host == record.host
            and candidate.is_process_create
            and candidate.ts is not None
            and 0.0 < float(candidate.ts) - float(record.ts) <= ARTIFACT_TO_EXECUTION_SECONDS
            and LOLBIN_BASENAME_RE.fullmatch(_path_basename(candidate.image))
            and payload_path in _canonical_path(candidate.command)
            for candidate in self.records
        )

    def is_exact_materialized_module(self, record: Record) -> bool:
        """Require an exact same-host path from an earlier selected file write."""
        if (
            not record.is_module_load
            or not record.host
            or not record.module_path
            or record.ts is None
        ):
            return False
        module_path = _canonical_path(record.module_path)
        return any(
            candidate.host == record.host
            and candidate.is_file_write
            and candidate.file_path
            and _canonical_path(candidate.file_path) == module_path
            and candidate.ts is not None
            and 0.05 <= float(record.ts) - float(candidate.ts) <= ARTIFACT_TO_EXECUTION_SECONDS
            for candidate in self.selected
        )

    def has_rtf_execution_context(self, record: Record) -> bool:
        owners = self.network_peers(record) if record.network is not None else [record]
        return any(
            _same_process_instance(
                owner,
                anchor,
                window=ACTIVE_CONTENT_FOLLOWUP_SECONDS,
            )
            for owner in owners
            for anchor in self.rtf_anchors
            if owner.host and (owner.stable_id or owner.pid)
        )


def infer_storyline_tactic(
    record: Record,
    selection: Selection,
    context: TacticEvidenceContext | None = None,
) -> tuple[str, float, str] | None:
    """Infer one ATT&CK tactic from public evidence carried by a selected record.

    The detector never sees the hidden ``storyline_id`` or tactic labels.  It emits
    an evidence-scoped claim which the evaluator can map to the hidden storyline
    only after prediction has completed.
    """
    text = unquote_plus(f"{record.text} {selection.reason}")
    lower = text.lower()
    reason_lower = selection.reason.lower()
    edge = selection.edge.lower()
    engine = selection.anchor_engine.lower()
    image_basename = _path_basename(_canonical_path(record.image))

    def claim(tactic: str, confidence: float, reason: str) -> tuple[str, float, str]:
        return tactic, min(selection.confidence, confidence), reason

    if record.is_process_terminate:
        return claim("Execution", 0.94, "termination belongs to an executed process lifecycle")

    if record.event_id == 4698 or any(
        token in lower
        for token in (
            "scheduled task",
            "schtasks",
            "run key",
            "startup folder",
            "portproxy persistence",
            "service from writable",
        )
    ):
        return claim("Persistence", 0.99, "task, service, or autostart persistence behavior")

    if (
        record.object_type == "REGISTRY"
        or (record.fmt == "windows_event_sysmon" and record.event_id in {12, 13, 14})
    ) and re.search(r"\\CurrentVersion\\Run(?:Once)?(?:\\|$)|\\Startup\\", text, re.I):
        return claim("Persistence", 0.98, "registry or startup-folder autostart behavior")

    if context is not None and context.is_credential_activity(record):
        return claim("Credential Access", 0.98, "credential material access or extraction")

    if context is not None and context.is_credential_staging(record):
        return claim("Collection", 0.96, "credential material staged by the same process instance")

    if record.object_type == "FILE" and record.action == "DELETE":
        return claim("Defense Evasion", 0.98, "artifact deletion or cleanup behavior")

    if record.network is not None and context is not None and context.is_connectivity_probe(record):
        return claim(
            "Discovery",
            0.96,
            "transaction targets a well-known public connectivity-check endpoint",
        )

    if context is not None and context.is_exfiltration(record):
        return claim(
            "Exfiltration",
            0.97,
            "exact process read a credential-staging artifact immediately before transfer",
        )

    if record.object_type == "FILE" and record.action == "READ":
        return claim("Collection", 0.9, "selected process read a file for collection or use")

    if record.network is not None:
        if any(token in lower for token in ("exfil", "upload", "staged archive")):
            return claim("Exfiltration", 0.96, "outbound transfer of collected or staged data")
        if context is not None and context.has_rtf_execution_context(record):
            return claim(
                "Execution",
                0.97,
                "network payload retrieval belongs to a corroborated RTF exploit process",
            )
        if "rdp_to_lateral" in edge or "lateral" in lower:
            return claim("Lateral Movement", 0.96, "authenticated movement to another host")
        if "external_rdp" in edge or "external rdp" in lower:
            return claim("Initial Access", 0.96, "successful remote access from an external host")
        if engine == "web_exploit" or "web_exploit" in edge:
            return claim("Execution", 0.98, "web exploit request capable of command execution")
        return claim(
            "Command and Control",
            0.94,
            "network transaction associated with a bounded malicious process or beacon",
        )

    if CREDENTIAL_MATERIAL_RE.search(lower):
        return claim("Credential Access", 0.98, "credential material access or extraction")

    if any(token in lower for token in ("exfil", "upload credentials", "onedrive")):
        return claim("Exfiltration", 0.96, "explicit upload or exfiltration behavior")

    if engine == "artifact_sequence" or any(
        token in lower
        for token in (
            "bulk database export",
            "data staging",
            "staged data archived",
            "archive consumes exact high-risk output",
            "sensitive material archive",
        )
    ):
        return claim("Collection", 0.95, "collection or staging of data for later use")

    if any(
        token in lower
        for token in (
            "host reconnaissance",
            "network configuration discovery",
            "domain discovery",
            "domain admins",
            "get-computerinfo",
        )
    ):
        return claim("Discovery", 0.95, "host, account, domain, or network discovery behavior")

    if engine == "web_exploit" or "web exploit" in lower:
        return claim("Execution", 0.98, "web exploit request capable of command execution")

    if context is not None and context.is_archive_extraction_materialization(record):
        return claim(
            "Defense Evasion",
            0.97,
            "same process materialized an executable after writing an exact archive artifact",
        )

    if context is not None and context.is_proxy_payload_materialization(record):
        return claim(
            "Defense Evasion",
            0.97,
            "materialized payload is later referenced by exact path in a LOLBin invocation",
        )

    if context is not None and context.is_download_materialization(record):
        return claim(
            "Command and Control",
            0.96,
            "same process materialized an executable payload after a bounded download transaction",
        )

    if context is not None and context.has_rtf_execution_context(record):
        return claim(
            "Execution",
            0.96,
            "record belongs to a corroborated RTF exploit process instance",
        )

    if record.is_process_create and edge in {
        "active_content_swf_lure_anchor",
        "active_content_rtf_exploit_anchor",
        "double_extension_process_anchor",
        "download_lure_process_anchor",
    }:
        return claim("Execution", 0.97, "user execution of a lure or disguised executable")

    if record.is_process_create and image_basename in {"powershell", "powershell.exe", "pwsh.exe"}:
        return claim("Execution", 0.96, "PowerShell command or script execution")

    if record.is_process_create and re.search(
        r"\bcmd(?:\.exe)?\b.*(?:/c\s+)?start\b.*\.(?:pdf|docx?|xlsx?|pptx?)\b",
        record.command,
        re.I,
    ):
        return claim("Defense Evasion", 0.94, "decoy document opened during disguised execution")

    defense_edges = {
        "office_lolbin_process_anchor",
        "writable_system_lookalike_anchor",
        "remote_thread_anchor",
    }
    if (record.is_process_create or record.is_module_load or record.is_remote_thread) and (
        edge in defense_edges
        or (
            record.is_process_create
            and image_basename
            in {"mshta", "mshta.exe", "rundll32", "rundll32.exe", "msiexec", "msiexec.exe"}
        )
        or any(
            token in reason_lower
            for token in (
                "mshta",
                "rundll32",
                "msiexec",
                "system-lookalike",
                "side-loaded",
                "side-load",
                "deobfuscat",
                "certutil decode",
                "cleanup",
                "indicator removal",
            )
        )
    ):
        return claim("Defense Evasion", 0.96, "proxy execution, masquerading, or cleanup behavior")

    if any(
        token in reason_lower
        for token in (
            "double extension",
            "masquerad",
        )
    ):
        return claim("Defense Evasion", 0.94, "masquerading or disguised artifact behavior")

    if record.is_remote_thread:
        return claim("Execution", 0.9, "thread execution in a selected process instance")
    if record.is_module_load and edge == "module_load_anchor":
        return claim("Execution", 0.96, "unsigned writable-path module was explicitly loaded")
    if record.is_module_load and (
        edge == "file_path_to_module_load"
        or (context is not None and context.is_exact_materialized_module(record))
    ):
        return claim("Execution", 0.92, "exact materialized artifact was loaded as a module")
    if record.is_process_create or record.fmt == "bash_history":
        return claim("Execution", 0.9, "selected command or process execution")

    # File writes and other association-only records are intentionally left
    # unclassified unless their content provides a tactic-specific signal.
    return None


class BoundedGraph:
    def __init__(self, records: Sequence[Record]) -> None:
        self.records = list(records)
        self.selected: dict[str, Selection] = {}
        self.by_host_stable: dict[tuple[str, str], list[Record]] = defaultdict(list)
        self.by_host_pid: dict[tuple[str, str], list[Record]] = defaultdict(list)
        self.children_by_parent_stable: dict[tuple[str, str], list[Record]] = defaultdict(list)
        self.children_by_parent_pid: dict[tuple[str, str], list[Record]] = defaultdict(list)
        self.by_uid: dict[str, list[Record]] = defaultdict(list)
        self.by_fuid: dict[str, list[Record]] = defaultdict(list)
        self.by_asa_connection: dict[str, list[Record]] = defaultdict(list)
        self.by_host_file_path: dict[tuple[str, str], list[Record]] = defaultdict(list)
        self.processes_by_host_image: dict[tuple[str, str], list[Record]] = defaultdict(list)
        self.modules_by_host_path: dict[tuple[str, str], list[Record]] = defaultdict(list)
        self.processes_by_host: dict[str, list[Record]] = defaultdict(list)
        self.by_host_logon_id: dict[tuple[str, str], list[Record]] = defaultdict(list)
        self.by_path_index: dict[tuple[str, int], Record] = {}
        self.host_ips: dict[str, set[str]] = defaultdict(set)
        self.ip_hosts: dict[str, set[str]] = defaultdict(set)
        for record in self.records:
            if record.host and record.stable_id:
                self.by_host_stable[(record.host, record.stable_id)].append(record)
            if record.host and record.pid:
                self.by_host_pid[(record.host, record.pid)].append(record)
            if record.host and record.parent_stable_id:
                self.children_by_parent_stable[(record.host, record.parent_stable_id)].append(
                    record
                )
            if record.host and record.parent_pid:
                self.children_by_parent_pid[(record.host, record.parent_pid)].append(record)
            for uid in record.uids:
                self.by_uid[uid].append(record)
            for fuid in record.fuids:
                self.by_fuid[fuid].append(record)
            for connection_id in record.asa_connection_ids:
                self.by_asa_connection[connection_id].append(record)
            if record.host and record.file_path:
                self.by_host_file_path[(record.host, _canonical_path(record.file_path))].append(
                    record
                )
            if record.host and record.is_process_create and record.image:
                self.processes_by_host_image[(record.host, _canonical_path(record.image))].append(
                    record
                )
                self.processes_by_host[record.host].append(record)
            if record.host and record.is_module_load and record.module_path:
                self.modules_by_host_path[
                    (record.host, _canonical_path(record.module_path))
                ].append(record)
            for logon_id in record.logon_ids:
                if record.host:
                    self.by_host_logon_id[(record.host, logon_id)].append(record)
            self.by_path_index[
                (_scalar(record.row.get("relative_path")), int(record.row.get("record_index") or 0))
            ] = record
            if (
                record.fmt == "ecar"
                and record.object_type == "FLOW"
                and record.host
                and record.network
            ):
                self.host_ips[record.host].add(record.network[0])
                self.ip_hosts[record.network[0]].add(record.host)
            if record.fmt == "zeek_dhcp":
                host = _canonical_host(record.features.get("host_name"))
                ip = _scalar(record.features.get("client_addr"))
                if host and ip:
                    self.host_ips[host].add(ip)
                    self.ip_hosts[ip].add(host)

    def add(self, record: Record, reason: str, confidence: float, edge: str, engine: str) -> bool:
        if not record.physical_id:
            return False
        candidate = Selection(reason, confidence, edge, engine)
        current = self.selected.get(record.physical_id)
        if current is None or candidate.confidence > current.confidence:
            self.selected[record.physical_id] = candidate
            return current is None
        return False

    def _lifetime_for_create(self, create: Record) -> tuple[float, float, Record | None]:
        start = float(create.ts) if create.ts is not None else -math.inf
        candidates: list[Record] = []
        if create.host and create.stable_id:
            candidates.extend(self.by_host_stable[(create.host, create.stable_id)])
        # PID fallback requires the same host and image and is bounded by the
        # nearest termination/reuse boundary. It is never a global PID edge.
        if create.host and create.pid:
            candidates.extend(
                record
                for record in self.by_host_pid[(create.host, create.pid)]
                if not create.image
                or not record.image
                or record.image.lower() == create.image.lower()
            )
        terminates = sorted(
            (
                record
                for record in candidates
                if record.is_process_terminate
                and record.ts is not None
                and float(record.ts) >= start
            ),
            key=lambda record: float(record.ts),
        )
        terminate = terminates[0] if terminates else None
        end = (
            float(terminate.ts)
            if terminate is not None
            else start + PROCESS_FALLBACK_LIFETIME_SECONDS
        )
        return start, end, terminate

    def _same_instance_records(self, create: Record, start: float, end: float) -> Iterable[Record]:
        seen: set[str] = set()
        if create.host and create.stable_id:
            for record in self.by_host_stable[(create.host, create.stable_id)]:
                timestamp = float(record.ts) if record.ts is not None else None
                in_lifetime = timestamp is not None and start - 1 <= timestamp <= end + 1
                exact_termination_skew = (
                    timestamp is not None
                    and record.is_process_terminate
                    and end < timestamp <= end + PROCESS_TERMINATION_EMITTER_SKEW_SECONDS
                )
                if (
                    record.is_process_related
                    and (in_lifetime or exact_termination_skew)
                    and record.physical_id not in seen
                ):
                    # A long-lived malicious process can later load ordinary
                    # system DLLs as routine baseline activity. Inherit only
                    # initial modules; later modules need their own explicit
                    # module-behavior anchor.
                    if (
                        record.is_module_load
                        and timestamp is not None
                        and timestamp > start + PROCESS_INITIAL_MODULE_WINDOW_SECONDS
                        and record.physical_id not in self.selected
                    ):
                        continue
                    seen.add(record.physical_id)
                    yield record
        if create.host and create.pid:
            for record in self.by_host_pid[(create.host, create.pid)]:
                if (
                    not record.is_process_related
                    or record.ts is None
                    or not (start - 1 <= float(record.ts) <= end + 1)
                ):
                    continue
                if (
                    record.is_module_load
                    and float(record.ts) > start + PROCESS_INITIAL_MODULE_WINDOW_SECONDS
                    and record.physical_id not in self.selected
                ):
                    continue
                if create.image and record.image and record.image.lower() != create.image.lower():
                    continue
                if record.physical_id not in seen:
                    seen.add(record.physical_id)
                    yield record

    def expand_processes(self, direct_process_anchors: Sequence[Record]) -> None:
        for anchor in direct_process_anchors:
            creates: list[Record]
            if anchor.is_process_create:
                creates = [anchor]
            elif anchor.host and anchor.stable_id:
                creates = [
                    item
                    for item in self.by_host_stable[(anchor.host, anchor.stable_id)]
                    if item.is_process_create
                ]
            else:
                creates = []
            for create in creates:
                start, end, terminate = self._lifetime_for_create(create)
                for related in self._same_instance_records(create, start, end):
                    exact_termination = related.is_process_terminate and (
                        related is terminate
                        or bool(
                            create.stable_id
                            and related.stable_id == create.stable_id
                            and related.ts is not None
                            and float(related.ts) <= end + PROCESS_TERMINATION_EMITTER_SKEW_SECONDS
                        )
                    )
                    edge = (
                        "process_create_to_exact_terminate"
                        if exact_termination
                        else (
                            "host_process_guid"
                            if create.stable_id and related.stable_id == create.stable_id
                            else "host_pid_lifetime_image"
                        )
                    )
                    confidence = (
                        0.99
                        if exact_termination
                        else (0.985 if edge == "host_process_guid" else 0.965)
                    )
                    self.add(
                        related,
                        f"same bounded process instance as {create.physical_id}",
                        confidence,
                        edge,
                        "process_graph",
                    )

                # Different emitters of the same canonical process creation do
                # not necessarily share ProcessGuid (Security 4688 may even
                # omit NewProcessId). Exact host + image + command + tight time
                # is the bounded cross-format fan-out key.
                for peer in self.records:
                    if not peer.is_process_create or peer.host != create.host or peer.ts is None:
                        continue
                    if abs(float(peer.ts) - start) > 1.5:
                        continue
                    same_image = bool(
                        create.image and peer.image and create.image.lower() == peer.image.lower()
                    )
                    same_command = bool(
                        create.command
                        and peer.command
                        and create.command.lower() == peer.command.lower()
                    )
                    if same_image and same_command:
                        self.add(
                            peer,
                            f"same canonical process-create emission as {create.physical_id}",
                            0.985,
                            "canonical_process_fanout",
                            "process_graph",
                        )

                # Parent to child is exactly one hop. Grandchildren are not
                # queued as new parents.
                children: list[Record] = []
                if create.host and create.stable_id:
                    children.extend(self.children_by_parent_stable[(create.host, create.stable_id)])
                if create.host and create.pid:
                    children.extend(self.children_by_parent_pid[(create.host, create.pid)])
                for child in children:
                    if (
                        not child.is_process_create
                        or child.ts is None
                        or not (start <= float(child.ts) <= end)
                    ):
                        continue
                    self.add(
                        child,
                        f"one-hop child of selected process {create.physical_id}",
                        0.92,
                        "parent_child_one_hop",
                        "process_graph",
                    )
                    child_start, child_end, child_terminate = self._lifetime_for_create(child)
                    for child_related in self._same_instance_records(child, child_start, child_end):
                        exact_child_termination = child_related.is_process_terminate and (
                            child_related is child_terminate
                            or bool(
                                child.stable_id
                                and child_related.stable_id == child.stable_id
                                and child_related.ts is not None
                                and float(child_related.ts)
                                <= child_end + PROCESS_TERMINATION_EMITTER_SKEW_SECONDS
                            )
                        )
                        child_edge = (
                            "process_create_to_exact_terminate"
                            if exact_child_termination
                            else "child_process_lifecycle"
                        )
                        self.add(
                            child_related,
                            f"bounded lifecycle of one-hop child {child.physical_id}",
                            0.97 if exact_child_termination else 0.94,
                            child_edge,
                            "process_graph",
                        )

    def process_anchors_from_selected_flows(self) -> list[Record]:
        """Resolve selected FLOW/endpoint network records back to their owner."""
        derived: list[Record] = []
        for flow in self.records:
            if flow.physical_id not in self.selected or flow.network is None or not flow.host:
                continue
            candidates: list[Record] = []
            if flow.stable_id:
                candidates.extend(self.by_host_stable[(flow.host, flow.stable_id)])
            if flow.pid:
                candidates.extend(self.by_host_pid[(flow.host, flow.pid)])
            for create in candidates:
                if not create.is_process_create or create.ts is None or flow.ts is None:
                    continue
                # A selected callback can be issued through a hijacked or
                # user-driven browser. Selecting every unrelated connection
                # of that long-lived client would be precisely the forbidden
                # PID-wide propagation pattern.
                if SHARED_CLIENT_PROCESS_RE.search(create.image):
                    continue
                start, end, _terminate = self._lifetime_for_create(create)
                if not (start <= float(flow.ts) <= end):
                    continue
                edge = (
                    "ecar_flow_actor_to_process" if flow.fmt == "ecar" else "network_process_guid"
                )
                confidence = (
                    0.985 if flow.stable_id and create.stable_id == flow.stable_id else 0.95
                )
                if self.add(
                    create,
                    f"owner process of selected network record {flow.physical_id}",
                    confidence,
                    edge,
                    "network_graph",
                ):
                    derived.append(create)
        return derived

    def expand_web_to_process(self, web_anchors: Sequence[Record]) -> list[Record]:
        derived: list[Record] = []
        for anchor in web_anchors:
            if anchor.ts is None or not anchor.host:
                continue
            start = float(anchor.ts)
            candidates = [
                record
                for record in self.records
                if record.is_process_create
                and record.host == anchor.host
                and record.ts is not None
                and start <= float(record.ts) <= start + 15 * 60
                and (
                    re.search(r"(?:java|tomcat|jetty|w3wp|httpd|nginx)", record.parent_image, re.I)
                    or any(pattern.search(record.text) for _name, pattern in TERMINAL_RULES)
                    or IOC_PATTERN.search(record.text)
                    or re.search(r"\b(?:cmd|powershell|curl|wget)(?:\.exe)?\b", record.image, re.I)
                )
            ]
            for record in candidates[:4]:
                if self.add(
                    record,
                    f"server-side process after exploit {anchor.physical_id}",
                    0.94,
                    "web_to_process",
                    "web_graph",
                ):
                    derived.append(record)
        return derived

    def expand_artifacts(self) -> list[Record]:
        """Expand exact materialized paths into later executions on the same host."""
        materializations: list[tuple[str, str, float, str]] = []
        selected_records = [
            record for record in self.records if record.physical_id in self.selected
        ]
        for record in selected_records:
            if record.host and record.is_file_write and record.file_path and record.ts is not None:
                materializations.append(
                    (
                        record.host,
                        _canonical_path(record.file_path),
                        float(record.ts),
                        record.physical_id,
                    )
                )
            if not record.host or record.ts is None:
                continue
            for path in _command_output_paths(record.command):
                materializations.append((record.host, path, float(record.ts), record.physical_id))
                for file_record in self.by_host_file_path[(record.host, path)]:
                    if (
                        not file_record.is_file_write
                        or file_record.ts is None
                        or abs(float(file_record.ts) - float(record.ts)) > ARTIFACT_EMISSION_SECONDS
                    ):
                        continue
                    self.add(
                        file_record,
                        f"exact output path {path} materialized by {record.physical_id}",
                        0.985,
                        "command_output_to_file",
                        "artifact_graph",
                    )
                    materializations.append(
                        (
                            file_record.host,
                            path,
                            float(file_record.ts),
                            file_record.physical_id,
                        )
                    )

        derived: list[Record] = []
        seen_materializations: set[tuple[str, str, float]] = set()
        for host, path, materialized_at, source_id in materializations:
            key = (host, path, materialized_at)
            if key in seen_materializations:
                continue
            seen_materializations.add(key)
            candidates = list(self.processes_by_host_image[(host, path)])
            for process in self.processes_by_host[host]:
                if process in candidates:
                    continue
                image_name = _path_basename(process.image)
                if (
                    image_name
                    and re.search(
                        r"^(?:powershell|pwsh|cmd|wscript|cscript|mshta|rundll32)\.exe$",
                        image_name,
                        re.I,
                    )
                    and path in _canonical_path(process.command)
                ):
                    candidates.append(process)
            for process in candidates:
                if (
                    process.ts is None
                    or not 0.05
                    <= float(process.ts) - materialized_at
                    <= ARTIFACT_TO_EXECUTION_SECONDS
                ):
                    continue
                if self.add(
                    process,
                    f"exact same-host artifact {path} executed after {source_id}",
                    0.97,
                    "file_path_to_process_execution",
                    "artifact_graph",
                ):
                    derived.append(process)
            for module in self.modules_by_host_path[(host, path)]:
                if (
                    module.ts is None
                    or not 0.05
                    <= float(module.ts) - materialized_at
                    <= ARTIFACT_TO_EXECUTION_SECONDS
                ):
                    continue
                if self.add(
                    module,
                    f"exact same-host artifact {path} loaded after {source_id}",
                    0.97,
                    "file_path_to_module_load",
                    "artifact_graph",
                ):
                    derived.append(module)
        return derived

    def expand_identity(self) -> None:
        """Expand only exact network/login and host/logon-ID companions."""
        selected_records = [
            record for record in self.records if record.physical_id in self.selected
        ]
        ecar_logins = [
            record
            for record in self.records
            if record.fmt == "ecar"
            and record.object_type == "USER_SESSION"
            and record.action == "LOGIN"
            and record.ts is not None
        ]
        for selected in selected_records:
            if selected.network is None or selected.ts is None or not selected.host:
                continue
            src, src_port, _dst, _dst_port, _proto = selected.network
            for login in ecar_logins:
                if (
                    login.host == selected.host
                    and login.source_ip == src
                    and login.source_port == str(src_port)
                    and abs(float(login.ts) - float(selected.ts)) <= IDENTITY_FANOUT_SECONDS
                ):
                    self.add(
                        login,
                        f"exact source tuple and host of selected session {selected.physical_id}",
                        0.99,
                        "network_to_login_tuple",
                        "identity_graph",
                    )

        selected_records = [
            record for record in self.records if record.physical_id in self.selected
        ]
        for selected in selected_records:
            is_identity_record = (
                selected.fmt == "ecar" and selected.object_type == "USER_SESSION"
            ) or (selected.fmt == "windows_event_security" and selected.event_id in {4624, 4672})
            if not is_identity_record or not selected.host or selected.ts is None:
                continue
            for logon_id in selected.logon_ids:
                for peer in self.by_host_logon_id[(selected.host, logon_id)]:
                    is_login_companion = (
                        peer.fmt == "ecar" and peer.object_type == "USER_SESSION"
                    ) or (peer.fmt == "windows_event_security" and peer.event_id in {4624, 4672})
                    if (
                        not is_login_companion
                        or peer.ts is None
                        or abs(float(peer.ts) - float(selected.ts)) > IDENTITY_FANOUT_SECONDS
                    ):
                        continue
                    self.add(
                        peer,
                        f"same host and exact logon ID {logon_id} as {selected.physical_id}",
                        0.99,
                        "host_logon_id",
                        "identity_graph",
                    )

    def expand_process_flows(self) -> None:
        selected_instances: list[tuple[str, str, str, float, float]] = []
        for record in self.records:
            if record.physical_id not in self.selected or not record.is_process_create:
                continue
            start, end, _terminate = self._lifetime_for_create(record)
            selected_instances.append((record.host, record.stable_id, record.pid, start, end))
        for record in self.records:
            if record.ts is None or record.network is None:
                continue
            for host, stable_id, pid, start, end in selected_instances:
                if record.host != host or not (start <= float(record.ts) <= end):
                    continue
                exact_stable = bool(stable_id and record.stable_id == stable_id)
                bounded_pid = bool(pid and record.pid == pid)
                if exact_stable or bounded_pid:
                    self.add(
                        record,
                        "network event owned by selected bounded process instance",
                        0.975 if exact_stable else 0.94,
                        "ecar_flow_actor" if record.fmt == "ecar" else "process_network",
                        "network_graph",
                    )
                    break

    def _expand_exact_network_closure(self) -> None:
        """Close exact UID/FUID/ASA IDs and bounded five-tuples to a fixed point."""
        for _round in range(6):
            before = len(self.selected)
            selected_records = [
                record for record in self.records if record.physical_id in self.selected
            ]
            selected_uids = {uid for record in selected_records for uid in record.uids}
            selected_fuids = {fuid for record in selected_records for fuid in record.fuids}
            selected_asa = {cid for record in selected_records for cid in record.asa_connection_ids}
            for uid in selected_uids:
                for record in self.by_uid[uid]:
                    if record.physical_id not in self.selected:
                        self.add(record, f"same Zeek UID {uid}", 0.995, "zeek_uid", "network_graph")
            for fuid in selected_fuids:
                for record in self.by_fuid[fuid]:
                    if record.physical_id not in self.selected:
                        self.add(
                            record, f"same Zeek FUID {fuid}", 0.995, "zeek_fuid", "network_graph"
                        )
            for connection_id in selected_asa:
                for record in self.by_asa_connection[connection_id]:
                    if record.physical_id not in self.selected:
                        self.add(
                            record,
                            f"same ASA connection ID {connection_id}",
                            0.99,
                            "asa_connection_id",
                            "network_graph",
                        )

            selected_network = [
                record for record in selected_records if record.network and record.ts is not None
            ]
            for record in self.records:
                if (
                    record.network is None
                    or record.ts is None
                    or record.physical_id in self.selected
                ):
                    continue
                for selected in selected_network:
                    if (
                        record.network == selected.network
                        and abs(float(record.ts) - float(selected.ts)) <= TUPLE_TIME_SECONDS
                    ):
                        self.add(
                            record,
                            f"same five-tuple and time as {selected.physical_id}",
                            0.985,
                            "five_tuple_time",
                            "network_graph",
                        )
                        break
            if len(self.selected) == before:
                break

    def _expand_proxy_paths(self) -> None:
        """Bridge selected proxy requests to internal transport and proxy-origin DNS."""
        selected_proxy = [
            record
            for record in self.records
            if record.physical_id in self.selected
            and record.fmt == "proxy_access"
            and record.ts is not None
            and record.target_host
        ]
        for proxy in selected_proxy:
            client_ip = _scalar(proxy.features.get("client_ip"))
            if not client_ip:
                continue
            matching_http = [
                record
                for record in self.records
                if record.fmt == "zeek_http"
                and record.ts is not None
                and record.network is not None
                and record.network[0] == client_ip
                and record.network[3] in PROXY_PORTS
                and proxy.target_host in record.domains
                and abs(float(record.ts) - float(proxy.ts)) <= PROXY_BRIDGE_SECONDS
            ]
            proxy_ips: set[str] = set()
            for http in matching_http:
                self.add(
                    http,
                    f"proxy client/domain/time bridge for {proxy.physical_id}",
                    0.99,
                    "proxy_http_client_domain_time",
                    "network_graph",
                )
                if http.network is not None:
                    proxy_ips.add(http.network[2])

            # If HTTP parsing is unavailable, accept only one unambiguous
            # client-to-private-proxy tuple at this tick. Never fan out across
            # every connection from the client or host time window.
            if not proxy_ips:
                candidates: dict[tuple[str, int, str, int, str], list[Record]] = defaultdict(list)
                for record in self.records:
                    if (
                        record.network is None
                        or record.ts is None
                        or record.network[0] != client_ip
                        or record.network[3] not in PROXY_PORTS
                        or not _is_private_ip(record.network[2])
                        or abs(float(record.ts) - float(proxy.ts)) > PROXY_BRIDGE_SECONDS
                    ):
                        continue
                    candidates[record.network].append(record)
                if len(candidates) == 1:
                    network, members = next(iter(candidates.items()))
                    proxy_ips.add(network[2])
                    for member in members:
                        self.add(
                            member,
                            f"unique proxy client/port/time bridge for {proxy.physical_id}",
                            0.965,
                            "proxy_unique_client_port_time",
                            "network_graph",
                        )

            for dns in self.records:
                if (
                    dns.fmt != "zeek_dns"
                    or dns.ts is None
                    or dns.network is None
                    or dns.network[0] not in proxy_ips
                    or proxy.target_host not in dns.domains
                    or not 0 <= float(dns.ts) - float(proxy.ts) <= PROXY_DNS_SECONDS
                ):
                    continue
                self.add(
                    dns,
                    f"proxy-origin DNS for selected target {proxy.target_host}",
                    0.98,
                    "proxy_target_to_dns",
                    "network_graph",
                )

    def _expand_wfp_companions(self) -> None:
        selected_records = [
            record for record in self.records if record.physical_id in self.selected
        ]
        selected_network = [
            record for record in selected_records if record.network and record.ts is not None
        ]
        # Some generated Security 5156 records expose only SourcePort. Keep the
        # correlation bounded by endpoint host, exact ephemeral port, and a
        # 500 ms window instead of widening it to host/time-only propagation.
        for wfp in self.records:
            if wfp.fmt != "windows_event_security" or wfp.event_id != 5156 or wfp.ts is None:
                continue
            event_data = wfp.features.get("event_data")
            if not isinstance(event_data, Mapping):
                continue
            source_port = _int_text(event_data.get("SourcePort"))
            if not source_port:
                continue
            for connection in selected_network:
                src, src_port, _dst, _dst_port, _proto = connection.network or ("", 0, "", 0, "")
                host_matches = (
                    wfp.host in self.ip_hosts.get(src, set()) or wfp.host == connection.host
                )
                if (
                    host_matches
                    and source_port == str(src_port)
                    and abs(float(wfp.ts) - float(connection.ts)) <= 0.5
                ):
                    self.add(
                        wfp,
                        f"host-scoped WFP source port/time companion for {connection.physical_id}",
                        0.975,
                        "wfp_host_port_time",
                        "network_graph",
                    )
                    break

    def expand_network(self) -> None:
        self._expand_proxy_paths()
        self._expand_exact_network_closure()
        self._expand_wfp_companions()

        selected_records = [
            record for record in self.records if record.physical_id in self.selected
        ]
        selected_network = [
            record for record in selected_records if record.network and record.ts is not None
        ]
        for dns in self.records:
            if dns.fmt != "zeek_dns" or dns.ts is None or not dns.dns_answers:
                continue
            for connection in selected_network:
                src, _sp, dst, dst_port, _proto = connection.network or ("", 0, "", 0, "")
                dns_src = dns.network[0] if dns.network else ""
                if (
                    dst_port not in SYSTEM_PORTS
                    and not _is_private_ip(dst)
                    and dst in dns.dns_answers
                    and (not dns_src or dns_src == src)
                    and 0 <= float(connection.ts) - float(dns.ts) <= DNS_TO_CONNECT_SECONDS
                ):
                    self.add(
                        dns,
                        f"DNS answer resolved selected destination {dst}",
                        0.97,
                        "dns_answer_to_connection",
                        "network_graph",
                    )
                    break

        # Selected DNS rows can also lead forward to the proxy-origin or host
        # connection. This is the inverse of the connection-to-prior-DNS edge
        # above and remains bounded by resolver source, exact answer, and time.
        selected_dns = [
            record
            for record in self.records
            if record.physical_id in self.selected
            and self.selected[record.physical_id].edge == "proxy_target_to_dns"
            and record.fmt == "zeek_dns"
            and record.ts is not None
            and record.network is not None
            and any(not _is_private_ip(answer) for answer in record.dns_answers)
        ]
        for dns in selected_dns:
            dns_src = dns.network[0] if dns.network else ""
            for connection in self.records:
                if connection.network is None or connection.ts is None:
                    continue
                src, _sp, dst, _dp, _proto = connection.network
                if (
                    src == dns_src
                    and dst in dns.dns_answers
                    and not _is_private_ip(dst)
                    and 0 <= float(connection.ts) - float(dns.ts) <= DNS_TO_CONNECT_SECONDS
                ):
                    self.add(
                        connection,
                        f"selected DNS answer {dst} led to subsequent connection",
                        0.975,
                        "dns_answer_to_connection",
                        "network_graph",
                    )

        # DNS and proxy bridges may introduce new UIDs/FUIDs after the first
        # closure. Re-run the fixed point so all exact physical companions are
        # included, then revisit partial WFP rows for newly selected tuples.
        self._expand_exact_network_closure()
        self._expand_wfp_companions()

        # NAT rows sometimes omit the tuple/connection ID. Only an immediately
        # adjacent 305011/305012 paired with a selected 302013/302014 is valid.
        expected = {"305011": "302013", "305012": "302014"}
        for record in self.records:
            if record.fmt != "cisco_asa" or record.ts is None:
                continue
            msg_id = _int_text(record.features.get("msg_id"))
            if msg_id not in expected:
                continue
            previous = self.by_path_index.get(
                (
                    _scalar(record.row.get("relative_path")),
                    int(record.row.get("record_index") or 0) - 1,
                )
            )
            if (
                previous is not None
                and previous.physical_id in self.selected
                and previous.ts is not None
                and _int_text(previous.features.get("msg_id")) == expected[msg_id]
                and abs(float(record.ts) - float(previous.ts)) <= 1.1
            ):
                self.add(
                    record,
                    f"adjacent ASA NAT pair for {previous.physical_id}",
                    0.985,
                    "asa_adjacent_nat",
                    "network_graph",
                )


def detect_record_graph(
    *,
    case_id: str,
    rows: Sequence[Mapping[str, Any]],
    baseline_domains: Iterable[str] = (),
    baseline_ips: Iterable[str] = (),
    benign_tokens: Sequence[str] = (),
    predict_storyline_tactics: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    records = normalize_records(rows)
    graph = BoundedGraph(records)
    baseline_domain_set = {str(item).lower().rstrip(".") for item in baseline_domains}
    baseline_ip_set = {str(item) for item in baseline_ips}

    discoveries: dict[str, list[tuple[Record, str, float, str]]] = {
        "beacon": discover_periodic(
            records,
            baseline_domains=baseline_domain_set,
            baseline_ips=baseline_ip_set,
            benign_tokens=benign_tokens,
        ),
        "terminal": discover_terminal(records),
        "scheduled_task": discover_scheduled_task(records),
        "endpoint_behavior": discover_endpoint_behavior(records),
        "process_anomaly": discover_process_anomaly(records),
        "module_behavior": discover_module_behavior(records),
        "web_exploit": discover_web(records),
        "one_shot_network": discover_one_shot_network(records),
        "auth_anomaly": discover_auth_anomaly(records),
        "artifact_sequence": discover_artifact_sequence(records),
        "ioc": discover_ioc(records),
    }
    process_anchors: list[Record] = []
    web_anchors: list[Record] = []
    findings: list[dict[str, Any]] = []
    sequence = 0
    for engine, anchors in discoveries.items():
        for record, reason, confidence, edge in anchors:
            graph.add(record, reason, confidence, edge, engine)
            if record.is_process_create or record.is_module_load or record.is_remote_thread:
                process_anchors.append(record)
            if engine == "web_exploit":
                web_anchors.append(record)
            findings.append(
                {
                    "finding_id": f"gold-{case_id}-{sequence:06d}",
                    "case_id": case_id,
                    "engine": engine,
                    "host": record.host or None,
                    "timestamp": datetime.fromtimestamp(record.ts, UTC)
                    .isoformat()
                    .replace("+00:00", "Z")
                    if record.ts is not None
                    else None,
                    "confidence": confidence,
                    "reason": reason,
                    "evidence": [
                        {
                            "physical_record_id": record.physical_id,
                            "relative_path": _scalar(record.row.get("relative_path")),
                            "record_index": int(record.row.get("record_index") or 0),
                        }
                    ],
                }
            )
            sequence += 1

    process_anchors.extend(graph.expand_web_to_process(web_anchors))
    process_anchors.extend(graph.process_anchors_from_selected_flows())
    graph.expand_processes(process_anchors)
    for _round in range(3):
        artifact_processes = graph.expand_artifacts()
        if not artifact_processes:
            break
        graph.expand_processes(artifact_processes)
    graph.expand_process_flows()
    graph.expand_network()
    graph.expand_identity()
    graph.expand_network()

    record_by_id = {record.physical_id: record for record in records}
    predictions: list[dict[str, Any]] = []
    for physical_id, selection in sorted(
        graph.selected.items(),
        key=lambda item: (
            _scalar(record_by_id[item[0]].row.get("relative_path")),
            int(record_by_id[item[0]].row.get("record_index") or 0),
        ),
    ):
        record = record_by_id[physical_id]
        predictions.append(
            {
                "physical_record_id": physical_id,
                "relative_path": _scalar(record.row.get("relative_path")),
                "record_index": int(record.row.get("record_index") or 0),
                "label": "malicious",
                "confidence": round(selection.confidence, 4),
                "reason": selection.reason,
                "association_strength": selection.edge,
                "anchor_engine": selection.anchor_engine,
            }
        )

    source_counts = Counter(record.fmt for record in records)
    selected_source_counts = Counter(
        record_by_id[item["physical_record_id"]].fmt for item in predictions
    )
    edge_counts = Counter(item["association_strength"] for item in predictions)
    storyline_tactic_predictions: list[dict[str, Any]] = []
    if predict_storyline_tactics:
        tactic_context = TacticEvidenceContext(records, graph.selected)
        for prediction in predictions:
            physical_id = prediction["physical_record_id"]
            tactic_claim = infer_storyline_tactic(
                record_by_id[physical_id],
                graph.selected[physical_id],
                tactic_context,
            )
            if tactic_claim is None:
                continue
            tactic, confidence, reason = tactic_claim
            storyline_tactic_predictions.append(
                {
                    "evidence_physical_record_id": physical_id,
                    "tactic": tactic,
                    "confidence": round(confidence, 4),
                    "reason": reason,
                }
            )
    tactic_counts = Counter(item["tactic"] for item in storyline_tactic_predictions)
    output = {
        "detector": DETECTOR_NAME,
        "detector_version": DETECTOR_VERSION,
        "analysis_summary": (
            f"record-index graph detector v{DETECTOR_VERSION} ran {len(discoveries)} "
            f"independent discovery engines, found "
            f"{sum(len(items) for items in discoveries.values())} anchors, and selected {len(predictions)} bounded physical records"
        ),
        "predictions": predictions,
        "diagnostics": {
            "case_id": case_id,
            "records_indexed": len(records),
            "source_counts": dict(sorted(source_counts.items())),
            "selected_source_counts": dict(sorted(selected_source_counts.items())),
            "discovery_anchor_counts": {
                engine: len(items) for engine, items in discoveries.items()
            },
            "association_edge_counts": dict(sorted(edge_counts.items())),
            "allowlisted_source_formats": sorted(SOURCE_FIELD_ALLOWLIST),
        },
    }
    if predict_storyline_tactics:
        output["storyline_tactic_predictions"] = storyline_tactic_predictions
        output["diagnostics"]["storyline_tactic_prediction_enabled"] = True
        output["diagnostics"]["storyline_tactic_prediction_counts"] = dict(
            sorted(tactic_counts.items())
        )
    finding_output = {
        "schema_version": 2,
        "detector": DETECTOR_NAME,
        "detector_version": DETECTOR_VERSION,
        "findings": findings,
        "diagnostics": output["diagnostics"],
    }
    return output, finding_output


__all__ = [
    "BoundedGraph",
    "Record",
    "SOURCE_FIELD_ALLOWLIST",
    "allowlisted_features",
    "detect_record_graph",
    "discover_ioc",
    "discover_periodic",
    "discover_scheduled_task",
    "discover_terminal",
    "discover_web",
    "infer_storyline_tactic",
    "normalize_records",
]
