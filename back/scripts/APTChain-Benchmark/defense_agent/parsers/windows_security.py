"""Parser for Windows Security/Event XML and Sysmon XML.

Format: <Events><Event><System><Provider Name="..."/><EventID>...</EventID>
<TimeCreated SystemTime="..."/><Computer>...</Computer></System>
<EventData><Data Name="...">value</Data>...</EventData></Event></Events>

We walk every <Event>, extract EventID + relevant Data Name fields, map to
CanonicalEvent. EventID coverage is intentionally wide; unknown IDs still
become a CanonicalEvent with event_type="win_event_<id>" so detectors can
pattern-match on raw fields if needed.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterator

from .base import CanonicalEvent, parse_timestamp

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Map EventID -> (event_type, friendly). Anything not here gets a generic type.
WIN_EVENT_TYPE_MAP = {
    4624: ("logon", "successful logon"),
    4625: ("logon_failed", "failed logon"),
    4634: ("logoff", "logoff"),
    4647: ("logoff_user_initiated", "user-initiated logoff"),
    4648: ("explicit_credential_logon", "explicit credential logon"),
    4672: ("special_privilege_assigned", "special privileges"),
    4688: ("process_create", "process create"),
    4689: ("process_exit", "process exit"),
    4698: ("scheduled_task_created", "scheduled task created"),
    4699: ("scheduled_task_deleted", "scheduled task deleted"),
    4700: ("scheduled_task_enabled", "scheduled task enabled"),
    4701: ("scheduled_task_disabled", "scheduled task disabled"),
    4702: ("scheduled_task_updated", "scheduled task updated"),
    4720: ("user_account_created", "user account created"),
    4722: ("user_account_enabled", "user account enabled"),
    4723: ("user_account_password_change", "password change attempt"),
    4724: ("user_account_password_reset", "password reset attempt"),
    4726: ("user_account_deleted", "user account deleted"),
    4728: ("group_member_added", "member added to security-enabled group"),
    4732: ("group_member_added_local", "member added to local group"),
    4738: ("user_account_changed", "user account changed"),
    4756: ("group_member_added_universal", "member added to universal group"),
    4768: ("kerberos_tgt_requested", "Kerberos TGT requested"),
    4769: ("kerberos_tgs_requested", "Kerberos service ticket requested"),
    4770: ("kerberos_tgs_renewed", "Kerberos ticket renewed"),
    4771: ("kerberos_preauth_failed", "Kerberos pre-auth failed"),
    4776: ("ntlm_validation", "NTLM credential validation"),
    4778: ("rdp_session_reconnect", "RDP session reconnected"),
    4779: ("rdp_session_disconnect", "RDP session disconnected"),
    4800: ("workstation_locked", "workstation locked"),
    4801: ("workstation_unlocked", "workstation unlocked"),
    5140: ("network_share_accessed", "network share accessed"),
    5145: ("network_share_object_accessed", "network share object accessed"),
    5156: ("windows_firewall_connection_allowed", "windows firewall allowed"),
    5157: ("windows_firewall_connection_blocked", "windows firewall blocked"),
    1102: ("audit_log_cleared", "audit log cleared"),
    7045: ("service_installed", "service installed"),
}

SYSMON_EVENT_TYPE_MAP = {
    1: ("process_create", "sysmon process create"),
    2: ("file_creation_time_changed", "file creation time changed"),
    3: ("network_connection", "sysmon network connection"),
    4: ("sysmon_service_state_changed", "sysmon service state changed"),
    5: ("process_exit", "sysmon process exit"),
    6: ("driver_loaded", "driver loaded"),
    7: ("image_loaded", "image (dll) loaded"),
    8: ("create_remote_thread", "create remote thread"),
    9: ("raw_access_read", "raw access read"),
    10: ("process_access", "process access"),
    11: ("file_create", "file create"),
    12: ("registry_create_delete", "registry create/delete"),
    13: ("registry_value_set", "registry value set"),
    14: ("registry_key_renamed", "registry key renamed"),
    15: ("file_create_stream_hash", "file stream hash"),
    17: ("pipe_created", "pipe created"),
    18: ("pipe_connected", "pipe connected"),
    22: ("dns_query", "sysmon dns query"),
    23: ("file_delete", "file delete"),
    25: ("process_tampering", "process tampering"),
    26: ("file_delete_detected", "file delete detected"),
    29: ("file_executable_created", "executable created"),
}


def _provider_kind(provider_name: str) -> str:
    p = provider_name.lower()
    if "sysmon" in p:
        return "sysmon"
    if "security-auditing" in p:
        return "security"
    return "windows_unknown"


def _event_data_to_dict(event_data_elem: ET.Element | None) -> dict[str, str]:
    if event_data_elem is None:
        return {}
    out: dict[str, str] = {}
    for data in event_data_elem.findall(f"{NS}Data"):
        name = data.attrib.get("Name", "")
        text = (data.text or "").strip()
        if name:
            out[name] = text
    if not out:
        # Fallback: positional Data elements without Name attribute
        for idx, data in enumerate(event_data_elem.findall(f"{NS}Data")):
            text = (data.text or "").strip()
            out[f"_pos_{idx}"] = text
    return out


def _extract_pid_from_subject(data: dict[str, str]) -> int | None:
    """SubjectUserSid ends with -<RID>. We don't get a real PID; skip."""
    return None


def _extract_logon(data: dict[str, str]) -> tuple[int | None, str | None, str | None]:
    logon_type = data.get("LogonType") or data.get("TargetLogonType")
    if logon_type is not None:
        try:
            logon_type = int(logon_type)
        except ValueError:
            logon_type = None
    target_user = data.get("TargetUserName") or data.get("SubjectUserName")
    logon_id = data.get("TargetLogonId") or data.get("SubjectLogonId")
    return logon_type, target_user, logon_id


def parse_windows_xml(path: Path) -> Iterator[CanonicalEvent]:
    """Parse a Windows Security or Sysmon XML file into CanonicalEvents."""
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        return
    root = tree.getroot()

    type_map = {**WIN_EVENT_TYPE_MAP, **SYSMON_EVENT_TYPE_MAP}

    for event_elem in root.findall(f"{NS}Event"):
        system_elem = event_elem.find(f"{NS}System")
        if system_elem is None:
            continue

        provider = system_elem.find(f"{NS}Provider")
        provider_name = provider.attrib.get("Name", "") if provider is not None else ""

        event_id_elem = system_elem.find(f"{NS}EventID")
        event_id = int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text else None

        time_elem = system_elem.find(f"{NS}TimeCreated")
        timestamp = parse_timestamp(time_elem.attrib.get("SystemTime") if time_elem is not None else None)

        computer_elem = system_elem.find(f"{NS}Computer")
        computer = computer_elem.text.strip() if computer_elem is not None and computer_elem.text else ""

        record_id_elem = system_elem.find(f"{NS}EventRecordID")
        record_id = record_id_elem.text.strip() if record_id_elem is not None and record_id_elem.text else None

        data = _event_data_to_dict(event_elem.find(f"{NS}EventData"))

        kind = _provider_kind(provider_name)
        if kind == "sysmon":
            source = "windows_sysmon"
            event_type, friendly = SYSMON_EVENT_TYPE_MAP.get(event_id, (f"sysmon_event_{event_id}", f"sysmon event {event_id}"))
        else:
            source = "windows_security"
            event_type, friendly = WIN_EVENT_TYPE_MAP.get(event_id, (f"win_event_{event_id}", f"win event {event_id}"))

        # Build the CanonicalEvent with common fields
        # Use Computer as host; fall back to root field
        host = computer or data.get("SubjectDomainName") or ""

        # Map Data fields → CanonicalEvent fields per EventID
        pid = None
        tid = None
        ppid = None
        process_name = None
        command_line = None
        user = data.get("SubjectUserName") or data.get("TargetUserName")
        src_ip = data.get("IpAddress") or data.get("SourceIp") or data.get("WorkstationName") or data.get("ClientAddress")
        src_port = None
        dst_ip = None
        dst_port = None
        url = None
        domain = data.get("QueryName")
        file_path = None
        registry_key = None
        logon_id = None
        logon_type = None
        http_method = None
        http_status = None

        if event_id == 4688:
            new_proc = data.get("NewProcessName") or data.get("ProcessName") or ""
            process_name = new_proc
            command_line = data.get("CommandLine") or data.get("ParentCommandLine")
            token_elev = data.get("TokenElevationType")
            parent_proc = data.get("ParentProcessName")
            logon_id = data.get("SubjectLogonId") or data.get("TargetLogonId")
            if data.get("NewProcessId"):
                try:
                    pid = int(data["NewProcessId"].rsplit("-", 1)[-1], 16)
                except (ValueError, IndexError):
                    pid = None
            if data.get("ProcessId"):
                try:
                    pid = int(data["ProcessId"].rsplit("-", 1)[-1], 16)
                except (ValueError, IndexError):
                    pid = None
            if data.get("ParentProcessId"):
                try:
                    ppid = int(data["ParentProcessId"].rsplit("-", 1)[-1], 16)
                except (ValueError, IndexError):
                    ppid = None
        elif event_id == 4624:
            logon_type, target_user, logon_id = _extract_logon(data)
            user = target_user or user
            src_ip = data.get("IpAddress") or data.get("WorkstationName")
            src_port = data.get("IpPort")
            try:
                src_port = int(src_port) if src_port else None
            except ValueError:
                src_port = None
            auth_package = data.get("AuthenticationPackageName")
        elif event_id == 4625:
            logon_type, _, _ = _extract_logon(data)
            src_ip = data.get("IpAddress") or data.get("WorkstationName")
            user = data.get("TargetUserName")
            auth_package = data.get("AuthenticationPackageName")
        elif event_id in (4634, 4647):
            user = data.get("TargetUserName") or user
            logon_id = data.get("TargetLogonId")
        elif event_id == 4698:
            task_name = data.get("TaskName")
            command_line = data.get("TaskContent")
            file_path = task_name
            logon_id = data.get("SubjectLogonId") or data.get("TargetLogonId")
        elif event_id == 1 and source == "windows_sysmon":
            process_name = data.get("Image") or data.get("OriginalFileName")
            command_line = data.get("CommandLine")
            user = data.get("User") or user
            try:
                pid = int(data["ProcessId"]) if data.get("ProcessId") else None
            except ValueError:
                pid = None
            parent_image = data.get("ParentImage")
            if parent_image and process_name:
                ppid = None  # ParentProcessId often GUID; we don't extract
            logon_id = data.get("User") or logon_id
        elif event_id == 3 and source == "windows_sysmon":
            process_name = data.get("Image")
            user = data.get("User") or user
            try:
                pid = int(data["ProcessId"]) if data.get("ProcessId") else None
            except ValueError:
                pid = None
            dst_ip = data.get("DestinationIp") or data.get("DestinationHostname")
            try:
                dst_port = int(data["DestinationPort"]) if data.get("DestinationPort") else None
            except ValueError:
                dst_port = None
            protocol = data.get("Protocol")
            logon_id = data.get("User") or logon_id
        elif event_id == 5 and source == "windows_sysmon":
            process_name = data.get("Image")
            try:
                pid = int(data["ProcessId"]) if data.get("ProcessId") else None
            except ValueError:
                pid = None
        elif event_id == 8 and source == "windows_sysmon":
            src_image = data.get("SourceImage")
            tgt_image = data.get("TargetImage")
            try:
                pid = int(data["SourceProcessId"]) if data.get("SourceProcessId") else None
            except ValueError:
                pid = None
            process_name = src_image
            command_line = f"remote_thread → {tgt_image}"
        elif event_id == 10 and source == "windows_sysmon":
            src_image = data.get("SourceImage")
            tgt_image = data.get("TargetImage")
            try:
                pid = int(data["SourceProcessId"]) if data.get("SourceProcessId") else None
            except ValueError:
                pid = None
            process_name = src_image
            command_line = f"access → {tgt_image}"
        elif event_id == 11 and source == "windows_sysmon":
            file_path = data.get("TargetFilename")
            process_name = data.get("Image")
        elif event_id == 22 and source == "windows_sysmon":
            domain = data.get("QueryName")
            url = data.get("QueryName")
            process_name = data.get("Image")
            user = data.get("User") or user
        elif event_id == 12 and source == "windows_sysmon":
            registry_key = data.get("TargetObject")
            process_name = data.get("Image")
        elif event_id == 13 and source == "windows_sysmon":
            registry_key = data.get("TargetObject")
            details = data.get("Details") or ""
            file_path = f"{data.get('TargetObject','')}={details}"
        elif event_id == 4768:
            user = data.get("TargetUserName")
            src_ip = data.get("IpAddress")
            logon_id = None
        elif event_id == 4769:
            user = data.get("TargetUserName")
            src_ip = data.get("IpAddress")
        elif event_id == 7045:
            process_name = data.get("ServiceName")
            command_line = data.get("ServiceFileName") or data.get("ImagePath")

        # Many SubjectUserSid/Data fields still carry "DOMAIN\user" — keep as-is
        if user and "\\" in user:
            user = user.split("\\")[-1]

        message = f"{provider_name} EventID={event_id} {friendly}"

        yield CanonicalEvent(
            timestamp=timestamp,
            host=host,
            source=source,
            event_type=event_type,
            pid=pid,
            tid=tid,
            ppid=ppid,
            process_name=process_name,
            command_line=command_line,
            user=user,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=data.get("Protocol"),
            url=url,
            domain=domain,
            file_path=file_path,
            registry_key=registry_key,
            logon_id=logon_id,
            logon_type=logon_type,
            http_method=http_method,
            http_status=http_status,
            record_id=record_id,
            message=message,
            raw={**data, "EventID": event_id, "Provider": provider_name},
        )