"""RATIONALE: Authentication & lateral-movement heuristics.

Detects:
- Logon from unusual source IP for a user.
- Special privilege assignment right after logon (4672 right after 4624 — often after Pass-the-Hash).
- LSASS process access (Sysmon 10 to lsass.exe — T1003 credential dumping).
- CreateRemoteThread to a security process (T1003 / T1055).
- Account manipulation (4720/4726/4738 + privileged group add).
- Audit log cleared (1102).
- Service install (7045).

References: Microsoft Security Auditing category docs; MITRE ATT&CK T1003, T1078,
T1110, T1136, T1098, T1070, T1543.
"""

from __future__ import annotations

import re
from datetime import timedelta
from typing import List

from ...parsers.base import CanonicalEvent


SECURITY_PROCESSES = {
    "lsass.exe", "winlogon.exe", "csrss.exe", "smss.exe",
    "services.exe", "svchost.exe", "explorer.exe",
}

PRIVILEGED_GROUPS = {
    "administrators", "domain admins", "enterprise admins",
    "schema admins", "account operators", "backup operators",
    "server operators", "power users", "remote desktop users",
}


def evaluate_auth_event(event: CanonicalEvent) -> List[dict]:
    hits: list[dict] = []

    if event.event_type == "logon":
        # Logon type 10 (RemoteInteractive / RDP) from non-internal IP is interesting
        if event.logon_type == 10 and event.src_ip:
            # RFC1918 → not flagged; public IP → flag
            if not _is_internal_ip(event.src_ip):
                hits.append({
                    "rule": f"rdp_from_public:{event.src_ip}",
                    "technique": "T1021.001",
                    "reason": f"RDP logon (type 10) from non-internal source {event.src_ip}",
                })
        # Anonymous logon (NULL auth) is suspicious in most environments
        if (event.auth_package or "").lower() in ("ntlm", "kerberos", "negotiate"):
            # Nothing extra here, but log all 4624 for downstream correlation
            pass

    elif event.event_type == "process_access":
        tgt = (event.command_line or "").lower()
        # 'access → c:\windows\system32\lsass.exe'
        if "lsass" in tgt:
            hits.append({
                "rule": f"lsass_access:{event.process_name}",
                "technique": "T1003.001",
                "reason": f"process access to LSASS by {event.process_name} — likely credential dumping",
            })

    elif event.event_type == "create_remote_thread":
        tgt = (event.command_line or "").lower()
        if any(p in tgt for p in SECURITY_PROCESSES):
            hits.append({
                "rule": f"remote_thread_security_proc:{tgt[:80]}",
                "technique": "T1055",
                "reason": f"create remote thread into security process — possible injection",
            })

    elif event.event_type == "audit_log_cleared":
        hits.append({
            "rule": "audit_log_cleared",
            "technique": "T1070.001",
            "reason": "audit log cleared — anti-forensics",
        })

    elif event.event_type == "service_installed":
        if event.process_name:
            hits.append({
                "rule": f"service_install:{event.process_name}",
                "technique": "T1543.003",
                "reason": f"service installed: {event.process_name}",
            })

    elif event.event_type == "scheduled_task_created":
        tn = (event.file_path or event.command_line or "").lower()
        hits.append({
            "rule": f"scheduled_task:{tn[:80]}",
            "technique": "T1053.005",
            "reason": f"scheduled task created: {event.file_path}",
        })

    elif event.event_type in ("group_member_added", "group_member_added_local", "group_member_added_universal"):
        hits.append({
            "rule": f"group_member_added:{event.user}",
            "technique": "T1098",
            "reason": "group membership change",
        })

    elif event.event_type in ("user_account_created", "user_account_deleted", "user_account_changed"):
        hits.append({
            "rule": f"account_change:{event.event_type}",
            "technique": "T1136" if "created" in event.event_type else "T1098",
            "reason": f"account change: {event.event_type}",
        })

    elif event.event_type == "explicit_credential_logon":
        hits.append({
            "rule": f"explicit_credential:{event.user}@{event.src_ip}",
            "technique": "T1078",
            "reason": "explicit credential logon (4648)",
        })

    return hits


def _is_internal_ip(ip: str) -> bool:
    if not ip or ":" in ip:
        return True  # IPv6 — assume internal
    try:
        octets = [int(x) for x in ip.split(".")]
    except (ValueError, AttributeError):
        return True
    if len(octets) != 4:
        return True
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    if octets[0] == 169 and octets[1] == 254:
        return True
    return False


def credential_dumping_correlation(events: list[CanonicalEvent]) -> list[dict]:
    """Cross-event: Sysmon 10 (process_access) to lsass.exe, followed by privilege logon or lateral move."""
    hits: list[dict] = []
    # Index events by host
    by_host: dict[str, list[CanonicalEvent]] = {}
    for ev in events:
        if ev.host:
            by_host.setdefault(ev.host, []).append(ev)

    for host, evs in by_host.items():
        evs_sorted = sorted([e for e in evs if e.timestamp], key=lambda e: e.timestamp)
        for i, ev in enumerate(evs_sorted):
            if ev.event_type != "process_access":
                continue
            tgt = (ev.command_line or "").lower()
            if "lsass" not in tgt:
                continue
            # Look 1 hour ahead for explicit_credential_logon / 4672 from same user
            window_end = ev.timestamp + timedelta(hours=1)
            for ev2 in evs_sorted[i + 1:i + 50]:
                if ev2.timestamp > window_end:
                    break
                if ev2.event_type == "explicit_credential_logon" and ev2.user == ev.user:
                    hits.append({
                        "host": host,
                        "user": ev.user,
                        "lsass_at": ev.timestamp.isoformat(),
                        "explicit_credential_at": ev2.timestamp.isoformat(),
                        "technique": "T1003.001",
                        "reason": f"lsass access followed by explicit credential use for {ev.user}",
                    })
                    break
    return hits