"""Parser for Linux/RFC3164 syslog.

Format (typical):
    <86>1 2021-01-30T10:01:26.326837Z ATK-LNX-01 sshd 667152 - - pam_unix(sshd:session): session closed for user attacker

Sometimes wrapped in RSYSLOG traditional format:
    <priority>timestamp hostname program[pid]: message

We support both.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from .base import CanonicalEvent, parse_timestamp

# Generic traditional-format syslog line
TRADITIONAL_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<rest>.*)$"
)

# RFC5424-ish (used by rsyslog/imjournal): <PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG
RFC5424_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d+)\s+"
    r"(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd>-|\[.*?\](?:\[.*?\])*)\s+(?P<msg>.*)$"
)


def _syslog_severity(pri: int) -> str:
    sev = pri & 0x07
    return {0: "emerg", 1: "alert", 2: "crit", 3: "err", 4: "warn", 5: "notice", 6: "info", 7: "debug"}.get(sev, "info")


def parse_syslog(path: Path) -> Iterator[CanonicalEvent]:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for offset, line in enumerate(fh, start=1):
            line = line.rstrip("\n")
            if not line.strip():
                continue

            m = TRADITIONAL_RE.match(line)
            if not m:
                continue
            pri = int(m.group("pri"))
            rest = m.group("rest").strip()
            severity = _syslog_severity(pri)

            host = ""
            app = ""
            procid = ""
            ts_str = ""
            msg = rest

            # Try RFC5424
            m2 = RFC5424_RE.match(line)
            if m2:
                ts_str = m2.group("ts")
                host = m2.group("host")
                app = m2.group("app")
                procid = m2.group("procid")
                msg = m2.group("msg").strip()
            else:
                # Traditional: split into tokens up to first ':'
                # Example: "2021-01-30T10:01:26.326837Z ATK-LNX-01 sshd 667152 - - pam_unix..."
                tokens = rest.split(" ", 5)
                if len(tokens) >= 5:
                    ts_str, host, app, procid, _, _, *rest_msg = tokens
                    msg = " ".join(rest_msg).strip() if rest_msg else ""
                elif len(tokens) >= 1:
                    ts_str = tokens[0]
                    host = tokens[1] if len(tokens) > 1 else ""
                    app = tokens[2] if len(tokens) > 2 else ""
                    msg = " ".join(tokens[3:]).strip()

            timestamp = parse_timestamp(ts_str) or parse_timestamp(line[:30])

            # Heuristics to enrich fields
            event_type = "syslog_message"
            process_name = app or None
            command_line = None
            user = None
            src_ip = None
            dst_ip = None
            domain = None
            url = None
            file_path = None
            logon_id = None

            low_msg = msg.lower()
            low_app = (app or "").lower()

            if "sshd" in low_app:
                if "accepted password" in low_msg or "accepted publickey" in low_msg or "session opened" in low_msg:
                    event_type = "ssh_login"
                    # "Accepted password for <user> from <ip> port <port>"
                    user = _extract_between(msg, "for ", " from ")
                    src_ip = _extract_between(msg, "from ", " port")
                    if not user:
                        user = _extract_between(msg, "session opened for user ", " ")
                elif "session closed" in low_msg or "session opened" in low_msg:
                    event_type = "ssh_session_event"
                    user = _extract_between(msg, "for user ", " ")
                    user = user or _extract_between(msg, "session opened for user ", " by")
                    user = user or _extract_between(msg, "for ", " ")
                elif "failed password" in low_msg or "authentication failure" in low_msg:
                    event_type = "ssh_login_failed"
                    user = _extract_between(msg, "for ", " from ")
                    src_ip = _extract_between(msg, "from ", " port")
            elif "sudo" in low_app:
                event_type = "sudo_command"
                user = _extract_between(msg, "for ", " :")
                command_line = _extract_after(msg, " ; ")
            elif "cron" in low_app:
                event_type = "cron_job"
                # "CRON[pid]: (user) CMD (command)"
                command_line = _extract_between(msg, "CMD (", ")")
            elif "systemd" in low_app or "systemctl" in low_msg:
                event_type = "systemd_event"
            elif "kernel" in low_app:
                event_type = "kernel_event"
            elif "ufw" in low_app or "iptables" in low_app or "firewalld" in low_app:
                event_type = "firewall_event"
            elif "pam_unix" in low_msg or "su[" in low_app:
                if "session opened" in low_msg:
                    event_type = "pam_session_opened"
                    user = _extract_between(msg, "session opened for user ", " ")
                elif "session closed" in low_msg:
                    event_type = "pam_session_closed"
                    user = _extract_between(msg, "session closed for user ", " ")
            elif "apt" in low_app or "dpkg" in low_app:
                event_type = "package_install"
            elif "named" in low_app or "dnsmasq" in low_app:
                event_type = "dns_server"

            yield CanonicalEvent(
                timestamp=timestamp,
                host=host,
                source="syslog",
                event_type=event_type,
                process_name=process_name,
                command_line=command_line,
                user=user,
                src_ip=src_ip,
                dst_ip=dst_ip,
                domain=domain,
                url=url,
                file_path=file_path,
                logon_id=logon_id,
                record_id=f"{path.name}:{offset}",
                message=msg,
                raw={"pri": pri, "severity": severity, "app": app, "procid": procid},
                source_offset=offset,
            )


def _extract_between(text: str, start_marker: str, end_marker: str) -> str | None:
    i = text.find(start_marker)
    if i < 0:
        return None
    j = text.find(end_marker, i + len(start_marker))
    if j < 0:
        return text[i + len(start_marker):].strip()
    return text[i + len(start_marker):j].strip() or None


def _extract_after(text: str, marker: str) -> str | None:
    i = text.find(marker)
    if i < 0:
        return None
    return text[i + len(marker):].strip() or None