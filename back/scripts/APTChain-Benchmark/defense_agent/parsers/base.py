"""CanonicalEvent — 跨源统一事件模型.

每个 parser 把自家格式映射成 CanonicalEvent, 检测器只看这一种结构,
从而对多源异构数据做到"形不同而意同"。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class CanonicalEvent:
    """Unified event model shared across all parsers."""

    timestamp: datetime  # UTC, with tzinfo
    host: str  # source host (Computer / hostname / id.orig_h if Zeek)
    source: str  # windows_security / windows_sysmon / ecar / zeek_conn / zeek_dns / zeek_http / syslog
    event_type: str  # process_create / process_exit / logon / logoff / connection / dns_query / http_request / file_create / user_session_login / user_session_logout / module_load / scheduled_task / file_write / ...

    # Process / identity
    pid: int | None = None
    tid: int | None = None
    ppid: int | None = None
    process_name: str | None = None
    command_line: str | None = None
    user: str | None = None

    # Network
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    url: str | None = None
    domain: str | None = None
    user_agent: str | None = None
    http_method: str | None = None
    http_status: int | None = None
    http_status_msg: str | None = None

    # File / registry
    file_path: str | None = None
    registry_key: str | None = None

    # Auth
    logon_id: str | None = None
    logon_type: int | None = None
    auth_package: str | None = None

    # Zeek
    uid: str | None = None
    conn_state: str | None = None
    duration: float | None = None
    orig_bytes: int | None = None
    resp_bytes: int | None = None

    # Misc / debug
    record_id: str | None = None  # source-native ID (e.g., Zeek uid, EventRecordID, sysmon uuid)
    message: str | None = None  # human-readable summary
    raw: dict[str, Any] = field(default_factory=dict)
    source_offset: int | None = None  # line number / record offset

    def with_extra(self, **kwargs: Any) -> "CanonicalEvent":
        """Return a copy with extra fields overridden (useful when adding reason/verdict later)."""
        from dataclasses import replace
        return replace(self, **kwargs)


def parse_timestamp(value: Any) -> datetime | None:
    """Best-effort timestamp coercion.

    Accepts: ISO 8601 str, epoch seconds (float/int), epoch milliseconds (int).
    Returns timezone-aware UTC datetime or None.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        # Heuristic: > 1e12 → ms, else seconds
        ts = float(value)
        if ts > 1e12:
            ts = ts / 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(value, str):
        s = value.strip()
        # Zeek ts is float seconds
        try:
            f = float(s)
            return datetime.fromtimestamp(f, tz=timezone.utc)
        except ValueError:
            pass
        # ISO 8601
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    return None