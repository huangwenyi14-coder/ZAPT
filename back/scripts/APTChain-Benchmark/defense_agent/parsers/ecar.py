"""Parser for eCAR (NDJSON) — EvidenceForge's EDR/host telemetry format.

eCAR records carry object/action pairs (PROCESS/CREATE, FLOW/CLOSE,
USER_SESSION/LOGIN, USER_SESSION/LOGOUT, MODULE_LOAD/LOAD, FILE/CREATE).

We map object+action → CanonicalEvent.event_type, fill process/network/auth
fields from properties.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from .base import CanonicalEvent, parse_timestamp

OBJECT_ACTION_TYPE = {
    ("PROCESS", "CREATE"): "process_create",
    ("PROCESS", "TERMINATE"): "process_exit",
    ("FLOW", "OPEN"): "network_connection_open",
    ("FLOW", "CLOSE"): "network_connection_close",
    ("FLOW", "CONNECT"): "flow_connect",
    ("USER_SESSION", "LOGIN"): "user_session_login",
    ("USER_SESSION", "LOGOUT"): "user_session_logout",
    ("MODULE_LOAD", "LOAD"): "module_load",
    ("FILE", "CREATE"): "file_create",
    ("FILE", "WRITE"): "file_write",
    ("FILE", "READ"): "file_read",
    ("FILE", "DELETE"): "file_delete",
    ("REGISTRY", "CREATE"): "registry_create",
    ("REGISTRY", "SET"): "registry_value_set",
    ("REGISTRY", "DELETE"): "registry_delete",
    ("REGISTRY", "MODIFY"): "registry_modify",
}


def parse_ecar(path: Path) -> Iterator[CanonicalEvent]:
    source = "ecar"
    with path.open("r", encoding="utf-8") as fh:
        for offset, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            timestamp = parse_timestamp(record.get("timestamp_ms"))
            host = record.get("hostname", "") or ""
            object_kind = record.get("object", "")
            action = record.get("action", "")
            properties = record.get("properties") or {}

            event_type = OBJECT_ACTION_TYPE.get((object_kind, action), f"{object_kind.lower()}_{action.lower()}")

            pid = record.get("pid")
            tid = record.get("tid")
            ppid = record.get("ppid")
            process_name = properties.get("image_path") or properties.get("image")
            command_line = properties.get("command_line")
            user = record.get("principal") or properties.get("user")

            src_ip = properties.get("src_ip") or properties.get("local_ip")
            src_port = properties.get("src_port") or properties.get("local_port")
            dst_ip = properties.get("dst_ip") or properties.get("remote_ip")
            dst_port = properties.get("dst_port") or properties.get("remote_port")
            protocol = properties.get("protocol")
            domain = properties.get("hostname") or properties.get("domain")
            url = properties.get("url")
            file_path = properties.get("file_path") or properties.get("path") or properties.get("target_path")
            logon_id = properties.get("logon_id")
            auth_package = properties.get("auth_package")

            # Coerce numeric port strings
            for key in ("src_port", "dst_port"):
                val = locals().get(key)
                if isinstance(val, str):
                    try:
                        if key == "src_port":
                            src_port = int(val)
                        else:
                            dst_port = int(val)
                    except ValueError:
                        if key == "src_port":
                            src_port = None
                        else:
                            dst_port = None

            yield CanonicalEvent(
                timestamp=timestamp,
                host=host,
                source=source,
                event_type=event_type,
                pid=pid if isinstance(pid, int) else None,
                tid=tid if isinstance(tid, int) else None,
                ppid=ppid if isinstance(ppid, int) else None,
                process_name=process_name,
                command_line=command_line,
                user=user,
                src_ip=src_ip,
                src_port=src_port if isinstance(src_port, int) else None,
                dst_ip=dst_ip,
                dst_port=dst_port if isinstance(dst_port, int) else None,
                protocol=protocol,
                url=url,
                domain=domain,
                file_path=file_path,
                logon_id=logon_id,
                auth_package=auth_package,
                record_id=record.get("id") or record.get("objectID"),
                message=f"eCAR {object_kind}/{action} pid={pid}",
                raw=record,
                source_offset=offset,
            )