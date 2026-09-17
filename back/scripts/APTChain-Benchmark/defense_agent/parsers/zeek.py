"""Parser for Zeek NDJSON logs: conn.json / dns.json / http.json / files.json / ssl.json / x509.json / dhcp.json / ntp.json / ocsp.json / pe.json.

Each line is a single JSON object with Zeek's documented field names.
We map each Zeek log type to CanonicalEvent.event_type and fill network/dns/http/etc.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from .base import CanonicalEvent, parse_timestamp

# Mapping from filename → source label and event_type mapping
ZEEK_FILE_SOURCE = {
    "conn.json": "zeek_conn",
    "dns.json": "zeek_dns",
    "http.json": "zeek_http",
    "files.json": "zeek_files",
    "ssl.json": "zeek_ssl",
    "x509.json": "zeek_x509",
    "dhcp.json": "zeek_dhcp",
    "ntp.json": "zeek_ntp",
    "ocsp.json": "zeek_ocsp",
    "pe.json": "zeek_pe",
}

# Common id.orig_h / id.orig_p / id.resp_h / id.resp_p → CanonicalEvent fields
def _common_network(record: dict) -> tuple[str | None, int | None, str | None, int | None, str | None]:
    src_ip = record.get("id.orig_h")
    dst_ip = record.get("id.resp_h")
    src_port = record.get("id.orig_p")
    dst_port = record.get("id.resp_p")
    protocol = record.get("proto")
    try:
        src_port = int(src_port) if src_port is not None else None
    except (TypeError, ValueError):
        src_port = None
    try:
        dst_port = int(dst_port) if dst_port is not None else None
    except (TypeError, ValueError):
        dst_port = None
    return src_ip, src_port, dst_ip, dst_port, protocol


def parse_zeek_file(path: Path) -> Iterator[CanonicalEvent]:
    name = path.name
    source = ZEEK_FILE_SOURCE.get(name, f"zeek_{path.stem}")

    with path.open("r", encoding="utf-8") as fh:
        for offset, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            timestamp = parse_timestamp(record.get("ts"))
            src_ip, src_port, dst_ip, dst_port, protocol = _common_network(record)
            uid = record.get("uid")
            host = src_ip or "zeek_sensor"

            if name == "conn.json":
                event_type = "zeek_connection"
                duration = record.get("duration")
                conn_state = record.get("conn_state")
                orig_bytes = record.get("orig_bytes")
                resp_bytes = record.get("resp_bytes")
                service = record.get("service")
                message = f"Zeek conn {src_ip}:{src_port} → {dst_ip}:{dst_port} {protocol}/{service} state={conn_state}"
                yield CanonicalEvent(
                    timestamp=timestamp,
                    host=host,
                    source=source,
                    event_type=event_type,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=protocol,
                    duration=duration if isinstance(duration, (int, float)) else None,
                    conn_state=conn_state,
                    orig_bytes=orig_bytes if isinstance(orig_bytes, int) else None,
                    resp_bytes=resp_bytes if isinstance(resp_bytes, int) else None,
                    record_id=uid,
                    message=message,
                    raw=record,
                    source_offset=offset,
                )
            elif name == "dns.json":
                event_type = "dns_query"
                query = record.get("query")
                qtype = record.get("qtype_name") or record.get("qtype")
                rcode = record.get("rcode_name") or record.get("rcode")
                answers = record.get("answers") or []
                domain = query
                message = f"Zeek DNS {src_ip} → {dst_ip} {query} ({qtype}) {rcode}"
                yield CanonicalEvent(
                    timestamp=timestamp,
                    host=host,
                    source=source,
                    event_type=event_type,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port or 53,
                    protocol=protocol or "udp",
                    domain=domain,
                    url=query,
                    record_id=uid,
                    message=message,
                    raw={**record, "answers": answers, "qtype": qtype, "rcode": rcode},
                    source_offset=offset,
                )
            elif name == "http.json":
                event_type = "http_request"
                method = record.get("method")
                host_header = record.get("host")
                uri = record.get("uri")
                user_agent = record.get("user_agent")
                status_code = record.get("status_code")
                status_msg = record.get("status_msg")
                resp_mime = record.get("resp_mime_type")
                req_len = record.get("request_body_len")
                resp_len = record.get("response_body_len")
                url = f"{method or 'GET'} {host_header}{uri}"
                message = f"Zeek HTTP {src_ip} → {dst_ip} {method} {host_header}{uri} → {status_code} {status_msg}"
                yield CanonicalEvent(
                    timestamp=timestamp,
                    host=host,
                    source=source,
                    event_type=event_type,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port or 80,
                    protocol=protocol or "tcp",
                    url=url,
                    domain=host_header,
                    user_agent=user_agent,
                    http_method=method,
                    http_status=status_code if isinstance(status_code, int) else None,
                    http_status_msg=status_msg,
                    file_path=resp_mime,
                    orig_bytes=req_len if isinstance(req_len, int) else None,
                    resp_bytes=resp_len if isinstance(resp_len, int) else None,
                    record_id=uid,
                    message=message,
                    raw=record,
                    source_offset=offset,
                )
            elif name == "files.json":
                event_type = "file_transfer"
                fname = record.get("fuid")
                tx_hosts = record.get("tx_hosts") or []
                rx_hosts = record.get("rx_hosts") or []
                message = f"Zeek files fuid={fname} tx={tx_hosts} rx={rx_hosts}"
                yield CanonicalEvent(
                    timestamp=timestamp,
                    host=host,
                    source=source,
                    event_type=event_type,
                    src_ip=tx_hosts[0] if tx_hosts else None,
                    dst_ip=rx_hosts[0] if rx_hosts else None,
                    record_id=uid,
                    message=message,
                    raw=record,
                    source_offset=offset,
                )
            elif name == "ssl.json":
                event_type = "ssl_handshake"
                server_name = record.get("server_name")
                subject = record.get("subject")
                issuer = record.get("issuer")
                version = record.get("version")
                cipher = record.get("cipher")
                yield CanonicalEvent(
                    timestamp=timestamp,
                    host=host,
                    source=source,
                    event_type=event_type,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port or 443,
                    domain=server_name,
                    record_id=uid,
                    message=f"Zeek SSL {src_ip} → {dst_ip} SNI={server_name}",
                    raw=record,
                    source_offset=offset,
                )
            elif name == "x509.json":
                event_type = "x509_cert"
                subject = record.get("subject")
                issuer = record.get("issuer")
                yield CanonicalEvent(
                    timestamp=timestamp,
                    host=host,
                    source=source,
                    event_type=event_type,
                    record_id=record.get("fingerprint") or record.get("serial"),
                    message=f"Zeek x509 subject={subject}",
                    raw=record,
                    source_offset=offset,
                )
            elif name == "dhcp.json":
                event_type = "dhcp_lease"
                client_addr = record.get("client_addr")
                server_addr = record.get("server_addr")
                mac = record.get("mac")
                host_name = record.get("host_name")
                yield CanonicalEvent(
                    timestamp=timestamp,
                    host=host,
                    source=source,
                    event_type=event_type,
                    src_ip=client_addr,
                    dst_ip=server_addr,
                    domain=host_name,
                    record_id=uid or mac,
                    message=f"Zeek DHCP {client_addr} ← {server_addr} mac={mac}",
                    raw=record,
                    source_offset=offset,
                )
            elif name == "ntp.json":
                event_type = "ntp_request"
                yield CanonicalEvent(
                    timestamp=timestamp,
                    host=host,
                    source=source,
                    event_type=event_type,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port or 123,
                    protocol=protocol or "udp",
                    record_id=uid,
                    message=f"Zeek NTP {src_ip} → {dst_ip}",
                    raw=record,
                    source_offset=offset,
                )
            elif name == "ocsp.json":
                event_type = "ocsp_request"
                yield CanonicalEvent(
                    timestamp=timestamp,
                    host=host,
                    source=source,
                    event_type=event_type,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    record_id=uid,
                    message=f"Zeek OCSP {src_ip} → {dst_ip}",
                    raw=record,
                    source_offset=offset,
                )
            elif name == "pe.json":
                event_type = "pe_metadata"
                yield CanonicalEvent(
                    timestamp=timestamp,
                    host=host,
                    source=source,
                    event_type=event_type,
                    record_id=uid,
                    message=f"Zeek PE {record.get('machine')}",
                    raw=record,
                    source_offset=offset,
                )
            else:
                yield CanonicalEvent(
                    timestamp=timestamp,
                    host=host,
                    source=source,
                    event_type="zeek_other",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    record_id=uid,
                    message=f"Zeek {name}",
                    raw=record,
                    source_offset=offset,
                )