"""RATIONALE: Network-behavior heuristics — beaconing, suspicious destinations, ports.

These heuristics target observable behaviors:
- Beaconing: periodic C2 check-ins to a single destination.
- Suspicious ports: SMB / RDP / WinRM / VNC / unusual ports on outbound.
- Anomalous DNS: high NXDOMAIN rate, long random-looking queries (potential DGA),
  high TTL variance, TXT-record volume.
- DGA / tunneling: query length, entropy, charset, repetition.

Public references:
- Carbon Black / Elastic / CrowdStrike beaconing detection writeups.
- Cisco / Palo Alto / Talos blog posts on APT infrastructure.
- MITRE ATT&CK T1071 (Application Layer Protocol), T1568 (Dynamic Resolution),
  T1572 (Protocol Tunneling).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import List

from ...parsers.base import CanonicalEvent

# Common ports that should rarely initiate outbound from a workstation
SUSPICIOUS_OUTBOUND_PORTS = {
    22, 23, 135, 139, 445, 3389, 4444, 5900, 5985, 5986,
    8080, 8443, 9001, 9090, 9999,
}

# Common dynamic DNS providers (publicly known abuse vectors)
DYNAMIC_DNS_SUFFIXES = (
    ".duckdns.org", ".no-ip.com", ".no-ip.org", ".hopto.org",
    ".ddns.net", ".servegame.com", ".serveftp.com", ".myftp.org",
    ".bounceme.net", ".redirectme.net", ".dyndns.org", ".dyn.com",
    ".zapto.org", ".gotdns.ch", ".myvnc.com", ".publicip.com",
    ".myftp.biz", ".myhttp.biz", ".co.cc", ".co.nr",
    ".servegame.org", ".x64.me", ".ddns.info", ".blogspot.com",
    ".wordpress.com", ".github.io",
)

# High-entropy randomness check — DNS labels above 20 chars with mixed charset
DGA_LABEL_RE = re.compile(r"^[a-z0-9]{16,}$")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def evaluate_dns_query(event: CanonicalEvent) -> List[dict]:
    hits: list[dict] = []
    q = event.domain or ""
    if not q or event.event_type not in ("dns_query", "sysmon dns query"):
        return hits

    q_lower = q.lower()
    # 1) Dynamic DNS suffix
    for suf in DYNAMIC_DNS_SUFFIXES:
        if q_lower.endswith(suf):
            hits.append({
                "rule": f"dynamic_dns:{suf}",
                "technique": "T1568.002",
                "reason": f"query resolves via dynamic-DNS provider ({suf}) — common C2 pattern",
            })
            break

    # 2) Long / high-entropy subdomain (DGA candidate)
    label = q_lower.split(".", 1)[0] if "." in q_lower else q_lower
    if DGA_LABEL_RE.match(label) and len(label) >= 20 and shannon_entropy(label) > 3.5:
        hits.append({
            "rule": f"dga_candidate:{len(label)}@{shannon_entropy(label):.2f}",
            "technique": "T1568.002",
            "reason": f"DNS label looks machine-generated (len={len(label)}, entropy={shannon_entropy(label):.2f})",
        })

    # 3) Excessive subdomain depth (DNS tunneling)
    if q_lower.count(".") >= 6:
        hits.append({
            "rule": f"deep_subdomain:{q_lower.count('.')}",
            "technique": "T1572",
            "reason": f"subdomain depth {q_lower.count('.')} — possible DNS tunneling",
        })

    # 4) High NXDOMAIN ratio is captured at scenario level (separate helper)

    return hits


def evaluate_connection(event: CanonicalEvent) -> List[dict]:
    """Connections / flows / HTTP."""
    hits: list[dict] = []
    if event.event_type not in (
        "zeek_connection", "network_connection", "network_connection_open",
        "flow_connect", "http_request",
    ):
        return hits

    # 1) Suspicious outbound port
    if event.dst_port and event.dst_port in SUSPICIOUS_OUTBOUND_PORTS:
        hits.append({
            "rule": f"suspicious_port:{event.dst_port}",
            "technique": "T1071",
            "reason": f"outbound connection to port {event.dst_port} (commonly abused)",
        })

    # 2) Outbound to non-RFC1918 IP — flag for review
    if event.dst_ip and not _is_internal_ip(event.dst_ip):
        # Skip well-known service ports (53, 80, 443, 123) on regular hosts — only flag from non-server hosts
        if event.dst_port and event.dst_port not in (53, 80, 443, 123, 25, 587, 993, 995):
            hits.append({
                "rule": f"outbound_external:{event.dst_ip}:{event.dst_port}",
                "technique": "T1071.001",
                "reason": f"outbound to external {event.dst_ip}:{event.dst_port}",
            })

    # 3) Plaintext HTTP for what is typically a sensitive API call
    if event.event_type == "http_request":
        if event.http_method and event.http_method.upper() in ("POST", "PUT"):
            hits.append({
                "rule": f"http_upload:{event.http_method}",
                "technique": "T1041",
                "reason": f"HTTP {event.http_method} — possible data exfiltration",
            })

    # 4) High bytes out / small bytes in (upload asymmetry)
    if event.orig_bytes and event.resp_bytes is not None:
        if event.orig_bytes > 10 * max(event.resp_bytes, 1) and event.orig_bytes > 1_000_000:
            hits.append({
                "rule": f"upload_asymmetry:{event.orig_bytes}/{event.resp_bytes}",
                "technique": "T1041",
                "reason": f"orig_bytes {event.orig_bytes} >> resp_bytes {event.resp_bytes} — possible exfil",
            })

    return hits


def _is_internal_ip(ip: str) -> bool:
    if not ip or ":" in ip:
        return True
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
    if octets[0] == 100 and 64 <= octets[1] <= 127:  # CGNAT
        return True
    return False


def beaconing_detections(events: list[CanonicalEvent], min_attempts: int = 5, jitter_pct: float = 0.4) -> list[dict]:
    """Cross-event periodic check-in detector.

    For each (src_ip, dst_ip, dst_port) bucket, sort by timestamp and compute
    inter-arrival intervals. If ≥ min_attempts with low jitter, flag as beacon.
    This is a scenario-level helper, not a per-event rule.
    """
    buckets: dict[tuple, list[CanonicalEvent]] = {}
    for ev in events:
        if ev.event_type not in ("zeek_connection", "flow_connect", "network_connection", "network_connection_open"):
            continue
        if not (ev.src_ip and ev.dst_ip and ev.dst_port):
            continue
        key = (ev.src_ip, ev.dst_ip, ev.dst_port)
        buckets.setdefault(key, []).append(ev)

    beacons: list[dict] = []
    for key, evs in buckets.items():
        evs_sorted = sorted([e for e in evs if e.timestamp], key=lambda e: e.timestamp)
        if len(evs_sorted) < min_attempts:
            continue
        intervals = []
        for a, b in zip(evs_sorted, evs_sorted[1:]):
            intervals.append((b.timestamp - a.timestamp).total_seconds())
        if len(intervals) < min_attempts - 1:
            continue
        # Filter intervals > 0
        intervals = [iv for iv in intervals if iv > 0]
        if len(intervals) < min_attempts - 1:
            continue
        mean_iv = sum(intervals) / len(intervals)
        if mean_iv <= 0:
            continue
        # Coefficient of variation
        variance = sum((iv - mean_iv) ** 2 for iv in intervals) / len(intervals)
        stdev = math.sqrt(variance)
        cv = stdev / mean_iv
        if cv < jitter_pct:
            beacons.append({
                "src_ip": key[0],
                "dst_ip": key[1],
                "dst_port": key[2],
                "attempts": len(evs_sorted),
                "mean_interval": round(mean_iv, 2),
                "jitter_cv": round(cv, 3),
                "first": evs_sorted[0].timestamp.isoformat(),
                "last": evs_sorted[-1].timestamp.isoformat(),
                "technique": "T1071.001",
                "reason": f"periodic check-in to {key[1]}:{key[2]} ({len(evs_sorted)} attempts, mean {mean_iv:.0f}s, jitter {cv:.2f})",
            })
    return beacons


def horizontal_movement(events: list[CanonicalEvent]) -> list[dict]:
    """Detect candidate lateral movement: same user authenticating to multiple hosts in short window."""
    hits: list[dict] = []
    # Group successful logons by user
    by_user: dict[str, list[CanonicalEvent]] = {}
    for ev in events:
        if ev.event_type not in ("logon", "user_session_login", "ssh_login"):
            continue
        u = ev.user
        if not u:
            continue
        by_user.setdefault(u, []).append(ev)

    for u, evs in by_user.items():
        evs_sorted = sorted([e for e in evs if e.timestamp], key=lambda e: e.timestamp)
        if len(evs_sorted) < 3:
            continue
        # Sliding window of 30 minutes
        from datetime import timedelta
        for i, ev_a in enumerate(evs_sorted):
            window_end = ev_a.timestamp + timedelta(minutes=30)
            hosts_in_window = {ev_a.host}
            for ev_b in evs_sorted[i + 1:i + 20]:
                if ev_b.timestamp > window_end:
                    break
                hosts_in_window.add(ev_b.host)
            if len(hosts_in_window) >= 3:
                hits.append({
                    "user": u,
                    "hosts": sorted(hosts_in_window),
                    "first": ev_a.timestamp.isoformat(),
                    "technique": "T1021",
                    "reason": f"user {u} authenticated to {len(hosts_in_window)} hosts in 30 min",
                })
                break  # one hit per user is enough
    return hits