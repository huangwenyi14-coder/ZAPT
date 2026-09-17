"""Chain-level FP scorer: filter obviously-benign chains by composite score.

Signals (higher = more likely FP):
  - size = 1 isolated single event               +0.30
  - single-process chain (no diversity)          +0.20
  - all users are service accounts (root/SYSTEM) +0.40 if sshd-only
  - all processes in vendor/OS whitelist         +0.50
  - all dst_ips are internal infrastructure      +0.30

Threshold: score >= 0.50 → filter out.
"""

from __future__ import annotations

from typing import Any

# Service / system account usernames that on their own don't indicate attack intent
SERVICE_USERS = {
    "root", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "ANONYMOUS LOGON", "svc_app", "svc_backup", "ops", "admin",
    "systemd-resolve", "sysstat", "nt authority\\system",
}

# Process names that on their own are unlikely to indicate an attack (vendor / OS / service)
VENDOR_WHITELIST = {
    "systemd-resolved", "dns.exe", "pangps.exe", "runtimebroker.exe",
    "vmtoolsd.exe", "vmstatsprovider.dll", "dllhost.exe", "taskhostw.exe",
    "mpcmdrun.exe", "msmpeng.exe", "cleanmgr.exe", "googleupdater.exe",
    "vpnagent.exe", "debian-sa1", "sysstat", "irqbalance", "snapd",
    "dbus-daemon", "systemd-logind", "wmiprvse.exe", "searchindexer.exe",
    "csrss.exe", "svchost.exe", "explorer.exe", "lsass.exe", "services.exe",
}

# Internal infrastructure IPs that are usually benign (DC, DNS, DHCP, etc.)
INTERNAL_INFRA_IPS = {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}


def _proc_basename(p: str | None) -> str:
    if not p:
        return ""
    return p.split("\\")[-1].lower()


def score_chain_fp(members: list[dict]) -> tuple[float, list[str]]:
    """Return (score, list_of_signal_names_that_fired)."""
    score = 0.0
    fired: list[str] = []
    if not members:
        return 0.0, fired

    n = len(members)
    procs = {_proc_basename(m.get("process_name")) for m in members}
    procs.discard("")
    users = {m.get("user", "") for m in members if m.get("user")}
    dst_ips = {m.get("dst_ip", "") for m in members if m.get("dst_ip")}

    # Signal 1: single-event chain — high weight because single-event
    # chains with no other ID-linked events are almost always orphan
    # siblings (a file_create / registry_value_set that was linked to a
    # process by the engine but never made it into a multi-event chain).
    if n == 1:
        score += 0.60
        fired.append("n_eq_1")

    # Signal 2: single-process chain (only useful when n is small)
    if procs and len(procs) == 1 and 2 <= n <= 5:
        score += 0.20
        fired.append("single_proc_small")

    # Signal 3: service users + sshd-only activity
    if users and users.issubset(SERVICE_USERS):
        sshd_only = bool(procs) and all("/sshd" in p or p == "systemd-resolved" for p in procs)
        if sshd_only:
            score += 0.40
            fired.append("service_user_sshd_only")

    # Signal 4: all processes in vendor whitelist
    if procs and procs.issubset(VENDOR_WHITELIST):
        score += 0.50
        fired.append("vendor_whitelist")

    # Signal 5: all dst_ips are internal infrastructure
    if dst_ips and dst_ips.issubset(INTERNAL_INFRA_IPS):
        score += 0.30
        fired.append("internal_dc_only")

    return round(score, 3), fired


def filter_chains(
    chain_candidates: list[dict],
    chain_members: dict[str, list[dict]],
    threshold: float = 0.50,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Return (kept, dropped, dropped_with_reason).

    `chain_members` maps candidate_id -> list of member event dicts.
    """
    kept: list[dict] = []
    dropped: list[dict] = []
    dropped_with_reason: list[dict] = []
    for cand in chain_candidates:
        cid = cand["candidate_id"]
        members = chain_members.get(cid, [])
        score, fired = score_chain_fp(members)
        if score >= threshold:
            dropped.append(cand)
            dropped_with_reason.append({**cand, "_fp_score": score, "_fp_signals": fired})
        else:
            kept.append(cand)
    return kept, dropped, dropped_with_reason