"""Reconstruct a victim-side attack chain and score it against competition labels.

Detection never reads labels or ground truth. It first narrows the corpus to one
victim asset, deduplicates cross-source observations, builds process/file/network
relationships, and emits a compact ordered chain. Labels are loaded only by the
final evaluation function.

An optional Anthropic pass may relabel the already-grounded candidate steps. The
model must reference every candidate ID exactly once and cannot invent evidence.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import re
import statistics
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from defense_agent.parsers import load_scenario  # noqa: E402
from defense_agent.parsers.base import CanonicalEvent  # noqa: E402

OFFICE_IMAGES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
LOLBINS = {"mshta.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe"}
DISCOVERY_COMMANDS = ("whoami", "ipconfig", "systeminfo", "tasklist", "netstat", "nltest")
DOCUMENT_EXTENSIONS = (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf")
DOWNLOAD_EXTENSIONS = (".exe", ".dll", ".hta", ".tmp", ".dat", ".bin")
INFRASTRUCTURE_PORTS = {53, 67, 68, 88, 123, 137, 138, 139, 389, 445, 464, 636}


@dataclass
class Evidence:
    """One source-native observation cited by a reconstructed step."""

    timestamp: str
    source: str
    event_type: str
    record_id: str | None
    host: str
    pid: int | None = None
    summary: str = ""


@dataclass
class ChainStep:
    """One analyst-facing action reconstructed without answer data."""

    candidate_id: str
    timestamp: str
    kind: str
    title: str
    description: str
    confidence: float
    entities: dict[str, list[str]] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    relation_reasons: list[str] = field(default_factory=list)


def normalize_host(value: str | None) -> str:
    """Normalize FQDN and short-host representations."""
    return (value or "").split(".", 1)[0].upper()


def basename(value: str | None) -> str:
    """Return a platform-neutral lower-case basename."""
    return re.split(r"[\\/]", value or "")[-1].lower()


def iso(value: datetime) -> str:
    """Render an aware timestamp consistently."""
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def evidence(event: CanonicalEvent) -> Evidence:
    """Convert a canonical event to a compact citation."""
    return Evidence(
        timestamp=iso(event.timestamp),
        source=event.source,
        event_type=event.event_type,
        record_id=event.record_id,
        host=event.host,
        pid=event.pid,
        summary=(event.message or event.command_line or event.file_path or event.url or "")[:500],
    )


def is_external(value: str | None) -> bool:
    """Return whether an address is globally routed rather than local/infrastructure."""
    if not value:
        return False
    try:
        return not ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def victim_scope(
    events: list[CanonicalEvent], victim_host: str, victim_ip: str
) -> list[CanonicalEvent]:
    """Keep victim endpoint events and network observations initiated by the victim."""
    wanted_host = normalize_host(victim_host)
    scoped = [
        event
        for event in events
        if normalize_host(event.host) == wanted_host
        or event.src_ip == victim_ip
        or (event.host == victim_ip and event.src_ip == victim_ip)
    ]
    return sorted(scoped, key=lambda item: item.timestamp)


def suspicious_process_score(event: CanonicalEvent) -> float:
    """Score generic process characteristics without scenario-specific IOCs."""
    image = basename(event.process_name)
    command = (event.command_line or "").lower()
    path = (event.process_name or "").lower()
    score = 0.0
    if image in OFFICE_IMAGES and any(ext in command for ext in DOCUMENT_EXTENSIONS):
        score = max(score, 0.38)
    if image in LOLBINS and ("http://" in command or "https://" in command):
        score = max(score, 0.93)
    if image == "powershell.exe" and any(
        token in command for token in ("downloadfile", "webclient", "-windowstyle hidden")
    ):
        score = max(score, 0.96)
    if image == "schtasks.exe" and "/create" in command:
        score = max(score, 0.92)
    if path.endswith(".exe") and any(
        token in path for token in ("\\appdata\\local\\temp\\", "\\programdata\\")
    ):
        score = max(score, 0.76)
    if image in {"svch0st.exe", "scvhost.exe", "lsasss.exe"}:
        score = max(score, 0.98)
    return score


def process_index(
    scoped: list[CanonicalEvent], victim_host: str
) -> tuple[dict[int, CanonicalEvent], dict[int, list[CanonicalEvent]], set[int]]:
    """Build canonical process ancestry and identify suspicious PID families."""
    processes: dict[int, CanonicalEvent] = {}
    corroboration: dict[int, list[CanonicalEvent]] = defaultdict(list)
    wanted = normalize_host(victim_host)
    for event in scoped:
        if (
            normalize_host(event.host) != wanted
            or event.event_type != "process_create"
            or event.pid is None
        ):
            continue
        corroboration[event.pid].append(event)
        current = processes.get(event.pid)
        if current is None or (current.source != "ecar" and event.source == "ecar"):
            processes[event.pid] = event

    suspicious = {pid for pid, event in processes.items() if suspicious_process_score(event) >= 0.7}
    changed = True
    while changed:
        changed = False
        for pid, event in processes.items():
            if pid in suspicious:
                continue
            if event.ppid in suspicious and (
                suspicious_process_score(event) >= 0.3
                or any(token in (event.command_line or "").lower() for token in DISCOVERY_COMMANDS)
            ):
                suspicious.add(pid)
                changed = True
        for pid in tuple(suspicious):
            parent = processes.get(processes[pid].ppid or -1)
            if parent and basename(parent.process_name) in OFFICE_IMAGES | LOLBINS:
                if parent.pid not in suspicious:
                    suspicious.add(parent.pid)  # type: ignore[arg-type]
                    changed = True
    return processes, corroboration, suspicious


def related_events(
    scoped: list[CanonicalEvent], anchor: CanonicalEvent, *, seconds: float = 1.5
) -> list[CanonicalEvent]:
    """Collect cross-source copies of one fact around an anchor."""
    result: list[CanonicalEvent] = []
    anchor_image = basename(anchor.process_name)
    for event in scoped:
        if abs((event.timestamp - anchor.timestamp).total_seconds()) > seconds:
            continue
        same_process = (
            anchor.event_type == "process_create"
            and event.event_type == "process_create"
            and basename(event.process_name) == anchor_image
            and event.command_line == anchor.command_line
        )
        same_file = (
            anchor.file_path
            and event.file_path == anchor.file_path
            and event.event_type == anchor.event_type
        )
        same_network = (
            anchor.dst_ip
            and event.dst_ip == anchor.dst_ip
            and event.dst_port == anchor.dst_port
            and event.src_ip == anchor.src_ip
        )
        if same_process or same_file or same_network or event is anchor:
            result.append(event)
    return result


def nearest_pid_for_network(
    scoped: list[CanonicalEvent], event: CanonicalEvent, suspicious_pids: set[int]
) -> int | None:
    """Attribute a sensor transaction to a nearby endpoint FLOW."""
    candidates: list[tuple[float, int]] = []
    for item in scoped:
        if item.source != "ecar" or item.event_type != "flow_connect" or item.pid is None:
            continue
        if item.pid not in suspicious_pids:
            continue
        if item.dst_ip != event.dst_ip or item.dst_port != event.dst_port:
            continue
        delta = abs((item.timestamp - event.timestamp).total_seconds())
        if delta <= 4.0:
            candidates.append((delta, item.pid))
    return min(candidates)[1] if candidates else None


def extract_download_target(command: str | None) -> str | None:
    """Extract the local target of common DownloadFile syntax."""
    if not command:
        return None
    match = re.search(
        r"downloadfile\(\s*['\"][^'\"]+['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        command,
        flags=re.IGNORECASE,
    )
    return match.group(1) if match else None


def make_process_steps(
    scoped: list[CanonicalEvent],
    processes: dict[int, CanonicalEvent],
    corroboration: dict[int, list[CanonicalEvent]],
    suspicious_pids: set[int],
) -> list[ChainStep]:
    """Convert suspicious process lineage into candidate attack actions."""
    steps: list[ChainStep] = []
    discovery: list[CanonicalEvent] = []
    for pid, event in sorted(processes.items(), key=lambda item: item[1].timestamp):
        if pid not in suspicious_pids:
            continue
        image = basename(event.process_name)
        command = event.command_line or ""
        lower = command.lower()
        kind = ""
        title = ""
        description = ""
        confidence = suspicious_process_score(event)
        reasons: list[str] = []
        if image in OFFICE_IMAGES and any(ext in lower for ext in DOCUMENT_EXTENSIONS):
            kind = "initial_access"
            title = "User opened a suspicious document"
            description = f"{image} opened a document from a user-controlled path."
            confidence = 0.82
            reasons.append("Office document is the ancestor of a suspicious LOLBin chain")
        elif image == "mshta.exe" and ("http://" in lower or "https://" in lower):
            kind = "exploitation"
            title = "Office spawned mshta for a remote HTA"
            description = "mshta executed a remote URL as a child of the Office process."
            confidence = 0.98
            reasons.append("Office-to-mshta parent/child relationship with remote URL")
        elif image == "powershell.exe" and "downloadfile" in lower:
            kind = "script_download"
            title = "Hidden PowerShell downloaded a payload"
            description = "PowerShell used WebClient.DownloadFile to stage an executable."
            confidence = 0.98
            reasons.append("mshta-to-PowerShell lineage and explicit download command")
        elif any(token in lower for token in DISCOVERY_COMMANDS):
            discovery.append(event)
            continue
        elif image == "schtasks.exe" and "/create" in lower:
            kind = "persistence"
            title = "Malware created a logon scheduled task"
            description = "A suspicious parent launched schtasks.exe with /Create."
            confidence = 0.99
            reasons.append("Scheduled-task command is directly parented by suspicious malware")
        elif image.endswith(".exe") and any(
            token in (event.process_name or "").lower()
            for token in ("\\appdata\\local\\temp\\", "\\programdata\\")
        ):
            target = next(
                (
                    extract_download_target(item.command_line)
                    for item in processes.values()
                    if extract_download_target(item.command_line)
                    and basename(extract_download_target(item.command_line)) == image
                ),
                None,
            )
            suspicious_parent = event.ppid in suspicious_pids
            masquerade = image in {"svch0st.exe", "scvhost.exe", "lsasss.exe"}
            if not (target or suspicious_parent or masquerade):
                # User-writable paths are useful seeds, but common software
                # installers must not become incident steps without lineage.
                continue
            kind = "malware_start"
            title = f"Suspicious executable started: {image}"
            description = "An executable launched from a user-writable or shared data directory."
            confidence = max(0.82, confidence)
            if suspicious_parent:
                reasons.append("Process is a child of the established malicious process family")
            if target:
                reasons.append("Executable path matches an earlier DownloadFile target")
        if not kind:
            continue
        entities = {
            "process": [image],
            "process_path": [event.process_name or ""],
            "command_line": [command],
        }
        entities = {key: [value for value in values if value] for key, values in entities.items()}
        cited = related_events(scoped, event)
        steps.append(
            ChainStep(
                candidate_id=f"proc-{pid}",
                timestamp=iso(event.timestamp),
                kind=kind,
                title=title,
                description=description,
                confidence=round(confidence, 3),
                entities=entities,
                evidence=[evidence(item) for item in cited or corroboration[pid]],
                relation_reasons=reasons,
            )
        )

    if discovery:
        discovery.sort(key=lambda item: item.timestamp)
        all_evidence: list[Evidence] = []
        for item in discovery:
            all_evidence.extend(evidence(event) for event in related_events(scoped, item))
        steps.append(
            ChainStep(
                candidate_id="proc-discovery-burst",
                timestamp=iso(discovery[0].timestamp),
                kind="discovery",
                title="C2 process launched host discovery commands",
                description="Several short-lived discovery utilities share the same suspicious parent.",
                confidence=0.99,
                entities={
                    "process": sorted({basename(item.process_name) for item in discovery}),
                    "command_line": sorted({item.command_line or "" for item in discovery}),
                },
                evidence=all_evidence,
                relation_reasons=["Discovery processes share the established malware parent PID"],
            )
        )
    return steps


def make_http_steps(
    scoped: list[CanonicalEvent],
    processes: dict[int, CanonicalEvent],
    suspicious_pids: set[int],
) -> list[ChainStep]:
    """Recover downloads and periodic C2 from victim-origin HTTP observations."""
    http = [
        event
        for event in scoped
        if event.source == "zeek_http" and event.event_type == "http_request"
    ]
    groups: dict[tuple[str, int, str, str], list[CanonicalEvent]] = defaultdict(list)
    for event in http:
        uri = str(event.raw.get("uri") or "")
        groups[(event.dst_ip or "", event.dst_port or 0, event.domain or "", uri)].append(event)

    steps: list[ChainStep] = []
    for (dst_ip, dst_port, domain, uri), items in groups.items():
        items.sort(key=lambda item: item.timestamp)
        if dst_port in INFRASTRUCTURE_PORTS or not is_external(dst_ip):
            continue
        pids = {
            pid
            for item in items
            if (pid := nearest_pid_for_network(scoped, item, suspicious_pids)) is not None
        }
        if not pids:
            continue
        intervals = [
            (right.timestamp - left.timestamp).total_seconds()
            for left, right in zip(items, items[1:], strict=False)
        ]
        if len(items) >= 5 and intervals:
            mean = statistics.mean(intervals)
            cv = statistics.pstdev(intervals) / mean if mean else math.inf
            if 30 <= mean <= 3600 and cv < 0.4:
                pid = min(pids)
                proc = processes.get(pid)
                cited = [evidence(item) for item in items]
                for item in scoped:
                    if (
                        item.source == "ecar"
                        and item.event_type == "flow_connect"
                        and item.pid == pid
                        and item.dst_ip == dst_ip
                        and item.dst_port == dst_port
                        and items[0].timestamp - timedelta(seconds=3)
                        <= item.timestamp
                        <= items[-1].timestamp + timedelta(seconds=3)
                    ):
                        cited.append(evidence(item))
                steps.append(
                    ChainStep(
                        candidate_id=f"beacon-{dst_ip}-{dst_port}",
                        timestamp=iso(items[0].timestamp),
                        kind="c2_beacon",
                        title="Stable periodic C2 beacon",
                        description=(
                            f"{len(items)} HTTP requests recur every {mean:.1f}s "
                            f"(CV={cv:.3f}) from one suspicious process."
                        ),
                        confidence=0.995,
                        entities={
                            "process": [basename(proc.process_name) if proc else ""],
                            "process_path": [proc.process_name or "" if proc else ""],
                            "domain": [domain],
                            "dst_ip": [dst_ip],
                            "dst_port": [str(dst_port)],
                            "network_url": [items[0].url or ""],
                        },
                        evidence=cited,
                        relation_reasons=[
                            "Periodic network behavior",
                            "All endpoint FLOWs retain the same suspicious PID",
                        ],
                    )
                )
                continue

        representative = items[0]
        method = (representative.http_method or "").upper()
        if method != "GET" or not uri.lower().endswith(DOWNLOAD_EXTENSIONS):
            continue
        # HTA and DownloadFile traffic are already represented by their process step.
        if uri.lower().endswith(".hta") or "officeupdate" in uri.lower():
            continue
        pid = min(pids)
        proc = processes.get(pid)
        kind = "payload_download" if uri.lower().endswith((".tmp", ".bin")) else "tool_download"
        steps.append(
            ChainStep(
                candidate_id=f"http-{representative.record_id}",
                timestamp=iso(representative.timestamp),
                kind=kind,
                title="Suspicious process downloaded a payload",
                description=f"GET {domain}{uri} was attributed to PID {pid}.",
                confidence=0.96,
                entities={
                    "process": [basename(proc.process_name) if proc else ""],
                    "process_path": [proc.process_name or "" if proc else ""],
                    "domain": [domain],
                    "dst_ip": [dst_ip],
                    "dst_port": [str(dst_port)],
                    "network_url": [f"http://{domain}{uri}"],
                },
                evidence=[evidence(item) for item in items],
                relation_reasons=["Sensor HTTP request matches a nearby endpoint FLOW PID"],
            )
        )
    return steps


def make_file_and_exfil_steps(
    scoped: list[CanonicalEvent], processes: dict[int, CanonicalEvent], suspicious_pids: set[int]
) -> list[ChainStep]:
    """Recover collection, archive creation, and large outbound upload actions."""
    file_events = [
        event
        for event in scoped
        if event.source == "ecar"
        and event.pid in suspicious_pids
        and event.event_type in {"file_read", "file_create", "file_write"}
        and event.file_path
    ]
    groups: list[list[CanonicalEvent]] = []
    for event in file_events:
        if not groups or (event.timestamp - groups[-1][-1].timestamp) > timedelta(seconds=4):
            groups.append([event])
        else:
            groups[-1].append(event)

    steps: list[ChainStep] = []
    for group in groups:
        document_reads = [
            event
            for event in group
            if event.event_type == "file_read"
            and (event.file_path or "").lower().endswith(DOCUMENT_EXTENSIONS)
        ]
        created = [event for event in group if event.event_type in {"file_create", "file_write"}]
        if len(document_reads) >= 2 and not created:
            pid = document_reads[0].pid
            proc = processes.get(pid or -1)
            steps.append(
                ChainStep(
                    candidate_id=f"files-collect-{pid}-{int(group[0].timestamp.timestamp())}",
                    timestamp=iso(group[0].timestamp),
                    kind="file_collection",
                    title="Malware collected multiple user documents",
                    description="One suspicious process read several office documents in a burst.",
                    confidence=0.98,
                    entities={
                        "process": [basename(proc.process_name) if proc else ""],
                        "process_path": [proc.process_name or "" if proc else ""],
                        "file": sorted({event.file_path or "" for event in document_reads}),
                    },
                    evidence=[evidence(event) for event in document_reads],
                    relation_reasons=["Multiple sensitive-looking documents share one malware PID"],
                )
            )
        if len(document_reads) >= 2 and created:
            output = max(created, key=lambda event: event.timestamp)
            pid = output.pid
            proc = processes.get(pid or -1)
            steps.append(
                ChainStep(
                    candidate_id=f"files-archive-{pid}-{int(group[0].timestamp.timestamp())}",
                    timestamp=iso(group[0].timestamp),
                    kind="archive_create",
                    title="Malware staged collected files into an archive",
                    description="Document reads were immediately followed by creation of one data file.",
                    confidence=0.99,
                    entities={
                        "process": [basename(proc.process_name) if proc else ""],
                        "process_path": [proc.process_name or "" if proc else ""],
                        "file": sorted({event.file_path or "" for event in document_reads}),
                        "output_file": [output.file_path or ""],
                    },
                    evidence=[evidence(event) for event in group],
                    relation_reasons=["Same PID owns all input reads and the output file create"],
                )
            )

    uploads = [
        event
        for event in scoped
        if event.source == "zeek_conn"
        and event.event_type == "zeek_connection"
        and event.src_ip
        and is_external(event.dst_ip)
        and (event.orig_bytes or 0) >= 1_000_000
    ]
    for upload in uploads:
        pid = nearest_pid_for_network(scoped, upload, suspicious_pids)
        if pid is None:
            continue
        proc = processes.get(pid)
        prior_reads = [
            item
            for item in file_events
            if item.pid == pid
            and item.event_type == "file_read"
            and timedelta(seconds=0) <= upload.timestamp - item.timestamp <= timedelta(seconds=10)
        ]
        source_file = prior_reads[-1].file_path if prior_reads else ""
        steps.append(
            ChainStep(
                candidate_id=f"upload-{upload.record_id}",
                timestamp=iso(upload.timestamp),
                kind="exfiltration",
                title="Malware uploaded a staged archive over TLS",
                description=(
                    f"A suspicious PID read a local artifact and sent {upload.orig_bytes} bytes "
                    "to an external TLS service."
                ),
                confidence=0.995 if prior_reads else 0.9,
                entities={
                    "process": [basename(proc.process_name) if proc else ""],
                    "process_path": [proc.process_name or "" if proc else ""],
                    "source_file": [source_file],
                    "dst_ip": [upload.dst_ip or ""],
                    "dst_port": [str(upload.dst_port or "")],
                    "orig_bytes": [str(upload.orig_bytes or 0)],
                },
                evidence=[evidence(upload), *[evidence(item) for item in prior_reads]],
                relation_reasons=[
                    "File read, endpoint FLOW, and large sensor upload share PID/time"
                ],
            )
        )
    return steps


def reconstruct(
    events: list[CanonicalEvent], victim_host: str, victim_ip: str
) -> tuple[list[ChainStep], dict[str, Any]]:
    """Run victim-scoped deterministic reconstruction without answer data."""
    scoped = victim_scope(events, victim_host, victim_ip)
    processes, corroboration, suspicious_pids = process_index(scoped, victim_host)
    steps = [
        *make_process_steps(scoped, processes, corroboration, suspicious_pids),
        *make_http_steps(scoped, processes, suspicious_pids),
        *make_file_and_exfil_steps(scoped, processes, suspicious_pids),
    ]
    steps.sort(key=lambda item: item.timestamp)
    for index, step in enumerate(steps, 1):
        step.candidate_id = f"step-{index:03d}:{step.candidate_id}"
    return steps, {
        "all_events": len(events),
        "victim_scoped_events": len(scoped),
        "victim_reduction_ratio": round(1 - (len(scoped) / len(events)), 4) if events else 0.0,
        "processes": len(processes),
        "suspicious_processes": len(suspicious_pids),
        "candidate_steps": len(steps),
    }


def llm_relabel(steps: list[ChainStep], model: str) -> list[ChainStep]:
    """Ask Anthropic to relabel grounded steps while forbidding evidence invention."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set")
    compact = [
        {
            "candidate_id": step.candidate_id,
            "timestamp": step.timestamp,
            "kind": step.kind,
            "title": step.title,
            "entities": step.entities,
            "relations": step.relation_reasons,
        }
        for step in steps
    ]
    prompt = (
        "You are a senior incident responder. Relabel these already-grounded victim-side "
        "attack-chain steps. Do not add, remove, merge, split, or reorder candidates. Return "
        'JSON only as {"steps":[{"candidate_id":...,"title":...,'
        '"description":...,"confidence":0..1}]}. Every candidate_id must appear once.\n'
        + json.dumps(compact, ensure_ascii=False)
    )
    body = json.dumps(
        {
            "model": model,
            "max_tokens": 3000,
            "system": "Return strict JSON only. Never invent evidence.",
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode()
    request = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
            payload = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Anthropic request failed: {exc}") from exc
    text = "".join(
        block.get("text", "") for block in payload.get("content", []) if block.get("type") == "text"
    )
    parsed = json.loads(text)
    rows = parsed.get("steps", [])
    expected = {step.candidate_id for step in steps}
    received = {str(row.get("candidate_id")) for row in rows}
    if expected != received or len(rows) != len(steps):
        raise RuntimeError("LLM response did not preserve every grounded candidate exactly once")
    by_id = {step.candidate_id: step for step in steps}
    for row in rows:
        step = by_id[str(row["candidate_id"])]
        step.title = str(row.get("title") or step.title)
        step.description = str(row.get("description") or step.description)
        step.confidence = max(0.0, min(float(row.get("confidence", step.confidence)), 1.0))
    return steps


def normalized_entities(values: Iterable[str]) -> set[str]:
    """Produce comparison tokens for post-hoc label evaluation."""
    result: set[str] = set()
    for value in values:
        text = str(value).strip().lower()
        if not text:
            continue
        result.add(text)
        if "\\" in text or "/" in text:
            result.add(basename(text))
        for domain in re.findall(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", text):
            result.add(domain)
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            result.add(ip)
    return result


def step_tokens(step: ChainStep) -> set[str]:
    """Flatten predicted entities for evaluation."""
    values = [value for group in step.entities.values() for value in group]
    return normalized_entities(values)


def label_tokens(step: dict[str, Any]) -> set[str]:
    """Flatten label entities for evaluation."""
    values = [value for group in step.get("key_entities", {}).values() for value in group]
    return normalized_entities(str(value) for value in values)


def type_compatible(predicted: str, label_type: str) -> float:
    """Score broad semantic compatibility between reconstructed and label types."""
    mapping = {
        "initial_access": {"process"},
        "exploitation": {"process", "connection,process"},
        "script_download": {"process"},
        "malware_start": {"process"},
        "payload_download": {"connection"},
        "tool_download": {"connection"},
        "c2_beacon": {"beacon"},
        "discovery": {"process"},
        "persistence": {"process,scheduled_task_created", "scheduled_task_created"},
        "file_collection": {"file_collection"},
        "archive_create": {"archive_create"},
        "exfiltration": {"connection"},
    }
    return 1.0 if label_type in mapping.get(predicted, set()) else 0.0


def pair_score(predicted: ChainStep, label: dict[str, Any]) -> float:
    """Score one predicted/label action pair without influencing detection."""
    pred_time = datetime.fromisoformat(predicted.timestamp.replace("Z", "+00:00"))
    label_time = datetime.fromisoformat(str(label["timestamp"]).replace("Z", "+00:00"))
    delta = abs((pred_time - label_time).total_seconds())
    time_score = max(0.0, 1.0 - (delta / 180.0))
    pred_tokens = step_tokens(predicted)
    truth_tokens = label_tokens(label)
    overlap = len(pred_tokens & truth_tokens) / len(truth_tokens) if truth_tokens else 0.0
    kind_score = type_compatible(predicted.kind, str(label.get("event_type", "")))
    return (0.45 * overlap) + (0.35 * kind_score) + (0.20 * time_score)


def evaluate(steps: list[ChainStep], labels_path: Path) -> dict[str, Any]:
    """Order-align reconstructed steps to labels and compute chain metrics."""
    labels = json.loads(labels_path.read_text(encoding="utf-8"))["predicted_storyline"]
    n, m = len(steps), len(labels)
    dp = [[0.0] * (m + 1) for _ in range(n + 1)]
    move = [[""] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            similarity = pair_score(steps[i - 1], labels[j - 1])
            choices = [(dp[i - 1][j], "pred_skip"), (dp[i][j - 1], "label_skip")]
            if similarity >= 0.42:
                choices.append((dp[i - 1][j - 1] + similarity, "match"))
            dp[i][j], move[i][j] = max(choices, key=lambda item: item[0])
    matches: list[dict[str, Any]] = []
    i, j = n, m
    while i and j:
        action = move[i][j]
        if action == "match":
            score = pair_score(steps[i - 1], labels[j - 1])
            matches.append(
                {
                    "candidate_id": steps[i - 1].candidate_id,
                    "predicted_title": steps[i - 1].title,
                    "storyline_id": labels[j - 1]["storyline_id"],
                    "label_description": labels[j - 1]["description"],
                    "similarity": round(score, 4),
                }
            )
            i -= 1
            j -= 1
        elif action == "pred_skip":
            i -= 1
        else:
            j -= 1
    matches.reverse()
    matched_predictions = {row["candidate_id"] for row in matches}
    matched_labels = {row["storyline_id"] for row in matches}
    precision = len(matches) / n if n else 0.0
    recall = len(matches) / m if m else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    entity_accuracy = statistics.mean(row["similarity"] for row in matches) if matches else 0.0
    order_score = len(matches) / max(n, m) if max(n, m) else 0.0
    final_score = (0.45 * f1) + (0.25 * recall) + (0.15 * order_score) + (0.15 * entity_accuracy)
    return {
        "predicted_steps": n,
        "label_steps": m,
        "matched_steps": len(matches),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "order_score": round(order_score, 4),
        "entity_accuracy": round(entity_accuracy, 4),
        "final_score": round(final_score * 100, 2),
        "matches": matches,
        "false_positive_candidates": [
            step.candidate_id for step in steps if step.candidate_id not in matched_predictions
        ],
        "missed_storylines": [
            step["storyline_id"] for step in labels if step["storyline_id"] not in matched_labels
        ],
    }


def write_report(
    output_dir: Path,
    scenario: str,
    stats: dict[str, Any],
    steps: list[ChainStep],
    score: dict[str, Any] | None,
    llm_mode: str,
) -> None:
    """Write machine-readable and analyst-readable reconstruction artifacts."""
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "scenario": scenario,
        "detection_policy": "victim-only; labels/ground truth excluded until evaluation",
        "llm_mode": llm_mode,
        "stats": stats,
        "steps": [asdict(step) for step in steps],
    }
    (output_dir / "reconstructed_chain.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if score is not None:
        (output_dir / "label_score.json").write_text(
            json.dumps(score, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    lines = [
        f"# Victim-side chain reconstruction: {scenario}",
        "",
        f"- LLM mode: `{llm_mode}`",
        f"- Parsed events: {stats['all_events']}",
        f"- Victim-scoped events: {stats['victim_scoped_events']}",
        f"- Noise removed before reasoning: {stats['victim_reduction_ratio'] * 100:.2f}%",
        f"- Reconstructed steps: {len(steps)}",
    ]
    if score:
        lines.extend(
            [
                f"- Matched label steps: {score['matched_steps']}/{score['label_steps']}",
                f"- Step P/R/F1: {score['precision']:.4f}/{score['recall']:.4f}/{score['f1']:.4f}",
                f"- Order score: {score['order_score']:.4f}",
                f"- Entity accuracy: {score['entity_accuracy']:.4f}",
                f"- Final score: **{score['final_score']:.2f}/100**",
            ]
        )
    lines.extend(["", "## Reconstructed chain", ""])
    for index, step in enumerate(steps, 1):
        lines.extend(
            [
                f"### {index}. {step.title}",
                "",
                f"- Time: `{step.timestamp}`",
                f"- Kind: `{step.kind}`",
                f"- Confidence: `{step.confidence:.3f}`",
                f"- Description: {step.description}",
                f"- Relations: {'; '.join(step.relation_reasons)}",
                f"- Entities: `{json.dumps(step.entities, ensure_ascii=False)}`",
                f"- Evidence rows: {len(step.evidence)}",
                "",
            ]
        )
    (output_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", help="Scenario name under output/")
    parser.add_argument("--victim-host", default="WS-VICTIM-01")
    parser.add_argument("--victim-ip", default="10.10.20.20")
    parser.add_argument("--labels", type=Path, default=None, help="Optional post-hoc label JSON")
    parser.add_argument("--out", type=Path, default=ROOT / "defense_agent/reports_reconstruction")
    parser.add_argument("--llm", choices=("none", "anthropic"), default="none")
    parser.add_argument("--model", default="claude-haiku-4-5-20251001")
    return parser.parse_args()


def main() -> int:
    """Run reconstruction and optional post-hoc evaluation."""
    args = parse_args()
    scenario_dir = ROOT / "output" / args.scenario
    name, events = load_scenario(scenario_dir)
    steps, stats = reconstruct(events, args.victim_host, args.victim_ip)
    llm_mode = "disabled"
    if args.llm == "anthropic":
        steps = llm_relabel(steps, args.model)
        llm_mode = f"anthropic:{args.model}"
    score = evaluate(steps, args.labels) if args.labels else None
    output_dir = args.out / name
    write_report(output_dir, name, stats, steps, score, llm_mode)
    print(
        f"{name}: events={stats['all_events']} victim={stats['victim_scoped_events']} "
        f"steps={len(steps)}"
    )
    if score:
        print(
            f"matched={score['matched_steps']}/{score['label_steps']} "
            f"P/R/F1={score['precision']:.3f}/{score['recall']:.3f}/{score['f1']:.3f} "
            f"score={score['final_score']:.2f}/100"
        )
    print(f"Report: {output_dir / 'summary.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
