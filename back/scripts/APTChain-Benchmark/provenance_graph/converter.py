"""Convert EvidenceForge eCAR records into a DARPA TC-inspired property graph."""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import ValidationError

from provenance_graph.models import (
    ConversionResult,
    DatasetCatalog,
    DatasetSpec,
    EcarRecord,
    EdgeLabel,
    GraphEdge,
    GraphNode,
    NodeType,
    SourceReference,
    SpadeEdge,
    SpadeVertex,
)

LOGGER = logging.getLogger(__name__)
SCHEMA_VERSION = "0.1.0"

EVENT_TYPES: dict[tuple[str, str], str] = {
    ("PROCESS", "CREATE"): "EVENT_EXECUTE",
    ("PROCESS", "OPEN"): "EVENT_OPEN_PROCESS",
    ("PROCESS", "TERMINATE"): "EVENT_EXIT",
    ("FILE", "CREATE"): "EVENT_CREATE_OBJECT",
    ("FILE", "READ"): "EVENT_READ",
    ("FILE", "WRITE"): "EVENT_WRITE",
    ("FILE", "DELETE"): "EVENT_UNLINK",
    ("MODULE", "LOAD"): "EVENT_LOADLIBRARY",
    ("FLOW", "CONNECT"): "EVENT_CONNECT",
    ("REGISTRY", "MODIFY"): "EVENT_REGISTRY_MODIFY",
    ("THREAD", "REMOTE_CREATE"): "EVENT_INJECT",
    ("USER_SESSION", "LOGIN"): "EVENT_LOGIN",
    ("USER_SESSION", "LOGOUT"): "EVENT_LOGOUT",
}


class ProvenanceConversionError(RuntimeError):
    """Raised when a dataset cannot be converted without corrupting the graph."""


class _NodeStore:
    """Merge repeated observations of CDM-like entities."""

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.conflicts: list[str] = []

    def ensure(
        self,
        *,
        node_id: str,
        node_type: NodeType,
        host: str | None,
        natural_key: str,
        timestamp_ns: int,
        properties: dict[str, Any] | None = None,
    ) -> str:
        """Create or enrich a node and return its identifier."""
        incoming_properties = _compact_dict(properties or {})
        existing = self.nodes.get(node_id)
        if existing is None:
            self.nodes[node_id] = GraphNode(
                id=node_id,
                type=node_type,
                host=host,
                natural_key=natural_key,
                first_seen_ns=timestamp_ns,
                last_seen_ns=timestamp_ns,
                properties=incoming_properties,
            )
            return node_id

        if existing.type != node_type:
            raise ProvenanceConversionError(
                f"node {node_id} changed type from {existing.type} to {node_type}"
            )

        existing.first_seen_ns = min(existing.first_seen_ns, timestamp_ns)
        existing.last_seen_ns = max(existing.last_seen_ns, timestamp_ns)
        if existing.host != host and host is not None:
            observers = set(existing.properties.get("observed_on_hosts", []))
            if existing.host is not None:
                observers.add(existing.host)
            observers.add(host)
            existing.host = None
            existing.properties["observed_on_hosts"] = sorted(observers)

        for key, value in incoming_properties.items():
            if key not in existing.properties or existing.properties[key] in (None, "", "-"):
                existing.properties[key] = value
            elif existing.properties[key] != value and key not in {"pid", "tid"}:
                conflict = f"{node_id}:{key}"
                if conflict not in self.conflicts:
                    self.conflicts.append(conflict)
        return node_id


class _UnionFind:
    """Small dependency-free weak-component implementation for readiness metrics."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}
        self.size: dict[str, int] = {}

    def add(self, item: str) -> None:
        """Add a graph node if it has not been seen."""
        if item not in self.parent:
            self.parent[item] = item
            self.size[item] = 1

    def find(self, item: str) -> str:
        """Return the component root with path compression."""
        self.add(item)
        parent = self.parent[item]
        if parent != item:
            self.parent[item] = self.find(parent)
        return self.parent[item]

    def union(self, left: str, right: str) -> None:
        """Merge two weak components."""
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        if self.size[left_root] < self.size[right_root]:
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root
        self.size[left_root] += self.size[right_root]


def _stable_id(kind: str, natural_key: str) -> str:
    """Build a deterministic UUID for entities that lack a native UUID."""
    return str(uuid5(NAMESPACE_URL, f"evidenceforge-provenance:{kind}:{natural_key}"))


def _native_or_stable_id(kind: str, value: str) -> str:
    """Preserve valid source UUIDs and deterministically map any other identifier."""
    try:
        return str(UUID(value))
    except ValueError:
        return _stable_id(kind, value)


def _compact_dict(values: dict[str, Any]) -> dict[str, Any]:
    """Drop absent values while preserving meaningful zero and false values."""
    return {key: value for key, value in values.items() if value is not None and value != ""}


def _host_id(hostname: str) -> str:
    return _stable_id("host", hostname.lower())


def _principal_id(principal: str) -> str:
    return _stable_id("principal", principal.lower())


def _process_id(source_id: str) -> str:
    return _native_or_stable_id("process", source_id)


def _object_id(kind: str, source_id: str) -> str:
    return _native_or_stable_id(kind.lower(), source_id)


def _read_jsonl(path: Path) -> Iterable[tuple[int, dict[str, Any]]]:
    """Yield non-empty JSONL records with zero-based record indexes."""
    record_index = 0
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ProvenanceConversionError(
                    f"invalid JSON in {path} at line {line_number}: {exc.msg}"
                ) from exc
            if not isinstance(value, dict):
                raise ProvenanceConversionError(
                    f"expected an object in {path} at line {line_number}"
                )
            yield record_index, value
            record_index += 1


def _write_jsonl(path: Path, records: Iterable[GraphNode | GraphEdge | EdgeLabel]) -> None:
    """Atomically write validated model instances as compact JSONL."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        temporary_path = Path(handle.name)
        for record in records:
            handle.write(record.model_dump_json(exclude_none=True))
            handle.write("\n")
    os.replace(temporary_path, path)


def _write_spade_jsonl(path: Path, records: Iterable[SpadeVertex | SpadeEdge]) -> None:
    """Atomically write SPADE JSON reporter records with aliased edge keys."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        temporary_path = Path(handle.name)
        for record in records:
            handle.write(record.model_dump_json(by_alias=True))
            handle.write("\n")
    os.replace(temporary_path, path)


def _write_json(path: Path, value: dict[str, Any]) -> None:
    """Atomically write a deterministic JSON document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        temporary_path = Path(handle.name)
        json.dump(value, handle, indent=2, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
    os.replace(temporary_path, path)


def _ensure_host_and_principal(
    nodes: _NodeStore, record: EcarRecord, timestamp_ns: int
) -> tuple[str, str | None]:
    host_id = nodes.ensure(
        node_id=_host_id(record.hostname),
        node_type="HOST",
        host=record.hostname,
        natural_key=record.hostname,
        timestamp_ns=timestamp_ns,
        properties={"hostname": record.hostname},
    )
    principal_id: str | None = None
    if record.principal and record.principal != "-":
        principal_id = nodes.ensure(
            node_id=_principal_id(record.principal),
            node_type="PRINCIPAL",
            host=None,
            natural_key=record.principal,
            timestamp_ns=timestamp_ns,
            properties={"principal": record.principal},
        )
    return host_id, principal_id


def _ensure_process(
    nodes: _NodeStore,
    *,
    source_id: str,
    record: EcarRecord,
    timestamp_ns: int,
    pid: int | None = None,
    image_path: str | None = None,
    command_line: str | None = None,
    principal: str | None = None,
) -> str:
    process_id = _process_id(source_id)
    return nodes.ensure(
        node_id=process_id,
        node_type="SUBJECT",
        host=record.hostname,
        natural_key=f"{record.hostname}:{source_id}",
        timestamp_ns=timestamp_ns,
        properties=_compact_dict(
            {
                "source_uuid": source_id,
                "pid": pid,
                "image_path": image_path,
                "command_line": command_line,
                "principal": principal,
            }
        ),
    )


def _resolve_actor(
    nodes: _NodeStore,
    record: EcarRecord,
    timestamp_ns: int,
    active_pids: dict[int, str],
) -> str | None:
    source_actor_id = record.actor_id
    if source_actor_id is None and record.pid is not None:
        source_actor_id = active_pids.get(record.pid)
    if source_actor_id is None:
        return None
    return _ensure_process(
        nodes,
        source_id=source_actor_id,
        record=record,
        timestamp_ns=timestamp_ns,
        pid=record.pid,
        image_path=record.properties.get("image_path"),
        command_line=record.properties.get("command_line"),
        principal=record.principal,
    )


def _build_edge(
    *,
    record: EcarRecord,
    source: SourceReference,
    sequence: int,
    subject_id: str,
    object_id: str | None,
    causal_from: str | None,
    causal_to: str | None,
) -> GraphEdge:
    event_type = EVENT_TYPES.get(
        (record.object.upper(), record.action.upper()),
        f"EVENT_{record.object.upper()}_{record.action.upper()}",
    )
    properties = {
        "source_object": record.object,
        "source_action": record.action,
        "source_object_id": record.object_id,
        "source_actor_id": record.actor_id,
        "pid": record.pid,
        "tid": record.tid,
        "ppid": record.ppid,
        "principal": record.principal,
        **record.properties,
    }
    return GraphEdge(
        id=_native_or_stable_id("event", record.id),
        sequence=sequence,
        timestamp_ns=record.timestamp_ms * 1_000_000,
        type=event_type,
        subject_id=subject_id,
        object_id=object_id,
        causal_from=causal_from,
        causal_to=causal_to,
        host=record.hostname,
        properties=_compact_dict(properties),
        source=source,
    )


def _convert_record(
    *,
    nodes: _NodeStore,
    record: EcarRecord,
    source: SourceReference,
    sequence: int,
    active_pids: dict[int, str],
) -> GraphEdge:
    timestamp_ns = record.timestamp_ms * 1_000_000
    host_id, principal_id = _ensure_host_and_principal(nodes, record, timestamp_ns)
    object_kind = record.object.upper()
    action = record.action.upper()
    # USER_SESSION.actorID can identify a related/resumed session, not a process actor.
    # PROCESS/CREATE actorID is the parent, while image_path and command_line describe the
    # child; the dedicated branch below attributes each side with the correct properties.
    actor_id = (
        None
        if object_kind == "USER_SESSION" or (object_kind == "PROCESS" and action == "CREATE")
        else _resolve_actor(nodes, record, timestamp_ns, active_pids)
    )

    subject_id = actor_id or host_id
    object_id: str | None
    causal_from: str | None
    causal_to: str | None

    if object_kind == "PROCESS" and action == "CREATE":
        child_id = _ensure_process(
            nodes,
            source_id=record.object_id,
            record=record,
            timestamp_ns=timestamp_ns,
            pid=record.pid,
            image_path=record.properties.get("image_path"),
            command_line=record.properties.get("command_line"),
            principal=record.principal,
        )
        parent_source_id = record.actor_id
        if parent_source_id is None and record.ppid is not None:
            parent_source_id = active_pids.get(record.ppid)
        if parent_source_id is not None:
            subject_id = _ensure_process(
                nodes,
                source_id=parent_source_id,
                record=record,
                timestamp_ns=timestamp_ns,
                pid=record.ppid,
                image_path=record.properties.get("parent_image_path"),
            )
        object_id = child_id
        causal_from, causal_to = subject_id, child_id
        if record.pid is not None:
            active_pids[record.pid] = record.object_id

    elif object_kind == "PROCESS" and action == "TERMINATE":
        process_id = _ensure_process(
            nodes,
            source_id=record.object_id,
            record=record,
            timestamp_ns=timestamp_ns,
            pid=record.pid,
            image_path=record.properties.get("image_path"),
            principal=record.principal,
        )
        subject_id = process_id
        object_id = None
        causal_from = process_id
        causal_to = None
        if record.pid is not None and active_pids.get(record.pid) == record.object_id:
            del active_pids[record.pid]

    elif object_kind == "PROCESS" and action == "OPEN":
        target_source_id = str(record.properties.get("target_process_uuid") or record.object_id)
        target_id = _ensure_process(
            nodes,
            source_id=target_source_id,
            record=record,
            timestamp_ns=timestamp_ns,
            pid=_optional_int(record.properties.get("target_pid")),
            image_path=record.properties.get("target_image_path"),
        )
        object_id = target_id
        causal_from, causal_to = subject_id, target_id

    elif object_kind in {"FILE", "MODULE"}:
        node_type: NodeType = "FILE_OBJECT"
        path = str(record.properties.get("file_path") or record.object_id)
        object_id = nodes.ensure(
            node_id=_object_id(object_kind, record.object_id),
            node_type=node_type,
            host=record.hostname,
            natural_key=f"{record.hostname}:{path}",
            timestamp_ns=timestamp_ns,
            properties={
                "source_uuid": record.object_id,
                "path": path,
                "object_class": object_kind,
            },
        )
        if action in {"READ", "LOAD"}:
            causal_from, causal_to = object_id, subject_id
        else:
            causal_from, causal_to = subject_id, object_id

    elif object_kind == "FLOW":
        flow_properties = {
            key: record.properties.get(key)
            for key in (
                "src_ip",
                "src_port",
                "dst_ip",
                "dst_port",
                "protocol",
                "direction",
                "outcome",
            )
        }
        object_id = nodes.ensure(
            node_id=_object_id("flow", record.object_id),
            node_type="NET_FLOW_OBJECT",
            host=record.hostname,
            natural_key=record.object_id,
            timestamp_ns=timestamp_ns,
            properties={"source_uuid": record.object_id, **flow_properties},
        )
        if str(record.properties.get("direction", "")).upper() == "INBOUND":
            causal_from, causal_to = object_id, subject_id
        else:
            causal_from, causal_to = subject_id, object_id

    elif object_kind == "REGISTRY":
        registry_key = str(record.properties.get("registry_key") or record.object_id)
        object_id = nodes.ensure(
            node_id=_object_id("registry", record.object_id),
            node_type="REGISTRY_KEY_OBJECT",
            host=record.hostname,
            natural_key=f"{record.hostname}:{registry_key}",
            timestamp_ns=timestamp_ns,
            properties={"source_uuid": record.object_id, "registry_key": registry_key},
        )
        causal_from, causal_to = subject_id, object_id

    elif object_kind == "THREAD" and action == "REMOTE_CREATE":
        thread_id = nodes.ensure(
            node_id=_object_id("thread", record.object_id),
            node_type="THREAD",
            host=record.hostname,
            natural_key=f"{record.hostname}:{record.object_id}",
            timestamp_ns=timestamp_ns,
            properties={
                "source_uuid": record.object_id,
                "tid": record.properties.get("tgt_tid"),
            },
        )
        target_source_id = record.properties.get("target_process_uuid")
        if target_source_id:
            target_id = _ensure_process(
                nodes,
                source_id=str(target_source_id),
                record=record,
                timestamp_ns=timestamp_ns,
                pid=_optional_int(record.properties.get("target_pid")),
            )
            object_id = target_id
            causal_from, causal_to = subject_id, target_id
        else:
            object_id = thread_id
            causal_from, causal_to = subject_id, thread_id

    elif object_kind == "USER_SESSION":
        session_id = nodes.ensure(
            node_id=_object_id("session", record.object_id),
            node_type="SESSION",
            host=record.hostname,
            natural_key=f"{record.hostname}:{record.object_id}",
            timestamp_ns=timestamp_ns,
            properties={
                "source_uuid": record.object_id,
                "principal": record.principal,
                **record.properties,
            },
        )
        if action == "LOGIN":
            subject_id = principal_id or actor_id or host_id
            object_id = session_id
            causal_from, causal_to = subject_id, session_id
        else:
            subject_id = session_id
            object_id = principal_id
            causal_from, causal_to = session_id, principal_id

    else:
        object_id = nodes.ensure(
            node_id=_object_id(object_kind, record.object_id),
            node_type="UNKNOWN_OBJECT",
            host=record.hostname,
            natural_key=f"{record.hostname}:{record.object_id}",
            timestamp_ns=timestamp_ns,
            properties={"source_uuid": record.object_id, "object_class": object_kind},
        )
        causal_from, causal_to = subject_id, object_id

    return _build_edge(
        record=record,
        source=source,
        sequence=sequence,
        subject_id=subject_id,
        object_id=object_id,
        causal_from=causal_from,
        causal_to=causal_to,
    )


def _optional_int(value: Any) -> int | None:
    """Return an integer when a source property contains an integer-like value."""
    if value in (None, "", "-"):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _load_labels(dataset_root: Path, edge_ids: set[str]) -> tuple[list[EdgeLabel], dict[str, Any]]:
    labels_path = dataset_root / "RECORD_GROUND_TRUTH.jsonl"
    if not labels_path.exists():
        return [], {
            "available": False,
            "reason": "RECORD_GROUND_TRUTH.jsonl is absent",
            "all_malicious_records": 0,
            "ecar_malicious_records": 0,
        }

    labels: list[EdgeLabel] = []
    all_malicious_records = 0
    ecar_malicious_records = 0
    unmatched_ecar_records = 0
    all_storyline_ids: set[str] = set()
    ecar_storyline_ids: set[str] = set()
    for _, value in _read_jsonl(labels_path):
        if value.get("label") == "malicious":
            all_malicious_records += 1
            storyline_values = value.get("contributing_storyline_ids") or []
            all_storyline_ids.update(str(item) for item in storyline_values if item)
            if value.get("storyline_id"):
                all_storyline_ids.add(str(value["storyline_id"]))
        if value.get("source_format") != "ecar":
            continue

        native_record_id = value.get("native_record_id") or {}
        correlation_features = value.get("correlation_features") or {}
        source_event_id = native_record_id.get("id") or correlation_features.get("id")
        if not source_event_id:
            unmatched_ecar_records += 1
            continue
        edge_id = _native_or_stable_id("event", str(source_event_id))
        if edge_id not in edge_ids:
            unmatched_ecar_records += 1
            continue

        contributing_storyline_ids = [
            str(item) for item in value.get("contributing_storyline_ids", [])
        ]
        label = EdgeLabel(
            edge_id=edge_id,
            label=value["label"],
            storyline_id=value.get("storyline_id"),
            contributing_storyline_ids=contributing_storyline_ids,
            logical_event_id=value.get("logical_event_id"),
            contributing_logical_event_ids=[
                str(item) for item in value.get("contributing_logical_event_ids", [])
            ],
            physical_record_id=value["physical_record_id"],
            event_type=value["event_type"],
            provenance_kind=value["provenance_kind"],
            detectability_class=value["detectability_class"],
            detectability_reason=value["detectability_reason"],
            causal_parentage_status=value["causal_parentage_status"],
            parent_logical_event_ids=[
                str(item) for item in value.get("parent_logical_event_ids", [])
            ],
        )
        labels.append(label)
        if label.label == "malicious":
            ecar_malicious_records += 1
            ecar_storyline_ids.update(contributing_storyline_ids)
            if label.storyline_id:
                ecar_storyline_ids.add(label.storyline_id)

    labels.sort(key=lambda item: item.edge_id)
    return labels, {
        "available": True,
        "all_malicious_records": all_malicious_records,
        "ecar_malicious_records": ecar_malicious_records,
        "unmatched_ecar_records": unmatched_ecar_records,
        "all_malicious_storyline_ids": len(all_storyline_ids),
        "ecar_malicious_storyline_ids": len(ecar_storyline_ids),
    }


def _storyline_coverage(dataset_root: Path) -> tuple[int, int, float | None]:
    manifest_path = dataset_root / "OBSERVATION_MANIFEST.json"
    if not manifest_path.exists():
        return 0, 0, None
    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    storyline_events = value.get("storyline_events", [])
    total = len(storyline_events)
    covered = sum(
        1
        for event in storyline_events
        if int((event.get("source_status", {}).get("ecar", {}) or {}).get("visible", 0)) > 0
    )
    return covered, total, covered / total if total else None


def _readiness_metrics(
    *,
    dataset_root: Path,
    nodes: dict[str, GraphNode],
    edges: list[GraphEdge],
    labels: list[EdgeLabel],
) -> dict[str, Any]:
    covered_storyline_events, total_storyline_events, storyline_coverage = _storyline_coverage(
        dataset_root
    )
    malicious_edge_ids = {label.edge_id for label in labels if label.label == "malicious"}
    malicious_edges = [edge for edge in edges if edge.id in malicious_edge_ids]
    direct_labels = [
        label
        for label in labels
        if label.label == "malicious" and label.detectability_class == "direct"
    ]
    direct_ratio = len(direct_labels) / len(malicious_edge_ids) if malicious_edge_ids else None

    attributed_edges = sum(1 for edge in edges if nodes[edge.subject_id].type != "HOST")
    actor_attribution = attributed_edges / len(edges) if edges else None

    process_creates = {
        edge.object_id
        for edge in edges
        if edge.type == "EVENT_EXECUTE" and edge.object_id is not None
    }
    process_exits = {edge.subject_id for edge in edges if edge.type == "EVENT_EXIT"}
    lifecycle_ratio = (
        len(process_creates & process_exits) / len(process_creates) if process_creates else None
    )

    endpoint_integrity = (
        sum(
            1
            for edge in edges
            if edge.subject_id in nodes and (edge.object_id is None or edge.object_id in nodes)
        )
        / len(edges)
        if edges
        else None
    )

    union_find = _UnionFind()
    malicious_nodes: set[str] = set()
    for edge in malicious_edges:
        malicious_nodes.add(edge.subject_id)
        if edge.object_id is not None:
            malicious_nodes.add(edge.object_id)
            union_find.union(edge.subject_id, edge.object_id)
        else:
            union_find.add(edge.subject_id)
    component_counts = Counter(union_find.find(node_id) for node_id in malicious_nodes)
    largest_component_ratio = (
        max(component_counts.values()) / len(malicious_nodes) if malicious_nodes else None
    )

    weighted_metrics: list[tuple[float | None, float]] = [
        (storyline_coverage, 40.0),
        (direct_ratio, 15.0),
        (actor_attribution, 15.0),
        (lifecycle_ratio, 10.0),
        (endpoint_integrity, 10.0),
        (largest_component_ratio, 10.0),
    ]
    available_weight = sum(weight for metric, weight in weighted_metrics if metric is not None)
    weighted_score = sum(
        metric * weight for metric, weight in weighted_metrics if metric is not None
    )
    readiness_score = (
        round(weighted_score * 100.0 / available_weight, 2) if available_weight else None
    )

    return {
        "score_name": "provenance_graph_readiness",
        "score_scope": "conversion/graph suitability; not detector accuracy",
        "score": readiness_score,
        "components": {
            "storyline_event_coverage": {
                "value": _rounded(storyline_coverage),
                "weight": 40,
                "covered": covered_storyline_events,
                "total": total_storyline_events,
            },
            "malicious_direct_detectability": {
                "value": _rounded(direct_ratio),
                "weight": 15,
                "direct_edges": len(direct_labels),
                "malicious_edges": len(malicious_edge_ids),
            },
            "actor_attribution": {
                "value": _rounded(actor_attribution),
                "weight": 15,
                "attributed_edges": attributed_edges,
                "edges": len(edges),
            },
            "process_lifecycle_completeness": {
                "value": _rounded(lifecycle_ratio),
                "weight": 10,
                "paired_processes": len(process_creates & process_exits),
                "created_processes": len(process_creates),
            },
            "edge_endpoint_integrity": {
                "value": _rounded(endpoint_integrity),
                "weight": 10,
            },
            "malicious_subgraph_largest_component": {
                "value": _rounded(largest_component_ratio),
                "weight": 10,
                "malicious_nodes": len(malicious_nodes),
                "weak_components": len(component_counts),
            },
        },
    }


def _rounded(value: float | None) -> float | None:
    return round(value, 4) if value is not None else None


def _string_annotations(values: dict[str, Any]) -> dict[str, str]:
    """Flatten typed properties into SPADE's string-only annotation map."""
    annotations: dict[str, str] = {}
    for key, value in _compact_dict(values).items():
        if isinstance(value, (dict, list)):
            annotations[key] = json.dumps(value, ensure_ascii=False, sort_keys=True)
        elif isinstance(value, bool):
            annotations[key] = str(value).lower()
        else:
            annotations[key] = str(value)
    return annotations


def _spade_vertex_type(node_type: NodeType) -> str:
    if node_type == "SUBJECT":
        return "Subject"
    if node_type == "PRINCIPAL":
        return "Principal"
    return "Object"


def _spade_cdm_type(node_type: NodeType) -> str:
    return {
        "HOST": "Host",
        "PRINCIPAL": "Principal",
        "SUBJECT": "Subject",
        "FILE_OBJECT": "FileObject",
        "NET_FLOW_OBJECT": "NetFlowObject",
        "REGISTRY_KEY_OBJECT": "RegistryKeyObject",
        "SESSION": "UserSession",
        "THREAD": "Thread",
        "UNKNOWN_OBJECT": "Object",
    }[node_type]


def _spade_records(
    nodes: list[GraphNode], edges: list[GraphEdge]
) -> Iterable[SpadeVertex | SpadeEdge]:
    """Yield vertices before edges, as required by SPADE's reporters."""
    for node in nodes:
        yield SpadeVertex(
            id=node.id,
            type=_spade_vertex_type(node.type),
            annotations=_string_annotations(
                {
                    "uuid": node.id,
                    "cdm.type": _spade_cdm_type(node.type),
                    "host": node.host,
                    "naturalKey": node.natural_key,
                    "firstSeenNanos": node.first_seen_ns,
                    "lastSeenNanos": node.last_seen_ns,
                    **node.properties,
                }
            ),
        )
    for edge in edges:
        from_id = edge.causal_from or edge.subject_id
        to_id = edge.causal_to or edge.object_id or edge.subject_id
        yield SpadeEdge(
            from_id=from_id,
            to_id=to_id,
            annotations=_string_annotations(
                {
                    "eventUuid": edge.id,
                    "cdm.type": edge.type,
                    "timestampNanos": edge.timestamp_ns,
                    "sequence": edge.sequence,
                    "host": edge.host,
                    "subjectUuid": edge.subject_id,
                    "objectUuid": edge.object_id,
                    "source.format": edge.source.format,
                    "source.relativePath": edge.source.relative_path,
                    "source.recordIndex": edge.source.record_index,
                    **edge.properties,
                }
            ),
        )


def _input_inventory(data_dir: Path) -> dict[str, Any]:
    all_files = [path for path in data_dir.glob("**/*") if path.is_file()]
    ecar_files = sorted(path for path in all_files if path.name == "ecar.json")
    suffix_counts = Counter(path.name for path in all_files if path.name != "ecar.json")
    return {
        "converted": {
            "ecar": [path.relative_to(data_dir).as_posix() for path in ecar_files],
        },
        "deferred_evidence_sources": dict(sorted(suffix_counts.items())),
        "deferred_reason": (
            "v0.1 uses eCAR as the canonical host-provenance source; parallel raw logs are "
            "kept out of the causal graph to prevent duplicate events and label leakage"
        ),
    }


def convert_dataset(
    *,
    dataset_name: str,
    dataset_root: Path,
    output_root: Path,
    include_offline_labels: bool = True,
) -> ConversionResult:
    """Convert one EvidenceForge output directory into graph JSONL files.

    Args:
        dataset_name: Stable name for the generated graph directory.
        dataset_root: EvidenceForge output root containing ``data/``.
        output_root: Parent directory for converted graph artifacts.
        include_offline_labels: Generate a physically separate labels file when ground truth exists.

    Returns:
        Counts and readiness score for the converted dataset.

    Raises:
        ProvenanceConversionError: If required input is missing or malformed.
    """
    dataset_root = dataset_root.resolve()
    data_dir = dataset_root / "data"
    if not data_dir.is_dir():
        raise ProvenanceConversionError(
            f"dataset {dataset_name} has no data/ directory: {data_dir}"
        )
    ecar_files = sorted(data_dir.glob("**/ecar.json"))
    if not ecar_files:
        raise ProvenanceConversionError(f"dataset {dataset_name} contains no data/**/ecar.json")

    nodes = _NodeStore()
    edges: list[GraphEdge] = []
    source_sequence = 0
    for ecar_path in ecar_files:
        active_pids: dict[int, str] = {}
        relative_path = ecar_path.relative_to(data_dir).as_posix()
        for record_index, value in _read_jsonl(ecar_path):
            try:
                record = EcarRecord.model_validate(value)
            except ValidationError as exc:
                raise ProvenanceConversionError(
                    f"invalid eCAR record {relative_path}:{record_index}: {exc}"
                ) from exc
            source = SourceReference(
                relative_path=relative_path,
                record_index=record_index,
                source_instance=ecar_path.parent.name,
            )
            edges.append(
                _convert_record(
                    nodes=nodes,
                    record=record,
                    source=source,
                    sequence=source_sequence,
                    active_pids=active_pids,
                )
            )
            source_sequence += 1

    edges.sort(key=lambda edge: (edge.timestamp_ns, edge.source.relative_path, edge.sequence))
    for sequence, edge in enumerate(edges):
        edge.sequence = sequence

    output_dir = output_root.resolve() / dataset_name
    output_dir.mkdir(parents=True, exist_ok=True)
    sorted_nodes = sorted(nodes.nodes.values(), key=lambda node: (node.type, node.id))
    _write_jsonl(output_dir / "nodes.jsonl", sorted_nodes)
    _write_jsonl(output_dir / "edges.jsonl", edges)
    _write_spade_jsonl(output_dir / "spade.jsonl", _spade_records(sorted_nodes, edges))

    edge_ids = {edge.id for edge in edges}
    labels: list[EdgeLabel] = []
    label_summary: dict[str, Any] = {"available": False, "reason": "disabled"}
    if include_offline_labels:
        labels, label_summary = _load_labels(dataset_root, edge_ids)
        _write_jsonl(output_dir / "labels.jsonl", labels)

    readiness = _readiness_metrics(
        dataset_root=dataset_root,
        nodes=nodes.nodes,
        edges=edges,
        labels=labels,
    )
    node_counts = Counter(node.type for node in sorted_nodes)
    edge_counts = Counter(edge.type for edge in edges)
    malicious_edge_count = sum(label.label == "malicious" for label in labels)
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "dataset": dataset_name,
        "created_at": datetime.now(UTC).isoformat(),
        "source_dataset": str(dataset_root),
        "input_boundary": "data/",
        "input_inventory": _input_inventory(data_dir),
        "artifacts": {
            "detector_inputs": ["nodes.jsonl", "edges.jsonl"],
            "spade_json_reporter_input": "spade.jsonl",
            "offline_evaluation_only": ["labels.jsonl"],
        },
        "counts": {
            "nodes": len(sorted_nodes),
            "edges": len(edges),
            "labels": len(labels),
            "malicious_edges": malicious_edge_count,
            "nodes_by_type": dict(sorted(node_counts.items())),
            "edges_by_type": dict(sorted(edge_counts.items())),
        },
        "integrity": {
            "unique_node_ids": len(nodes.nodes) == len(sorted_nodes),
            "unique_edge_ids": len(edge_ids) == len(edges),
            "node_property_conflicts": nodes.conflicts,
        },
        "label_summary": label_summary,
        "readiness": readiness,
    }
    _write_json(output_dir / "manifest.json", manifest)

    return ConversionResult(
        dataset=dataset_name,
        output_dir=output_dir,
        node_count=len(sorted_nodes),
        edge_count=len(edges),
        labeled_edge_count=len(labels),
        malicious_edge_count=malicious_edge_count,
        readiness_score=readiness["score"],
    )


def convert_catalog(
    *,
    repository_root: Path,
    catalog_path: Path,
    output_root: Path,
    include_offline_labels: bool = True,
) -> list[ConversionResult]:
    """Convert every dataset listed in a portable catalog."""
    try:
        catalog_value = json.loads(catalog_path.read_text(encoding="utf-8"))
        catalog = DatasetCatalog.model_validate(catalog_value)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise ProvenanceConversionError(f"invalid dataset catalog {catalog_path}: {exc}") from exc

    results: list[ConversionResult] = []
    for spec in catalog.datasets:
        results.append(
            convert_dataset(
                dataset_name=spec.name,
                dataset_root=repository_root / spec.source,
                output_root=output_root,
                include_offline_labels=include_offline_labels,
            )
        )
    _write_summary_report(results, output_root)
    return results


def _write_summary_report(results: list[ConversionResult], output_root: Path) -> None:
    scored_results = [
        result.readiness_score for result in results if result.readiness_score is not None
    ]
    average_score = sum(scored_results) / len(scored_results) if scored_results else None
    lines = [
        "# Provenance Graph Conversion Summary",
        "",
        (
            "The score below measures graph conversion/readiness only. It is not the precision, "
            "recall, F1, or accuracy of any published detector."
        ),
        "",
        "| Dataset | Nodes | Edges | Malicious graph edges | Readiness / 100 |",
        "|---|---:|---:|---:|---:|",
    ]
    for result in results:
        score = f"{result.readiness_score:.2f}" if result.readiness_score is not None else "n/a"
        lines.append(
            f"| {result.dataset} | {result.node_count} | {result.edge_count} | "
            f"{result.malicious_edge_count} | {score} |"
        )
    average_display = f"{average_score:.2f}" if average_score is not None else "n/a"
    lines.append(
        f"| **Total / mean** | **{sum(item.node_count for item in results)}** | "
        f"**{sum(item.edge_count for item in results)}** | "
        f"**{sum(item.malicious_edge_count for item in results)}** | "
        f"**{average_display}** |"
    )
    lines.extend(
        [
            "",
            "Detector inputs are `nodes.jsonl` and `edges.jsonl`. `labels.jsonl` is for offline "
            "evaluation only and must never be loaded during inference.",
            "",
        ]
    )
    report_path = output_root.resolve() / "SUMMARY.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=report_path.parent,
        prefix=f".{report_path.name}.",
        delete=False,
    ) as handle:
        temporary_path = Path(handle.name)
        handle.write("\n".join(lines))
    os.replace(temporary_path, report_path)


def load_default_catalog(repository_root: Path) -> tuple[DatasetCatalog, Path]:
    """Load the checked-in seven-dataset catalog for inspection tools."""
    catalog_path = repository_root / "provenance_graph" / "datasets.json"
    value = json.loads(catalog_path.read_text(encoding="utf-8"))
    return DatasetCatalog.model_validate(value), catalog_path


def resolved_specs(
    repository_root: Path, catalog: DatasetCatalog
) -> list[tuple[DatasetSpec, Path]]:
    """Resolve catalog dataset roots without mutating the portable specs."""
    return [(spec, (repository_root / spec.source).resolve()) for spec in catalog.datasets]
