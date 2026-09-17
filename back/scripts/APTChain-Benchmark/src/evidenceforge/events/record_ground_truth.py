# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Record-level provenance and ground-truth sidecar support.

The generated logs intentionally remain source-native.  Provenance is carried
out-of-band while events move through the dispatcher and emitters, then written
to ``RECORD_GROUND_TRUTH.jsonl`` after the final physical records are materialized.
"""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Any, Literal, cast

from evidenceforge.utils.paths import safe_write_text

if TYPE_CHECKING:
    from evidenceforge.events.base import SecurityEvent


RECORD_GROUND_TRUTH_FILENAME = "RECORD_GROUND_TRUTH.jsonl"
RECORD_GROUND_TRUTH_SCHEMA_VERSION = 3
RECORD_PROVENANCE_KEY = "_evidenceforge_record_provenance"

RecordLabel = Literal["malicious", "red_herring", "benign"]
ProvenanceKind = Literal["storyline", "red_herring", "baseline", "raw", "unattributed"]
AttributionStatus = Literal["exact", "partial", "unattributed"]
DetectabilityClass = Literal[
    "direct",
    "association_required",
    "provenance_only",
    "not_applicable",
]


@dataclass(frozen=True, slots=True)
class RecordProvenance:
    """Generation-time provenance shared by all physical rows from one logical event."""

    logical_event_id: str
    storyline_id: str | None
    label: RecordLabel
    provenance_kind: ProvenanceKind
    event_type: str
    detectability_class: DetectabilityClass | None = None
    parent_logical_event_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation for threaded/deferred emitters."""
        data = asdict(self)
        data["parent_logical_event_ids"] = list(self.parent_logical_event_ids)
        return data

    @classmethod
    def from_value(cls, value: RecordProvenance | dict[str, Any] | None) -> RecordProvenance | None:
        """Normalize an in-memory or JSON-round-tripped provenance value."""
        if value is None or isinstance(value, cls):
            return value
        return cls(
            logical_event_id=str(value["logical_event_id"]),
            storyline_id=value.get("storyline_id"),
            label=value.get("label", "benign"),
            provenance_kind=value.get("provenance_kind", "unattributed"),
            event_type=str(value.get("event_type", "raw")),
            detectability_class=_normalize_detectability_class(value.get("detectability_class")),
            parent_logical_event_ids=tuple(value.get("parent_logical_event_ids", ())),
        )


_CURRENT_RECORD_PROVENANCE: ContextVar[RecordProvenance | None] = ContextVar(
    "evidenceforge_record_provenance",
    default=None,
)


def current_record_provenance() -> RecordProvenance | None:
    """Return provenance active for the current emitter call/thread."""
    return _CURRENT_RECORD_PROVENANCE.get()


@contextmanager
def activate_record_provenance(
    provenance: RecordProvenance | dict[str, Any] | None,
) -> Iterator[None]:
    """Temporarily activate provenance while rendering or buffering a record."""
    normalized = RecordProvenance.from_value(provenance)
    token = _CURRENT_RECORD_PROVENANCE.set(normalized)
    try:
        yield
    finally:
        _CURRENT_RECORD_PROVENANCE.reset(token)


def attach_record_provenance(
    event_data: dict[str, Any],
    provenance: RecordProvenance | dict[str, Any] | None = None,
) -> None:
    """Attach JSON-safe internal provenance to a deferred event dictionary."""
    normalized = RecordProvenance.from_value(provenance) or current_record_provenance()
    if normalized is not None:
        event_data[RECORD_PROVENANCE_KEY] = normalized.to_dict()


def pop_record_provenance(event_data: dict[str, Any]) -> RecordProvenance | None:
    """Remove and normalize internal provenance from an event dictionary."""
    return RecordProvenance.from_value(event_data.pop(RECORD_PROVENANCE_KEY, None))


class RecordGroundTruthRecorder:
    """Collect exact physical-record receipts and write the JSONL sidecar."""

    def __init__(self, output_dir: Path, dataset_id: str) -> None:
        self.output_dir = Path(output_dir).resolve()
        self.dataset_id = dataset_id
        self._lock = Lock()
        self._logical_counter = 0
        self._record_indexes: Counter[str] = Counter()
        self._records: list[dict[str, Any]] = []
        self._provenances: dict[tuple[str, int], tuple[RecordProvenance, ...]] = {}

    def provenance_for_event(self, event: SecurityEvent) -> RecordProvenance:
        """Assign stable logical provenance to a canonical event if needed."""
        with self._lock:
            if not event.logical_event_id:
                self._logical_counter += 1
                event.logical_event_id = self._logical_id(self._logical_counter, event.event_type)

        storyline_id = event.storyline_cluster_id
        if event.ground_truth_label:
            label: RecordLabel = event.ground_truth_label
        elif storyline_id and storyline_id.startswith("red_herring:"):
            label = "red_herring"
        elif storyline_id:
            label = "malicious"
        else:
            label = "benign"

        if event.provenance_kind:
            kind: ProvenanceKind = event.provenance_kind
        elif label == "malicious":
            kind = "storyline"
        elif label == "red_herring":
            kind = "red_herring"
        else:
            kind = "baseline"

        event.ground_truth_label = label
        event.provenance_kind = kind
        detectability_class = _normalize_detectability_class(event.ground_truth_detectability_class)
        return RecordProvenance(
            logical_event_id=event.logical_event_id,
            storyline_id=storyline_id,
            label=label,
            provenance_kind=kind,
            event_type=event.event_type,
            detectability_class=detectability_class,
            parent_logical_event_ids=tuple(event.parent_logical_event_ids),
        )

    def provenance_for_raw(self, event_type: str = "raw") -> RecordProvenance:
        """Create benign provenance for a raw entry that bypasses SecurityEvent."""
        with self._lock:
            self._logical_counter += 1
            logical_event_id = self._logical_id(self._logical_counter, event_type)
        return RecordProvenance(
            logical_event_id=logical_event_id,
            storyline_id=None,
            label="benign",
            provenance_kind="raw",
            event_type=event_type,
        )

    def record_written(
        self,
        *,
        output_path: Path,
        source_format: str,
        rendered: str,
        provenance: (
            RecordProvenance | dict[str, Any] | Sequence[RecordProvenance | dict[str, Any]] | None
        ) = None,
        byte_offset: int | None = None,
    ) -> dict[str, Any]:
        """Register one final logical log record after it is written."""
        provenances = _normalize_provenances(provenance)
        normalized = provenances[0] if provenances else None
        encoded = rendered.encode("utf-8")
        record_sha256 = hashlib.sha256(encoded).hexdigest()
        relative_path = self._relative_path(output_path)

        with self._lock:
            if normalized is None:
                self._logical_counter += 1
                normalized = RecordProvenance(
                    logical_event_id=self._logical_id(
                        self._logical_counter,
                        f"unattributed:{source_format}",
                    ),
                    storyline_id=None,
                    label="benign",
                    provenance_kind="unattributed",
                    event_type="unattributed",
                )
                provenances = [normalized]
            record_index = self._record_indexes[relative_path]
            self._record_indexes[relative_path] += 1
            attribution_status: AttributionStatus
            if all(item.provenance_kind == "unattributed" for item in provenances):
                attribution_status = "unattributed"
            elif any(item.provenance_kind == "unattributed" for item in provenances):
                attribution_status = "partial"
            else:
                attribution_status = "exact"
            parent_logical_event_ids = _unique_values(
                parent_id for item in provenances for parent_id in item.parent_logical_event_ids
            )
            physical_record_id = self._physical_id(
                relative_path,
                record_index,
                record_sha256,
            )
            label = _strongest_label(provenances)
            record = {
                "schema_version": RECORD_GROUND_TRUTH_SCHEMA_VERSION,
                "dataset_id": self.dataset_id,
                "physical_record_id": physical_record_id,
                "logical_event_id": normalized.logical_event_id,
                "storyline_id": normalized.storyline_id,
                "label": label,
                "provenance_kind": normalized.provenance_kind,
                "event_type": normalized.event_type,
                "parent_logical_event_ids": parent_logical_event_ids,
                "contributing_logical_event_ids": _unique_values(
                    item.logical_event_id for item in provenances
                ),
                "contributing_storyline_ids": _unique_values(
                    item.storyline_id for item in provenances if item.storyline_id
                ),
                "contributing_event_types": _unique_values(item.event_type for item in provenances),
                "attribution_status": attribution_status,
                "causal_parentage_status": (
                    "explicit" if parent_logical_event_ids else "not_available"
                ),
                "mapping_method": "generation_provenance",
                "source_format": source_format,
                "source_instance": self._source_instance(relative_path),
                "relative_path": relative_path,
                "record_index": record_index,
                "byte_offset": byte_offset,
                "byte_length": len(encoded),
                "record_sha256": record_sha256,
            }
            native_id = _extract_native_record_id(source_format, rendered)
            if native_id:
                record["native_record_id"] = native_id
            observed_time = _extract_observed_time(source_format, rendered)
            if observed_time:
                record["observed_time"] = observed_time
            correlation_features = _extract_correlation_features(source_format, rendered)
            if source_format == "bash_history":
                correlation_features.setdefault("hostname", self._source_instance(relative_path))
                filename = Path(relative_path).name
                suffix = ".bash_history"
                if filename.endswith(suffix):
                    correlation_features.setdefault("username", filename[: -len(suffix)])
            if correlation_features:
                record["correlation_features"] = correlation_features
            detectability_class, detectability_reason, required_anchor_types = (
                _classify_record_detectability(
                    label=label,
                    source_format=source_format,
                    event_types=tuple(item.event_type for item in provenances),
                    correlation_features=correlation_features,
                    explicit_classes=tuple(
                        item.detectability_class
                        for item in provenances
                        if item.detectability_class is not None
                    ),
                )
            )
            record["detectability_class"] = detectability_class
            record["detectability_reason"] = detectability_reason
            record["required_anchor_types"] = required_anchor_types
            self._records.append(record)
            self._provenances[(relative_path, record_index)] = tuple(provenances)
            return record

    def refresh_path(self, output_path: Path, source_format: str) -> None:
        """Refresh receipts after a source-native, order-preserving file rewrite.

        Finalizers such as ASA connection-ID normalization may change rendered
        bytes after the writer has flushed.  Rebuild locators and hashes from the
        final file while preserving provenance by physical record position.
        """
        relative_path = self._relative_path(output_path)
        with self._lock:
            previous = sorted(
                (record for record in self._records if record["relative_path"] == relative_path),
                key=lambda record: record["record_index"],
            )
            previous_provenances = [
                self._provenances.get(
                    (relative_path, int(record["record_index"])),
                    (_provenance_from_receipt(record),),
                )
                for record in previous
            ]
        lines = Path(output_path).read_text(encoding="utf-8").splitlines()
        if len(lines) != len(previous):
            raise ValueError(
                f"Cannot refresh {relative_path}: final record count {len(lines)} "
                f"does not match receipt count {len(previous)}"
            )
        self.remove_path(output_path)
        byte_offset = 0
        for line, provenances in zip(lines, previous_provenances, strict=True):
            self.record_written(
                output_path=output_path,
                source_format=source_format,
                rendered=line,
                provenance=provenances,
                byte_offset=byte_offset,
            )
            byte_offset += len((line + "\n").encode("utf-8"))

    def validate_final_records(self) -> None:
        """Fail if a receipt no longer identifies its exact final on-disk bytes."""
        with self._lock:
            records = list(self._records)
        seen_ids: set[str] = set()
        errors: list[str] = []
        for record in records:
            physical_id = str(record["physical_record_id"])
            if physical_id in seen_ids:
                errors.append(f"duplicate physical_record_id {physical_id}")
            seen_ids.add(physical_id)
            if record.get("attribution_status") != "exact":
                errors.append(
                    f"{physical_id}: attribution_status={record.get('attribution_status')}"
                )
            offset = record.get("byte_offset")
            if not isinstance(offset, int):
                errors.append(f"{physical_id}: missing byte_offset")
                continue
            path = self.output_dir / str(record["relative_path"])
            if not path.is_file():
                errors.append(f"{physical_id}: missing file {path}")
                continue
            with path.open("rb") as handle:
                handle.seek(offset)
                payload = handle.read(int(record["byte_length"]))
            digest = hashlib.sha256(payload).hexdigest()
            if digest != record["record_sha256"]:
                errors.append(
                    f"{physical_id}: content mismatch at {record['relative_path']}:{offset}"
                )
        if errors:
            preview = "; ".join(errors[:10])
            raise ValueError(f"Record ground-truth integrity validation failed: {preview}")

    def remove_path(self, output_path: Path) -> None:
        """Forget receipts for a file that an emitter is about to rewrite/truncate."""
        relative_path = self._relative_path(output_path)
        with self._lock:
            self._records = [r for r in self._records if r["relative_path"] != relative_path]
            self._provenances = {
                key: value for key, value in self._provenances.items() if key[0] != relative_path
            }
            self._record_indexes[relative_path] = 0

    def write_jsonl(self, output_path: Path) -> None:
        """Write receipts in deterministic file/index order."""
        with self._lock:
            records = sorted(
                self._records,
                key=lambda item: (item["relative_path"], item["record_index"]),
            )
        content = "".join(
            json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
            for record in records
        )
        safe_write_text(output_path, content, encoding="utf-8")

    @property
    def record_count(self) -> int:
        """Return the number of final physical records collected."""
        with self._lock:
            return len(self._records)

    def snapshot_records(self) -> list[dict[str, Any]]:
        """Return a stable shallow copy for derived sidecars and validation."""
        with self._lock:
            return [dict(record) for record in self._records]

    def _logical_id(self, counter: int, event_type: str) -> str:
        payload = f"{self.dataset_id}|logical|{counter}|{event_type}"
        return "le-" + hashlib.sha256(payload.encode()).hexdigest()[:24]

    def _physical_id(self, relative_path: str, record_index: int, digest: str) -> str:
        payload = f"{self.dataset_id}|physical|{relative_path}|{record_index}|{digest}"
        return "pr-" + hashlib.sha256(payload.encode()).hexdigest()[:24]

    def _relative_path(self, output_path: Path) -> str:
        path = Path(output_path).resolve()
        try:
            return path.relative_to(self.output_dir).as_posix()
        except ValueError:
            return path.as_posix()

    @staticmethod
    def _source_instance(relative_path: str) -> str:
        path = Path(relative_path)
        if path.is_absolute():
            return path.parent.name
        parts = path.parts
        return parts[0] if len(parts) > 1 else ""


_WINDOWS_FIELD_RE = {
    "computer": re.compile(r"<Computer>(.*?)</Computer>", re.DOTALL),
    "event_id": re.compile(r"<EventID[^>]*>(\d+)</EventID>"),
    "event_record_id": re.compile(r"<EventRecordID>(\d+)</EventRecordID>"),
}

_WINDOWS_CORRELATION_FIELDS = (
    "ProcessGuid",
    "ProcessId",
    "ParentProcessGuid",
    "ParentProcessId",
    "SourceProcessGuid",
    "SourceProcessId",
    "TargetProcessGuid",
    "TargetProcessId",
    "SourceIp",
    "SourcePort",
    "DestinationIp",
    "DestinationPort",
    "Protocol",
    "User",
    "SubjectUserSid",
    "SubjectUserName",
    "SubjectDomainName",
    "SubjectLogonId",
    "TargetUserSid",
    "TargetUserName",
    "TargetDomainName",
    "TargetLogonId",
    "LogonGuid",
    "LogonId",
    "Image",
    "NewProcessName",
    "ParentImage",
    "CommandLine",
    "ParentCommandLine",
    "Company",
    "Description",
    "FileVersion",
    "GrantedAccess",
    "Hashes",
    "ImageLoaded",
    "OriginalFileName",
    "Signature",
    "SignatureStatus",
    "Signed",
    "SourceImage",
    "TargetFilename",
    "TargetObject",
    "Details",
    "TargetImage",
    "QueryName",
    "QueryResults",
)

# Security audit records reuse field names with different roles.  Keep the
# public Record Index explicit per EventID so, for example, 4688 ``ProcessId``
# (creator/parent) is never confused with ``NewProcessId`` (the child), and so
# WFP/task fields are not silently dropped by one generic field list.
_WINDOWS_SECURITY_COMMON_CORRELATION_FIELDS = frozenset(
    {
        "SubjectUserSid",
        "SubjectUserName",
        "SubjectDomainName",
        "SubjectLogonId",
        "TargetUserSid",
        "TargetUserName",
        "TargetDomainName",
        "TargetLogonId",
    }
)

_WINDOWS_SECURITY_EVENT_CORRELATION_FIELDS: dict[int, frozenset[str]] = {
    4624: frozenset(
        {
            "LogonType",
            "LogonProcessName",
            "AuthenticationPackageName",
            "WorkstationName",
            "LogonGuid",
            "ProcessId",
            "ProcessName",
            "IpAddress",
            "IpPort",
            "ElevatedToken",
        }
    ),
    4688: frozenset(
        {
            "NewProcessId",
            "NewProcessName",
            "TokenElevationType",
            "ProcessId",
            "CommandLine",
            "ParentProcessName",
            "CreatorProcessName",
            "MandatoryLabel",
        }
    ),
    4689: frozenset({"Status", "ProcessId", "ProcessName"}),
    4698: frozenset(
        {
            "TaskName",
            "TaskContent",
            "ClientProcessId",
            "ParentProcessId",
            "RpcCallClientLocality",
            "FQDN",
        }
    ),
    5156: frozenset(
        {
            "ProcessID",
            "Application",
            "Direction",
            "SourceAddress",
            "SourcePort",
            "DestAddress",
            "DestPort",
            "Protocol",
            "FilterRTID",
            "LayerName",
            "LayerRTID",
            "RemoteUserID",
            "RemoteMachineID",
        }
    ),
}

_JSON_CORRELATION_FIELDS = (
    "hostname",
    "object",
    "action",
    "actorID",
    "principal",
    "pid",
    "ppid",
    "tid",
    "uid",
    "fuid",
    "id",
    "objectID",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "conn_state",
    "trans_id",
    "query",
    "qtype_name",
    "rcode_name",
    "answers",
    "method",
    "host",
    "uri",
    "status_code",
    "user_agent",
    "resp_fuids",
    "tx_hosts",
    "rx_hosts",
    "conn_uids",
    "filename",
    "mime_type",
    "md5",
    "sha1",
    "sha256",
    "server_name",
    "cert_chain_fuids",
    "fingerprint",
    "certificate.serial",
    "certificate.subject",
    "certificate.issuer",
    "mac",
    "assigned_ip",
    "client_addr",
    "server_addr",
    "host_name",
    "domain",
    "mode",
    "stratum",
    "ref_id",
    "hashAlgorithm",
    "issuerNameHash",
    "issuerKeyHash",
    "serialNumber",
    "status",
    "machine",
    "compile_ts",
    "trans_depth",
    "helo",
    "mailfrom",
    "rcptto",
    "date",
    "from",
    "to",
    "reply_to",
    "msg_id",
    "in_reply_to",
    "subject",
    "x_originating_ip",
    "path",
    "fuids",
    "name",
    "addl",
    "notice",
    "peer",
)

_ECAR_PROPERTY_CORRELATION_FIELDS = (
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "image_path",
    "parent_image_path",
    "command_line",
    "file_path",
    "file_name",
    "hash",
    "sha256",
    "logon_id",
    "session_id",
    "target_pid",
    "src_pid",
    "target_process_uuid",
    "target_process_object_id",
    "source_process_object_id",
)

_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d+)>1\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+"
    r"(?P<app_name>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+"
)
_WEB_ACCESS_RE = re.compile(
    r"^(?P<client_ip>\S+)\s+-\s+(?P<username>\S+)\s+\[(?P<timestamp>[^]]+)]\s+"
    r'"(?P<method>\S+)\s+(?P<target>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r"(?P<status_code>\d+)\s+(?P<bytes_sent>\S+)"
)
_SNORT_RE = re.compile(
    r"^(?P<timestamp>\S+)\s+\[\*\*]\s+"
    r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)]"
    r".*\{(?P<protocol>[^}]+)}\s+"
    r"(?P<src_ip>[^:\s]+)(?::(?P<src_port>\d+))?\s+->\s+"
    r"(?P<dst_ip>[^:\s]+)(?::(?P<dst_port>\d+))?"
)
_ASA_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<timestamp>\w{3}\s+\d+\s+\d\d:\d\d:\d\d)\s+"
    r"(?P<hostname>\S+)\s+%ASA-(?P<severity>\d+)-(?P<msg_id>\d+):\s+(?P<message>.*)$"
)
_ASA_CONNECTION_ID_RE = re.compile(r"\bconnection\s+(?P<connection_id>\d+)\s+for\b")


def _normalize_provenances(
    value: (RecordProvenance | dict[str, Any] | Sequence[RecordProvenance | dict[str, Any]] | None),
) -> list[RecordProvenance]:
    if value is None:
        return []
    if isinstance(value, RecordProvenance | dict):
        normalized = RecordProvenance.from_value(value)
        return [normalized] if normalized is not None else []
    result: list[RecordProvenance] = []
    for item in value:
        normalized = RecordProvenance.from_value(item)
        if normalized is not None:
            result.append(normalized)
    return result


def _unique_values(values: Iterator[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _strongest_label(provenances: Sequence[RecordProvenance]) -> RecordLabel:
    labels = {item.label for item in provenances}
    if "malicious" in labels:
        return "malicious"
    if "red_herring" in labels:
        return "red_herring"
    return "benign"


def _normalize_detectability_class(value: Any) -> DetectabilityClass | None:
    if value in (None, ""):
        return None
    normalized = str(value).strip().lower()
    allowed = {"direct", "association_required", "provenance_only", "not_applicable"}
    if normalized not in allowed:
        raise ValueError(
            "ground_truth_detectability_class must be one of "
            "direct, association_required, provenance_only, or not_applicable"
        )
    return cast(DetectabilityClass, normalized)


def _nested_features(
    source_format: str,
    correlation_features: dict[str, Any],
) -> dict[str, Any]:
    key = "properties" if source_format == "ecar" else "event_data"
    value = correlation_features.get(key)
    return value if isinstance(value, dict) else {}


def _detectability_anchor_types(
    source_format: str,
    correlation_features: dict[str, Any],
) -> list[str]:
    """Return public, label-free anchors that can associate a physical row."""
    nested = _nested_features(source_format, correlation_features)
    anchors: list[str] = []

    process_guids = (
        nested.get("ProcessGuid"),
        nested.get("SourceProcessGuid"),
        nested.get("TargetProcessGuid"),
    )
    if any(value not in (None, "", "-") for value in process_guids):
        anchors.append("host_process_guid")

    if source_format == "ecar":
        object_type = str(correlation_features.get("object") or "").upper()
        object_id = correlation_features.get("objectID")
        actor_id = correlation_features.get("actorID")
        if object_type == "PROCESS" and object_id not in (None, "", "-"):
            anchors.append("ecar_process_object_id")
        if actor_id not in (None, "", "-"):
            anchors.append("ecar_actor_id")

    pid = (
        correlation_features.get("pid")
        or correlation_features.get("procid")
        or nested.get("ProcessId")
        or nested.get("NewProcessId")
        or nested.get("SourceProcessId")
        or nested.get("TargetProcessId")
    )
    image = nested.get("image_path") or nested.get("Image") or nested.get("NewProcessName")
    host = correlation_features.get("hostname") or correlation_features.get("computer")
    if host not in (None, "", "-") and pid not in (None, "", "-"):
        anchors.append("host_pid_image_lifetime" if image else "host_pid_time")

    logon_id = (
        nested.get("logon_id")
        or nested.get("LogonId")
        or nested.get("LogonGuid")
        or nested.get("SubjectLogonId")
        or nested.get("TargetLogonId")
    )
    if logon_id not in (None, "", "-"):
        anchors.append("host_logon_id")

    uid_values = correlation_features.get("uid") or correlation_features.get("conn_uids")
    if uid_values not in (None, "", [], (), "-"):
        anchors.append("zeek_uid")
    fuid_values = (
        correlation_features.get("fuid")
        or correlation_features.get("resp_fuids")
        or correlation_features.get("cert_chain_fuids")
    )
    if fuid_values not in (None, "", [], (), "-"):
        anchors.append("zeek_fuid")

    src_ip = (
        correlation_features.get("id.orig_h")
        or correlation_features.get("src_ip")
        or nested.get("SourceIp")
        or nested.get("SourceAddress")
        or nested.get("src_ip")
    )
    dst_ip = (
        correlation_features.get("id.resp_h")
        or correlation_features.get("dst_ip")
        or nested.get("DestinationIp")
        or nested.get("DestinationAddress")
        or nested.get("dst_ip")
    )
    src_port = (
        correlation_features.get("id.orig_p")
        or correlation_features.get("src_port")
        or nested.get("SourcePort")
        or nested.get("src_port")
    )
    dst_port = (
        correlation_features.get("id.resp_p")
        or correlation_features.get("dst_port")
        or nested.get("DestinationPort")
        or nested.get("dst_port")
    )
    if all(value not in (None, "", "-") for value in (src_ip, dst_ip, src_port, dst_port)):
        anchors.append("five_tuple_time")
    elif host not in (None, "", "-") and src_port not in (None, "", "-"):
        anchors.append("host_source_port_time")

    if correlation_features.get("connection_id") not in (None, "", "-"):
        anchors.append("asa_connection_id")
    if correlation_features.get("query") not in (None, "", "-") and correlation_features.get(
        "answers"
    ) not in (None, "", [], (), "-"):
        anchors.append("dns_answer_time")
    if all(
        correlation_features.get(key) not in (None, "", "-")
        for key in ("client_ip", "target", "timestamp")
    ):
        anchors.append("proxy_client_target_time")
    if nested.get("file_path") not in (None, "", "-") or nested.get("TargetFilename") not in (
        None,
        "",
        "-",
    ):
        anchors.append("host_file_path_time")
    return list(dict.fromkeys(anchors))


def _record_exposes_primary_semantics(
    source_format: str,
    event_types: tuple[str, ...],
    correlation_features: dict[str, Any],
) -> bool:
    """Return whether the source row exposes the canonical action itself."""
    nested = _nested_features(source_format, correlation_features)
    event_type_set = set(event_types)
    if source_format == "bash_history":
        return bool(correlation_features.get("command"))
    if source_format in {"web_access", "proxy_access"}:
        return bool(correlation_features.get("method") and correlation_features.get("target"))
    if source_format == "zeek_http":
        return bool(
            correlation_features.get("method")
            and (correlation_features.get("uri") or correlation_features.get("host"))
        )
    if "process_create" in event_type_set or "system_process_create" in event_type_set:
        return bool(
            nested.get("command_line")
            or nested.get("CommandLine")
            or nested.get("image_path")
            or nested.get("Image")
            or nested.get("NewProcessName")
            or correlation_features.get("command")
        )
    if event_type_set.intersection({"file_create", "file_modify", "file_delete"}):
        return bool(nested.get("file_path") or nested.get("TargetFilename"))
    if "registry_read" in event_type_set:
        return source_format == "ecar"
    if event_type_set.intersection(
        {"registry_modify", "service_installed", "scheduled_task_created"}
    ):
        return source_format in {"ecar", "windows_event_security", "windows_event_sysmon"}
    if event_type_set.intersection(
        {"log_clear", "remote_thread", "process_access", "account_created", "account_deleted"}
    ):
        return source_format in {"ecar", "windows_event_security", "windows_event_sysmon"}
    return False


def _classify_record_detectability(
    *,
    label: RecordLabel,
    source_format: str,
    event_types: tuple[str, ...],
    correlation_features: dict[str, Any],
    explicit_classes: tuple[DetectabilityClass, ...],
) -> tuple[DetectabilityClass, str, list[str]]:
    anchors = _detectability_anchor_types(source_format, correlation_features)
    if label != "malicious":
        return "not_applicable", "record is not part of a malicious storyline", anchors
    if explicit_classes:
        ranking = {
            "not_applicable": 0,
            "provenance_only": 1,
            "association_required": 2,
            "direct": 3,
        }
        selected = max(explicit_classes, key=ranking.__getitem__)
        return selected, "explicit canonical-event detectability override", anchors
    if _record_exposes_primary_semantics(source_format, event_types, correlation_features):
        return "direct", "source row exposes the canonical action's primary fields", anchors
    if anchors:
        return (
            "association_required",
            "source row requires one or more public correlation anchors",
            anchors,
        )
    return (
        "provenance_only",
        "generation provenance is exact but the public row has no reliable association anchor",
        [],
    )


def _provenance_from_receipt(record: dict[str, Any]) -> RecordProvenance:
    return RecordProvenance(
        logical_event_id=str(record["logical_event_id"]),
        storyline_id=record.get("storyline_id"),
        label=record.get("label", "benign"),
        provenance_kind=record.get("provenance_kind", "unattributed"),
        event_type=str(record.get("event_type", "unattributed")),
        detectability_class=_normalize_detectability_class(record.get("detectability_class")),
        parent_logical_event_ids=tuple(record.get("parent_logical_event_ids", ())),
    )


def _extract_native_record_id(source_format: str, rendered: str) -> dict[str, Any]:
    if source_format in {"windows_event_security", "windows_event_sysmon"}:
        result: dict[str, Any] = {}
        for name, pattern in _WINDOWS_FIELD_RE.items():
            match = pattern.search(rendered)
            if match:
                value: Any = match.group(1)
                if name in {"event_id", "event_record_id"}:
                    value = int(value)
                result[name] = value
        if result:
            return result
        snare = _parse_windows_snare(rendered)
        return {
            key: snare[key] for key in ("computer", "event_id", "event_record_id") if key in snare
        }
    data = _parse_json_record(rendered)
    if data is not None and (source_format.startswith("zeek_") or source_format == "ecar"):
        result = {}
        for key in ("uid", "fuid", "id", "objectID", "actorID"):
            value = data.get(key)
            if value not in (None, "", "-"):
                result[key] = value
        return result
    if source_format == "cisco_asa":
        asa_match = _ASA_RE.match(rendered)
        if asa_match is None:
            return {}
        result = {"message_id": int(asa_match.group("msg_id"))}
        connection_match = _ASA_CONNECTION_ID_RE.search(asa_match.group("message"))
        if connection_match is not None:
            result["connection_id"] = int(connection_match.group("connection_id"))
        return result
    if source_format == "snort_alert":
        match = _SNORT_RE.match(rendered)
        if match is not None:
            return {
                "gid": int(match.group("gid")),
                "sid": int(match.group("sid")),
                "rev": int(match.group("rev")),
            }
    return {}


def _extract_observed_time(source_format: str, rendered: str) -> str | None:
    if source_format in {"windows_event_security", "windows_event_sysmon"}:
        match = re.search(r'<TimeCreated SystemTime="([^"]+)"', rendered)
        if match is not None:
            return match.group(1)
        snare = _parse_windows_snare(rendered)
        value = snare.get("observed_time_native")
        return str(value) if value else None
    data = _parse_json_record(rendered)
    if data is not None and (source_format.startswith("zeek_") or source_format == "ecar"):
        value = data.get("ts")
        if value is None and source_format == "ecar":
            timestamp_ms = data.get("timestamp_ms")
            if isinstance(timestamp_ms, int | float):
                value = float(timestamp_ms) / 1000.0
        if isinstance(value, int | float):
            return datetime.fromtimestamp(float(value), tz=UTC).isoformat().replace("+00:00", "Z")
        if isinstance(value, str) and value:
            return value
    if source_format == "syslog":
        match = _RFC5424_RE.match(rendered)
        if match is not None:
            return match.group("timestamp")
        rfc3164 = _extract_rfc3164_features(rendered)
        value = rfc3164.get("timestamp")
        return str(value) if value else None
    if source_format in {"web_access", "proxy_access"}:
        match = _WEB_ACCESS_RE.match(rendered)
        return match.group("timestamp") if match is not None else None
    if source_format == "cisco_asa":
        match = _ASA_RE.match(rendered)
        return match.group("timestamp") if match is not None else None
    if source_format == "snort_alert":
        match = _SNORT_RE.match(rendered)
        return match.group("timestamp") if match is not None else None
    if source_format == "bash_history":
        first_line = rendered.splitlines()[0] if rendered else ""
        if first_line.startswith("#") and first_line[1:].isdigit():
            return (
                datetime.fromtimestamp(int(first_line[1:]), tz=UTC)
                .isoformat()
                .replace("+00:00", "Z")
            )
    return None


def extract_public_correlation_features(source_format: str, rendered: str) -> dict[str, Any]:
    """Extract label-free fields suitable for a public Record Index row."""
    return _extract_correlation_features(source_format, rendered)


def _extract_correlation_features(source_format: str, rendered: str) -> dict[str, Any]:
    if source_format in {"windows_event_security", "windows_event_sysmon"}:
        return _extract_windows_correlation_features(source_format, rendered)

    data = _parse_json_record(rendered)
    if data is not None:
        features = _select_nonempty(data, _JSON_CORRELATION_FIELDS)
        properties = data.get("properties")
        if isinstance(properties, dict):
            selected_properties = _select_nonempty(
                properties,
                _ECAR_PROPERTY_CORRELATION_FIELDS,
            )
            if selected_properties:
                features["properties"] = selected_properties
        return features

    if source_format == "syslog":
        match = _RFC5424_RE.match(rendered)
        if match is not None:
            return _clean_match_groups(match, integer_fields={"pri", "procid"})
        return _extract_rfc3164_features(rendered)
    if source_format in {"web_access", "proxy_access"}:
        match = _WEB_ACCESS_RE.match(rendered)
        if match is not None:
            return _clean_match_groups(match, integer_fields={"status_code", "bytes_sent"})
    if source_format == "cisco_asa":
        match = _ASA_RE.match(rendered)
        if match is not None:
            features = _clean_match_groups(
                match,
                integer_fields={"pri", "severity", "msg_id"},
                excluded={"message"},
            )
            features.update(_extract_network_tuple(match.group("message")))
            connection_match = _ASA_CONNECTION_ID_RE.search(match.group("message"))
            if connection_match is not None:
                features["connection_id"] = int(connection_match.group("connection_id"))
            return features
    if source_format == "snort_alert":
        match = _SNORT_RE.match(rendered)
        if match is not None:
            return _clean_match_groups(
                match,
                integer_fields={"gid", "sid", "rev", "src_port", "dst_port"},
            )
    if source_format == "bash_history":
        lines = rendered.splitlines()
        if lines:
            result: dict[str, Any] = {"command": lines[-1]}
            if lines[0].startswith("#") and lines[0][1:].isdigit():
                result["history_timestamp"] = int(lines[0][1:])
            return result
    return {}


def _extract_windows_correlation_features(source_format: str, rendered: str) -> dict[str, Any]:
    try:
        root = ET.fromstring(rendered)
    except ET.ParseError:
        return _parse_windows_snare(rendered)
    system_fields: dict[str, Any] = {}
    event_data: dict[str, Any] = {}
    system_key_names = {
        "Provider": "provider",
        "Channel": "channel",
        "Computer": "computer",
        "EventID": "event_id",
        "EventRecordID": "event_record_id",
    }
    event_id: int | None = None
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "EventID":
            continue
        value = (element.text or "").strip()
        if value.isdigit():
            event_id = int(value)
        break
    allowed_event_data_fields = frozenset(_WINDOWS_CORRELATION_FIELDS)
    if source_format == "windows_event_security" and event_id is not None:
        allowed_event_data_fields = _WINDOWS_SECURITY_COMMON_CORRELATION_FIELDS.union(
            _WINDOWS_SECURITY_EVENT_CORRELATION_FIELDS.get(event_id, frozenset())
        )

    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1]
        text = (element.text or "").strip()
        if local_name in {"Provider", "Channel", "Computer", "EventID", "EventRecordID"}:
            if local_name == "Provider":
                value = element.attrib.get("Name")
            else:
                value = text
            if value not in (None, "", "-"):
                system_fields[system_key_names[local_name]] = _coerce_integer(value)
        elif local_name == "Data":
            name = element.attrib.get("Name")
            if name in allowed_event_data_fields and text not in ("", "-"):
                event_data[name] = _coerce_integer(text)
    if event_data:
        system_fields["event_data"] = event_data
    return system_fields


def _parse_json_record(rendered: str) -> dict[str, Any] | None:
    try:
        value = json.loads(rendered)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _select_nonempty(data: dict[str, Any], keys: Sequence[str]) -> dict[str, Any]:
    return {key: data[key] for key in keys if key in data and data[key] not in (None, "", "-")}


def _coerce_integer(value: Any) -> Any:
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value


def _clean_match_groups(
    match: re.Match[str],
    *,
    integer_fields: set[str] | None = None,
    excluded: set[str] | None = None,
) -> dict[str, Any]:
    integer_fields = integer_fields or set()
    excluded = excluded or set()
    result: dict[str, Any] = {}
    for key, value in match.groupdict().items():
        if key in excluded or value in (None, "", "-"):
            continue
        result[key] = int(value) if key in integer_fields and value.isdigit() else value
    return result


def _extract_rfc3164_features(rendered: str) -> dict[str, Any]:
    match = re.match(
        r"^(?:<(?P<pri>\d+)>)?(?P<timestamp>\w{3}\s+\d+\s+\d\d:\d\d:\d\d)\s+"
        r"(?P<hostname>\S+)\s+(?P<app_name>[^\s:\[]+)"
        r"(?:\[(?P<procid>\d+)])?:",
        rendered,
    )
    return _clean_match_groups(match, integer_fields={"pri", "procid"}) if match is not None else {}


def _parse_windows_snare(rendered: str) -> dict[str, Any]:
    columns = rendered.split("\t")
    if len(columns) < 14 or columns[1] != "MSWinEventLog":
        return {}
    features: dict[str, Any] = {
        "channel": columns[3],
        "event_record_id": _coerce_integer(columns[4]),
        "observed_time_native": columns[5],
        "event_id": _coerce_integer(columns[6]),
        "provider": columns[7],
        "username": columns[8],
        "computer": columns[11],
        "category": columns[12],
    }
    event_data: dict[str, Any] = {}
    for piece in columns[13].split("  "):
        key, separator, value = piece.partition(": ")
        if separator and key and value not in ("", "-"):
            event_data[key] = _coerce_integer(value)
    if event_data:
        features["event_data"] = event_data
    return features


def _extract_network_tuple(message: str) -> dict[str, Any]:
    match = re.search(
        r"(?:src\s+\S+:|for\s+\S+:)(?P<src_ip>[^/\s(]+)/(?P<src_port>\d+)"
        r".*?(?:dst\s+\S+:|\sto\s+\S+:)(?P<dst_ip>[^/\s(]+)/(?P<dst_port>\d+)",
        message,
    )
    return (
        _clean_match_groups(match, integer_fields={"src_port", "dst_port"})
        if match is not None
        else {}
    )
