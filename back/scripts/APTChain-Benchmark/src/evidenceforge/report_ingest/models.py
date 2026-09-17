# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Strict data contracts for threat-report extraction."""

import ipaddress
import json
import re
from enum import StrEnum
from typing import Any, Self, TypeVar
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.json_schema import SkipJsonSchema


class StrictModel(BaseModel):
    """Base model that rejects fields outside the extraction contract."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SourceSpan(StrictModel):
    """One stable, bounded citation unit inside normalized report text."""

    span_id: str = Field(pattern=r"^span-\d{4,5}-[a-f0-9]{12}$")
    page_number: int | None = Field(default=None, ge=1)
    paragraph_number: int | None = Field(default=None, ge=1)
    char_start: int = Field(ge=0)
    char_end: int = Field(gt=0)
    text_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    quote: str = Field(min_length=1, max_length=600)

    @model_validator(mode="after")
    def validate_locator_and_range(self) -> Self:
        """Require exactly one source locator and a non-empty character range."""
        if (self.page_number is None) == (self.paragraph_number is None):
            raise ValueError("来源片段必须且只能包含 PDF 页码或 TXT 段落号")
        if self.char_end <= self.char_start:
            raise ValueError("来源片段 char_end 必须大于 char_start")
        return self


class FieldOrigin(StrEnum):
    """How one semantic field entered the report-driven dataset."""

    SOURCE = "source"
    DERIVED = "derived"
    AI_COMPLETED = "ai_completed"
    ENGINE_GENERATED = "engine_generated"


class FieldProvenance(StrictModel):
    """Field-level source, derivation, or simulation provenance."""

    origin: FieldOrigin
    source_span_ids: list[str] = Field(default_factory=list, max_length=50)
    source_ids: list[str] = Field(default_factory=list, max_length=50)
    reason: str | None = Field(default=None, max_length=1000)

    @field_validator("source_span_ids", "source_ids")
    @classmethod
    def deduplicate_references(cls, values: list[str]) -> list[str]:
        """Keep provenance references stable and unique."""
        return _unique_strings(values)

    @model_validator(mode="after")
    def validate_origin_contract(self) -> Self:
        """Prevent completed fields from masquerading as report facts."""
        if self.origin == FieldOrigin.SOURCE and not self.source_span_ids:
            raise ValueError("source 来源必须提供 source_span_ids")
        if self.origin == FieldOrigin.DERIVED:
            if not self.source_span_ids and not self.source_ids:
                raise ValueError("derived 来源必须引用来源片段或来源事实")
            if not self.reason:
                raise ValueError("derived 来源必须说明确定性推导理由")
        if self.origin in {FieldOrigin.AI_COMPLETED, FieldOrigin.ENGINE_GENERATED}:
            if self.source_span_ids:
                raise ValueError("AI 或引擎生成字段不能声明来源片段")
            if not self.reason:
                raise ValueError("AI 或引擎生成字段必须说明生成理由")
        return self


class EntityType(StrEnum):
    """Entity families represented in a source fact ledger."""

    PROCESS = "process"
    FILE = "file"
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    HASH = "hash"
    NETWORK_ENDPOINT = "network_endpoint"
    SCHEDULED_TASK = "scheduled_task"
    REGISTRY = "registry"
    COMMAND = "command"
    EMAIL = "email"
    USER = "user"
    HOST = "host"
    MALWARE = "malware"
    SERVICE = "service"
    OTHER = "other"


class IndicatorKind(StrEnum):
    """Report-level indicator families."""

    HASH = "hash"
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"


_EXTERNAL_ENTITY_TYPES = {
    EntityType.URL,
    EntityType.DOMAIN,
    EntityType.IP,
    EntityType.HASH,
    EntityType.NETWORK_ENDPOINT,
}


def normalize_entity_value(entity_type: EntityType, value: str) -> str:
    """Return a deterministic comparison key without changing the display value."""
    normalized = re.sub(r"\s+", " ", value.strip())
    if entity_type == EntityType.HASH:
        return normalized.lower()
    if entity_type == EntityType.DOMAIN:
        return _normalize_defanged_value(normalized).lower().rstrip(".")
    if entity_type == EntityType.IP:
        return str(ipaddress.ip_address(_normalize_defanged_value(normalized)))
    if entity_type == EntityType.URL:
        defanged = _normalize_defanged_value(normalized)
        parts = urlsplit(defanged)
        if not parts.scheme or not parts.hostname:
            raise ValueError("URL 实体必须包含协议和主机")
        hostname = parts.hostname.lower()
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        default_port = (parts.scheme.lower(), parts.port) in {("http", 80), ("https", 443)}
        netloc = hostname if parts.port is None or default_port else f"{hostname}:{parts.port}"
        path = parts.path.rstrip("/")
        return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, parts.fragment))
    if entity_type in {
        EntityType.PROCESS,
        EntityType.SCHEDULED_TASK,
        EntityType.REGISTRY,
    }:
        return normalized.replace("/", "\\").casefold()
    if entity_type == EntityType.NETWORK_ENDPOINT:
        return _normalize_defanged_value(normalized).casefold()
    if entity_type == EntityType.FILE:
        if "\\" in normalized or re.match(r"(?i)^[a-z]:", normalized) or "%" in normalized:
            return normalized.replace("/", "\\").casefold()
        return normalized
    if entity_type in {EntityType.HOST, EntityType.MALWARE}:
        return normalized.casefold()
    return normalized


class ReportEntity(StrictModel):
    """One normalized, reusable entity from the source report."""

    entity_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,95}$")
    entity_type: EntityType
    value: str = Field(min_length=1, max_length=5000)
    canonical_value: SkipJsonSchema[str | None] = Field(
        default=None,
        min_length=1,
        max_length=5000,
    )
    aliases: list[str] = Field(default_factory=list, max_length=100)
    attributes: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    provenance: FieldProvenance

    @field_validator("aliases")
    @classmethod
    def deduplicate_aliases(cls, values: list[str]) -> list[str]:
        """Preserve stable aliases without concatenating multiple entities."""
        return _unique_strings(values)

    @model_validator(mode="after")
    def validate_canonical_value_and_origin(self) -> Self:
        """Compute the local comparison key and forbid invented external infrastructure."""
        expected = normalize_entity_value(self.entity_type, self.value)
        self.canonical_value = expected
        if self.entity_type in {EntityType.URL, EntityType.HASH} and (
            self.provenance.origin != FieldOrigin.SOURCE
        ):
            raise ValueError("精确 URL 和哈希实体必须直接来自报告")
        if self.entity_type in _EXTERNAL_ENTITY_TYPES and self.provenance.origin in {
            FieldOrigin.AI_COMPLETED,
            FieldOrigin.ENGINE_GENERATED,
        }:
            raise ValueError("外部攻击实体不能由 AI 或生成引擎凭空补全")
        return self


def deduplicate_report_entities(
    entities: list[ReportEntity],
) -> tuple[list[ReportEntity], dict[str, str]]:
    """Merge canonical duplicates while returning an old-to-new ID mapping."""
    merged: list[ReportEntity] = []
    index_by_key: dict[tuple[EntityType, str], int] = {}
    entity_id_map: dict[str, str] = {}
    for entity in entities:
        key = (entity.entity_type, entity.canonical_value or "")
        existing_index = index_by_key.get(key)
        if existing_index is None:
            index_by_key[key] = len(merged)
            merged.append(entity.model_copy(deep=True))
            entity_id_map[entity.entity_id] = entity.entity_id
            continue

        existing = merged[existing_index]
        aliases = [*existing.aliases]
        if entity.value != existing.value:
            aliases.append(entity.value)
        aliases.extend(entity.aliases)
        updated = existing.model_copy(
            update={
                "aliases": _unique_strings(aliases),
                "provenance": _merge_field_provenance(existing.provenance, entity.provenance),
            },
            deep=True,
        )
        merged[existing_index] = updated
        entity_id_map[entity.entity_id] = existing.entity_id
    return merged, entity_id_map


class EndpointOS(StrEnum):
    """Endpoint operating systems supported by the report compiler."""

    WINDOWS = "windows"
    LINUX = "linux"


class SceneRole(StrEnum):
    """Roles accepted for report-side scene nodes."""

    ATTACKER = "attacker"
    VICTIM = "victim"


class ActionType(StrEnum):
    """Source action families understood by the existing compiler."""

    EMAIL = "email"
    PROCESS = "process"
    FILE_TRANSFER = "file_transfer"
    SOCKET = "socket"
    WEBSITE = "website"
    DNS = "dns"
    REGISTRY = "registry"
    PERSISTENCE = "persistence"
    METADATA = "metadata"


class SceneTag(StrEnum):
    """Conservative scene-tag subset supported by the existing compiler."""

    SPEARPHISHING_ATTACHMENT = "spearphishing_attachment"
    MALWARE_EXECUTION = "malware_execution"
    DECOY_DOCUMENT_DOWNLOAD = "decoy_document_download"
    DECOY_DOCUMENT_OPEN = "decoy_document_open"
    PAYLOAD_DOWNLOAD = "payload_download"
    PAYLOAD_DOWNLOAD_EXECUTE = "payload_download_execute"
    HOST_RECON = "host_recon"
    NETWORK_CONNECTIVITY_CHECK = "network_connectivity_check"
    ANTI_DEBUG_ANTI_VM = "anti_debug_anti_vm"
    PERSISTENCE_SCHEDULED_TASK = "persistence_scheduled_task"
    SERVICE_INSTALLATION = "service_installation"
    REGISTRY_RUN_PERSISTENCE = "registry_run_persistence"
    C2_DNS_RESOLUTION = "c2_dns_resolution"
    C2_CHECKIN = "c2_checkin"
    C2_BEACON_HTTPS = "c2_beacon_https"
    C2_COMMAND_FETCH = "c2_command_fetch"
    C2_SYSTEM_INFO_EXFIL = "c2_system_info_exfil"
    REMOTE_COMMAND_EXECUTION = "remote_command_execution"
    SCREEN_CAPTURE = "screen_capture"
    CREDENTIAL_THEFT_CHROME = "credential_theft_chrome"
    CREDENTIAL_THEFT_FIREFOX = "credential_theft_firefox"
    BROWSER_HISTORY_THEFT = "browser_history_theft"
    CLIPBOARD_THEFT = "clipboard_theft"
    DOCUMENT_FILENAME_COLLECTION = "document_filename_collection"
    DATA_EXFILTRATION = "data_exfiltration"
    SELF_DELETION = "self_deletion"


SCENE_TAGS: tuple[str, ...] = tuple(tag.value for tag in SceneTag)
ACTION_TYPE_BY_TAG: dict[str, str] = {
    SceneTag.SPEARPHISHING_ATTACHMENT.value: ActionType.EMAIL.value,
    SceneTag.MALWARE_EXECUTION.value: ActionType.PROCESS.value,
    SceneTag.DECOY_DOCUMENT_DOWNLOAD.value: ActionType.FILE_TRANSFER.value,
    SceneTag.DECOY_DOCUMENT_OPEN.value: ActionType.PROCESS.value,
    SceneTag.PAYLOAD_DOWNLOAD.value: ActionType.FILE_TRANSFER.value,
    SceneTag.PAYLOAD_DOWNLOAD_EXECUTE.value: ActionType.FILE_TRANSFER.value,
    SceneTag.HOST_RECON.value: ActionType.PROCESS.value,
    SceneTag.NETWORK_CONNECTIVITY_CHECK.value: ActionType.SOCKET.value,
    SceneTag.ANTI_DEBUG_ANTI_VM.value: ActionType.PROCESS.value,
    SceneTag.PERSISTENCE_SCHEDULED_TASK.value: ActionType.PERSISTENCE.value,
    SceneTag.SERVICE_INSTALLATION.value: ActionType.PERSISTENCE.value,
    SceneTag.REGISTRY_RUN_PERSISTENCE.value: ActionType.REGISTRY.value,
    SceneTag.C2_DNS_RESOLUTION.value: ActionType.DNS.value,
    SceneTag.C2_CHECKIN.value: ActionType.SOCKET.value,
    SceneTag.C2_BEACON_HTTPS.value: ActionType.SOCKET.value,
    SceneTag.C2_COMMAND_FETCH.value: ActionType.SOCKET.value,
    SceneTag.C2_SYSTEM_INFO_EXFIL.value: ActionType.SOCKET.value,
    SceneTag.REMOTE_COMMAND_EXECUTION.value: ActionType.PROCESS.value,
    SceneTag.SCREEN_CAPTURE.value: ActionType.PROCESS.value,
    SceneTag.CREDENTIAL_THEFT_CHROME.value: ActionType.PROCESS.value,
    SceneTag.CREDENTIAL_THEFT_FIREFOX.value: ActionType.PROCESS.value,
    SceneTag.BROWSER_HISTORY_THEFT.value: ActionType.PROCESS.value,
    SceneTag.CLIPBOARD_THEFT.value: ActionType.PROCESS.value,
    SceneTag.DOCUMENT_FILENAME_COLLECTION.value: ActionType.PROCESS.value,
    SceneTag.DATA_EXFILTRATION.value: ActionType.SOCKET.value,
    SceneTag.SELF_DELETION.value: ActionType.PROCESS.value,
}


def _unique_strings(values: list[str]) -> list[str]:
    """Return trimmed, stable, case-sensitive unique strings."""
    return list(dict.fromkeys(value.strip() for value in values if value.strip()))


def _normalize_defanged_value(value: str) -> str:
    """Normalize common defanging without importing the IOC module."""
    normalized = re.sub(r"(?i)^hxxps://", "https://", value)
    normalized = re.sub(r"(?i)^hxxp://", "http://", normalized)
    return re.sub(
        r"\[(?:\.|dot)\]|\((?:\.|dot)\)|\{(?:\.|dot)\}",
        ".",
        normalized,
        flags=re.IGNORECASE,
    )


def _merge_field_provenance(
    first: FieldProvenance,
    second: FieldProvenance,
) -> FieldProvenance:
    """Merge duplicate-entity provenance while retaining the strongest source."""
    trust_order = {
        FieldOrigin.SOURCE: 0,
        FieldOrigin.DERIVED: 1,
        FieldOrigin.AI_COMPLETED: 2,
        FieldOrigin.ENGINE_GENERATED: 3,
    }
    origin = min((first.origin, second.origin), key=trust_order.__getitem__)
    reasons = _unique_strings([first.reason or "", second.reason or ""])
    reason = "; ".join(reasons) or None
    if origin in {FieldOrigin.DERIVED, FieldOrigin.AI_COMPLETED, FieldOrigin.ENGINE_GENERATED}:
        reason = reason or "合并重复实体的来源说明"
    return FieldProvenance(
        origin=origin,
        source_span_ids=_unique_strings(
            [*first.source_span_ids, *second.source_span_ids]
            if origin in {FieldOrigin.SOURCE, FieldOrigin.DERIVED}
            else []
        ),
        source_ids=_unique_strings([*first.source_ids, *second.source_ids]),
        reason=reason,
    )


class ReportMeta(StrictModel):
    """Report-level facts extracted from the source document."""

    report_name: str = Field(min_length=1, max_length=300)
    apt_group: str | None = Field(default=None, max_length=120)
    target_countries: list[str] = Field(default_factory=list, max_length=30)
    target_industries: list[str] = Field(default_factory=list, max_length=50)
    malware_families: list[str] = Field(default_factory=list, max_length=50)
    vulnerabilities: list[str] = Field(default_factory=list, max_length=50)
    references: list[str] = Field(default_factory=list, max_length=30)
    description: str = Field(min_length=1, max_length=4000)

    @field_validator(
        "target_countries",
        "target_industries",
        "malware_families",
        "vulnerabilities",
        "references",
    )
    @classmethod
    def deduplicate_lists(cls, value: list[str]) -> list[str]:
        """Normalize report metadata lists."""
        return _unique_strings(value)


class ReportFact(StrictModel):
    """One atomic source behavior or necessary simulation prerequisite."""

    fact_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,95}$")
    behavior: str = Field(pattern=r"^[a-z][a-z0-9_]{0,95}$")
    order: int = Field(ge=1, le=10000)
    description: str = Field(min_length=1, max_length=5000)
    uncertainty: list[str] = Field(default_factory=list, max_length=50)
    provenance: FieldProvenance

    @field_validator("uncertainty")
    @classmethod
    def deduplicate_uncertainty(cls, values: list[str]) -> list[str]:
        """Keep uncertainty notes stable."""
        return _unique_strings(values)


class ReportRelation(StrictModel):
    """One directed fact-to-entity or entity-to-entity relationship."""

    relation_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,95}$")
    source_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,95}$")
    predicate: str = Field(pattern=r"^[a-z][a-z0-9_]{0,95}$")
    target_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,95}$")
    provenance: FieldProvenance


class ReportIndicator(StrictModel):
    """One report-level indicator with exact source provenance."""

    indicator_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,95}$")
    kind: IndicatorKind
    value: str = Field(min_length=1, max_length=4000)
    normalized_value: str | None = Field(default=None, min_length=1, max_length=4000)
    provenance: FieldProvenance

    @model_validator(mode="after")
    def validate_normalized_value_and_origin(self) -> Self:
        """Normalize exact indicators and reject synthetic external values."""
        entity_type = EntityType(self.kind.value)
        expected = normalize_entity_value(entity_type, self.value)
        if self.normalized_value is not None and self.normalized_value != expected:
            raise ValueError("normalized_value 与 IOC 规范化结果不一致")
        self.normalized_value = expected
        if self.kind in {IndicatorKind.URL, IndicatorKind.HASH} and (
            self.provenance.origin != FieldOrigin.SOURCE
        ):
            raise ValueError("报告级 URL 和哈希必须直接来自报告")
        if self.provenance.origin in {
            FieldOrigin.AI_COMPLETED,
            FieldOrigin.ENGINE_GENERATED,
        }:
            raise ValueError("报告级 IOC 不能由 AI 或生成引擎补全")
        return self


class ReportFactLedger(StrictModel):
    """Source spans, atomic facts, reusable entities, and directed relations."""

    source_spans: list[SourceSpan] = Field(min_length=1, max_length=10000)
    source_metadata: ReportMeta
    metadata_provenance: FieldProvenance
    facts: list[ReportFact] = Field(default_factory=list, max_length=1000)
    entities: list[ReportEntity] = Field(default_factory=list, max_length=5000)
    relations: list[ReportRelation] = Field(default_factory=list, max_length=10000)
    report_iocs: list[ReportIndicator] = Field(default_factory=list, max_length=1000)

    @model_validator(mode="after")
    def validate_ledger_integrity(self) -> Self:
        """Reject duplicate identities, dangling relations, and unknown citations."""
        _require_unique("source_spans.span_id", [span.span_id for span in self.source_spans])
        _require_unique("facts.fact_id", [fact.fact_id for fact in self.facts])
        _require_unique("entities.entity_id", [entity.entity_id for entity in self.entities])
        _require_unique(
            "relations.relation_id", [relation.relation_id for relation in self.relations]
        )
        _require_unique(
            "report_iocs.indicator_id", [indicator.indicator_id for indicator in self.report_iocs]
        )

        fact_ids = {fact.fact_id for fact in self.facts}
        entity_ids = {entity.entity_id for entity in self.entities}
        if fact_ids & entity_ids:
            raise ValueError("事实 ID 与实体 ID 必须全局唯一")
        reference_ids = fact_ids | entity_ids
        for relation in self.relations:
            missing = {relation.source_id, relation.target_id} - reference_ids
            if missing:
                raise ValueError(f"关系 {relation.relation_id} 包含未知引用: {sorted(missing)}")

        span_ids = {span.span_id for span in self.source_spans}
        provenance_items = [
            ("metadata_provenance", self.metadata_provenance),
            *((f"facts[{item.fact_id}]", item.provenance) for item in self.facts),
            *((f"entities[{item.entity_id}]", item.provenance) for item in self.entities),
            *((f"relations[{item.relation_id}]", item.provenance) for item in self.relations),
            *((f"report_iocs[{item.indicator_id}]", item.provenance) for item in self.report_iocs),
        ]
        for location, provenance in provenance_items:
            unknown_spans = set(provenance.source_span_ids) - span_ids
            if unknown_spans:
                raise ValueError(f"{location} 引用了未知来源片段: {sorted(unknown_spans)}")
            unknown_sources = set(provenance.source_ids) - reference_ids
            if unknown_sources:
                raise ValueError(f"{location} 引用了未知来源事实或实体: {sorted(unknown_sources)}")

        canonical_entities = [
            (entity.entity_type, entity.canonical_value) for entity in self.entities
        ]
        if len(canonical_entities) != len(set(canonical_entities)):
            raise ValueError("实体存在重复规范值，请先执行确定性去重")
        canonical_iocs = [
            (indicator.kind, indicator.normalized_value) for indicator in self.report_iocs
        ]
        if len(canonical_iocs) != len(set(canonical_iocs)):
            raise ValueError("报告级 IOC 存在重复规范值")
        return self


class ReportFactExtraction(StrictModel):
    """MiniMax A output that references, but does not echo, local source spans."""

    source_metadata: ReportMeta
    metadata_provenance: FieldProvenance
    facts: list[ReportFact] = Field(default_factory=list, max_length=1000)
    entities: list[ReportEntity] = Field(default_factory=list, max_length=5000)
    relations: list[ReportRelation] = Field(default_factory=list, max_length=10000)
    report_iocs: list[ReportIndicator] = Field(default_factory=list, max_length=1000)

    @model_validator(mode="after")
    def validate_source_only_extraction(self) -> Self:
        """Keep task A limited to report facts and internally valid references."""
        fact_ids = [fact.fact_id for fact in self.facts]
        entity_ids = [entity.entity_id for entity in self.entities]
        _require_unique("facts.fact_id", fact_ids)
        _require_unique("entities.entity_id", entity_ids)
        _require_unique(
            "relations.relation_id", [relation.relation_id for relation in self.relations]
        )
        _require_unique(
            "report_iocs.indicator_id", [indicator.indicator_id for indicator in self.report_iocs]
        )
        if set(fact_ids) & set(entity_ids):
            raise ValueError("事实 ID 与实体 ID 必须全局唯一")
        valid_ids = set(fact_ids) | set(entity_ids)
        for relation in self.relations:
            missing = {relation.source_id, relation.target_id} - valid_ids
            if missing:
                raise ValueError(f"关系 {relation.relation_id} 包含未知引用: {sorted(missing)}")

        provenance_items = [
            self.metadata_provenance,
            *(item.provenance for item in self.facts),
            *(item.provenance for item in self.entities),
            *(item.provenance for item in self.relations),
            *(item.provenance for item in self.report_iocs),
        ]
        if any(item.origin != FieldOrigin.SOURCE for item in provenance_items):
            raise ValueError("MiniMax A 只能输出 source 来源事实")
        if any(item.source_ids for item in provenance_items):
            raise ValueError("MiniMax A 的 source 来源只能引用 source_span_ids")
        return self

    def to_ledger(
        self, source_spans: list[SourceSpan] | tuple[SourceSpan, ...]
    ) -> ReportFactLedger:
        """Attach trusted local spans and normalize one extraction into a ledger."""
        return merge_fact_extractions([self], source_spans)


class AuditAction(StrEnum):
    """Suggestion actions available to the non-mutating audit stage."""

    ADD_FACT = "add_fact"
    ADD_ENTITY = "add_entity"
    ADD_RELATION = "add_relation"
    REMOVE_DUPLICATE = "remove_duplicate"
    REPLACE_RELATION = "replace_relation"
    SPLIT_FACT = "split_fact"
    REMOVE_UNSUPPORTED = "remove_unsupported"


class FactAuditSuggestion(StrictModel):
    """One evidence-backed proposal that local code may accept or reject."""

    suggestion_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,95}$")
    action: AuditAction
    description: str = Field(min_length=1, max_length=3000)
    affected_ids: list[str] = Field(default_factory=list, max_length=100)
    source_span_ids: list[str] = Field(default_factory=list, max_length=100)
    proposed_fact: ReportFact | None = None
    proposed_entity: ReportEntity | None = None
    proposed_relation: ReportRelation | None = None
    replacement_facts: list[ReportFact] = Field(default_factory=list, max_length=20)

    @field_validator("affected_ids", "source_span_ids")
    @classmethod
    def deduplicate_audit_references(cls, values: list[str]) -> list[str]:
        """Keep suggestion references stable."""
        return _unique_strings(values)

    @model_validator(mode="after")
    def validate_action_payload(self) -> Self:
        """Require exactly the proposal payload appropriate for one action."""
        payload_counts = {
            "fact": int(self.proposed_fact is not None),
            "entity": int(self.proposed_entity is not None),
            "relation": int(self.proposed_relation is not None),
            "replacement_facts": int(bool(self.replacement_facts)),
        }
        expected_payload = {
            AuditAction.ADD_FACT: "fact",
            AuditAction.ADD_ENTITY: "entity",
            AuditAction.ADD_RELATION: "relation",
            AuditAction.REPLACE_RELATION: "relation",
            AuditAction.SPLIT_FACT: "replacement_facts",
        }.get(self.action)
        present_payloads = {name for name, count in payload_counts.items() if count}
        if expected_payload is None and present_payloads:
            raise ValueError(f"审核动作 {self.action.value} 不得携带新增内容")
        if expected_payload is not None and present_payloads != {expected_payload}:
            raise ValueError(f"审核动作 {self.action.value} 必须且只能携带对应建议内容")
        if self.action == AuditAction.SPLIT_FACT and len(self.replacement_facts) < 2:
            raise ValueError("split_fact 至少需要两个替换事实")
        if (
            expected_payload is not None
            and expected_payload != "relation"
            and not self.source_span_ids
        ):
            raise ValueError("新增事实/实体或拆分建议必须提供 source_span_ids")
        if (
            self.action
            in {
                AuditAction.REMOVE_DUPLICATE,
                AuditAction.REPLACE_RELATION,
                AuditAction.SPLIT_FACT,
                AuditAction.REMOVE_UNSUPPORTED,
            }
            and not self.affected_ids
        ):
            raise ValueError(f"审核动作 {self.action.value} 必须提供 affected_ids")
        return self


class FactAuditResult(StrictModel):
    """MiniMax B output containing suggestions rather than a rewritten ledger."""

    summary: str = Field(min_length=1, max_length=3000)
    ledger_complete: bool
    suggestions: list[FactAuditSuggestion] = Field(default_factory=list, max_length=500)
    unresolved_questions: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def validate_unique_suggestions(self) -> Self:
        """Require stable suggestion IDs."""
        _require_unique(
            "suggestions.suggestion_id",
            [suggestion.suggestion_id for suggestion in self.suggestions],
        )
        if self.ledger_complete and self.suggestions:
            raise ValueError("ledger_complete 为 true 时不得同时返回修改建议")
        return self


class CompletionRequest(StrictModel):
    """One compiler-owned field that MiniMax C is allowed to complete."""

    request_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,95}$")
    target_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,95}$")
    field_path: str = Field(pattern=r"^[a-z][A-Za-z0-9_.\[\]-]{0,199}$")
    description: str = Field(min_length=1, max_length=2000)
    allowed_origins: list[FieldOrigin] = Field(min_length=1, max_length=2)
    source_ids: list[str] = Field(min_length=1, max_length=50)
    constraints: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("allowed_origins")
    @classmethod
    def validate_completion_origins(cls, values: list[FieldOrigin]) -> list[FieldOrigin]:
        """Only bounded derivation, AI, or engine completion is legal here."""
        allowed = {
            FieldOrigin.DERIVED,
            FieldOrigin.AI_COMPLETED,
            FieldOrigin.ENGINE_GENERATED,
        }
        if not set(values) <= allowed:
            raise ValueError("补全请求只允许 derived、ai_completed 或 engine_generated")
        return list(dict.fromkeys(values))

    @field_validator("source_ids", "constraints")
    @classmethod
    def deduplicate_completion_references(cls, values: list[str]) -> list[str]:
        """Keep request references and constraints stable."""
        return _unique_strings(values)

    @field_validator("field_path")
    @classmethod
    def reject_forbidden_completion_fields(cls, value: str) -> str:
        """Prevent the compiler from asking AI to invent external attack facts."""
        forbidden = (
            "report_iocs",
            "network.url",
            "network.host",
            "network.ip",
            "hash",
            "command_line",
            "vulnerability",
            "malware_family",
        )
        if any(token in value.casefold() for token in forbidden):
            raise ValueError("补全请求不能指向外部 IOC、哈希、命令或攻击归因字段")
        return value


class SimulationCompletion(StrictModel):
    """One bounded value returned for an explicit completion request."""

    request_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,95}$")
    target_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,95}$")
    field_path: str = Field(pattern=r"^[a-z][A-Za-z0-9_.\[\]-]{0,199}$")
    value: str | int | float | bool
    origin: FieldOrigin
    reason: str = Field(min_length=1, max_length=2000)
    compatible: bool
    compatibility_explanation: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def validate_completion_origin(self) -> Self:
        """Forbid completed values from being mislabeled as report source."""
        if self.origin not in {
            FieldOrigin.DERIVED,
            FieldOrigin.AI_COMPLETED,
            FieldOrigin.ENGINE_GENERATED,
        }:
            raise ValueError("仿真补全只能标记为 derived、ai_completed 或 engine_generated")
        return self


class SimulationPlan(StrictModel):
    """MiniMax C output for compiler-owned missing-field requests."""

    completions: list[SimulationCompletion] = Field(default_factory=list, max_length=1000)
    unresolved_request_ids: list[str] = Field(default_factory=list, max_length=1000)

    @model_validator(mode="after")
    def validate_unique_completion_requests(self) -> Self:
        """Return at most one value or unresolved marker per request."""
        completion_ids = [completion.request_id for completion in self.completions]
        _require_unique("completions.request_id", completion_ids)
        _require_unique("unresolved_request_ids", self.unresolved_request_ids)
        overlap = set(completion_ids) & set(self.unresolved_request_ids)
        if overlap:
            raise ValueError(f"补全请求不能同时完成和未解决: {sorted(overlap)}")
        return self


class CompiledEventType(StrEnum):
    """EvidenceForge event families emitted by the report compiler."""

    PROCESS = "process"
    CONNECTION = "connection"
    DNS_QUERY = "dns_query"
    FILE_CREATE = "file_create"
    FILE_DELETE = "file_delete"
    FILE_COLLECTION = "file_collection"
    SCHEDULED_TASK_CREATED = "scheduled_task_created"
    SERVICE_INSTALLED = "service_installed"
    REGISTRY_QUERY = "registry_query"
    REGISTRY_SET = "registry_set"
    EMAIL_MESSAGE = "email_message"
    PROCESS_ACCESS = "process_access"
    IMAGE_LOAD = "image_load"


class CompilationStatus(StrEnum):
    """Whether one source fact can be rendered without semantic invention."""

    MATERIALIZED = "materialized"
    NEEDS_COMPLETION = "needs_completion"
    GROUND_TRUTH_ONLY = "ground_truth_only"


class SourceCategory(StrEnum):
    """Step-level provenance summary used by Ground Truth."""

    SOURCE_FACT = "source_fact"
    PARTIALLY_AI_COMPLETED = "partially_ai_completed"
    PARTIALLY_ENGINE_GENERATED = "partially_engine_generated"
    FULLY_SYNTHETIC = "fully_synthetic"


class ExpectedVisibility(StrEnum):
    """Security evidence families expected for one compiled event."""

    ENDPOINT_PROCESS = "endpoint_process"
    ENDPOINT_FILE = "endpoint_file"
    ENDPOINT_REGISTRY = "endpoint_registry"
    NETWORK_FLOW = "network_flow"
    DNS = "dns"
    EMAIL = "email"
    GROUND_TRUTH = "ground_truth"


CompiledScalar = str | int | float | bool


class CompiledField(StrictModel):
    """One compiler field paired with its exact provenance."""

    value: CompiledScalar | list[str]
    provenance: FieldProvenance


class CompiledScenarioEvent(StrictModel):
    """One validated event intent before conversion to scenario YAML."""

    event_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
    fact_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,95}$")
    order: int = Field(ge=1, le=100000)
    event_type: CompiledEventType | None = None
    activity: str = Field(min_length=1, max_length=5000)
    subject_entity_id: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$",
    )
    object_entity_ids: list[str] = Field(default_factory=list, max_length=1000)
    channel_entity_ids: list[str] = Field(default_factory=list, max_length=1000)
    fields: dict[str, CompiledField] = Field(default_factory=dict, max_length=100)
    source_category: SourceCategory
    status: CompilationStatus
    expected_visibility: list[ExpectedVisibility] = Field(default_factory=list, max_length=20)
    completion_request_ids: list[str] = Field(default_factory=list, max_length=100)
    degradation_reason: str | None = Field(default=None, max_length=3000)
    necessity_reason: str | None = Field(default=None, max_length=3000)

    @field_validator(
        "object_entity_ids",
        "channel_entity_ids",
        "completion_request_ids",
    )
    @classmethod
    def deduplicate_compiled_references(cls, values: list[str]) -> list[str]:
        """Keep entity and completion references stable."""
        return _unique_strings(values)

    @field_validator("expected_visibility")
    @classmethod
    def deduplicate_visibility(
        cls,
        values: list[ExpectedVisibility],
    ) -> list[ExpectedVisibility]:
        """Keep expected visibility stable without duplicates."""
        return list(dict.fromkeys(values))

    @field_validator("fields")
    @classmethod
    def validate_compiled_field_names(
        cls,
        values: dict[str, CompiledField],
    ) -> dict[str, CompiledField]:
        """Require simple scenario-compatible field names."""
        invalid = [name for name in values if re.fullmatch(r"[a-z][a-z0-9_]{0,95}", name) is None]
        if invalid:
            raise ValueError(f"编译字段名无效: {sorted(invalid)}")
        return values

    @model_validator(mode="after")
    def validate_compilation_contract(self) -> Self:
        """Enforce status, completion, and synthetic-bridge boundaries."""
        if self.status == CompilationStatus.MATERIALIZED and self.event_type is None:
            raise ValueError("已物化事件必须指定 event_type")
        if self.status == CompilationStatus.NEEDS_COMPLETION:
            if self.event_type is None:
                raise ValueError("待补全事件必须声明预期 event_type")
            if not self.completion_request_ids:
                raise ValueError("待补全事件必须引用补全请求")
        if self.status == CompilationStatus.GROUND_TRUTH_ONLY:
            if self.event_type is not None:
                raise ValueError("仅 Ground Truth 事实不得伪装成可渲染事件")
            if not self.degradation_reason:
                raise ValueError("仅 Ground Truth 事实必须记录降级原因")
            if self.expected_visibility != [ExpectedVisibility.GROUND_TRUTH]:
                raise ValueError("仅 Ground Truth 事实的预期可见性必须是 ground_truth")

        if self.source_category == SourceCategory.FULLY_SYNTHETIC:
            if not self.necessity_reason:
                raise ValueError("完全合成桥接步骤必须记录必要性原因")
            forbidden_external_fields = {
                "domain",
                "dst_ip",
                "hash",
                "hostname",
                "ip",
                "uri",
                "url",
            }
            unexpected = forbidden_external_fields & self.fields.keys()
            if unexpected:
                raise ValueError(f"完全合成桥接步骤不得携带新的外部 IOC: {sorted(unexpected)}")
        return self


class ReportScenarioCompilation(StrictModel):
    """Deterministic compiler output before EvidenceForge scenario serialization."""

    events: list[CompiledScenarioEvent] = Field(default_factory=list, max_length=10000)
    generated_entities: list[ReportEntity] = Field(default_factory=list, max_length=1000)
    completion_requests: list[CompletionRequest] = Field(default_factory=list, max_length=1000)

    @model_validator(mode="after")
    def validate_compilation_references(self) -> Self:
        """Require unique compiler identities and known completion references."""
        _require_unique("events.event_id", [event.event_id for event in self.events])
        _require_unique(
            "generated_entities.entity_id",
            [entity.entity_id for entity in self.generated_entities],
        )
        _require_unique(
            "completion_requests.request_id",
            [request.request_id for request in self.completion_requests],
        )
        request_ids = {request.request_id for request in self.completion_requests}
        unknown_requests = {
            request_id
            for event in self.events
            for request_id in event.completion_request_ids
            if request_id not in request_ids
        }
        if unknown_requests:
            raise ValueError(f"编译事件引用了未知补全请求: {sorted(unknown_requests)}")
        return self


def merge_fact_extractions(
    extractions: list[ReportFactExtraction],
    source_spans: list[SourceSpan] | tuple[SourceSpan, ...],
) -> ReportFactLedger:
    """Merge chunk extractions without dropping distinct multi-value facts."""
    if not extractions:
        raise ValueError("至少需要一个来源事实抽取结果")

    first = extractions[0]
    metadata = first.source_metadata.model_copy(deep=True)
    metadata_provenance = first.metadata_provenance.model_copy(deep=True)
    facts: list[ReportFact] = []
    scoped_fact_maps: list[dict[str, str]] = []
    temporary_entities: list[ReportEntity] = []
    scoped_entity_maps: list[dict[str, str]] = []

    for chunk_index, extraction in enumerate(extractions, start=1):
        metadata.target_countries = _unique_strings(
            [*metadata.target_countries, *extraction.source_metadata.target_countries]
        )
        metadata.target_industries = _unique_strings(
            [*metadata.target_industries, *extraction.source_metadata.target_industries]
        )
        metadata.malware_families = _unique_strings(
            [*metadata.malware_families, *extraction.source_metadata.malware_families]
        )
        metadata.vulnerabilities = _unique_strings(
            [*metadata.vulnerabilities, *extraction.source_metadata.vulnerabilities]
        )
        metadata.references = _unique_strings(
            [*metadata.references, *extraction.source_metadata.references]
        )
        if not metadata.apt_group and extraction.source_metadata.apt_group:
            metadata.apt_group = extraction.source_metadata.apt_group
        metadata_provenance = _merge_field_provenance(
            metadata_provenance,
            extraction.metadata_provenance,
        )

        fact_map: dict[str, str] = {}
        for fact in sorted(extraction.facts, key=lambda item: (item.order, item.fact_id)):
            new_id = f"fact-{len(facts) + 1:04d}"
            fact_map[fact.fact_id] = new_id
            facts.append(
                fact.model_copy(
                    update={"fact_id": new_id, "order": len(facts) + 1},
                    deep=True,
                )
            )
        scoped_fact_maps.append(fact_map)

        entity_map: dict[str, str] = {}
        for entity_index, entity in enumerate(extraction.entities, start=1):
            temporary_id = f"chunk-{chunk_index:04d}-entity-{entity_index:04d}"
            entity_map[entity.entity_id] = temporary_id
            temporary_entities.append(
                entity.model_copy(update={"entity_id": temporary_id}, deep=True)
            )
        scoped_entity_maps.append(entity_map)

    deduplicated_entities, temporary_to_primary = deduplicate_report_entities(temporary_entities)
    primary_to_final: dict[str, str] = {}
    entities: list[ReportEntity] = []
    for index, entity in enumerate(deduplicated_entities, start=1):
        final_id = f"entity-{index:04d}"
        primary_to_final[entity.entity_id] = final_id
        entities.append(entity.model_copy(update={"entity_id": final_id}, deep=True))

    relations: list[ReportRelation] = []
    for chunk_index, extraction in enumerate(extractions):
        scoped_ids = {
            **scoped_fact_maps[chunk_index],
            **{
                old_id: primary_to_final[temporary_to_primary[temporary_id]]
                for old_id, temporary_id in scoped_entity_maps[chunk_index].items()
            },
        }
        for relation in extraction.relations:
            relations.append(
                relation.model_copy(
                    update={
                        "relation_id": f"relation-{len(relations) + 1:04d}",
                        "source_id": scoped_ids[relation.source_id],
                        "target_id": scoped_ids[relation.target_id],
                    },
                    deep=True,
                )
            )

    indicators: list[ReportIndicator] = []
    indicator_index: dict[tuple[IndicatorKind, str], int] = {}
    for extraction in extractions:
        for indicator in extraction.report_iocs:
            key = (indicator.kind, indicator.normalized_value or "")
            existing_index = indicator_index.get(key)
            if existing_index is None:
                indicator_index[key] = len(indicators)
                indicators.append(
                    indicator.model_copy(
                        update={"indicator_id": f"ioc-{len(indicators) + 1:04d}"},
                        deep=True,
                    )
                )
                continue
            existing = indicators[existing_index]
            indicators[existing_index] = existing.model_copy(
                update={
                    "provenance": _merge_field_provenance(
                        existing.provenance,
                        indicator.provenance,
                    )
                },
                deep=True,
            )

    return ReportFactLedger(
        source_spans=list(source_spans),
        source_metadata=metadata,
        metadata_provenance=metadata_provenance,
        facts=facts,
        entities=entities,
        relations=relations,
        report_iocs=indicators,
    )


def validate_simulation_plan(
    plan: SimulationPlan,
    requests: list[CompletionRequest],
    ledger: ReportFactLedger,
) -> list[str]:
    """Reject unrequested, incompatible, or wrongly targeted completion values."""
    errors: list[str] = []
    requests_by_id = {request.request_id: request for request in requests}
    if len(requests_by_id) != len(requests):
        errors.append("补全请求 ID 重复")
    ledger_ids = {fact.fact_id for fact in ledger.facts} | {
        entity.entity_id for entity in ledger.entities
    }
    for request in requests:
        if request.target_id not in ledger_ids:
            errors.append(f"requests[{request.request_id}]: target_id 不存在于事实账本")
        unknown_sources = set(request.source_ids) - ledger_ids
        if unknown_sources:
            errors.append(
                f"requests[{request.request_id}]: source_ids 包含未知引用 {sorted(unknown_sources)}"
            )

    completed_ids: set[str] = set()
    unexpected_output = False
    for completion in plan.completions:
        request = requests_by_id.get(completion.request_id)
        if request is None:
            errors.append(f"completions[{completion.request_id}]: 不属于编译器请求")
            unexpected_output = True
            continue
        completed_ids.add(completion.request_id)
        if completion.target_id != request.target_id or completion.field_path != request.field_path:
            errors.append(f"completions[{completion.request_id}]: 目标或字段路径被模型改写")
        if completion.origin not in request.allowed_origins:
            errors.append(f"completions[{completion.request_id}]: 来源类型不在允许范围")
        if not completion.compatible:
            errors.append(f"completions[{completion.request_id}]: 与来源事实不兼容")

    unresolved_ids = set(plan.unresolved_request_ids)
    for request_id in unresolved_ids - requests_by_id.keys():
        errors.append(f"unresolved_request_ids[{request_id}]: 不属于编译器请求")
        unexpected_output = True
    if not unexpected_output:
        for request_id in requests_by_id.keys() - completed_ids - unresolved_ids:
            errors.append(f"requests[{request_id}]: 模型既未补全也未标记为未解决")
    return errors


StructuredModelT = TypeVar("StructuredModelT", bound=BaseModel)


def parse_structured_json(content: str, model_type: type[StructuredModelT]) -> StructuredModelT:
    """Parse one fenced or plain JSON object into a requested strict model."""
    cleaned = content.strip()
    cleaned = re.sub(r"^<think>.*?</think>\s*", "", cleaned, flags=re.DOTALL)
    fence = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", cleaned, flags=re.DOTALL | re.IGNORECASE)
    if fence:
        cleaned = fence.group(1).strip()
    raw = json.loads(cleaned)
    if not isinstance(raw, dict):
        raise ValueError("模型响应必须是 JSON 对象")
    wrapper_names = {model_type.__name__, _camel_to_snake(model_type.__name__)}
    if len(raw) == 1:
        wrapped = next((raw.get(name) for name in wrapper_names if name in raw), None)
        if isinstance(wrapped, dict):
            raw = wrapped
    return model_type.model_validate(raw)


def _camel_to_snake(value: str) -> str:
    """Convert a Pydantic class name to a possible MiniMax wrapper key."""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", value).lower()


def _require_unique(label: str, values: list[str]) -> None:
    """Raise a stable validation error for duplicate ledger identifiers."""
    if len(values) != len(set(values)):
        raise ValueError(f"{label} 必须唯一")


class SceneNode(StrictModel):
    """Report-side actor or victim node used by the legacy compiler."""

    id: int = Field(ge=1, le=999999)
    name: str = Field(min_length=1, max_length=120)
    os: EndpointOS
    role: SceneRole


class AttackMapping(StrictModel):
    """Conservative Enterprise ATT&CK mapping for one source step."""

    technique_id: str | None = Field(default=None, max_length=20)
    technique: str | None = Field(default=None, max_length=200)
    tactic: str | None = Field(default=None, max_length=100)

    @field_validator("technique_id")
    @classmethod
    def validate_technique_id(cls, value: str | None) -> str | None:
        """Accept only Enterprise ATT&CK-style technique identifiers."""
        if value is None or not value.strip():
            return None
        normalized = value.strip().upper()
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", normalized):
            raise ValueError("technique_id 必须是 T1234 或 T1234.001 格式")
        return normalized


class IocFacts(StrictModel):
    """Exact indicators disclosed by the source report."""

    hashes: list[str] = Field(default_factory=list, max_length=200)
    domains: list[str] = Field(default_factory=list, max_length=200)
    ips: list[str] = Field(default_factory=list, max_length=200)
    urls: list[str] = Field(default_factory=list, max_length=200)
    malware_names: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("hashes", "domains", "ips", "urls", "malware_names")
    @classmethod
    def deduplicate_iocs(cls, value: list[str]) -> list[str]:
        """Normalize IOC lists without changing source case or values."""
        return _unique_strings(value)

    def merged(self, other: "IocFacts") -> "IocFacts":
        """Return a stable union of two IOC collections."""
        return IocFacts(
            hashes=_unique_strings([*self.hashes, *other.hashes]),
            domains=_unique_strings([*self.domains, *other.domains]),
            ips=_unique_strings([*self.ips, *other.ips]),
            urls=_unique_strings([*self.urls, *other.urls]),
            malware_names=_unique_strings([*self.malware_names, *other.malware_names]),
        )


class EmailFacts(StrictModel):
    """Source-disclosed phishing email facts."""

    sender: str | None = Field(default=None, max_length=320)
    recipient: str | None = Field(default=None, max_length=320)
    subject: str | None = Field(default=None, max_length=500)
    delivery_method: str | None = Field(default=None, max_length=200)


class ProcessFacts(StrictModel):
    """Source-disclosed process facts."""

    target_process: str | None = Field(default=None, max_length=1000)
    parent: str | None = Field(default=None, max_length=1000)


class CommandFacts(StrictModel):
    """Source-disclosed command-line facts."""

    command_line: str | None = Field(default=None, max_length=5000)
    interpreter: str | None = Field(default=None, max_length=200)


class NetworkFacts(StrictModel):
    """Source-disclosed network facts."""

    host: str | None = Field(default=None, max_length=253)
    ip: str | None = Field(default=None, max_length=45)
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = Field(default=None, max_length=50)
    method: str | None = Field(default=None, max_length=20)
    uri: str | None = Field(default=None, max_length=3000)


class FileFact(StrictModel):
    """One file fact disclosed by the source report."""

    file_name: str | None = Field(default=None, max_length=500)
    file_path: str | None = Field(default=None, max_length=2000)
    md5: str | None = Field(default=None, pattern=r"^[A-Fa-f0-9]{32}$")
    sha256: str | None = Field(default=None, pattern=r"^[A-Fa-f0-9]{64}$")
    description: str | None = Field(default=None, max_length=2000)


class PersistenceFacts(StrictModel):
    """Source-disclosed persistence parameters."""

    details: str | None = Field(default=None, max_length=2000)
    binary: str | None = Field(default=None, max_length=2000)
    command: str | None = Field(default=None, max_length=5000)


class RegistryFacts(StrictModel):
    """Source-disclosed registry parameters."""

    key: str | None = Field(default=None, max_length=2000)
    value_name: str | None = Field(default=None, max_length=500)
    data: str | None = Field(default=None, max_length=3000)


class StepParams(StrictModel):
    """Typed evidence fields carried by one extracted attack step."""

    attack_mapping: AttackMapping = Field(default_factory=AttackMapping)
    iocs: IocFacts = Field(default_factory=IocFacts)
    email: EmailFacts = Field(default_factory=EmailFacts)
    process: ProcessFacts = Field(default_factory=ProcessFacts)
    command: CommandFacts = Field(default_factory=CommandFacts)
    network: NetworkFacts = Field(default_factory=NetworkFacts)
    files: list[FileFact] = Field(default_factory=list, max_length=30)
    persistence: PersistenceFacts = Field(default_factory=PersistenceFacts)
    registry: RegistryFacts = Field(default_factory=RegistryFacts)
    evidence: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("evidence")
    @classmethod
    def deduplicate_evidence(cls, value: list[str]) -> list[str]:
        """Normalize evidence notes."""
        return _unique_strings(value)

    def has_observable_fact(self) -> bool:
        """Return whether the step has at least one source-backed parameter."""
        data = self.model_dump(mode="json", exclude_none=True)
        data.pop("attack_mapping", None)
        return bool(_prune(data))


class ReportStep(StrictModel):
    """One atomic and observable action extracted from the report."""

    step_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    order: int = Field(ge=1, le=1000)
    name: str = Field(min_length=1, max_length=300)
    action_type: ActionType
    scene_tag: SceneTag
    src: int = Field(default=145, ge=1, le=999999)
    end: int | None = Field(default=None, ge=1, le=999999)
    os: EndpointOS
    description: str = Field(min_length=1, max_length=5000)
    uncertainty: list[str] = Field(default_factory=list, max_length=20)
    params: StepParams

    @field_validator("uncertainty")
    @classmethod
    def deduplicate_uncertainty(cls, value: list[str]) -> list[str]:
        """Normalize uncertainty notes."""
        return _unique_strings(value)

    @model_validator(mode="after")
    def require_observable_fact(self) -> Self:
        """Reject prose-only steps that cannot become source-backed evidence."""
        if not self.params.has_observable_fact():
            raise ValueError("每个攻击步骤至少需要一个可观测的来源事实")
        return self


class ReportExtraction(StrictModel):
    """Complete structured result returned by MiniMax."""

    meta: ReportMeta
    scene_nodes: list[SceneNode] = Field(min_length=1, max_length=12)
    report_iocs: IocFacts = Field(default_factory=IocFacts)
    steps: list[ReportStep] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def validate_unique_ids(self) -> Self:
        """Require stable unique node and step identifiers."""
        node_ids = [node.id for node in self.scene_nodes]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("scene_nodes.id 必须唯一")
        step_ids = [step.step_id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("steps.step_id 必须唯一")
        return self

    def to_legacy_report(self) -> dict[str, Any]:
        """Convert the strict extraction into the existing report JSON shape."""
        meta: dict[str, Any] = {
            "report_name": self.meta.report_name,
            "APT group": self.meta.apt_group or "",
            "target country": self.meta.target_countries,
            "target industry": self.meta.target_industries,
            "malware_families": self.meta.malware_families,
            "vulnerabilities": self.meta.vulnerabilities,
            "references": self.meta.references,
            "description": self.meta.description,
        }
        scene_nodes = [node.model_dump(mode="json") for node in self.scene_nodes]
        steps: list[dict[str, Any]] = []
        for step in sorted(self.steps, key=lambda item: (item.order, item.step_id)):
            params = _prune(step.params.model_dump(mode="json", exclude_none=True)) or {}
            notes = "; ".join(step.uncertainty)
            legacy_step = {
                "step_id": step.step_id,
                "order": step.order,
                "name": step.name,
                "action_type": step.action_type.value,
                "scene_tag": step.scene_tag.value,
                "src": step.src,
                "end": step.end,
                "os": step.os.value,
                "description": step.description,
                "notes": notes,
                "params": params,
            }
            steps.append(_prune(legacy_step) or {})

        report_iocs = _prune(self.report_iocs.model_dump(mode="json"))
        if report_iocs:
            steps.append(
                {
                    "step_id": "ioc-summary",
                    "order": len(steps) + 1,
                    "name": "报告披露 IOC 汇总",
                    "action_type": ActionType.METADATA.value,
                    "scene_tag": "ioc_summary",
                    "src": 145,
                    "os": EndpointOS.WINDOWS.value,
                    "description": "报告中明确披露的指标汇总，不作为独立攻击动作。",
                    "params": {"iocs": report_iocs},
                }
            )
        return {"meta": _prune(meta) or {}, "scene_nodes": scene_nodes, "steps": steps}


def parse_report_json(content: str) -> ReportExtraction:
    """Parse one MiniMax response into the strict report model."""
    cleaned = content.strip()
    cleaned = re.sub(r"^<think>.*?</think>\s*", "", cleaned, flags=re.DOTALL)
    fence = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", cleaned, flags=re.DOTALL | re.IGNORECASE)
    if fence:
        cleaned = fence.group(1).strip()
    raw = json.loads(cleaned)
    if not isinstance(raw, dict):
        raise ValueError("模型响应必须是 JSON 对象")
    raw = _normalize_step_action_types(raw)
    raw = _remove_enumerated_process_targets(raw)
    raw = _drop_unobservable_step_payloads(raw)
    return ReportExtraction.model_validate(raw)


def merge_report_extractions(extractions: list[ReportExtraction]) -> ReportExtraction:
    """Merge chunk-level extractions while preserving report order."""
    if not extractions:
        raise ValueError("至少需要一个报告抽取结果")
    if len(extractions) == 1:
        return extractions[0]

    first = extractions[0]
    meta = first.meta.model_copy(deep=True)
    nodes_by_id = {node.id: node for extraction in extractions for node in extraction.scene_nodes}
    report_iocs = IocFacts()
    seen_steps: set[tuple[str, str, str]] = set()
    steps: list[ReportStep] = []

    for extraction in extractions:
        meta.target_countries = _unique_strings(
            [*meta.target_countries, *extraction.meta.target_countries]
        )
        meta.target_industries = _unique_strings(
            [*meta.target_industries, *extraction.meta.target_industries]
        )
        meta.malware_families = _unique_strings(
            [*meta.malware_families, *extraction.meta.malware_families]
        )
        meta.vulnerabilities = _unique_strings(
            [*meta.vulnerabilities, *extraction.meta.vulnerabilities]
        )
        meta.references = _unique_strings([*meta.references, *extraction.meta.references])
        if not meta.apt_group and extraction.meta.apt_group:
            meta.apt_group = extraction.meta.apt_group
        report_iocs = report_iocs.merged(extraction.report_iocs)
        for step in sorted(extraction.steps, key=lambda item: (item.order, item.step_id)):
            key = (
                step.scene_tag.value,
                step.name.casefold(),
                re.sub(r"\s+", " ", step.description).casefold(),
            )
            if key in seen_steps:
                continue
            seen_steps.add(key)
            steps.append(step)

    normalized_steps = [
        step.model_copy(update={"step_id": f"s{index:03d}", "order": index}, deep=True)
        for index, step in enumerate(steps, start=1)
    ]
    return ReportExtraction(
        meta=meta,
        scene_nodes=list(nodes_by_id.values()),
        report_iocs=report_iocs,
        steps=normalized_steps,
    )


def _prune(value: Any) -> Any:
    """Recursively remove absent and empty values from legacy JSON output."""
    if isinstance(value, dict):
        cleaned = {key: _prune(item) for key, item in value.items()}
        return {key: item for key, item in cleaned.items() if item not in (None, "", [], {})}
    if isinstance(value, list):
        cleaned_list = [_prune(item) for item in value]
        return [item for item in cleaned_list if item not in (None, "", [], {})]
    return value


def _drop_unobservable_step_payloads(raw: dict[str, Any]) -> dict[str, Any]:
    """Drop only well-formed step objects whose parameter payload is entirely empty."""
    steps = raw.get("steps")
    if not isinstance(steps, list):
        return raw
    retained: list[Any] = []
    for step in steps:
        if not isinstance(step, dict):
            retained.append(step)
            continue
        params = step.get("params")
        if not isinstance(params, dict):
            retained.append(step)
            continue
        observable = dict(params)
        observable.pop("attack_mapping", None)
        if _prune(observable):
            retained.append(step)
    return {**raw, "steps": retained}


def _normalize_step_action_types(raw: dict[str, Any]) -> dict[str, Any]:
    """Derive compiler routing types from the strict scene-tag vocabulary."""
    steps = raw.get("steps")
    if not isinstance(steps, list):
        return raw
    normalized_steps: list[Any] = []
    for step in steps:
        if not isinstance(step, dict):
            normalized_steps.append(step)
            continue
        action_type = ACTION_TYPE_BY_TAG.get(str(step.get("scene_tag") or ""))
        normalized_steps.append({**step, "action_type": action_type} if action_type else step)
    return {**raw, "steps": normalized_steps}


def _remove_enumerated_process_targets(raw: dict[str, Any]) -> dict[str, Any]:
    """Keep process enumeration lists out of the singular process-image field."""
    steps = raw.get("steps")
    if not isinstance(steps, list):
        return raw
    normalized_steps: list[Any] = []
    for step in steps:
        if not isinstance(step, dict):
            normalized_steps.append(step)
            continue
        params = step.get("params")
        process = params.get("process") if isinstance(params, dict) else None
        target = process.get("target_process") if isinstance(process, dict) else None
        if not isinstance(target, str) or len(re.findall(r"(?i)\.exe\b", target)) < 2:
            normalized_steps.append(step)
            continue
        normalized_process = {
            key: value for key, value in process.items() if key != "target_process"
        }
        normalized_params = {**params, "process": normalized_process}
        normalized_steps.append({**step, "params": normalized_params})
    return {**raw, "steps": normalized_steps}
