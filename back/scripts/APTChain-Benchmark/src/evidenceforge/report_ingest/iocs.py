# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Deterministic IOC extraction and model-provenance checks."""

import hashlib
import ipaddress
import re
import unicodedata
from collections.abc import Callable, Sequence
from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from evidenceforge.report_ingest.extractors import (
    ExtractedDocument,
    ReportInputError,
    validate_document_spans,
)
from evidenceforge.report_ingest.models import (
    AuditAction,
    EntityType,
    FactAuditResult,
    FactAuditSuggestion,
    FieldOrigin,
    FieldProvenance,
    IndicatorKind,
    IocFacts,
    ReportEntity,
    ReportExtraction,
    ReportFact,
    ReportFactExtraction,
    ReportFactLedger,
    ReportIndicator,
    ReportRelation,
    SourceSpan,
    StrictModel,
    normalize_entity_value,
)

IocChecker = Callable[["IocKind", str | None, str], None]

_CONTROLLED_REPORT_BEHAVIORS = {
    "anti_debug_anti_vm",
    "bios_registry_query",
    "browser_history_theft",
    "c2_beacon_https",
    "c2_checkin",
    "c2_command_fetch",
    "c2_dns_resolution",
    "c2_system_info_exfil",
    "clipboard_theft",
    "credential_theft_chrome",
    "credential_theft_firefox",
    "data_exfiltration",
    "decoy_document_download",
    "decoy_document_open",
    "document_filename_collection",
    "file_create",
    "host_recon",
    "malware_execution",
    "network_connectivity_check",
    "other",
    "payload_download",
    "payload_download_execute",
    "persistence_scheduled_task",
    "registry_query",
    "registry_read",
    "registry_run_persistence",
    "registry_set",
    "registry_write",
    "remote_command_execution",
    "screen_capture",
    "self_deletion",
    "service_installation",
    "spearphishing_attachment",
}
_NETWORK_AUTO_BIND_BEHAVIORS = {
    "c2_beacon_https",
    "c2_checkin",
    "c2_command_fetch",
    "c2_system_info_exfil",
    "data_exfiltration",
    "decoy_document_download",
    "network_connectivity_check",
    "payload_download",
}
_DOWNLOAD_AUTO_BIND_BEHAVIORS = {"decoy_document_download", "payload_download"}
_TASK_AUTO_BIND_BEHAVIORS = {"persistence_scheduled_task"}
_REGISTRY_QUERY_AUTO_BIND_BEHAVIORS = {
    "anti_debug_anti_vm",
    "bios_registry_query",
    "registry_query",
    "registry_read",
}
_ANTI_ANALYSIS_AUTO_BIND_BEHAVIORS = {"anti_debug_anti_vm"}
_PROCESS_OWNER_PREDICATES = {
    "executed_by",
    "executes",
    "performed_by",
    "runs",
    "source_process",
}
_ANTI_PROCESS_DESCRIPTION_MARKERS = (
    "进程",
    "遍历",
    "枚举",
    "调试器",
    "process",
    "debugger",
)
_ANTI_REGISTRY_DESCRIPTION_MARKERS = (
    "注册表",
    "bios",
    "registry",
)
_ANTI_CONDITION_MARKERS = ("如果", "若", "一旦", "if ", "when ")
_ANTI_CONSEQUENCE_MARKERS = (
    "删除",
    "自毁",
    "退出",
    "delete",
    "self-destruct",
    "self destruct",
    "terminate",
    "exit",
)
_EXECUTABLE_TOKEN_RE = re.compile(r"(?i)[A-Za-z0-9_.-]{1,128}?\.exe")
_TASK_ROW_RE = re.compile(
    r"(?i)(?P<name>[A-Za-z][A-Za-z0-9_-]{2,127})\s+"
    r"(?:启动|start(?:s)?|run(?:s)?)\s+"
    r"(?P<binary>(?:%[A-Za-z][A-Za-z0-9_]*%|[A-Za-z]:)\\[^\s，。；]+)"
)
_TASK_TRIGGER_RE = re.compile(
    r"(?i)(?:无限期的\s*)?(?:每\s*隔?\s*\d{1,6}\s*(?:分钟|分|小时)|"
    r"every\s+\d{1,6}\s*(?:minutes?|mins?|hours?|hrs?))"
)
_TASK_CREATION_METHOD_RE = re.compile(r"(?i)COM\s*组件|COM\s+component|schtasks(?:\.exe)?")
_VISIBLE_PDF_PAGE_HEADER_RE = re.compile(
    r"(?m)^[ \t]*\d{1,4}\s*/\s*\d{1,4}(?:[ \t]+|$)"
)
_DOCUMENT_URL_SUFFIXES = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf")
_EXPLICIT_IOC_CONTEXT_MARKERS = (
    "附录 ioc",
    "ioc ",
    "c2 &",
    "c2＆",
    "攻击指标",
    "indicators of compromise",
)
_REGISTRY_SET_AUTO_BIND_BEHAVIORS = {
    "registry_run_persistence",
    "registry_set",
    "registry_write",
}
_AUDIT_RELATION_PREDICATES = {
    "checks",
    "connects_to",
    "creates",
    "delivered_to",
    "detects",
    "downloads_from",
    "executed_by",
    "executes",
    "from",
    "inspects",
    "maps_to",
    "performed_by",
    "points_to",
    "queries",
    "resolves_to",
    "runs",
    "runs_in",
    "sent_by",
    "sent_to",
    "sets",
    "source_process",
    "targets",
    "triggered_by",
    "uses",
    "uses_command",
    "uses_process",
}
_RELATION_PREDICATE_ALIASES = {
    "connected_to": "connects_to",
}


class IocKind(StrEnum):
    """Supported deterministic IOC classes."""

    HASH = "hash"
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"


class IocCandidate(StrictModel):
    """One locally extracted source indicator."""

    kind: IocKind
    original: str = Field(min_length=1, max_length=4000)
    normalized: str = Field(min_length=1, max_length=4000)
    occurrences: list["SourceOccurrence"] = Field(default_factory=list, max_length=1000)


class SourceOccurrence(StrictModel):
    """One exact character occurrence and its enclosing source spans."""

    char_start: int = Field(ge=0)
    char_end: int = Field(gt=0)
    source_span_ids: list[str] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def validate_range(self) -> "SourceOccurrence":
        """Require a non-empty occurrence range."""
        if self.char_end <= self.char_start:
            raise ValueError("IOC 出现位置 char_end 必须大于 char_start")
        return self


_HASH_RE = re.compile(
    r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Fa-f0-9])"
)
_IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}(?:\.|\[\.\]|\(\.\)|\{\.\})){3}\d{1,3}(?![\d.])")
_URL_RE = re.compile(r"\b(?:https?|hxxps?)://[^\s<>\"'，。；、）】]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.|\[\.\]|\(\.\)|\{\.\})){1,}[A-Za-z]{2,63}(?![A-Za-z0-9_-])"
)
_TRAILING_PUNCTUATION = ".,;:!?)]}>，。；：！？）】》"
_FILE_LIKE_TLDS = {
    "7z",
    "bin",
    "dll",
    "doc",
    "docx",
    "exe",
    "gif",
    "jpeg",
    "jpg",
    "json",
    "log",
    "pdf",
    "png",
    "ppt",
    "pptx",
    "rar",
    "tmp",
    "txt",
    "xls",
    "xlsx",
    "yaml",
    "yml",
    "zip",
}
_SOURCE_ATTRIBUTE_ENTITY_TYPES = {
    "binary": EntityType.FILE,
    "creation_method": EntityType.OTHER,
    "port": EntityType.OTHER,
    "protocol": EntityType.OTHER,
    "service_name": EntityType.SERVICE,
    "trigger": EntityType.OTHER,
    "value_data": EntityType.OTHER,
    "value_name": EntityType.OTHER,
}


def normalize_defanged(value: str) -> str:
    """Undo only conventional, syntax-preserving IOC defanging."""
    normalized = value.strip().strip(_TRAILING_PUNCTUATION)
    normalized = re.sub(r"(?i)^hxxps://", "https://", normalized)
    normalized = re.sub(r"(?i)^hxxp://", "http://", normalized)
    normalized = re.sub(
        r"\[(?:\.|dot)\]|\((?:\.|dot)\)|\{(?:\.|dot)\}", ".", normalized, flags=re.IGNORECASE
    )
    return normalized


def extract_ioc_candidates(
    text: str,
    spans: Sequence[SourceSpan] = (),
) -> list[IocCandidate]:
    """Extract hashes, IPs, URLs, and domains without any network access."""
    candidates: list[IocCandidate] = []
    index_by_key: dict[tuple[IocKind, str], int] = {}

    def add(
        kind: IocKind,
        original: str,
        normalized: str,
        char_start: int,
        char_end: int,
    ) -> None:
        key = (kind, normalized.casefold())
        occurrence = SourceOccurrence(
            char_start=char_start,
            char_end=char_end,
            source_span_ids=_span_ids_for_range(spans, char_start, char_end),
        )
        existing_index = index_by_key.get(key)
        if existing_index is not None:
            existing = candidates[existing_index]
            occurrence_keys = {
                (item.char_start, item.char_end, tuple(item.source_span_ids))
                for item in existing.occurrences
            }
            occurrence_key = (
                occurrence.char_start,
                occurrence.char_end,
                tuple(occurrence.source_span_ids),
            )
            if occurrence_key not in occurrence_keys:
                candidates[existing_index] = existing.model_copy(
                    update={"occurrences": [*existing.occurrences, occurrence]},
                    deep=True,
                )
            return
        index_by_key[key] = len(candidates)
        candidates.append(
            IocCandidate(
                kind=kind,
                original=original,
                normalized=normalized,
                occurrences=[occurrence],
            )
        )

    for match in _HASH_RE.finditer(text):
        value = match.group(0)
        add(IocKind.HASH, value, value.lower(), match.start(), match.end())

    for match in _URL_RE.finditer(text):
        original = match.group(0).rstrip(_TRAILING_PUNCTUATION)
        normalized = normalize_defanged(original)
        parts = urlsplit(normalized)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            continue
        end = match.start() + len(original)
        add(IocKind.URL, original, normalized, match.start(), end)
        _add_host_candidate(parts.hostname, add, match.start(), end)

    for match in _IP_RE.finditer(text):
        original = match.group(0)
        normalized = normalize_defanged(original)
        try:
            parsed = ipaddress.ip_address(normalized)
        except ValueError:
            continue
        if parsed.version == 4:
            add(IocKind.IP, original, str(parsed), match.start(), match.end())

    for match in _DOMAIN_RE.finditer(text):
        original = match.group(0)
        normalized = normalize_defanged(original).lower()
        if normalized.rsplit(".", 1)[-1] in _FILE_LIKE_TLDS:
            continue
        if _valid_domain(normalized):
            add(IocKind.DOMAIN, original, normalized, match.start(), match.end())

    return candidates


def candidates_to_ioc_facts(candidates: list[IocCandidate]) -> IocFacts:
    """Group deterministic candidates into the model's report-level IOC shape."""
    return IocFacts(
        hashes=[item.normalized for item in candidates if item.kind == IocKind.HASH],
        domains=[item.normalized for item in candidates if item.kind == IocKind.DOMAIN],
        ips=[item.normalized for item in candidates if item.kind == IocKind.IP],
        urls=[item.normalized for item in candidates if item.kind == IocKind.URL],
    )


def extract_unique_domain_ip_mappings(text: str) -> dict[str, str]:
    """Extract unambiguous domain-to-IPv4 pairs explicitly joined in source text."""
    mappings: dict[str, set[str]] = {}
    pair_pattern = re.compile(
        rf"(?P<domain>{_DOMAIN_RE.pattern})\s*(?:-|–|—|=|:|：|->|→)\s*"
        rf"(?P<ip>{_IP_RE.pattern})",
        re.IGNORECASE,
    )
    for match in pair_pattern.finditer(text):
        domain = normalize_defanged(match.group("domain")).lower()
        ip = normalize_defanged(match.group("ip"))
        if not _valid_domain(domain):
            continue
        try:
            parsed_ip = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if parsed_ip.version == 4:
            mappings.setdefault(domain, set()).add(str(parsed_ip))
    return {domain: next(iter(ips)) for domain, ips in mappings.items() if len(ips) == 1}


def apply_domain_ip_mappings(
    report: ReportExtraction,
    mappings: dict[str, str],
) -> ReportExtraction:
    """Fill missing step IPs only from explicit, unambiguous source mappings."""
    if not mappings:
        return report
    steps = []
    for step in report.steps:
        network = step.params.network
        normalized_host = normalize_defanged(network.host or "").lower()
        mapped_ip = mappings.get(normalized_host)
        if network.ip or not mapped_ip:
            steps.append(step)
            continue
        updated_network = network.model_copy(update={"ip": mapped_ip}, deep=True)
        updated_params = step.params.model_copy(update={"network": updated_network}, deep=True)
        steps.append(step.model_copy(update={"params": updated_params}, deep=True))
    return report.model_copy(update={"steps": steps}, deep=True)


def merge_deterministic_iocs(
    report: ReportExtraction,
    candidates: list[IocCandidate],
) -> ReportExtraction:
    """Preserve high-confidence local hashes and IPs at report scope.

    Domains and URLs require report context because publication links and vendor
    references are syntactically indistinguishable from attack infrastructure.
    The model may select them only from the deterministic allowlist.
    """
    all_facts = candidates_to_ioc_facts(candidates)
    deterministic = IocFacts(hashes=all_facts.hashes, ips=all_facts.ips)
    return report.model_copy(
        update={"report_iocs": report.report_iocs.merged(deterministic)},
        deep=True,
    )


def merge_deterministic_report_indicators(
    ledger: ReportFactLedger,
    candidates: list[IocCandidate],
) -> ReportFactLedger:
    """合并高置信哈希/IP，并闭合已选技术 URL 的域名。

    域名和 URL 可能只是新闻或厂商引用，仍由任务 A/B 结合语义决定。
    但一个 URL 一旦已被 A/B 选为报告 IOC，其中逐字存在的域名不应再
    依赖模型重复抽取。
    """
    existing = {
        (indicator.kind.value, indicator.normalized_value) for indicator in ledger.report_iocs
    }
    indicators = [indicator.model_copy(deep=True) for indicator in ledger.report_iocs]
    for candidate in candidates:
        if candidate.kind not in {IocKind.HASH, IocKind.IP}:
            continue
        key = (candidate.kind.value, candidate.normalized)
        if key in existing:
            continue
        source_span_ids = list(
            dict.fromkeys(
                span_id
                for occurrence in candidate.occurrences
                for span_id in occurrence.source_span_ids
            )
        )
        if not source_span_ids:
            continue
        digest = hashlib.sha256(
            f"{candidate.kind.value}|{candidate.normalized}".encode()
        ).hexdigest()[:12]
        indicators.append(
            ReportIndicator(
                indicator_id=f"ioc-local-{candidate.kind.value}-{digest}",
                kind=IndicatorKind(candidate.kind.value),
                value=candidate.normalized,
                provenance=FieldProvenance(
                    origin=FieldOrigin.SOURCE,
                    source_span_ids=source_span_ids,
                ),
            )
        )
        existing.add(key)

    for indicator in tuple(indicators):
        if indicator.kind != IndicatorKind.URL:
            continue
        hostname = urlsplit(indicator.normalized_value or "").hostname
        if not hostname or not _valid_domain(hostname):
            continue
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            continue
        key = (IndicatorKind.DOMAIN.value, hostname)
        if key in existing:
            continue
        digest = hashlib.sha256(f"domain-from-url|{hostname}".encode()).hexdigest()[:12]
        indicators.append(
            ReportIndicator(
                indicator_id=f"ioc-local-domain-from-url-{digest}",
                kind=IndicatorKind.DOMAIN,
                value=hostname,
                provenance=indicator.provenance.model_copy(deep=True),
            )
        )
        existing.add(key)
    return ReportFactLedger.model_validate(
        {**ledger.model_dump(mode="json"), "report_iocs": indicators}
    )


def enrich_report_ledger_structure(ledger: ReportFactLedger) -> ReportFactLedger:
    """Promote verified IOCs and add only unambiguous source-local fact bindings."""
    kept_facts = [fact for fact in ledger.facts if fact.behavior in _CONTROLLED_REPORT_BEHAVIORS]
    kept_facts = _promote_explicit_inventory_exfil_facts(kept_facts, ledger.source_spans)
    kept_facts = _promote_explicit_executable_masquerade_facts(
        kept_facts,
        ledger.source_spans,
    )
    kept_facts = _reclassify_explicit_document_download_facts(kept_facts)
    kept_facts = _recover_explicit_conditional_self_deletion_facts(
        kept_facts,
        ledger.source_spans,
    )
    kept_facts = _recover_explicit_cleanup_self_deletion_facts(
        kept_facts,
        ledger.source_spans,
    )
    removed_fact_ids = {fact.fact_id for fact in ledger.facts} - {
        fact.fact_id for fact in kept_facts
    }
    relations: list[ReportRelation] = []
    for relation in ledger.relations:
        if relation.source_id in removed_fact_ids or relation.target_id in removed_fact_ids:
            continue
        normalized_predicate = _RELATION_PREDICATE_ALIASES.get(relation.predicate)
        if normalized_predicate is None:
            relations.append(relation)
            continue
        relations.append(
            relation.model_copy(
                update={
                    "predicate": normalized_predicate,
                    "provenance": FieldProvenance(
                        origin=FieldOrigin.DERIVED,
                        source_span_ids=relation.provenance.source_span_ids,
                        source_ids=[relation.source_id, relation.target_id],
                        reason="将模型关系同义词确定性归一为编译器受控谓词",
                    ),
                },
                deep=True,
            )
        )
    entities = [entity.model_copy(deep=True) for entity in ledger.entities]
    entity_index = {(entity.entity_type, entity.canonical_value): entity for entity in entities}
    indicator_types = {
        IndicatorKind.HASH: EntityType.HASH,
        IndicatorKind.DOMAIN: EntityType.DOMAIN,
        IndicatorKind.IP: EntityType.IP,
        IndicatorKind.URL: EntityType.URL,
    }
    for indicator in ledger.report_iocs:
        entity_type = indicator_types[indicator.kind]
        canonical = normalize_entity_value(entity_type, indicator.value)
        if (entity_type, canonical) in entity_index:
            continue
        digest = hashlib.sha256(f"{entity_type.value}|{canonical}".encode()).hexdigest()[:12]
        entity = ReportEntity(
            entity_id=f"entity-local-ioc-{entity_type.value}-{digest}",
            entity_type=entity_type,
            value=indicator.value,
            provenance=indicator.provenance.model_copy(deep=True),
        )
        entities.append(entity)
        entity_index[(entity_type, canonical)] = entity

    publisher_domains = _context_only_publisher_domains(
        ledger.report_iocs,
        ledger.source_spans,
    )
    publisher_entity_ids = {
        entity.entity_id
        for entity in entities
        if (
            entity.entity_type == EntityType.DOMAIN
            and entity.canonical_value in publisher_domains
        )
        or (
            entity.entity_type == EntityType.URL
            and urlsplit(entity.canonical_value or entity.value).hostname in publisher_domains
        )
    }
    if publisher_entity_ids:
        entities = [
            entity for entity in entities if entity.entity_id not in publisher_entity_ids
        ]
        relations = [
            relation
            for relation in relations
            if relation.source_id not in publisher_entity_ids
            and relation.target_id not in publisher_entity_ids
        ]

    entities = _promote_anti_analysis_process_entities(
        kept_facts,
        entities,
        ledger.source_spans,
    )
    entities = _promote_scheduled_task_entities(
        kept_facts,
        entities,
        ledger.source_spans,
    )
    relations = _repair_scheduled_task_relations(
        kept_facts,
        entities,
        relations,
    )
    relations = _repair_task_binary_network_relations(
        kept_facts,
        entities,
        relations,
    )
    relations = _repair_report_network_relations(
        kept_facts,
        entities,
        relations,
        ledger.report_iocs,
        ledger.source_spans,
    )

    existing_pairs = {
        (relation.source_id, relation.predicate, relation.target_id) for relation in relations
    }
    next_relation = 1
    for entity in entities:
        rule = _auto_binding_rule(entity.entity_type)
        if rule is None:
            continue
        behaviors, predicate = rule
        compatible = [
            fact
            for fact in kept_facts
            if fact.behavior in behaviors
            and set(fact.provenance.source_span_ids) & set(entity.provenance.source_span_ids)
        ]
        exact_description_matches = [
            fact
            for fact in compatible
            if _claim_mentioned_in_summary(entity.value, fact.description)
        ]
        if exact_description_matches:
            targets = exact_description_matches
        elif len(compatible) == 1:
            targets = compatible
        elif entity.entity_type in {EntityType.PROCESS, EntityType.REGISTRY}:
            targets = _preferred_anti_analysis_facts(entity.entity_type, compatible)
        else:
            targets = []
        if entity.entity_type == EntityType.PROCESS:
            targets = [
                fact
                for fact in targets
                if not any(
                    relation.source_id == fact.fact_id
                    and relation.target_id == entity.entity_id
                    and relation.predicate in _PROCESS_OWNER_PREDICATES
                    for relation in relations
                )
            ]
        for fact in targets:
            relation_predicate = (
                "creates"
                if entity.entity_type == EntityType.FILE
                and fact.behavior in _DOWNLOAD_AUTO_BIND_BEHAVIORS
                else (
                    "downloads_from"
                    if entity.entity_type == EntityType.URL
                    and fact.behavior in _DOWNLOAD_AUTO_BIND_BEHAVIORS
                    else (
                        "sets"
                        if entity.entity_type == EntityType.REGISTRY
                        and fact.behavior in _REGISTRY_SET_AUTO_BIND_BEHAVIORS
                        else predicate
                    )
                )
            )
            key = (fact.fact_id, relation_predicate, entity.entity_id)
            if key in existing_pairs:
                continue
            while any(
                relation.relation_id == f"relation-local-{next_relation:04d}"
                for relation in relations
            ):
                next_relation += 1
            relations.append(
                ReportRelation(
                    relation_id=f"relation-local-{next_relation:04d}",
                    source_id=fact.fact_id,
                    predicate=relation_predicate,
                    target_id=entity.entity_id,
                    provenance=FieldProvenance(
                        origin=FieldOrigin.DERIVED,
                        source_ids=[fact.fact_id, entity.entity_id],
                        reason="同一来源片段内只有一个兼容事实，确定性建立事实与精确实体关系",
                    ),
                )
            )
            existing_pairs.add(key)
            next_relation += 1

    kept_facts = _reclassify_context_only_anti_analysis_facts(
        kept_facts,
        relations,
        entities,
        ledger.source_spans,
    )
    kept_facts = _reclassify_task_attribute_context_facts(
        kept_facts,
        relations,
        entities,
    )
    report_iocs = _filter_contextual_report_indicators(
        ledger.report_iocs,
        entities,
        relations,
        kept_facts,
        ledger.source_spans,
    )

    return ReportFactLedger.model_validate(
        {
            **ledger.model_dump(mode="json"),
            "facts": kept_facts,
            "entities": entities,
            "relations": relations,
            "report_iocs": report_iocs,
        }
    )


def _promote_explicit_inventory_exfil_facts(
    facts: list[ReportFact],
    source_spans: list[SourceSpan],
) -> list[ReportFact]:
    """将同片段明确的主机信息发送恢复为独立外传事实。"""
    existing_spans = {
        span_id
        for fact in facts
        if fact.behavior == "c2_system_info_exfil"
        for span_id in fact.provenance.source_span_ids
    }
    result = [fact.model_copy(deep=True) for fact in facts]
    for span in source_spans:
        if span.span_id in existing_spans:
            continue
        text = unicodedata.normalize("NFKC", span.quote).casefold()
        has_inventory = any(
            marker in text
            for marker in (
                "当前用户名",
                "进程列表",
                "模块列表",
                "system information",
                "process list",
                "module list",
                "username",
            )
        )
        has_send = any(
            marker in text
            for marker in ("发送到", "上传到", "服务端", "send to", "sent to", "upload")
        )
        if not has_inventory or not has_send:
            continue
        digest = hashlib.sha256(f"inventory-exfil|{span.span_id}".encode()).hexdigest()[:12]
        span_orders = [
            fact.order for fact in result if span.span_id in fact.provenance.source_span_ids
        ]
        result.append(
            ReportFact(
                fact_id=f"fact-local-inventory-exfil-{digest}",
                behavior="c2_system_info_exfil",
                order=min(10_000, max(span_orders, default=0) + 1),
                description="将报告明确列出的当前用户、进程列表或模块列表发送到服务端",
                uncertainty=["由同一来源片段中明确的收集对象与发送动作确定性恢复"],
                provenance=FieldProvenance(
                    origin=FieldOrigin.SOURCE,
                    source_span_ids=[span.span_id],
                ),
            )
        )
    return result


def _promote_explicit_executable_masquerade_facts(
    facts: list[ReportFact],
    source_spans: list[SourceSpan],
) -> list[ReportFact]:
    """将同片段明确的可执行文件外观伪装恢复为来源上下文事实。"""
    if any(_is_executable_masquerade_text(fact.description) for fact in facts):
        return facts
    result = [fact.model_copy(deep=True) for fact in facts]
    for span in source_spans:
        if not _is_executable_masquerade_text(span.quote):
            continue
        digest = hashlib.sha256(f"executable-masquerade|{span.span_id}".encode()).hexdigest()[
            :12
        ]
        span_orders = [
            fact.order for fact in result if span.span_id in fact.provenance.source_span_ids
        ]
        result.append(
            ReportFact(
                fact_id=f"fact-local-executable-masquerade-{digest}",
                behavior="other",
                order=min(10_000, max(span_orders, default=0) + 1),
                description="报告明确描述恶意可执行文件通过修改图标或隐藏后缀进行伪装并诱导用户打开",
                uncertainty=["由同一来源片段中的可执行文件、外观伪装和诱导动作确定性恢复"],
                provenance=FieldProvenance(
                    origin=FieldOrigin.SOURCE,
                    source_span_ids=[span.span_id],
                ),
            )
        )
        break
    return result


def _is_executable_masquerade_text(text: str) -> bool:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    has_executable = any(
        marker in normalized
        for marker in ("恶意可执行文件", "可执行文件", "pe 文件", "executable")
    )
    has_appearance = any(
        marker in normalized for marker in ("图标", "文件名", "后缀", "icon", "extension")
    )
    has_deception = any(
        marker in normalized for marker in ("伪装", "隐藏", "诱导", "masquerad", "disguis")
    )
    return has_executable and has_appearance and has_deception


def _reclassify_explicit_document_download_facts(
    facts: list[ReportFact],
) -> list[ReportFact]:
    """将只描述诱饵文档下载的通用载荷事实恢复为文档下载角色。"""
    result: list[ReportFact] = []
    for fact in facts:
        text = unicodedata.normalize("NFKC", fact.description).casefold()
        is_generic_download = fact.behavior in {"payload_download", "payload_download_execute"}
        has_download = "下载" in text or "download" in text
        has_document = any(
            marker in text
            for marker in (
                "伪装文档",
                "伪装pdf",
                "伪装 pdf",
                "诱饵文档",
                "诱饵 pdf",
                "decoy document",
                ".pdf",
            )
        )
        has_attack_component = any(
            marker in text for marker in ("攻击组件", "后续组件", "payload", "component")
        )
        if not (is_generic_download and has_download and has_document and not has_attack_component):
            result.append(fact)
            continue
        result.append(
            fact.model_copy(
                update={
                    "behavior": "decoy_document_download",
                    "uncertainty": [
                        *fact.uncertainty,
                        "描述只包含诱饵文档下载且不含攻击组件，确定性恢复文档角色",
                    ],
                },
                deep=True,
            )
        )
    return result


def _recover_explicit_conditional_self_deletion_facts(
    facts: list[ReportFact],
    source_spans: list[SourceSpan],
) -> list[ReportFact]:
    """从来源条件句恢复自删除角色和条件限定，不依赖模型摘要措辞。"""
    conditional_span_ids = {
        span.span_id
        for span in source_spans
        if _is_explicit_conditional_self_deletion_text(span.quote)
    }
    original_self_deletion_spans = {
        span_id
        for fact in facts
        if fact.behavior == "self_deletion"
        for span_id in fact.provenance.source_span_ids
    }
    result: list[ReportFact] = []
    for fact in facts:
        fact_spans = set(fact.provenance.source_span_ids)
        source_proves_condition = bool(fact_spans & conditional_span_ids)
        description_proves_condition = _is_explicit_conditional_self_deletion_text(
            fact.description
        )
        if fact.behavior == "self_deletion" and (
            source_proves_condition or description_proves_condition
        ):
            if description_proves_condition:
                result.append(fact)
            else:
                result.append(
                    fact.model_copy(
                        update={
                            "description": "如果报告所述反分析条件成立，样本触发自毁机制并删除自身",
                            "uncertainty": [
                                *fact.uncertainty,
                                "模型摘要遗漏条件限定；由事实引用的来源片段确定性恢复",
                            ],
                        },
                        deep=True,
                    )
                )
            continue
        if fact.behavior != "anti_debug_anti_vm":
            result.append(fact)
            continue
        text = unicodedata.normalize("NFKC", fact.description).casefold()
        has_check_action = any(
            marker in text
            for marker in (
                "遍历进程",
                "枚举进程",
                "比对进程",
                "查询注册表",
                "读取注册表",
                "process enumeration",
                "process list",
                "registry query",
            )
        )
        shares_existing_self_deletion = bool(
            fact_spans & original_self_deletion_spans
        )
        if not (
            (source_proves_condition or description_proves_condition)
            and not has_check_action
            and not shares_existing_self_deletion
        ):
            result.append(fact)
            continue
        result.append(
            fact.model_copy(
                update={
                    "behavior": "self_deletion",
                    "description": "如果报告所述反分析条件成立，样本触发自毁机制并删除自身",
                    "uncertainty": [
                        *fact.uncertainty,
                        "该事实只表达反分析条件成立后的自毁/删除后果，确定性恢复为自删除",
                    ],
                },
                deep=True,
            )
        )
    covered_conditional_spans = {
        span_id
        for fact in result
        if fact.behavior == "self_deletion"
        for span_id in fact.provenance.source_span_ids
        if span_id in conditional_span_ids
    }
    for span_id in sorted(conditional_span_ids - covered_conditional_spans):
        digest = hashlib.sha256(f"conditional-self-delete|{span_id}".encode()).hexdigest()[
            :12
        ]
        span_orders = [
            fact.order for fact in result if span_id in fact.provenance.source_span_ids
        ]
        result.append(
            ReportFact(
                fact_id=f"fact-local-conditional-self-delete-{digest}",
                behavior="self_deletion",
                order=min(10_000, max(span_orders, default=0) + 1),
                description="如果报告所述反分析条件成立，样本触发自毁机制并删除自身",
                uncertainty=["由同一来源片段中的显式条件与自毁/删除自身后果确定性恢复"],
                provenance=FieldProvenance(
                    origin=FieldOrigin.SOURCE,
                    source_span_ids=[span_id],
                ),
            )
        )
    return result


def _is_explicit_conditional_self_deletion_text(text: str) -> bool:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    has_condition = any(
        marker in normalized for marker in _ANTI_CONDITION_MARKERS
    ) or bool(re.search(r"(?:检测到|发现|处于).{0,100}(?:时|则|后)", normalized))
    return has_condition and _has_explicit_self_deletion_action(normalized)


def _recover_explicit_cleanup_self_deletion_facts(
    facts: list[ReportFact],
    source_spans: list[SourceSpan],
) -> list[ReportFact]:
    """从来源单独恢复工作完成后的清理自删除。

    条件自毁和收尾清理可能使用同一 API，但它们的触发条件和攻击
    语义不同。即使模型将跨页内容合并成一个事实，也要保留两个独立行为。
    """
    cleanup_span_ids = {
        span.span_id
        for span in source_spans
        if _is_explicit_cleanup_self_deletion_text(span.quote)
    }
    if not cleanup_span_ids:
        return facts

    conditional_span_ids = {
        span.span_id
        for span in source_spans
        if _is_explicit_conditional_self_deletion_text(span.quote)
    }
    result: list[ReportFact] = []
    for fact in facts:
        if fact.behavior != "self_deletion" or not _is_explicit_conditional_self_deletion_text(
            fact.description
        ):
            result.append(fact)
            continue
        source_span_ids = fact.provenance.source_span_ids
        narrowed_span_ids = [
            span_id
            for span_id in source_span_ids
            if span_id not in cleanup_span_ids or span_id in conditional_span_ids
        ]
        if not narrowed_span_ids or narrowed_span_ids == source_span_ids:
            result.append(fact)
            continue
        result.append(
            fact.model_copy(
                update={
                    "provenance": fact.provenance.model_copy(
                        update={"source_span_ids": narrowed_span_ids},
                        deep=True,
                    ),
                    "uncertainty": [
                        *fact.uncertainty,
                        "已将收尾清理片段从条件自毁事实中分离",
                    ],
                },
                deep=True,
            )
        )

    covered_cleanup_spans = {
        span_id
        for fact in result
        if fact.behavior == "self_deletion"
        and not _is_explicit_conditional_self_deletion_text(fact.description)
        for span_id in fact.provenance.source_span_ids
        if span_id in cleanup_span_ids
    }
    next_order = max((fact.order for fact in result), default=0) + 1
    for offset, span_id in enumerate(sorted(cleanup_span_ids - covered_cleanup_spans)):
        digest = hashlib.sha256(f"cleanup-self-delete|{span_id}".encode()).hexdigest()[
            :12
        ]
        result.append(
            ReportFact(
                fact_id=f"fact-local-cleanup-self-delete-{digest}",
                behavior="self_deletion",
                order=min(10_000, next_order + offset),
                description="报告明确说明主要工作完成后，样本删除自身以清理痕迹",
                uncertainty=["由来源中独立的工作完成后清理语句确定性恢复"],
                provenance=FieldProvenance(
                    origin=FieldOrigin.SOURCE,
                    source_span_ids=[span_id],
                ),
            )
        )
    return result


def _is_explicit_cleanup_self_deletion_text(text: str) -> bool:
    """识别执行完成后为清理痕迹而进行的自删除。"""
    normalized = unicodedata.normalize("NFKC", text).casefold()
    has_cleanup_context = any(
        marker in normalized
        for marker in (
            "工作完成后",
            "任务完成后",
            "操作完成后",
            "执行完成后",
            "执行结束后",
            "工作结束后",
            "清理痕迹",
            "after completion",
            "after completing",
            "upon completion",
            "clean up traces",
            "cleanup traces",
            "cover tracks",
        )
    )
    return has_cleanup_context and _has_explicit_self_deletion_action(normalized)


def _has_explicit_self_deletion_action(normalized: str) -> bool:
    """检查文本是否明确表达样本删除自身。"""
    return any(
        marker in normalized
        for marker in (
            "自毁",
            "删除自身",
            "自删除",
            "self-delete",
            "self delete",
            "self-destruct",
            "self destruct",
            "delete itself",
        )
    )


def _promote_anti_analysis_process_entities(
    facts: list[ReportFact],
    entities: list[ReportEntity],
    source_spans: list[SourceSpan],
) -> list[ReportEntity]:
    """从明确的反分析来源片段提升精确 `.exe` 检查目标。"""
    anti_span_ids = {
        span_id
        for fact in facts
        if fact.behavior == "anti_debug_anti_vm"
        for span_id in fact.provenance.source_span_ids
    }
    if not anti_span_ids:
        return entities
    result = [entity.model_copy(deep=True) for entity in entities]
    index = {
        (entity.entity_type, entity.canonical_value): position
        for position, entity in enumerate(result)
    }
    for span in source_spans:
        if span.span_id not in anti_span_ids:
            continue
        normalized_quote = unicodedata.normalize("NFKC", span.quote).casefold()
        if not any(marker in normalized_quote for marker in _ANTI_PROCESS_DESCRIPTION_MARKERS):
            continue
        for match in _EXECUTABLE_TOKEN_RE.finditer(span.quote):
            value = match.group(0)
            canonical = normalize_entity_value(EntityType.PROCESS, value)
            key = (EntityType.PROCESS, canonical)
            position = index.get(key)
            if position is not None:
                entity = result[position]
                if (
                    entity.provenance.origin == FieldOrigin.SOURCE
                    and span.span_id not in entity.provenance.source_span_ids
                ):
                    provenance = entity.provenance.model_copy(
                        update={
                            "source_span_ids": [
                                *entity.provenance.source_span_ids,
                                span.span_id,
                            ]
                        },
                        deep=True,
                    )
                    result[position] = entity.model_copy(
                        update={"provenance": provenance},
                        deep=True,
                    )
                continue
            digest = hashlib.sha256(f"process|{canonical}".encode()).hexdigest()[:12]
            index[key] = len(result)
            result.append(
                ReportEntity(
                    entity_id=f"entity-local-process-{digest}",
                    entity_type=EntityType.PROCESS,
                    value=value,
                    provenance=FieldProvenance(
                        origin=FieldOrigin.SOURCE,
                        source_span_ids=[span.span_id],
                    ),
                )
            )
    return result


def _promote_scheduled_task_entities(
    facts: list[ReportFact],
    entities: list[ReportEntity],
    source_spans: list[SourceSpan],
) -> list[ReportEntity]:
    """从跨页“任务名/动作/路径”表恢复完整计划任务实体。"""
    task_span_ids = {
        span_id
        for fact in facts
        if fact.behavior == "persistence_scheduled_task"
        for span_id in fact.provenance.source_span_ids
    }
    if not task_span_ids:
        return entities
    positions = {
        index
        for index, span in enumerate(source_spans)
        if span.span_id in task_span_ids
    }
    positions.update(
        index
        for index, span in enumerate(source_spans)
        if (
            "任务名" in span.quote
            and any(marker in span.quote for marker in ("动作", "操作", "路径"))
        )
        or (
            "task name" in span.quote.casefold()
            and any(
                marker in span.quote.casefold()
                for marker in ("action", "command", "path")
            )
        )
    )
    relevant_positions = {
        nearby
        for position in positions
        for nearby in range(max(0, position - 2), min(len(source_spans), position + 3))
    }
    relevant_spans = [source_spans[index] for index in sorted(relevant_positions)]
    combined = "\n".join(span.quote for span in relevant_spans)
    table_text = _VISIBLE_PDF_PAGE_HEADER_RE.sub("", combined)
    trigger_match = _TASK_TRIGGER_RE.search(table_text)
    trigger = trigger_match.group(0) if trigger_match else None
    method_match = _TASK_CREATION_METHOD_RE.search(table_text)
    creation_method = method_match.group(0) if method_match else None
    result = [entity.model_copy(deep=True) for entity in entities]
    index_by_canonical = {
        (entity.entity_type, entity.canonical_value): index
        for index, entity in enumerate(result)
    }
    for match in _TASK_ROW_RE.finditer(table_text):
        name = match.group("name")
        binary = match.group("binary")
        claims = [name, binary, *(item for item in (trigger, creation_method) if item)]
        claim_span_ids = [
            span.span_id
            for span in relevant_spans
            if any(
                _normalize_source_match(claim, entity_type=EntityType.OTHER)
                in _normalize_source_match(span.quote, entity_type=EntityType.OTHER)
                for claim in claims
            )
        ]
        if not claim_span_ids:
            continue
        attributes: dict[str, str] = {"binary": binary}
        if trigger:
            attributes["trigger"] = trigger
        if creation_method:
            attributes["creation_method"] = creation_method
        canonical = normalize_entity_value(EntityType.SCHEDULED_TASK, name)
        key = (EntityType.SCHEDULED_TASK, canonical)
        position = index_by_canonical.get(key)
        if position is not None:
            entity = result[position]
            merged_attributes = {**entity.attributes, **attributes}
            provenance = entity.provenance.model_copy(
                update={
                    "source_span_ids": list(
                        dict.fromkeys(
                            [*entity.provenance.source_span_ids, *claim_span_ids]
                        )
                    )
                },
                deep=True,
            )
            result[position] = entity.model_copy(
                update={"attributes": merged_attributes, "provenance": provenance},
                deep=True,
            )
            continue
        digest = hashlib.sha256(f"scheduled-task|{canonical}".encode()).hexdigest()[:12]
        index_by_canonical[key] = len(result)
        result.append(
            ReportEntity(
                entity_id=f"entity-local-task-{digest}",
                entity_type=EntityType.SCHEDULED_TASK,
                value=name,
                attributes=attributes,
                provenance=FieldProvenance(
                    origin=FieldOrigin.SOURCE,
                    source_span_ids=claim_span_ids,
                ),
            )
        )
    return result


def _repair_scheduled_task_relations(
    facts: list[ReportFact],
    entities: list[ReportEntity],
    relations: list[ReportRelation],
) -> list[ReportRelation]:
    """将表内多个精确任务稳定绑定到创建事实，而非周期上下文事实。"""
    task_facts = [fact for fact in facts if fact.behavior == "persistence_scheduled_task"]
    task_entities = [
        entity
        for entity in entities
        if entity.entity_type == EntityType.SCHEDULED_TASK
        and isinstance(entity.attributes.get("binary"), str)
        and str(entity.attributes["binary"]).strip()
    ]
    if not task_facts or not task_entities:
        return relations
    task_entity_ids = {entity.entity_id for entity in task_entities}
    carrier_fact_ids = {
        relation.source_id
        for relation in relations
        if relation.predicate == "creates"
        and relation.target_id in task_entity_ids
        and any(fact.fact_id == relation.source_id for fact in task_facts)
    }
    creation_facts = [
        fact
        for fact in task_facts
        if any(
            marker in fact.description.casefold()
            for marker in ("创建", "建立", "注册", "create", "register")
        )
    ]
    existing = {(item.source_id, item.predicate, item.target_id) for item in relations}
    result = [relation.model_copy(deep=True) for relation in relations]
    for entity in task_entities:
        if any(
            relation.target_id == entity.entity_id and relation.predicate == "creates"
            for relation in result
        ):
            continue
        exact_facts = [
            fact
            for fact in task_facts
            if _claim_mentioned_in_summary(entity.value, fact.description)
            or _claim_mentioned_in_summary(
                str(entity.attributes["binary"]),
                fact.description,
            )
        ]
        if len(exact_facts) == 1:
            carrier = exact_facts[0]
        elif len(carrier_fact_ids) == 1:
            carrier = next(fact for fact in task_facts if fact.fact_id in carrier_fact_ids)
        elif len(creation_facts) == 1:
            carrier = creation_facts[0]
        elif len(task_facts) == 1:
            carrier = task_facts[0]
        else:
            continue
        key = (carrier.fact_id, "creates", entity.entity_id)
        if key in existing:
            continue
        result.append(
            _local_semantic_relation(
                *key,
                reason="报告任务表给出精确任务行；绑定唯一点名事实或唯一创建任务承载事实",
            )
        )
        existing.add(key)
        carrier_fact_ids.add(carrier.fact_id)
    return result


def _reclassify_task_attribute_context_facts(
    facts: list[ReportFact],
    relations: list[ReportRelation],
    entities: list[ReportEntity],
) -> list[ReportFact]:
    """已有精确任务承载时，把周期/字符串概括保留为上下文而非空任务。"""
    task_entity_ids = {
        entity.entity_id
        for entity in entities
        if entity.entity_type == EntityType.SCHEDULED_TASK
    }
    task_carriers = {
        relation.source_id
        for relation in relations
        if relation.predicate == "creates" and relation.target_id in task_entity_ids
    }
    if not task_carriers:
        return facts
    result: list[ReportFact] = []
    for fact in facts:
        if fact.behavior != "persistence_scheduled_task" or fact.fact_id in task_carriers:
            result.append(fact)
            continue
        text = fact.description.casefold()
        has_creation_action = any(
            marker in text for marker in ("创建", "建立", "注册", "create", "register")
        )
        is_attribute_context = any(
            marker in text
            for marker in (
                "当前时间",
                "每隔",
                "分钟",
                "小时",
                "无限期",
                "触发",
                "相关信息",
                "相关字符串",
                "interval",
                "trigger",
                "every ",
            )
        )
        if has_creation_action or not is_attribute_context:
            result.append(fact)
            continue
        result.append(
            fact.model_copy(
                update={
                    "behavior": "other",
                    "uncertainty": [
                        *fact.uncertainty,
                        "精确任务已由创建事实承载；本项仅描述周期或任务字符串上下文",
                    ],
                },
                deep=True,
            )
        )
    return result


def _repair_task_binary_network_relations(
    facts: list[ReportFact],
    entities: list[ReportEntity],
    relations: list[ReportRelation],
) -> list[ReportRelation]:
    """阻止计划任务二进制被无依据用作 C2/外传文件对象。"""
    task_binaries = {
        normalize_entity_value(EntityType.FILE, str(entity.attributes["binary"]))
        for entity in entities
        if entity.entity_type == EntityType.SCHEDULED_TASK
        and isinstance(entity.attributes.get("binary"), str)
        and str(entity.attributes["binary"]).strip()
    }
    if not task_binaries:
        return relations
    fact_by_id = {fact.fact_id: fact for fact in facts}
    entity_by_id = {entity.entity_id: entity for entity in entities}
    network_behaviors = _NETWORK_AUTO_BIND_BEHAVIORS | {
        "c2_dns_resolution",
        "payload_download_execute",
    }
    result: list[ReportRelation] = []
    for relation in relations:
        fact = fact_by_id.get(relation.source_id)
        entity = entity_by_id.get(relation.target_id)
        is_task_binary = (
            entity is not None
            and entity.entity_type == EntityType.FILE
            and entity.canonical_value in task_binaries
        )
        is_unrelated_network_fact = (
            fact is not None
            and fact.behavior in network_behaviors
            and fact.behavior not in {"payload_download", "payload_download_execute"}
            and not _claim_mentioned_in_summary(entity.value if entity else "", fact.description)
        )
        if is_task_binary and is_unrelated_network_fact:
            continue
        result.append(relation)
    return result


def _repair_report_network_relations(
    facts: list[ReportFact],
    entities: list[ReportEntity],
    relations: list[ReportRelation],
    report_iocs: list[ReportIndicator],
    source_spans: list[SourceSpan],
) -> list[ReportRelation]:
    """防止诱饵文档 URL 串绑 C2，并恢复明确的文档/C2 通道。"""
    fact_by_id = {fact.fact_id: fact for fact in facts}
    entity_by_id = {entity.entity_id: entity for entity in entities}
    c2_behaviors = {
        "c2_beacon_https",
        "c2_checkin",
        "c2_command_fetch",
        "c2_system_info_exfil",
        "data_exfiltration",
    }
    result: list[ReportRelation] = []
    for relation in relations:
        fact = fact_by_id.get(relation.source_id)
        entity = entity_by_id.get(relation.target_id)
        if (
            fact is not None
            and entity is not None
            and fact.behavior in _NETWORK_AUTO_BIND_BEHAVIORS
            | {"payload_download_execute"}
            and fact.behavior != "decoy_document_download"
            and entity.entity_type == EntityType.URL
            and urlsplit(entity.canonical_value or entity.value).path.casefold().endswith(
                _DOCUMENT_URL_SUFFIXES
            )
        ):
            continue
        result.append(relation)

    existing = {(item.source_id, item.predicate, item.target_id) for item in result}
    decoy_facts = [fact for fact in facts if fact.behavior == "decoy_document_download"]
    document_urls = [
        entity
        for entity in entities
        if entity.entity_type == EntityType.URL
        and urlsplit(entity.canonical_value or entity.value).path.casefold().endswith(
            _DOCUMENT_URL_SUFFIXES
        )
    ]
    if len(decoy_facts) == 1:
        for entity in document_urls:
            key = (decoy_facts[0].fact_id, "downloads_from", entity.entity_id)
            if key not in existing:
                result.append(_local_semantic_relation(*key, reason="报告只有一个诱饵文档下载事实，文档后缀 URL 确定绑定该事实"))
                existing.add(key)

    span_quotes = {span.span_id: span.quote.casefold() for span in source_spans}
    explicit_c2_domains = {
        indicator.normalized_value
        for indicator in report_iocs
        if indicator.kind == IndicatorKind.DOMAIN
        and any(
            "c2" in span_quotes.get(span_id, "")
            for span_id in indicator.provenance.source_span_ids
        )
    }
    domain_entities = [
        entity
        for entity in entities
        if entity.entity_type == EntityType.DOMAIN
        and entity.canonical_value in explicit_c2_domains
    ]
    c2_facts = [fact for fact in facts if fact.behavior in c2_behaviors]
    if len(domain_entities) == 1:
        for fact in c2_facts:
            key = (fact.fact_id, "connects_to", domain_entities[0].entity_id)
            if key not in existing:
                result.append(_local_semantic_relation(*key, reason="报告 IOC 区明确将唯一域名标为 C2，绑定来源 C2/外传事实"))
                existing.add(key)
    return result


def _local_semantic_relation(
    source_id: str,
    predicate: str,
    target_id: str,
    *,
    reason: str,
) -> ReportRelation:
    digest = hashlib.sha256(f"{source_id}|{predicate}|{target_id}".encode()).hexdigest()[:12]
    return ReportRelation(
        relation_id=f"relation-local-semantic-{digest}",
        source_id=source_id,
        predicate=predicate,
        target_id=target_id,
        provenance=FieldProvenance(
            origin=FieldOrigin.DERIVED,
            source_ids=[source_id, target_id],
            reason=reason,
        ),
    )


def _filter_contextual_report_indicators(
    indicators: list[ReportIndicator],
    entities: list[ReportEntity],
    relations: list[ReportRelation],
    facts: list[ReportFact],
    source_spans: list[SourceSpan],
) -> list[ReportIndicator]:
    """删除只是报告发布来源、且无攻击上下文的域名/URL。"""
    fact_behaviors = {fact.fact_id: fact.behavior for fact in facts}
    entity_by_key = {
        (entity.entity_type.value, entity.canonical_value): entity.entity_id
        for entity in entities
    }
    technical_entity_ids = {
        relation.target_id
        for relation in relations
        if fact_behaviors.get(relation.source_id) in _NETWORK_AUTO_BIND_BEHAVIORS
        | {"c2_system_info_exfil", "c2_dns_resolution"}
    }
    technical_url_hosts = {
        urlsplit(entity.canonical_value or entity.value).hostname
        for entity in entities
        if entity.entity_id in technical_entity_ids and entity.entity_type == EntityType.URL
    }
    span_quotes = {span.span_id: span.quote.casefold() for span in source_spans}
    publisher_domains = _context_only_publisher_domains(indicators, source_spans)
    result: list[ReportIndicator] = []
    for indicator in indicators:
        if indicator.kind not in {IndicatorKind.DOMAIN, IndicatorKind.URL}:
            result.append(indicator)
            continue
        indicator_host = (
            indicator.normalized_value
            if indicator.kind == IndicatorKind.DOMAIN
            else urlsplit(indicator.normalized_value).hostname
        )
        if indicator_host in publisher_domains:
            continue
        entity_id = entity_by_key.get((indicator.kind.value, indicator.normalized_value))
        cited_text = " ".join(
            span_quotes.get(span_id, "") for span_id in indicator.provenance.source_span_ids
        )
        explicit_context = any(marker in cited_text for marker in _EXPLICIT_IOC_CONTEXT_MARKERS)
        visibly_defanged = bool(
            re.search(r"(?i)^hxxps?://|\[(?:\.|dot)\]|\((?:\.|dot)\)|\{(?:\.|dot)\}", indicator.value)
        )
        domain_used_by_technical_url = (
            indicator.kind == IndicatorKind.DOMAIN
            and indicator.normalized_value in technical_url_hosts
        )
        if (
            entity_id in technical_entity_ids
            or domain_used_by_technical_url
            or explicit_context
            or visibly_defanged
        ):
            result.append(indicator)
    return result


def _context_only_publisher_domains(
    indicators: list[ReportIndicator],
    source_spans: list[SourceSpan],
) -> set[str]:
    """识别仅作为首页“域名 /s 报告标题”出现的发布站域名。"""
    span_by_id = {span.span_id: span for span in source_spans}
    result: set[str] = set()
    for indicator in indicators:
        if indicator.kind != IndicatorKind.DOMAIN:
            continue
        domain = indicator.normalized_value
        cited_spans = [
            span_by_id[span_id]
            for span_id in indicator.provenance.source_span_ids
            if span_id in span_by_id
        ]
        header_spans = [
            span
            for span in cited_spans
            if re.search(
                rf"(?i)^\s*(?:\d{{1,4}}\s*/\s*\d{{1,4}}\s+)?"
                rf"{re.escape(domain)}\s+/s(?:\s|$)",
                span.quote,
            )
            and any(
                marker in span.quote.casefold()
                for marker in ("报告", "analysis report", "security report")
            )
        ]
        if not header_spans:
            continue
        header_ids = {span.span_id for span in header_spans}
        has_independent_technical_occurrence = any(
            span.span_id not in header_ids
            and (
                any(
                    marker in span.quote.casefold()
                    for marker in _EXPLICIT_IOC_CONTEXT_MARKERS
                )
                or "[.]" in span.quote
                or "(.)" in span.quote
                or "{.}" in span.quote
            )
            for span in cited_spans
        )
        if not has_independent_technical_occurrence:
            result.add(domain)
    return result


def _preferred_anti_analysis_facts(
    entity_type: EntityType,
    facts: list[ReportFact],
) -> list[ReportFact]:
    """在同片段多个反分析概括中选择明确的目标类型。"""
    markers = (
        _ANTI_PROCESS_DESCRIPTION_MARKERS
        if entity_type == EntityType.PROCESS
        else _ANTI_REGISTRY_DESCRIPTION_MARKERS
    )
    matches = [
        fact
        for fact in facts
        if any(marker in fact.description.casefold() for marker in markers)
    ]
    return sorted(matches, key=lambda fact: (fact.order, fact.fact_id))[:1]


def _reclassify_context_only_anti_analysis_facts(
    facts: list[ReportFact],
    relations: list[ReportRelation],
    entities: list[ReportEntity],
    source_spans: list[SourceSpan],
) -> list[ReportFact]:
    """保留无新检查动作的条件/重复反分析项为报告上下文。"""
    entity_types = {entity.entity_id: entity.entity_type for entity in entities}
    target_fact_ids = {
        relation.source_id
        for relation in relations
        if (
            relation.predicate in {"checks", "detects", "inspects", "targets"}
            and entity_types.get(relation.target_id) == EntityType.PROCESS
        )
        or (
            relation.predicate == "queries"
            and entity_types.get(relation.target_id) == EntityType.REGISTRY
        )
    }
    targeted_spans = {
        span_id
        for fact in facts
        if fact.fact_id in target_fact_ids and fact.behavior == "anti_debug_anti_vm"
        for span_id in fact.provenance.source_span_ids
    }
    self_deletion_spans = {
        span_id
        for fact in facts
        if fact.behavior == "self_deletion"
        for span_id in fact.provenance.source_span_ids
    }
    span_quotes = {span.span_id: span.quote for span in source_spans}
    result: list[ReportFact] = []
    for fact in facts:
        if fact.behavior != "anti_debug_anti_vm" or fact.fact_id in target_fact_ids:
            result.append(fact)
            continue
        fact_spans = set(fact.provenance.source_span_ids)
        duplicate_context = bool(fact_spans & targeted_spans)
        context_text = " ".join(
            [fact.description, *(span_quotes.get(span_id, "") for span_id in fact_spans)]
        ).casefold()
        conditional_consequence = bool(fact_spans & self_deletion_spans) and any(
            marker in context_text for marker in _ANTI_CONDITION_MARKERS
        ) and any(marker in context_text for marker in _ANTI_CONSEQUENCE_MARKERS)
        if not duplicate_context and not conditional_consequence:
            result.append(fact)
            continue
        reason = (
            "同一来源片段的反分析检查已由有精确目标的事实承载；"
            "本项无新检查目标，作为条件/后果上下文保留"
        )
        result.append(
            fact.model_copy(
                update={
                    "behavior": "other",
                    "uncertainty": [*fact.uncertainty, reason],
                },
                deep=True,
            )
        )
    return result


def reanchor_fact_extraction_source_claims(
    extraction: ReportFactExtraction,
    document: ExtractedDocument,
) -> ReportFactExtraction:
    """Add exact local span matches when A cites only part of a source entity.

    PDF tables frequently split one logical entity across pages. The model may cite
    the task name's page but omit the page containing its binary. Re-anchoring is
    deterministic: it only adds spans in which the exact normalized claim is found;
    unsupported values remain unchanged and are rejected by provenance validation.
    """
    validate_document_spans(document)
    entities: list[ReportEntity] = []
    for entity in extraction.entities:
        claims = [(entity.value, entity.entity_type)]
        claims.extend(
            (str(value), entity_type)
            for attribute_name, entity_type in _SOURCE_ATTRIBUTE_ENTITY_TYPES.items()
            if (value := entity.attributes.get(attribute_name)) is not None
            and not isinstance(value, bool)
            and str(value).strip()
        )
        provenance = _reanchored_provenance(entity.provenance, claims, document)
        entities.append(entity.model_copy(update={"provenance": provenance}, deep=True))

    indicator_entity_types = {
        IndicatorKind.HASH: EntityType.HASH,
        IndicatorKind.DOMAIN: EntityType.DOMAIN,
        IndicatorKind.IP: EntityType.IP,
        IndicatorKind.URL: EntityType.URL,
    }
    indicators: list[ReportIndicator] = []
    for indicator in extraction.report_iocs:
        provenance = _reanchored_provenance(
            indicator.provenance,
            [(indicator.value, indicator_entity_types[indicator.kind])],
            document,
        )
        indicators.append(indicator.model_copy(update={"provenance": provenance}, deep=True))

    return extraction.model_copy(
        update={"entities": entities, "report_iocs": indicators},
        deep=True,
    )


def sanitize_fact_extraction_source_claims(
    extraction: ReportFactExtraction,
    document: ExtractedDocument,
) -> ReportFactExtraction:
    """Keep only exact source claims and recover unambiguous trigger wording.

    Facts and descriptions may summarize the report, but source entities and their
    technical attributes are exact claims. Unsupported entity claims and their
    relations are removed instead of being relabeled as source. An explicit schedule
    interval may be restored only by copying the unique matching clause from the
    entity's cited source spans.
    """
    anchored = reanchor_fact_extraction_source_claims(extraction, document)
    removed_entity_ids: set[str] = set()
    entities: list[ReportEntity] = []
    for entity in anchored.entities:
        span_ids = entity.provenance.source_span_ids
        if not _claim_in_cited_spans(
            entity.value,
            span_ids,
            document,
            entity_type=entity.entity_type,
        ):
            removed_entity_ids.add(entity.entity_id)
            continue

        attributes: dict[str, str | int | float | bool | None] = {}
        for attribute_name, value in entity.attributes.items():
            if value is None or isinstance(value, bool):
                attributes[attribute_name] = value
                continue
            claim = str(value).strip()
            entity_type = _SOURCE_ATTRIBUTE_ENTITY_TYPES.get(attribute_name, EntityType.OTHER)
            if _claim_in_cited_spans(
                claim,
                span_ids,
                document,
                entity_type=entity_type,
            ):
                attributes[attribute_name] = value
                continue
            recovered = _recover_source_attribute(
                attribute_name,
                claim,
                span_ids,
                document,
            )
            if recovered is not None:
                attributes[attribute_name] = recovered

        aliases = [
            alias
            for alias in entity.aliases
            if _claim_in_cited_spans(
                alias,
                span_ids,
                document,
                entity_type=entity.entity_type,
            )
        ]
        entities.append(
            entity.model_copy(
                update={"aliases": aliases, "attributes": attributes},
                deep=True,
            )
        )

    indicators = [
        indicator
        for indicator in anchored.report_iocs
        if _claim_in_cited_spans(
            indicator.value,
            indicator.provenance.source_span_ids,
            document,
            entity_type={
                IndicatorKind.HASH: EntityType.HASH,
                IndicatorKind.DOMAIN: EntityType.DOMAIN,
                IndicatorKind.IP: EntityType.IP,
                IndicatorKind.URL: EntityType.URL,
            }[indicator.kind],
        )
    ]
    relations = [
        relation
        for relation in anchored.relations
        if relation.source_id not in removed_entity_ids
        and relation.target_id not in removed_entity_ids
    ]
    return anchored.model_copy(
        update={
            "entities": entities,
            "relations": relations,
            "report_iocs": indicators,
        },
        deep=True,
    )


def apply_fact_audit_suggestions(
    audit: FactAuditResult,
    ledger: ReportFactLedger,
    document: ExtractedDocument,
    *,
    strict: bool = True,
) -> ReportFactLedger:
    """逐条校验并确定性应用任务 B 的来源事实建议。

    严格模式用于独立审计与测试；主管线使用顾问模式，仅忽略不合格建议，
    不让一条错误建议覆盖同批已通过的其他建议。
    """
    current = ledger.model_copy(deep=True)
    all_errors: list[str] = []
    for suggestion in audit.suggestions:
        single = FactAuditResult(
            summary=audit.summary,
            ledger_complete=False,
            suggestions=[suggestion],
            unresolved_questions=[],
        )
        errors = validate_fact_audit_suggestions(single, current, document)
        if errors:
            if strict:
                all_errors.extend(errors)
            continue
        payload = current.model_dump(mode="json")
        facts = list(current.facts)
        entities = list(current.entities)
        relations = list(current.relations)
        action = suggestion.action

        if action == AuditAction.ADD_FACT and suggestion.proposed_fact is not None:
            facts.append(suggestion.proposed_fact)
        elif action == AuditAction.ADD_ENTITY and suggestion.proposed_entity is not None:
            entities.append(suggestion.proposed_entity)
        elif action == AuditAction.ADD_RELATION and suggestion.proposed_relation is not None:
            relations.append(suggestion.proposed_relation)
        elif action == AuditAction.REPLACE_RELATION and suggestion.proposed_relation is not None:
            affected = set(suggestion.affected_ids)
            relations = [item for item in relations if item.relation_id not in affected]
            relations.append(suggestion.proposed_relation)
        elif action == AuditAction.SPLIT_FACT:
            affected = set(suggestion.affected_ids)
            facts = [item for item in facts if item.fact_id not in affected]
            facts.extend(suggestion.replacement_facts)
            relations = [
                item
                for item in relations
                if item.source_id not in affected and item.target_id not in affected
            ]
        elif action in {AuditAction.REMOVE_DUPLICATE, AuditAction.REMOVE_UNSUPPORTED}:
            affected = set(suggestion.affected_ids)
            facts = [item for item in facts if item.fact_id not in affected]
            entities = [item for item in entities if item.entity_id not in affected]
            relations = [
                item
                for item in relations
                if item.relation_id not in affected
                and item.source_id not in affected
                and item.target_id not in affected
            ]
        else:
            if strict:
                all_errors.append(f"suggestions[{suggestion.suggestion_id}]: 审核动作与载荷不匹配")
            continue

        payload.update(
            {
                "facts": facts,
                "entities": entities,
                "relations": relations,
            }
        )
        try:
            current = ReportFactLedger.model_validate(payload)
        except ValueError as exc:
            if strict:
                all_errors.append(f"suggestions[{suggestion.suggestion_id}]: 应用后账本无效：{exc}")

    if strict and all_errors:
        raise ValueError("审核建议未通过本地来源校验：" + "；".join(all_errors[:20]))
    return current


def reanchor_fact_audit_relation_suggestions(
    audit: FactAuditResult,
    ledger: ReportFactLedger,
) -> FactAuditResult:
    """Restore a missing relation-suggestion citation from verified shared endpoints.

    Only the suggestion envelope is repaired. Facts, entities, relation endpoints,
    predicates, and their provenance are never invented or rewritten here.
    """
    known = {
        **{fact.fact_id: fact for fact in ledger.facts},
        **{entity.entity_id: entity for entity in ledger.entities},
    }
    suggestions: list[FactAuditSuggestion] = []
    for suggestion in audit.suggestions:
        updated = suggestion
        relation = suggestion.proposed_relation
        if relation is not None and not suggestion.source_span_ids:
            source = known.get(relation.source_id)
            target = known.get(relation.target_id)
            if source is not None and target is not None:
                shared = list(
                    dict.fromkeys(
                        span_id
                        for span_id in source.provenance.source_span_ids
                        if span_id in set(target.provenance.source_span_ids)
                    )
                )
                if shared:
                    updated = suggestion.model_copy(
                        update={"source_span_ids": shared},
                        deep=True,
                    )
        suggestions.append(updated)
        if suggestion.proposed_fact is not None:
            known[suggestion.proposed_fact.fact_id] = suggestion.proposed_fact
        if suggestion.proposed_entity is not None:
            known[suggestion.proposed_entity.entity_id] = suggestion.proposed_entity
        for fact in suggestion.replacement_facts:
            known[fact.fact_id] = fact
    return audit.model_copy(update={"suggestions": suggestions}, deep=True)


def validate_ioc_provenance(
    report: ReportExtraction,
    candidates: list[IocCandidate],
) -> list[str]:
    """Return model-emitted IOC values that were absent from the source text."""
    allowed = {
        kind: {item.normalized.casefold() for item in candidates if item.kind == kind}
        for kind in IocKind
    }
    errors: list[str] = []

    def check(kind: IocKind, value: str | None, location: str) -> None:
        if not value:
            return
        normalized = normalize_defanged(value).casefold()
        if normalized not in allowed[kind]:
            errors.append(f"{location}: {value!r} 未在输入报告中找到")

    _check_ioc_facts(report.report_iocs, "report_iocs", check)
    for index, step in enumerate(report.steps):
        prefix = f"steps[{index}]"
        _check_ioc_facts(step.params.iocs, f"{prefix}.params.iocs", check)
        check(IocKind.DOMAIN, step.params.network.host, f"{prefix}.params.network.host")
        check(IocKind.IP, step.params.network.ip, f"{prefix}.params.network.ip")
        for file_index, file_fact in enumerate(step.params.files):
            check(IocKind.HASH, file_fact.md5, f"{prefix}.params.files[{file_index}].md5")
            check(IocKind.HASH, file_fact.sha256, f"{prefix}.params.files[{file_index}].sha256")
    return errors


def validate_fact_ledger_provenance(
    ledger: ReportFactLedger,
    document: ExtractedDocument,
) -> list[str]:
    """Validate exact source entity and IOC values inside their cited spans."""
    validate_document_spans(document)
    document_spans = {span.span_id: span for span in document.spans}
    errors: list[str] = []

    for span in ledger.source_spans:
        document_span = document_spans.get(span.span_id)
        if document_span is None:
            errors.append(f"source_spans[{span.span_id}]: 输入文档中不存在")
        elif document_span != span:
            errors.append(f"source_spans[{span.span_id}]: 与输入文档片段不一致")

    for entity in ledger.entities:
        if entity.provenance.origin != FieldOrigin.SOURCE:
            continue
        if not _claim_in_cited_spans(
            entity.value,
            entity.provenance.source_span_ids,
            document,
            entity_type=entity.entity_type,
        ):
            errors.append(
                f"entities[{entity.entity_id}].value: {entity.value!r} 未在所引片段中找到"
            )
        errors.extend(
            _source_attribute_errors(
                entity,
                prefix=f"entities[{entity.entity_id}]",
                document=document,
            )
        )

    entity_type_by_indicator = {
        IocKind.HASH.value: EntityType.HASH,
        IocKind.DOMAIN.value: EntityType.DOMAIN,
        IocKind.IP.value: EntityType.IP,
        IocKind.URL.value: EntityType.URL,
    }
    for indicator in ledger.report_iocs:
        if indicator.provenance.origin != FieldOrigin.SOURCE:
            continue
        entity_type = entity_type_by_indicator[indicator.kind.value]
        if not _claim_in_cited_spans(
            indicator.value,
            indicator.provenance.source_span_ids,
            document,
            entity_type=entity_type,
        ):
            errors.append(
                f"report_iocs[{indicator.indicator_id}].value: "
                f"{indicator.value!r} 未在所引片段中找到"
            )
    return errors


def validate_fact_audit_suggestions(
    audit: FactAuditResult,
    ledger: ReportFactLedger,
    document: ExtractedDocument,
) -> list[str]:
    """Validate audit proposals without mutating the accepted source ledger."""
    audit = reanchor_fact_audit_relation_suggestions(audit, ledger)
    validate_document_spans(document)
    errors: list[str] = []
    span_ids = {span.span_id for span in ledger.source_spans}
    ledger_ids = {fact.fact_id for fact in ledger.facts} | {
        entity.entity_id for entity in ledger.entities
    }
    relation_ids = {relation.relation_id for relation in ledger.relations}
    canonical_entities = {
        (entity.entity_type, entity.canonical_value) for entity in ledger.entities
    }

    for suggestion in audit.suggestions:
        prefix = f"suggestions[{suggestion.suggestion_id}]"
        unknown_spans = set(suggestion.source_span_ids) - span_ids
        if unknown_spans:
            errors.append(f"{prefix}: 引用了未知来源片段 {sorted(unknown_spans)}")
        unknown_affected = set(suggestion.affected_ids) - ledger_ids - relation_ids
        if unknown_affected:
            errors.append(f"{prefix}: affected_ids 包含未知引用 {sorted(unknown_affected)}")

        proposals = [
            item
            for item in (
                suggestion.proposed_fact,
                suggestion.proposed_entity,
                suggestion.proposed_relation,
                *suggestion.replacement_facts,
            )
            if item is not None
        ]
        for proposal in proposals:
            if isinstance(proposal, ReportRelation):
                if proposal.provenance.origin not in {
                    FieldOrigin.SOURCE,
                    FieldOrigin.DERIVED,
                }:
                    errors.append(f"{prefix}: 审核关系只能是 source 或可验证的 derived 来源")
            elif proposal.provenance.origin != FieldOrigin.SOURCE:
                errors.append(f"{prefix}: 审核新增事实或实体只能是 source 来源")
            if not set(proposal.provenance.source_span_ids) <= set(suggestion.source_span_ids):
                errors.append(f"{prefix}: 建议内容引用了建议范围外的来源片段")

        entity = suggestion.proposed_entity
        if entity is not None:
            if entity.entity_id in ledger_ids:
                errors.append(f"{prefix}.proposed_entity: entity_id 已存在")
            if (entity.entity_type, entity.canonical_value) in canonical_entities:
                errors.append(f"{prefix}.proposed_entity: 与现有实体规范值重复")
            if entity.provenance.origin == FieldOrigin.SOURCE and not _claim_in_cited_spans(
                entity.value,
                entity.provenance.source_span_ids,
                document,
                entity_type=entity.entity_type,
            ):
                errors.append(
                    f"{prefix}.proposed_entity.value: {entity.value!r} 未在所引片段中找到"
                )
            if entity.provenance.origin == FieldOrigin.SOURCE:
                errors.extend(
                    _source_attribute_errors(
                        entity,
                        prefix=f"{prefix}.proposed_entity",
                        document=document,
                    )
                )

        fact_proposals = [
            item
            for item in (suggestion.proposed_fact, *suggestion.replacement_facts)
            if item is not None
        ]
        for fact in fact_proposals:
            if fact.fact_id in ledger_ids:
                errors.append(f"{prefix}.proposed_fact: fact_id 已存在")

        relation = suggestion.proposed_relation
        if relation is not None:
            if relation.relation_id in relation_ids:
                errors.append(f"{prefix}.proposed_relation: relation_id 已存在")
            missing = {relation.source_id, relation.target_id} - ledger_ids
            if missing:
                errors.append(f"{prefix}.proposed_relation: 包含未知引用 {sorted(missing)}")
            if relation.predicate not in _AUDIT_RELATION_PREDICATES:
                errors.append(
                    f"{prefix}.proposed_relation: 使用了非受控谓词 {relation.predicate!r}"
                )
            if relation.provenance.origin == FieldOrigin.DERIVED and not missing:
                endpoint_by_id = {
                    **{fact.fact_id: fact for fact in ledger.facts},
                    **{entity.entity_id: entity for entity in ledger.entities},
                }
                endpoint_ids = {relation.source_id, relation.target_id}
                if relation.provenance.source_ids and (
                    set(relation.provenance.source_ids) != endpoint_ids
                ):
                    errors.append(
                        f"{prefix}.proposed_relation: derived source_ids 必须精确引用关系两端"
                    )
                shared_spans = set(
                    endpoint_by_id[relation.source_id].provenance.source_span_ids
                ) & set(endpoint_by_id[relation.target_id].provenance.source_span_ids)
                suggestion_spans = set(suggestion.source_span_ids)
                if not shared_spans or not shared_spans & suggestion_spans:
                    errors.append(
                        f"{prefix}.proposed_relation: derived 关系两端没有共享的建议来源片段"
                    )
    return errors


def _source_attribute_errors(
    entity: ReportEntity,
    *,
    prefix: str,
    document: ExtractedDocument,
) -> list[str]:
    """Require compiler-consumed source attributes to exist in their cited spans."""
    errors: list[str] = []
    for attribute_name, entity_type in _SOURCE_ATTRIBUTE_ENTITY_TYPES.items():
        value = entity.attributes.get(attribute_name)
        if value is None or isinstance(value, bool):
            continue
        claim = str(value).strip()
        if not claim:
            continue
        if not _claim_in_cited_spans(
            claim,
            entity.provenance.source_span_ids,
            document,
            entity_type=entity_type,
        ):
            errors.append(f"{prefix}.attributes.{attribute_name}: {claim!r} 未在所引片段中找到")
    return errors


def _check_ioc_facts(iocs: IocFacts, prefix: str, check: IocChecker) -> None:
    """Apply a provenance checker to each exact IOC field."""
    for index, value in enumerate(iocs.hashes):
        check(IocKind.HASH, value, f"{prefix}.hashes[{index}]")
    for index, value in enumerate(iocs.domains):
        check(IocKind.DOMAIN, value, f"{prefix}.domains[{index}]")
    for index, value in enumerate(iocs.ips):
        check(IocKind.IP, value, f"{prefix}.ips[{index}]")
    for index, value in enumerate(iocs.urls):
        check(IocKind.URL, value, f"{prefix}.urls[{index}]")


def _add_host_candidate(
    hostname: str,
    add: Callable[[IocKind, str, str, int, int], None],
    char_start: int,
    char_end: int,
) -> None:
    """Classify a URL hostname as an IP or domain candidate."""
    try:
        parsed = ipaddress.ip_address(hostname)
    except ValueError:
        if _valid_domain(hostname):
            add(IocKind.DOMAIN, hostname, hostname.lower(), char_start, char_end)
        return
    if parsed.version == 4:
        add(IocKind.IP, hostname, str(parsed), char_start, char_end)


def _span_ids_for_range(
    spans: Sequence[SourceSpan],
    char_start: int,
    char_end: int,
) -> list[str]:
    """Return enclosing spans, falling back to overlapping long-paragraph spans."""
    enclosing = [
        span.span_id
        for span in spans
        if span.char_start <= char_start and span.char_end >= char_end
    ]
    if enclosing:
        return enclosing
    return [
        span.span_id for span in spans if span.char_start < char_end and span.char_end > char_start
    ]


def _claim_in_cited_spans(
    claim: str,
    span_ids: list[str],
    document: ExtractedDocument,
    *,
    entity_type: EntityType,
) -> bool:
    """Match an exact value only against its own cited source fragments."""
    cited_texts: list[str] = []
    for span_id in span_ids:
        try:
            cited_texts.append(document.span_text(span_id))
        except ReportInputError:
            continue
    if not cited_texts:
        return False

    indicator_kind = {
        EntityType.HASH: IocKind.HASH,
        EntityType.DOMAIN: IocKind.DOMAIN,
        EntityType.IP: IocKind.IP,
        EntityType.URL: IocKind.URL,
    }.get(entity_type)
    if indicator_kind is not None:
        expected = normalize_entity_value(entity_type, claim)
        for cited_text in cited_texts:
            for candidate in extract_ioc_candidates(cited_text):
                if candidate.kind != indicator_kind:
                    continue
                if normalize_entity_value(entity_type, candidate.normalized) == expected:
                    return True
        return False

    normalized_claim = _normalize_source_match(claim, entity_type=entity_type)
    compact_claim = re.sub(r"\s+", "", normalized_claim)
    for cited_text in cited_texts:
        normalized_text = _normalize_source_match(cited_text, entity_type=entity_type)
        if normalized_claim in normalized_text:
            return True
        if compact_claim and compact_claim in re.sub(r"\s+", "", normalized_text):
            return True
    return False


def _reanchored_provenance(
    provenance: FieldProvenance,
    claims: list[tuple[str, EntityType]],
    document: ExtractedDocument,
) -> FieldProvenance:
    """Return source provenance enriched only with locally verified exact matches."""
    if provenance.origin != FieldOrigin.SOURCE:
        return provenance
    span_ids = list(provenance.source_span_ids)
    for claim, entity_type in claims:
        if _claim_in_cited_spans(claim, span_ids, document, entity_type=entity_type):
            continue
        for span in document.spans:
            if _claim_in_cited_spans(
                claim,
                [span.span_id],
                document,
                entity_type=entity_type,
            ):
                span_ids.append(span.span_id)
                break
    return provenance.model_copy(
        update={"source_span_ids": list(dict.fromkeys(span_ids))},
        deep=True,
    )


def _recover_source_attribute(
    attribute_name: str,
    claim: str,
    span_ids: list[str],
    document: ExtractedDocument,
) -> str | None:
    """Copy one unique source trigger clause with the same explicit interval."""
    if attribute_name != "trigger":
        return None
    interval = _explicit_interval_minutes(claim)
    if interval is None:
        return None
    candidates: list[str] = []
    patterns = (
        r"[^。；\n]{0,80}(?:每隔|每)\s*\d{1,6}\s*(?:分钟|分|小时)[^。；\n]{0,40}",
        r"[^.;\n]{0,80}\bevery\s+\d{1,6}\s*(?:minutes?|mins?|hours?|hrs?)[^.;\n]{0,40}",
    )
    for span_id in span_ids:
        try:
            cited_text = document.span_text(span_id)
        except ReportInputError:
            continue
        for pattern in patterns:
            for match in re.finditer(pattern, cited_text, flags=re.IGNORECASE):
                candidate = match.group(0).strip()
                if _explicit_interval_minutes(candidate) == interval:
                    candidates.append(candidate)
    unique = list(dict.fromkeys(candidates))
    return unique[0] if len(unique) == 1 else None


def _explicit_interval_minutes(value: str) -> int | None:
    """Read an explicitly stated repeated minute/hour interval from source text."""
    text = unicodedata.normalize("NFKC", value).casefold()
    minute = re.search(r"(?:每\s*隔?\s*|every\s+)(\d{1,6})\s*(?:分钟|分|minutes?|mins?)", text)
    if minute:
        result = int(minute.group(1))
        return result if 0 < result <= 525_600 else None
    hour = re.search(r"(?:每\s*隔?\s*|every\s+)(\d{1,4})\s*(?:小时|hours?|hrs?)", text)
    if hour:
        result = int(hour.group(1)) * 60
        return result if 0 < result <= 525_600 else None
    return None


def _auto_binding_rule(entity_type: EntityType) -> tuple[set[str], str] | None:
    if entity_type in {EntityType.URL, EntityType.DOMAIN, EntityType.IP}:
        return _NETWORK_AUTO_BIND_BEHAVIORS, "connects_to"
    if entity_type == EntityType.FILE:
        return _DOWNLOAD_AUTO_BIND_BEHAVIORS, "creates"
    if entity_type == EntityType.SCHEDULED_TASK:
        return _TASK_AUTO_BIND_BEHAVIORS, "creates"
    if entity_type == EntityType.REGISTRY:
        return (
            _REGISTRY_QUERY_AUTO_BIND_BEHAVIORS | _REGISTRY_SET_AUTO_BIND_BEHAVIORS,
            "queries",
        )
    if entity_type == EntityType.PROCESS:
        return _ANTI_ANALYSIS_AUTO_BIND_BEHAVIORS, "checks"
    return None


def _claim_mentioned_in_summary(claim: str, summary: str) -> bool:
    normalized_claim = re.sub(r"\s+", "", unicodedata.normalize("NFKC", claim)).casefold()
    normalized_summary = re.sub(r"\s+", "", unicodedata.normalize("NFKC", summary)).casefold()
    return bool(normalized_claim) and normalized_claim in normalized_summary


def _normalize_source_match(value: str, *, entity_type: EntityType) -> str:
    """Normalize layout and defanging while preserving URL path distinctions."""
    normalized = unicodedata.normalize("NFKC", value)
    normalized = normalized.translate(str.maketrans({"“": '"', "”": '"', "‘": "'", "’": "'"}))
    normalized = re.sub(r"(?i)\bhxxps(?=://)", "https", normalized)
    normalized = re.sub(r"(?i)\bhxxp(?=://)", "http", normalized)
    normalized = re.sub(
        r"\[(?:\.|dot)\]|\((?:\.|dot)\)|\{(?:\.|dot)\}",
        ".",
        normalized,
        flags=re.IGNORECASE,
    )
    normalized = re.sub(r"\s+", " ", normalized).strip()
    if entity_type == EntityType.URL:
        return normalized
    if entity_type in {
        EntityType.DOMAIN,
        EntityType.IP,
        EntityType.HASH,
        EntityType.PROCESS,
        EntityType.FILE,
        EntityType.SCHEDULED_TASK,
        EntityType.REGISTRY,
        EntityType.HOST,
        EntityType.MALWARE,
    }:
        return normalized.casefold()
    return normalized


def _valid_domain(value: str) -> bool:
    """Return whether a normalized value is a conservative FQDN."""
    if len(value) > 253 or "." not in value:
        return False
    labels = value.split(".")
    return all(
        0 < len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        and re.fullmatch(r"[A-Za-z0-9-]+", label) is not None
        for label in labels
    )
