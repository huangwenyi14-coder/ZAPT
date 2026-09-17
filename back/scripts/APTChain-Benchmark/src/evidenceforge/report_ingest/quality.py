# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""报告驱动数据集的端到端来源贴合质量门。

评分只使用本地结构化产物，不会为了评分再次调用模型。
"""

import ipaddress
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import Field

from evidenceforge.report_ingest.extractors import ExtractedDocument
from evidenceforge.report_ingest.iocs import validate_fact_ledger_provenance
from evidenceforge.report_ingest.models import (
    CompilationStatus,
    FieldOrigin,
    ReportFactLedger,
    ReportScenarioCompilation,
    StrictModel,
)

QUALITY_SCHEMA_VERSION = 1
MIN_QUALITY_SCORE = 85.0
MIN_MATERIALIZABLE_COVERAGE = 0.90
_CONTEXT_ONLY_BEHAVIORS = {"other"}


class QualityMetric(StrictModel):
    """一项可解释、可机器读取的质量指标。"""

    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    rate: float = Field(ge=0.0, le=1.0)
    weight: float = Field(ge=0.0, le=100.0)
    score: float = Field(ge=0.0, le=100.0)
    passed: bool


class ReportFidelityReport(StrictModel):
    """生成前或生成后的来源贴合评分。"""

    schema_version: int = QUALITY_SCHEMA_VERSION
    stage: Literal["pre_generation", "post_generation"]
    passed: bool
    score: float = Field(ge=0.0, le=100.0)
    metrics: dict[str, QualityMetric]
    hard_failures: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def evaluate_pre_generation(
    ledger: ReportFactLedger,
    compilation: ReportScenarioCompilation,
    document: ExtractedDocument,
) -> ReportFidelityReport:
    """在调用生成引擎前验证来源、补全标记和行为覆盖。"""
    failures: list[str] = []
    warnings: list[str] = []

    if not ledger.facts:
        failures.append("报告中没有可生成或保留的来源行为事实")

    provenance_errors = validate_fact_ledger_provenance(ledger, document)
    source_items = _ledger_source_item_count(ledger)
    valid_source_items = source_items if not provenance_errors else 0
    if provenance_errors:
        failures.append("来源精确引用未达到 100%：" + "；".join(provenance_errors[:10]))
        if len(provenance_errors) > 10:
            warnings.append(f"其余 {len(provenance_errors) - 10} 条来源错误已省略")

    fact_ids = {
        fact.fact_id for fact in ledger.facts if fact.behavior not in _CONTEXT_ONLY_BEHAVIORS
    }
    materialized_fact_ids = {
        event.fact_id
        for event in compilation.events
        if event.status == CompilationStatus.MATERIALIZED and event.fact_id in fact_ids
    }
    coverage_numerator = len(materialized_fact_ids)
    coverage_denominator = len(fact_ids)
    coverage_rate = _rate(coverage_numerator, coverage_denominator)
    if coverage_denominator == 0:
        coverage_rate = 0.0
        failures.append("报告中没有可物化的受控行为事实")
    if coverage_rate < MIN_MATERIALIZABLE_COVERAGE:
        failures.append(
            f"可物化来源行为覆盖率 {coverage_rate:.1%} 低于 {MIN_MATERIALIZABLE_COVERAGE:.0%} 门限"
        )

    relation_errors = _relation_errors(ledger)
    if relation_errors:
        failures.append("事实与实体关系不一致：" + "；".join(relation_errors[:10]))

    completion_errors = _compiled_provenance_errors(ledger, compilation)
    if completion_errors:
        failures.append("AI/引擎补全字段未 100% 标记：" + "；".join(completion_errors[:10]))

    degradation_events = [
        event for event in compilation.events if event.status == CompilationStatus.GROUND_TRUTH_ONLY
    ]
    unexplained = [event.event_id for event in degradation_events if not event.degradation_reason]
    if unexplained:
        failures.append("降级为 Ground Truth 的事实未 100% 记录原因：" + ", ".join(unexplained))

    pending = [
        event.event_id
        for event in compilation.events
        if event.status == CompilationStatus.NEEDS_COMPLETION
    ]
    if pending:
        failures.append("受控补全后仍有待补全事件：" + ", ".join(pending[:20]))

    indicator_closure_errors = _indicator_domain_closure_errors(
        (indicator.kind.value, indicator.normalized_value or "")
        for indicator in ledger.report_iocs
    )
    if indicator_closure_errors:
        failures.append(
            "报告 URL IOC 缺少对应域名 IOC："
            + ", ".join(indicator_closure_errors[:20])
        )

    metrics = {
        "source_reference_rate": _metric(valid_source_items, source_items, 30.0, required_rate=1.0),
        "materializable_behavior_coverage": _metric(
            coverage_numerator,
            coverage_denominator,
            25.0,
            required_rate=MIN_MATERIALIZABLE_COVERAGE,
            empty_rate=0.0,
        ),
        "relation_consistency": _metric(0 if relation_errors else 1, 1, 20.0, required_rate=1.0),
        "report_ioc_retention": _metric(
            len(ledger.report_iocs), len(ledger.report_iocs), 15.0, required_rate=1.0
        ),
        "physical_materialization": _metric(
            0 if completion_errors or pending else 1, 1, 10.0, required_rate=1.0
        ),
    }
    return _finish_report("pre_generation", metrics, failures, warnings)


def evaluate_post_generation(
    output_dir: Path,
    ledger: ReportFactLedger,
    compilation: ReportScenarioCompilation,
) -> ReportFidelityReport:
    """以稳定 ID 链检查 Ground Truth 和记录级标签。"""
    failures: list[str] = []
    warnings: list[str] = []
    ground_truth = _read_json_object(output_dir / "GROUND_TRUTH.json", failures)
    records = _read_json_lines(output_dir / "RECORD_GROUND_TRUTH.jsonl", failures)

    expected_events = {
        event.event_id: event
        for event in compilation.events
        if event.status == CompilationStatus.MATERIALIZED
    }
    gt_events = {
        event.get("storyline_id"): event
        for event in _object_list(ground_truth.get("events"))
        if isinstance(event.get("storyline_id"), str)
    }
    record_event_ids = {
        record.get("storyline_id")
        for record in records
        if record.get("label") == "malicious" and isinstance(record.get("storyline_id"), str)
    }

    source_valid_ids: set[str] = set()
    for event_id, compiled_event in expected_events.items():
        generated_event = gt_events.get(event_id)
        if generated_event is None:
            continue
        metadata = _source_metadata(generated_event)
        if _event_source_metadata_matches(compiled_event, metadata):
            source_valid_ids.add(event_id)

    if len(source_valid_ids) != len(expected_events):
        missing = sorted(set(expected_events) - source_valid_ids)
        failures.append("生成事件的来源字段链不完整：" + ", ".join(missing[:20]))

    context = ground_truth.get("report_context")
    context = context if isinstance(context, dict) else {}
    actual_iocs = {
        (str(item.get("kind")), str(item.get("normalized_value")))
        for item in _object_list(context.get("report_iocs"))
    }
    expected_iocs = {
        (indicator.kind.value, indicator.normalized_value or "") for indicator in ledger.report_iocs
    }
    retained_iocs = expected_iocs & actual_iocs
    if retained_iocs != expected_iocs:
        missing_iocs = sorted(expected_iocs - retained_iocs)
        failures.append(f"Ground Truth 未完整保留报告 IOC：{missing_iocs[:20]}")

    report_facts = {
        item.get("fact_id"): item
        for item in _object_list(context.get("facts"))
        if isinstance(item.get("fact_id"), str)
    }
    fact_chain_valid = 0
    for fact in ledger.facts:
        item = report_facts.get(fact.fact_id)
        if item is None:
            continue
        expected_ids = {
            event.event_id
            for event in compilation.events
            if event.fact_id == fact.fact_id and event.status == CompilationStatus.MATERIALIZED
        }
        actual_ids = {value for value in item.get("event_ids", []) if isinstance(value, str)}
        if expected_ids <= actual_ids:
            fact_chain_valid += 1
    if fact_chain_valid != len(ledger.facts):
        failures.append("Ground Truth 未完整保留事实到事件的 ID 链")

    physically_materialized = {
        event_id
        for event_id in expected_events
        if event_id in gt_events and event_id in record_event_ids
    }
    if len(physically_materialized) != len(expected_events):
        missing = sorted(set(expected_events) - physically_materialized)
        failures.append("事件未同时出现在 Ground Truth 和记录级标签中：" + ", ".join(missing[:20]))

    metrics = {
        "source_reference_rate": _metric(
            len(source_valid_ids), len(expected_events), 30.0, required_rate=1.0
        ),
        "materializable_behavior_coverage": _metric(
            fact_chain_valid, len(ledger.facts), 25.0, required_rate=1.0
        ),
        "relation_consistency": _metric(
            fact_chain_valid, len(ledger.facts), 20.0, required_rate=1.0
        ),
        "report_ioc_retention": _metric(
            len(retained_iocs), len(expected_iocs), 15.0, required_rate=1.0
        ),
        "physical_materialization": _metric(
            len(physically_materialized),
            len(expected_events),
            10.0,
            required_rate=1.0,
        ),
    }
    return _finish_report("post_generation", metrics, failures, warnings)


def evaluate_published_output(output_dir: Path) -> ReportFidelityReport:
    """不依赖模型中间响应，离线重评已发布产物的内部来源链。

    该检查能发现 Ground Truth、来源元数据和记录级标签被删改，
    但不会重新解释原报告。
    """
    failures: list[str] = []
    warnings: list[str] = []
    ground_truth = _read_json_object(output_dir / "GROUND_TRUTH.json", failures)
    records = _read_json_lines(output_dir / "RECORD_GROUND_TRUTH.jsonl", failures)
    events = _object_list(ground_truth.get("events"))
    gt_event_ids = {
        event.get("storyline_id") for event in events if isinstance(event.get("storyline_id"), str)
    }
    record_event_ids = {
        record.get("storyline_id")
        for record in records
        if record.get("label") == "malicious" and isinstance(record.get("storyline_id"), str)
    }
    context = ground_truth.get("report_context")
    context = context if isinstance(context, dict) else {}
    if not context:
        failures.append("GROUND_TRUTH.json 缺少 report_context")

    facts = _object_list(context.get("facts"))
    if not facts:
        failures.append("已发布产物没有报告事实")
    fact_ids = {item.get("fact_id") for item in facts if isinstance(item.get("fact_id"), str)}
    expected_event_ids: set[str] = set()
    valid_fact_chains = 0
    valid_source_items = 0
    source_item_count = 0
    for fact in facts:
        source_item_count += 1
        if _has_source_locations(fact):
            valid_source_items += 1
        status = fact.get("status")
        event_ids = {value for value in fact.get("event_ids", []) if isinstance(value, str)}
        if status == "materialized":
            expected_event_ids.update(event_ids)
            if event_ids and event_ids <= gt_event_ids:
                valid_fact_chains += 1
        elif status == "ground_truth_only" and fact.get("degradation_reason"):
            valid_fact_chains += 1

    iocs = _object_list(context.get("report_iocs"))
    valid_iocs = 0
    seen_iocs: set[tuple[str, str]] = set()
    for indicator in iocs:
        source_item_count += 1
        key = (str(indicator.get("kind") or ""), str(indicator.get("normalized_value") or ""))
        if all(key) and key not in seen_iocs and _has_source_locations(indicator):
            valid_iocs += 1
            valid_source_items += 1
            seen_iocs.add(key)

    valid_event_sources = 0
    for event in events:
        metadata = _source_metadata(event)
        metadata_fact_ids = metadata.get("fact_ids")
        field_sources = metadata.get("field_sources")
        if not isinstance(metadata_fact_ids, list) or not set(metadata_fact_ids) <= fact_ids:
            continue
        if not isinstance(field_sources, dict) or not field_sources:
            continue
        if all(_valid_published_field_source(value) for value in field_sources.values()):
            valid_event_sources += 1

    if valid_source_items != source_item_count or valid_event_sources != len(events):
        failures.append("已发布产物的来源位置或字段来源链不完整")
    if valid_fact_chains != len(facts):
        failures.append("报告事实状态、降级原因或事件 ID 链不完整")
    if valid_iocs != len(iocs):
        failures.append("已发布报告 IOC 存在重复、空值或缺少来源位置")
    indicator_closure_errors = _indicator_domain_closure_errors(seen_iocs)
    if indicator_closure_errors:
        failures.append(
            "已发布 URL IOC 缺少对应域名 IOC："
            + ", ".join(indicator_closure_errors[:20])
        )

    physical_ids = expected_event_ids & gt_event_ids & record_event_ids
    if physical_ids != expected_event_ids:
        failures.append(
            "已物化事件未同时存在于 Ground Truth 和记录级标签："
            + ", ".join(sorted(expected_event_ids - physical_ids)[:20])
        )

    metrics = {
        "source_reference_rate": _metric(
            valid_source_items + valid_event_sources,
            source_item_count + len(events),
            30.0,
            required_rate=1.0,
        ),
        "materializable_behavior_coverage": _metric(
            valid_fact_chains, len(facts), 25.0, required_rate=1.0
        ),
        "relation_consistency": _metric(valid_fact_chains, len(facts), 20.0, required_rate=1.0),
        "report_ioc_retention": _metric(valid_iocs, len(iocs), 15.0, required_rate=1.0),
        "physical_materialization": _metric(
            len(physical_ids), len(expected_event_ids), 10.0, required_rate=1.0
        ),
    }
    return _finish_report("post_generation", metrics, failures, warnings)


def _metric(
    numerator: int,
    denominator: int,
    weight: float,
    *,
    required_rate: float,
    empty_rate: float = 1.0,
) -> QualityMetric:
    rate = empty_rate if denominator == 0 else numerator / denominator
    return QualityMetric(
        numerator=numerator,
        denominator=denominator,
        rate=rate,
        weight=weight,
        score=round(rate * weight, 2),
        passed=rate >= required_rate,
    )


def _rate(numerator: int, denominator: int) -> float:
    return 1.0 if denominator == 0 else numerator / denominator


def _indicator_domain_closure_errors(
    indicators: Iterable[tuple[str, str]],
) -> list[str]:
    """返回已选 URL IOC 中未同时保留的域名主机。"""
    pairs = {
        (str(kind), str(value))
        for kind, value in indicators
        if kind and value
    }
    domains = {value for kind, value in pairs if kind == "domain"}
    missing: set[str] = set()
    for kind, value in pairs:
        if kind != "url":
            continue
        hostname = urlsplit(value).hostname
        if hostname and not _is_ip_literal(hostname) and hostname not in domains:
            missing.add(hostname)
    return sorted(missing)


def _is_ip_literal(hostname: str) -> bool:
    """保守识别 IPv4/IPv6 字面量，不对它们要求域名闭包。"""
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


def _finish_report(
    stage: Literal["pre_generation", "post_generation"],
    metrics: dict[str, QualityMetric],
    failures: list[str],
    warnings: list[str],
) -> ReportFidelityReport:
    score = round(sum(metric.score for metric in metrics.values()), 2)
    if score < MIN_QUALITY_SCORE:
        failures.append(f"来源贴合总分 {score:.2f} 低于 {MIN_QUALITY_SCORE:.0f} 分门限")
    failures = list(dict.fromkeys(failures))
    return ReportFidelityReport(
        stage=stage,
        passed=not failures and all(metric.passed for metric in metrics.values()),
        score=score,
        metrics=metrics,
        hard_failures=failures,
        warnings=list(dict.fromkeys(warnings)),
    )


def _ledger_source_item_count(ledger: ReportFactLedger) -> int:
    return (
        1
        + len(ledger.facts)
        + len(ledger.entities)
        + len(ledger.relations)
        + len(ledger.report_iocs)
    )


def _relation_errors(ledger: ReportFactLedger) -> list[str]:
    known_ids = {fact.fact_id for fact in ledger.facts} | {
        entity.entity_id for entity in ledger.entities
    }
    return [
        relation.relation_id
        for relation in ledger.relations
        if relation.source_id not in known_ids or relation.target_id not in known_ids
    ]


def _compiled_provenance_errors(
    ledger: ReportFactLedger,
    compilation: ReportScenarioCompilation,
) -> list[str]:
    span_ids = {span.span_id for span in ledger.source_spans}
    ledger_source_ids = {fact.fact_id for fact in ledger.facts} | {
        entity.entity_id for entity in ledger.entities
    }
    generated_entity_ids = {entity.entity_id for entity in compilation.generated_entities}
    source_ids = ledger_source_ids | generated_entity_ids
    errors: list[str] = []
    for entity in compilation.generated_entities:
        provenance = entity.provenance
        prefix = f"generated_entities[{entity.entity_id}]"
        if provenance.origin == FieldOrigin.SOURCE:
            if not provenance.source_span_ids:
                errors.append(f"{prefix} 缺少来源片段")
            if set(provenance.source_span_ids) - span_ids:
                errors.append(f"{prefix} 引用未知来源片段")
        elif provenance.origin in {
            FieldOrigin.AI_COMPLETED,
            FieldOrigin.ENGINE_GENERATED,
        }:
            if provenance.source_span_ids or not provenance.reason:
                errors.append(f"{prefix} 的补全来源标记不完整")
        if set(provenance.source_ids) - ledger_source_ids:
            errors.append(f"{prefix} 引用未知来源事实或实体")
    for event in compilation.events:
        for name, field in event.fields.items():
            provenance = field.provenance
            prefix = f"{event.event_id}.{name}"
            if provenance.origin == FieldOrigin.SOURCE:
                if not provenance.source_span_ids:
                    errors.append(f"{prefix} 缺少来源片段")
                if set(provenance.source_span_ids) - span_ids:
                    errors.append(f"{prefix} 引用未知来源片段")
            elif provenance.origin in {
                FieldOrigin.AI_COMPLETED,
                FieldOrigin.ENGINE_GENERATED,
            }:
                if provenance.source_span_ids or not provenance.reason:
                    errors.append(f"{prefix} 的补全来源标记不完整")
            if set(provenance.source_ids) - source_ids:
                errors.append(f"{prefix} 引用未知事实或实体")
    return errors


def _read_json_object(path: Path, failures: list[str]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        failures.append(f"无法读取 {path.name}：{exc}")
        return {}
    if not isinstance(value, dict):
        failures.append(f"{path.name} 顶层必须是 JSON 对象")
        return {}
    return value


def _read_json_lines(path: Path, failures: list[str]) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        failures.append(f"无法读取 {path.name}：{exc}")
        return []
    values: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            failures.append(f"{path.name} 第 {line_number} 行无效：{exc}")
            continue
        if not isinstance(value, dict):
            failures.append(f"{path.name} 第 {line_number} 行不是 JSON 对象")
            continue
        values.append(value)
    return values


def _object_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _source_metadata(event: dict[str, Any]) -> dict[str, Any]:
    attributes = event.get("attributes")
    if not isinstance(attributes, dict):
        return {}
    value = attributes.get("source_metadata")
    return value if isinstance(value, dict) else {}


def _event_source_metadata_matches(compiled_event: Any, metadata: dict[str, Any]) -> bool:
    fact_ids = metadata.get("fact_ids")
    if not isinstance(fact_ids, list) or compiled_event.fact_id not in fact_ids:
        return False
    if metadata.get("category") != compiled_event.source_category.value:
        return False
    field_sources = metadata.get("field_sources")
    if not isinstance(field_sources, dict):
        return False
    for name, field in compiled_event.fields.items():
        source = field_sources.get(name)
        if not isinstance(source, dict):
            return False
        if source.get("origin") != field.provenance.origin.value:
            return False
    return True


def _has_source_locations(value: dict[str, Any]) -> bool:
    locations = _object_list(value.get("source_locations"))
    return bool(locations) and all(
        isinstance(location.get("span_id"), str)
        and (
            isinstance(location.get("page_number"), int)
            ^ isinstance(location.get("paragraph_number"), int)
        )
        for location in locations
    )


def _valid_published_field_source(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    origin = value.get("origin")
    span_ids = value.get("source_span_ids")
    if not isinstance(span_ids, list):
        return False
    if origin == "source":
        return bool(span_ids) and all(isinstance(item, str) for item in span_ids)
    if origin in {"derived", "ai_completed", "engine_generated"}:
        return bool(value.get("reason")) and (
            origin not in {"ai_completed", "engine_generated"} or not span_ids
        )
    return False
