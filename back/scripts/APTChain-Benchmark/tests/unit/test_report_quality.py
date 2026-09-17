# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""报告来源贴合质量门测试。"""

import json
from pathlib import Path

from evidenceforge.report_ingest.compiler import compile_report_ledger
from evidenceforge.report_ingest.extractors import extract_document
from evidenceforge.report_ingest.models import (
    CompilationStatus,
    EntityType,
    FieldOrigin,
    FieldProvenance,
    IndicatorKind,
    ReportEntity,
    ReportFact,
    ReportFactLedger,
    ReportIndicator,
    ReportMeta,
    ReportRelation,
    SimulationCompletion,
    SimulationPlan,
)
from evidenceforge.report_ingest.quality import (
    evaluate_post_generation,
    evaluate_pre_generation,
    evaluate_published_output,
)


def _source_provenance(span_id: str) -> FieldProvenance:
    return FieldProvenance(origin=FieldOrigin.SOURCE, source_span_ids=[span_id])


def _process_ledger(tmp_path: Path) -> tuple[ReportFactLedger, object]:
    report = tmp_path / "report.txt"
    report.write_text(
        "报告明确说明 sample.exe 执行攻击逻辑，文件 MD5 为 e74d7351a73c0343c2b607c8f137f847。",
        encoding="utf-8",
    )
    document = extract_document(report)
    span_id = document.spans[0].span_id
    provenance = _source_provenance(span_id)
    fact = ReportFact(
        fact_id="fact-process",
        behavior="malware_execution",
        order=1,
        description="sample.exe 执行攻击逻辑",
        provenance=provenance,
    )
    process = ReportEntity(
        entity_id="entity-process",
        entity_type=EntityType.PROCESS,
        value="sample.exe",
        provenance=provenance,
    )
    ledger = ReportFactLedger(
        source_spans=list(document.spans),
        source_metadata=ReportMeta(
            report_name="质量门测试报告",
            description="单一进程行为",
        ),
        metadata_provenance=provenance,
        facts=[fact],
        entities=[process],
        relations=[
            ReportRelation(
                relation_id="relation-owner",
                source_id=fact.fact_id,
                predicate="performed_by",
                target_id=process.entity_id,
                provenance=provenance,
            )
        ],
        report_iocs=[
            ReportIndicator(
                indicator_id="ioc-md5",
                kind=IndicatorKind.HASH,
                value="e74d7351a73c0343c2b607c8f137f847",
                provenance=provenance,
            )
        ],
    )
    return ledger, document


def test_pre_generation_gate_scores_source_contract_and_materialization(tmp_path: Path) -> None:
    ledger, document = _process_ledger(tmp_path)
    compilation = compile_report_ledger(ledger)

    report = evaluate_pre_generation(ledger, compilation, document)

    assert report.passed is True
    assert report.score == 100.0
    assert report.metrics["source_reference_rate"].rate == 1.0
    assert report.metrics["materializable_behavior_coverage"].rate == 1.0
    assert report.hard_failures == []


def test_pre_generation_gate_accepts_marked_ai_generated_process_entity(tmp_path: Path) -> None:
    """C 阶段生成实体属于编译结果，不应被质量门误判为悬空引用。"""
    ledger, document = _process_ledger(tmp_path)
    ledger = ledger.model_copy(update={"entities": [], "relations": []}, deep=True)
    initial = compile_report_ledger(ledger)
    request = initial.completion_requests[0]
    plan = SimulationPlan(
        completions=[
            SimulationCompletion(
                request_id=request.request_id,
                target_id=request.target_id,
                field_path=request.field_path,
                value=r"C:\ProgramData\ReportLab\sample-host.exe",
                origin=FieldOrigin.AI_COMPLETED,
                reason="报告未披露镜像，仅补全隔离实验进程主体。",
                compatible=True,
                compatibility_explanation="不新增攻击行为或外部 IOC。",
            )
        ]
    )
    compilation = compile_report_ledger(ledger, plan)

    report = evaluate_pre_generation(ledger, compilation, document)

    assert report.passed is True, report.hard_failures
    assert report.score == 100.0


def test_pre_generation_gate_rejects_unexplained_low_materialization(tmp_path: Path) -> None:
    ledger, document = _process_ledger(tmp_path)
    ledger = ledger.model_copy(
        update={
            "facts": [
                ledger.facts[0].model_copy(
                    update={"behavior": "other", "description": "当前引擎无法无损物化"}
                )
            ],
            "relations": [],
        },
        deep=True,
    )
    compilation = compile_report_ledger(ledger)

    report = evaluate_pre_generation(ledger, compilation, document)

    assert report.passed is False
    assert report.metrics["materializable_behavior_coverage"].rate == 0.0
    assert report.metrics["materializable_behavior_coverage"].denominator == 0
    assert any("没有可物化的受控行为" in reason for reason in report.hard_failures)


def test_context_only_fact_is_retained_but_excluded_from_coverage(tmp_path: Path) -> None:
    ledger, document = _process_ledger(tmp_path)
    context_fact = ledger.facts[0].model_copy(
        update={
            "fact_id": "fact-context",
            "behavior": "other",
            "order": 2,
            "description": "保留为 Ground Truth 上下文。",
        }
    )
    ledger = ledger.model_copy(
        update={"facts": [*ledger.facts, context_fact]},
        deep=True,
    )
    compilation = compile_report_ledger(ledger)

    report = evaluate_pre_generation(ledger, compilation, document)

    assert report.passed is True, report.hard_failures
    coverage = report.metrics["materializable_behavior_coverage"]
    assert (coverage.numerator, coverage.denominator, coverage.rate) == (1, 1, 1.0)
    assert any(
        event.fact_id == context_fact.fact_id
        and event.status == CompilationStatus.GROUND_TRUTH_ONLY
        for event in compilation.events
    )


def _write_post_generation_outputs(
    output_dir: Path,
    ledger: ReportFactLedger,
    compilation,
    *,
    include_ioc: bool = True,
) -> None:
    output_dir.mkdir()
    event = compilation.events[0]
    indicator = ledger.report_iocs[0]
    report_iocs = (
        [
            {
                "indicator_id": indicator.indicator_id,
                "kind": indicator.kind.value,
                "value": indicator.value,
                "normalized_value": indicator.normalized_value,
                "source_locations": [
                    {
                        "span_id": ledger.source_spans[0].span_id,
                        "paragraph_number": 1,
                    }
                ],
            }
        ]
        if include_ioc
        else []
    )
    ground_truth = {
        "schema_version": 2,
        "report_context": {
            "source_name": "report.txt",
            "report_name": ledger.source_metadata.report_name,
            "report_iocs": report_iocs,
            "facts": [
                {
                    "fact_id": ledger.facts[0].fact_id,
                    "behavior": ledger.facts[0].behavior,
                    "description": ledger.facts[0].description,
                    "status": "materialized",
                    "event_ids": [event.event_id],
                    "source_locations": [
                        {
                            "span_id": ledger.source_spans[0].span_id,
                            "paragraph_number": 1,
                        }
                    ],
                }
            ],
        },
        "events": [
            {
                "kind": event.event_type.value,
                "storyline_id": event.event_id,
                "attributes": {
                    "source_metadata": {
                        "category": event.source_category.value,
                        "fact_ids": [event.fact_id],
                        "source_locations": [
                            {
                                "span_id": ledger.source_spans[0].span_id,
                                "paragraph_number": 1,
                            }
                        ],
                        "field_sources": {
                            name: {
                                "origin": field.provenance.origin.value,
                                "source_fact_ids": [event.fact_id],
                                "source_span_ids": field.provenance.source_span_ids,
                                **(
                                    {"reason": field.provenance.reason}
                                    if field.provenance.reason
                                    else {}
                                ),
                            }
                            for name, field in event.fields.items()
                        },
                        "expected_visibility": [
                            visibility.value for visibility in event.expected_visibility
                        ],
                    }
                },
            }
        ],
    }
    (output_dir / "GROUND_TRUTH.json").write_text(
        json.dumps(ground_truth, ensure_ascii=False), encoding="utf-8"
    )
    (output_dir / "RECORD_GROUND_TRUTH.jsonl").write_text(
        json.dumps(
            {
                "schema_version": 3,
                "label": "malicious",
                "storyline_id": event.event_id,
                "event_type": event.event_type.value,
            }
        )
        + "\n",
        encoding="utf-8",
    )


def test_post_generation_gate_uses_ids_and_ground_truth_not_tls_plaintext(
    tmp_path: Path,
) -> None:
    ledger, _document = _process_ledger(tmp_path)
    compilation = compile_report_ledger(ledger)
    output_dir = tmp_path / "output"
    _write_post_generation_outputs(output_dir, ledger, compilation)

    report = evaluate_post_generation(output_dir, ledger, compilation)

    assert report.passed is True
    assert report.score == 100.0
    assert report.metrics["report_ioc_retention"].rate == 1.0
    assert report.metrics["physical_materialization"].rate == 1.0


def test_post_generation_gate_rejects_missing_report_ioc(tmp_path: Path) -> None:
    ledger, _document = _process_ledger(tmp_path)
    compilation = compile_report_ledger(ledger)
    output_dir = tmp_path / "output"
    _write_post_generation_outputs(output_dir, ledger, compilation, include_ioc=False)

    report = evaluate_post_generation(output_dir, ledger, compilation)

    assert report.passed is False
    assert report.metrics["report_ioc_retention"].rate == 0.0
    assert any("报告 IOC" in reason for reason in report.hard_failures)


def test_published_output_can_be_rechecked_without_model_intermediate_json(
    tmp_path: Path,
) -> None:
    ledger, _document = _process_ledger(tmp_path)
    compilation = compile_report_ledger(ledger)
    output_dir = tmp_path / "output"
    _write_post_generation_outputs(output_dir, ledger, compilation)

    report = evaluate_published_output(output_dir)

    assert report.passed is True
    assert report.score == 100.0


def test_published_output_recheck_detects_removed_record_label(tmp_path: Path) -> None:
    ledger, _document = _process_ledger(tmp_path)
    compilation = compile_report_ledger(ledger)
    output_dir = tmp_path / "output"
    _write_post_generation_outputs(output_dir, ledger, compilation)
    (output_dir / "RECORD_GROUND_TRUTH.jsonl").write_text("", encoding="utf-8")

    report = evaluate_published_output(output_dir)

    assert report.passed is False
    assert report.metrics["physical_materialization"].rate == 0.0


def test_published_output_recheck_rejects_url_without_domain_ioc(tmp_path: Path) -> None:
    ledger, _document = _process_ledger(tmp_path)
    compilation = compile_report_ledger(ledger)
    output_dir = tmp_path / "output"
    _write_post_generation_outputs(output_dir, ledger, compilation)
    ground_truth_path = output_dir / "GROUND_TRUTH.json"
    ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    ground_truth["report_context"]["report_iocs"] = [
        {
            "indicator_id": "ioc-url-only",
            "kind": "url",
            "value": "https://c2.example/api",
            "normalized_value": "https://c2.example/api",
            "source_locations": [{"span_id": "span-test", "paragraph_number": 1}],
        }
    ]
    ground_truth_path.write_text(
        json.dumps(ground_truth, ensure_ascii=False),
        encoding="utf-8",
    )

    report = evaluate_published_output(output_dir)

    assert report.passed is False
    assert any("URL IOC 缺少对应域名" in reason for reason in report.hard_failures)
