# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""报告编译结果到 EvidenceForge Scenario 的适配测试。"""

import json
from pathlib import Path

import yaml

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.ground_truth import GroundTruthGenerator
from evidenceforge.models.scenario import Scenario
from evidenceforge.report_ingest.compiler import (
    build_report_scenario,
    compile_report_ledger,
)
from evidenceforge.report_ingest.extractors import extract_document
from evidenceforge.report_ingest.models import (
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
)
from evidenceforge.report_ingest.quality import (
    evaluate_post_generation,
    evaluate_published_output,
)


def _ledger_with_materialized_and_gt_only(tmp_path: Path) -> ReportFactLedger:
    source = tmp_path / "report.txt"
    source.write_text(
        "sample.exe 执行恶意逻辑，MD5 为 e74d7351a73c0343c2b607c8f137f847。\n\n"
        "报告还提到了当前引擎尚未支持的特殊行为。",
        encoding="utf-8",
    )
    document = extract_document(source)
    first_span, second_span = document.spans
    first = FieldProvenance(origin=FieldOrigin.SOURCE, source_span_ids=[first_span.span_id])
    second = FieldProvenance(origin=FieldOrigin.SOURCE, source_span_ids=[second_span.span_id])
    return ReportFactLedger(
        source_spans=list(document.spans),
        source_metadata=ReportMeta(
            report_name="端到端适配测试",
            description="进程行为与无法物化行为的测试报告",
        ),
        metadata_provenance=first,
        facts=[
            ReportFact(
                fact_id="fact-exec",
                behavior="malware_execution",
                order=1,
                description="sample.exe 执行恶意逻辑",
                provenance=first,
            ),
            ReportFact(
                fact_id="fact-special",
                behavior="unsupported_special_behavior",
                order=2,
                description="当前引擎尚未支持的特殊行为",
                provenance=second,
            ),
        ],
        entities=[
            ReportEntity(
                entity_id="entity-process",
                entity_type=EntityType.PROCESS,
                value="sample.exe",
                provenance=first,
            )
        ],
        relations=[
            ReportRelation(
                relation_id="relation-owner",
                source_id="fact-exec",
                predicate="performed_by",
                target_id="entity-process",
                provenance=first,
            )
        ],
        report_iocs=[
            ReportIndicator(
                indicator_id="ioc-md5",
                kind=IndicatorKind.HASH,
                value="e74d7351a73c0343c2b607c8f137f847",
                provenance=first,
            )
        ],
    )


def _ledger_with_process_access(tmp_path: Path) -> ReportFactLedger:
    source = tmp_path / "anti-analysis-report.txt"
    source.write_text(
        "sample.exe 会检查 vmtoolsd.exe 进程以识别虚拟机环境。",
        encoding="utf-8",
    )
    document = extract_document(source)
    provenance = FieldProvenance(
        origin=FieldOrigin.SOURCE,
        source_span_ids=[document.spans[0].span_id],
    )
    owner = ReportEntity(
        entity_id="entity-owner-process",
        entity_type=EntityType.PROCESS,
        value="sample.exe",
        provenance=provenance,
    )
    target = ReportEntity(
        entity_id="entity-target-process",
        entity_type=EntityType.PROCESS,
        value="vmtoolsd.exe",
        provenance=provenance,
    )
    return ReportFactLedger(
        source_spans=list(document.spans),
        source_metadata=ReportMeta(
            report_name="反分析记录物化测试",
            description="验证目标进程先建立、后访问。",
        ),
        metadata_provenance=provenance,
        facts=[
            ReportFact(
                fact_id="fact-anti-analysis",
                behavior="anti_debug_anti_vm",
                order=1,
                description="sample.exe 检查 vmtoolsd.exe",
                provenance=provenance,
            )
        ],
        entities=[owner, target],
        relations=[
            ReportRelation(
                relation_id="relation-owner",
                source_id="fact-anti-analysis",
                predicate="performed_by",
                target_id=owner.entity_id,
                provenance=provenance,
            ),
            ReportRelation(
                relation_id="relation-target",
                source_id="fact-anti-analysis",
                predicate="checks",
                target_id=target.entity_id,
                provenance=provenance,
            ),
        ],
    )


def test_adapter_builds_valid_native_scenario_and_keeps_report_context(tmp_path: Path) -> None:
    ledger = _ledger_with_materialized_and_gt_only(tmp_path)
    compilation = compile_report_ledger(ledger)

    scenario = build_report_scenario(ledger, compilation, source_name="report.txt")

    assert Scenario.model_validate(scenario.model_dump(mode="json")) == scenario
    serialized = yaml.safe_dump(scenario.model_dump(mode="json", exclude_none=True))
    assert Scenario.model_validate(yaml.safe_load(serialized)) == scenario
    assert [step.id for step in scenario.storyline or []] == ["event-0001-fact-exec"]
    process = scenario.storyline[0].events[0]
    assert process.type == "process"
    assert process.process_name == "sample.exe"
    assert process.persistent is True
    assert process.source_metadata.fact_ids == ["fact-exec"]
    assert process.source_metadata.source_locations[0].paragraph_number == 1
    assert process.source_metadata.field_sources["process_name"].origin == "source"

    context = scenario.report_context
    assert context is not None
    assert context.source_name == "report.txt"
    assert context.report_iocs[0].normalized_value == "e74d7351a73c0343c2b607c8f137f847"
    assert context.facts[0].status == "materialized"
    assert context.facts[1].status == "ground_truth_only"
    assert context.facts[1].degradation_reason


def test_ground_truth_copies_report_iocs_and_gt_only_facts(tmp_path: Path) -> None:
    ledger = _ledger_with_materialized_and_gt_only(tmp_path)
    scenario = build_report_scenario(
        ledger,
        compile_report_ledger(ledger),
        source_name="report.txt",
    )
    generator = GroundTruthGenerator(scenario, malicious_events=[])

    document = generator.build_document()
    output = tmp_path / "GROUND_TRUTH.md"
    generator.generate(output, document)

    assert document.report_context == scenario.report_context
    markdown = output.read_text(encoding="utf-8")
    assert "## 原始报告保留信息" in markdown
    assert "e74d7351a73c0343c2b607c8f137f847" in markdown
    assert "fact-special" in markdown
    assert "仅 Ground Truth" in markdown


def test_adapter_scenario_runs_the_original_generation_engine(tmp_path: Path) -> None:
    """适配结果必须真正生成日志，不得只通过 Schema 校验。"""
    ledger = _ledger_with_materialized_and_gt_only(tmp_path)
    compilation = compile_report_ledger(ledger)
    scenario = build_report_scenario(ledger, compilation, source_name="report.txt")
    payload = scenario.model_dump(mode="json")
    payload["time_window"] = {
        "start": "2024-01-15T08:00:00Z",
        "duration": "2h",
        "warmup": "1h",
    }
    payload["output"]["logs"] = [{"format": "windows"}, {"format": "ecar"}]
    scenario = Scenario.model_validate(payload)
    output = tmp_path / "generated"

    GenerationEngine(
        scenario,
        output / "data",
        ground_truth_dir=output,
        artifact_dir=output / "artifacts",
        scenario_root=tmp_path,
    ).generate()

    assert (output / "GROUND_TRUTH.json").is_file()
    assert (output / "RECORD_GROUND_TRUTH.jsonl").is_file()
    assert any(path.stat().st_size > 0 for path in (output / "data").rglob("*"))
    quality = evaluate_post_generation(output, ledger, compilation)
    assert quality.passed is True, quality.hard_failures
    rechecked = evaluate_published_output(output)
    assert rechecked.passed is True, rechecked.hard_failures


def test_process_access_target_prerequisite_reaches_record_labels(tmp_path: Path) -> None:
    """报告反分析目标必须先进入运行状态，再产生原生访问记录。"""
    ledger = _ledger_with_process_access(tmp_path)
    compilation = compile_report_ledger(ledger)
    scenario = build_report_scenario(ledger, compilation, source_name="anti-analysis-report.txt")
    payload = scenario.model_dump(mode="json")
    payload["time_window"] = {
        "start": "2024-01-15T08:00:00Z",
        "duration": "2h",
        "warmup": "1h",
    }
    payload["output"]["logs"] = [{"format": "windows"}, {"format": "ecar"}]
    scenario = Scenario.model_validate(payload)
    output = tmp_path / "process-access-generated"

    GenerationEngine(
        scenario,
        output / "data",
        ground_truth_dir=output,
        artifact_dir=output / "artifacts",
        scenario_root=tmp_path,
    ).generate()

    access_event = next(
        event
        for event in compilation.events
        if event.event_type is not None and event.event_type.value == "process_access"
    )
    records = [
        json.loads(line)
        for line in (output / "RECORD_GROUND_TRUTH.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(
        record.get("storyline_id") == access_event.event_id
        and record.get("label") == "malicious"
        for record in records
    )
    quality = evaluate_post_generation(output, ledger, compilation)
    assert quality.passed is True, quality.hard_failures
