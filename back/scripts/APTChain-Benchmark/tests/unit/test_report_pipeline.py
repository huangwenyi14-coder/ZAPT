# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""A/B/C 报告管线、质量门和原子发布测试。"""

import json
from pathlib import Path

import pytest
import yaml
from pydantic import BaseModel

from evidenceforge.models.scenario import Scenario
from evidenceforge.report_ingest.extractors import ExtractedDocument, extract_document
from evidenceforge.report_ingest.minimax import MiniMaxOutputTruncatedError
from evidenceforge.report_ingest.models import (
    EntityType,
    FactAuditResult,
    FieldOrigin,
    FieldProvenance,
    ReportEntity,
    ReportFact,
    ReportFactExtraction,
    ReportMeta,
    ReportRelation,
    SimulationPlan,
)
from evidenceforge.report_ingest.pipeline import (
    QUALITY_REPORT_FILENAME,
    REQUIRED_OUTPUTS,
    ReportPipeline,
    ReportPipelineError,
    ReportQualityError,
)

_MD5 = "e74d7351a73c0343c2b607c8f137f847"


class FakeStructuredClient:
    """按顺序返回结构化响应并记录阶段元数据。"""

    model = "MiniMax-test"

    def __init__(self, responses: list[str | Exception]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, object]] = []

    def complete(
        self,
        _system_prompt: str,
        _user_prompt: str,
        *,
        tool_name: str,
        tool_description: str,
        response_model: type[BaseModel],
        stage: str,
        prompt_version: str,
        repair: bool = False,
    ) -> str:
        self.calls.append(
            {
                "tool_name": tool_name,
                "tool_description": tool_description,
                "response_model": response_model.__name__,
                "stage": stage,
                "prompt_version": prompt_version,
                "repair": repair,
            }
        )
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _write_report(tmp_path: Path) -> tuple[Path, ExtractedDocument]:
    path = tmp_path / "report.txt"
    path.write_text(
        f"报告明确说明 sample.exe 执行恶意逻辑，文件 MD5 为 {_MD5}。",
        encoding="utf-8",
    )
    return path, extract_document(path)


def _fact_extraction(document: ExtractedDocument) -> ReportFactExtraction:
    provenance = FieldProvenance(
        origin=FieldOrigin.SOURCE,
        source_span_ids=[document.spans[0].span_id],
    )
    fact = ReportFact(
        fact_id="fact-exec",
        behavior="malware_execution",
        order=1,
        description="sample.exe 执行恶意逻辑",
        provenance=provenance,
    )
    process = ReportEntity(
        entity_id="entity-process",
        entity_type=EntityType.PROCESS,
        value="sample.exe",
        provenance=provenance,
    )
    return ReportFactExtraction(
        source_metadata=ReportMeta(
            report_name="管线测试报告",
            description="报告描述一个明确的恶意进程执行行为。",
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
        report_iocs=[],
    )


def _responses(document: ExtractedDocument, *, first: str | None = None) -> list[str]:
    values = [
        _fact_extraction(document).model_dump_json(),
        FactAuditResult(
            summary="事实账本完整，未发现遗漏或错绑。",
            ledger_complete=True,
        ).model_dump_json(),
        SimulationPlan().model_dump_json(),
    ]
    return ([first] if first is not None else []) + values


def _validate_scenario(path: Path) -> None:
    Scenario.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def _fake_generator(
    _scenario_path: Path,
    output_dir: Path,
    force: bool,
    *,
    omit_report_iocs: bool = False,
) -> None:
    assert force is False
    scenario = yaml.safe_load(_scenario_path.read_text(encoding="utf-8"))
    data_dir = output_dir / "data" / "endpoint"
    data_dir.mkdir(parents=True)
    (data_dir / "events.jsonl").write_text('{"event":"process"}\n', encoding="utf-8")

    context = scenario["report_context"]
    if omit_report_iocs:
        context["report_iocs"] = []
    events = []
    record_lines = []
    for step in scenario["storyline"]:
        for event in step["events"]:
            events.append(
                {
                    "kind": event["type"],
                    "storyline_id": step["id"],
                    "attributes": {"source_metadata": event["source_metadata"]},
                }
            )
            record_lines.append(
                json.dumps(
                    {
                        "schema_version": 3,
                        "label": "malicious",
                        "storyline_id": step["id"],
                        "event_type": event["type"],
                    }
                )
            )
    ground_truth = {
        "schema_version": 2,
        "report_context": context,
        "events": events,
    }
    (output_dir / "GROUND_TRUTH.json").write_text(
        json.dumps(ground_truth, ensure_ascii=False), encoding="utf-8"
    )
    (output_dir / "GROUND_TRUTH.md").write_text("# Ground Truth\n", encoding="utf-8")
    (output_dir / "GOLD_Label.json").write_text("{}\n", encoding="utf-8")
    (output_dir / "RECORD_GROUND_TRUTH.jsonl").write_text(
        "\n".join(record_lines) + "\n", encoding="utf-8"
    )


def _pipeline(client: FakeStructuredClient, tmp_path: Path, *, bad_iocs: bool = False):
    def generator(scenario_path: Path, output_dir: Path, force: bool) -> None:
        _fake_generator(
            scenario_path,
            output_dir,
            force,
            omit_report_iocs=bad_iocs,
        )

    return ReportPipeline(
        client,
        scenario_validator=_validate_scenario,
        dataset_generator=generator,
        workspace_root=tmp_path / "workspace",
    )


def test_pipeline_runs_a_b_c_and_publishes_only_checked_outputs(tmp_path: Path) -> None:
    report_path, document = _write_report(tmp_path)
    client = FakeStructuredClient(_responses(document))
    output = tmp_path / "output"

    result = _pipeline(client, tmp_path).run(report_path, output)

    assert [call["stage"] for call in client.calls] == [
        "fact_extraction_1",
        "fact_audit",
    ]
    assert result.model_calls == 2
    assert result.fact_count == 1
    assert result.materialized_event_count == 1
    assert result.materializable_coverage == 1.0
    assert result.quality_score == 100.0
    assert result.scenario_path.is_file()
    assert result.quality_report_path.name == QUALITY_REPORT_FILENAME
    assert all((output / name).exists() for name in REQUIRED_OUTPUTS)
    scenario = yaml.safe_load(result.scenario_path.read_text(encoding="utf-8"))
    assert scenario["report_context"]["report_iocs"][0]["normalized_value"] == _MD5
    quality = json.loads(result.quality_report_path.read_text(encoding="utf-8"))
    assert quality["pre_generation"]["passed"] is True
    assert quality["post_generation"]["passed"] is True
    assert not list(output.glob("*extraction*.json"))


def test_each_stage_gets_at_most_one_targeted_repair(tmp_path: Path) -> None:
    report_path, document = _write_report(tmp_path)
    client = FakeStructuredClient(_responses(document, first="不是 JSON"))

    result = _pipeline(client, tmp_path).run(report_path, tmp_path / "output")

    assert result.model_calls == 3
    assert client.calls[0]["repair"] is False
    assert client.calls[1]["repair"] is True
    assert client.calls[1]["stage"] == "fact_extraction_1"


def test_truncated_advisory_audit_keeps_verified_a_ledger(tmp_path: Path) -> None:
    report_path, document = _write_report(tmp_path)
    client = FakeStructuredClient(
        [
            _fact_extraction(document).model_dump_json(),
            MiniMaxOutputTruncatedError("MiniMax 输出达到 max_tokens 上限"),
        ]
    )
    output = tmp_path / "output"

    result = _pipeline(client, tmp_path).run(report_path, output)

    assert result.fact_count == 1
    assert result.materializable_coverage == 1.0
    assert result.model_calls == 2
    assert [call["stage"] for call in client.calls] == [
        "fact_extraction_1",
        "fact_audit",
    ]
    assert output.is_dir()


def test_invalid_advisory_audit_and_repair_keep_verified_a_ledger(
    tmp_path: Path,
) -> None:
    report_path, document = _write_report(tmp_path)
    client = FakeStructuredClient(
        [
            _fact_extraction(document).model_dump_json(),
            '{"summary":"建议结构错误","ledger_complete":false,"suggestions":{}}',
            '{"summary":"修复后仍错","ledger_complete":false,"suggestions":"invalid"}',
        ]
    )
    output = tmp_path / "output"

    result = _pipeline(client, tmp_path).run(report_path, output)

    assert result.fact_count == 1
    assert result.materializable_coverage == 1.0
    assert result.model_calls == 3
    assert [call["stage"] for call in client.calls] == [
        "fact_extraction_1",
        "fact_audit",
        "fact_audit",
    ]
    assert client.calls[-1]["repair"] is True
    assert output.is_dir()


def test_failed_post_quality_keeps_existing_output_untouched(tmp_path: Path) -> None:
    report_path, document = _write_report(tmp_path)
    output = tmp_path / "output"
    output.mkdir()
    (output / "keep.txt").write_text("用户原有产物", encoding="utf-8")

    with pytest.raises(ReportQualityError, match="post_generation"):
        _pipeline(
            FakeStructuredClient(_responses(document)),
            tmp_path,
            bad_iocs=True,
        ).run(report_path, output, force=True)

    assert (output / "keep.txt").read_text(encoding="utf-8") == "用户原有产物"
    assert sorted(output.iterdir()) == [output / "keep.txt"]
    assert not list(tmp_path.glob(".output.eforge-*"))


def test_pipeline_rejects_nonempty_output_without_force_before_model_call(
    tmp_path: Path,
) -> None:
    report_path, document = _write_report(tmp_path)
    output = tmp_path / "output"
    output.mkdir()
    (output / "keep.txt").write_text("用户数据", encoding="utf-8")
    client = FakeStructuredClient(_responses(document))

    with pytest.raises(ReportPipelineError, match="输出目录非空"):
        _pipeline(client, tmp_path).run(report_path, output)

    assert client.calls == []
