# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""从威胁报告到 EvidenceForge 原生数据集的端到端管线。"""

import json
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypeVar

import yaml
from pydantic import BaseModel
from pydantic import ValidationError as PydanticValidationError

from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.report_ingest.compiler import (
    build_report_scenario,
    compile_report_ledger,
    resolve_engine_completion_requests,
)
from evidenceforge.report_ingest.extractors import (
    DEFAULT_CHUNK_OVERLAP,
    ExtractedDocument,
    extract_document,
    split_document,
)
from evidenceforge.report_ingest.iocs import (
    IocCandidate,
    apply_fact_audit_suggestions,
    enrich_report_ledger_structure,
    extract_ioc_candidates,
    merge_deterministic_report_indicators,
    sanitize_fact_extraction_source_claims,
    validate_fact_ledger_provenance,
)
from evidenceforge.report_ingest.minimax import (
    AUDIT_TOOL_NAME,
    COMPLETION_TOOL_NAME,
    FACT_EXTRACTION_TOOL_NAME,
    MiniMaxOutputTruncatedError,
)
from evidenceforge.report_ingest.models import (
    FactAuditResult,
    ReportFactExtraction,
    ReportFactLedger,
    SimulationPlan,
    SourceSpan,
    merge_fact_extractions,
    parse_structured_json,
    validate_simulation_plan,
)
from evidenceforge.report_ingest.prompts import (
    PromptBundle,
    build_audit_prompt,
    build_completion_prompt,
    build_fact_extraction_prompt,
    build_structured_repair_prompt,
)
from evidenceforge.report_ingest.quality import (
    ReportFidelityReport,
    evaluate_post_generation,
    evaluate_pre_generation,
)

REQUIRED_OUTPUTS = (
    "data",
    "GROUND_TRUTH.md",
    "GROUND_TRUTH.json",
    "GOLD_Label.json",
    "RECORD_GROUND_TRUTH.jsonl",
)
QUALITY_REPORT_FILENAME = "REPORT_FIDELITY.json"
FACT_EXTRACTION_CHUNK_CHARS = 2_000
FACT_EXTRACTION_CHUNK_OVERLAP = 0


class ReportPipelineError(EvidenceForgeError):
    """报告生成管线的一个可命名阶段失败。"""


class ReportQualityError(ReportPipelineError):
    """确定性来源贴合质量门未通过。"""


class ReportModelOutputError(ReportPipelineError):
    """MiniMax 结构化响应在有限修复后仍无效。"""


class CompletionClient(Protocol):
    """MiniMax 客户端和测试替身共用的最小接口。"""

    model: str

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        tool_name: str,
        tool_description: str,
        response_model: type[BaseModel],
        stage: str,
        prompt_version: str,
        repair: bool = False,
    ) -> str:
        """返回一个结构化助手响应。"""


ScenarioValidator = Callable[[Path], None]
DatasetGenerator = Callable[[Path, Path, bool], None]
ProgressCallback = Callable[[str], None]
StructuredT = TypeVar("StructuredT", bound=BaseModel)


@dataclass(frozen=True)
class ReportPipelineResult:
    """不包含报告原文或模型响应的安全结果摘要。"""

    output_dir: Path
    scenario_path: Path
    quality_report_path: Path
    source_name: str
    fact_count: int
    materialized_event_count: int
    materializable_coverage: float
    quality_score: float
    model: str
    model_calls: int


class ReportPipeline:
    """编排 A 来源抽取、B 完整性审核、C 受控补全和原生生成。"""

    def __init__(
        self,
        client: CompletionClient,
        *,
        scenario_validator: ScenarioValidator,
        dataset_generator: DatasetGenerator,
        workspace_root: Path,
        progress: ProgressCallback | None = None,
    ) -> None:
        self.client = client
        self.scenario_validator = scenario_validator
        self.dataset_generator = dataset_generator
        self.workspace_root = workspace_root.resolve()
        self.progress = progress or (lambda _message: None)
        self._model_calls = 0

    def run(
        self, input_path: Path, output_dir: Path, *, force: bool = False
    ) -> ReportPipelineResult:
        """一轮生成完整数据集，只在全部质量门通过后发布。"""
        self._model_calls = 0
        safe_output = self._validate_output_path(output_dir, force=force)
        self.progress("[1/8] 提取 TXT/PDF 文本并建立稳定来源片段")
        document = extract_document(input_path)
        all_candidates = extract_ioc_candidates(document.text, document.spans)
        chunks = split_document(
            document.text,
            chunk_chars=FACT_EXTRACTION_CHUNK_CHARS,
            overlap_chars=FACT_EXTRACTION_CHUNK_OVERLAP,
        )
        chunk_spans = _source_spans_by_chunk(document, chunks)

        self.progress(f"[2/8] MiniMax A 抽取来源事实（{len(chunks)} 个分块）")
        extractions: list[ReportFactExtraction] = []
        for index, chunk in enumerate(chunks, start=1):
            visible_spans = chunk_spans[index - 1]
            prompt = build_fact_extraction_prompt(
                document,
                _candidates_for_chunk(all_candidates, chunk, visible_spans),
                chunk_text=chunk,
                chunk_index=index,
                chunk_count=len(chunks),
                source_spans=visible_spans,
            )
            extraction = self._call_structured(
                prompt,
                ReportFactExtraction,
                tool_name=FACT_EXTRACTION_TOOL_NAME,
                tool_description="提交只含报告明确事实与来源引用的事实账本分块。",
                stage=f"fact_extraction_{index}",
                validator=lambda value: validate_fact_ledger_provenance(
                    sanitize_fact_extraction_source_claims(value, document).to_ledger(
                        document.spans
                    ),
                    document,
                ),
            )
            extractions.append(sanitize_fact_extraction_source_claims(extraction, document))

        ledger = merge_fact_extractions(extractions, document.spans)
        ledger = merge_deterministic_report_indicators(ledger, all_candidates)
        ledger = enrich_report_ledger_structure(ledger)
        provenance_errors = validate_fact_ledger_provenance(ledger, document)
        if provenance_errors:
            raise ReportModelOutputError(
                "MiniMax A 合并后的来源校验失败：" + "；".join(provenance_errors[:20])
            )

        self.progress("[3/8] MiniMax B 审核遗漏、重复、错绑和顺序")
        audit_prompt = build_audit_prompt(document, ledger)
        try:
            audit = self._call_structured(
                audit_prompt,
                FactAuditResult,
                tool_name=AUDIT_TOOL_NAME,
                tool_description="提交针对当前来源事实账本的可校验完整性审核建议。",
                stage="fact_audit",
                validator=lambda value: _audit_validation_errors(value, ledger, document),
            )
        except (MiniMaxOutputTruncatedError, ReportModelOutputError):
            self.progress("MiniMax B 未形成完整有效审核；丢弃整份 B 并继续使用已验证 A 账本")
            audit = FactAuditResult(
                summary="B 审核未形成完整有效结构，未应用任何不完整建议。",
                ledger_complete=True,
            )
        try:
            ledger = apply_fact_audit_suggestions(
                audit,
                ledger,
                document,
                strict=False,
            )
        except ValueError as exc:
            raise ReportModelOutputError(_safe_parse_error(exc)) from exc
        ledger = merge_deterministic_report_indicators(ledger, all_candidates)
        ledger = enrich_report_ledger_structure(ledger)

        self.progress("[4/8] 确定性编译、本地安全补全，并按需调用 MiniMax C")
        initial_compilation = compile_report_ledger(ledger)
        engine_plan, model_requests = resolve_engine_completion_requests(
            initial_compilation.completion_requests,
            ledger,
        )
        model_plan = SimulationPlan()
        if model_requests:
            completion_prompt = build_completion_prompt(ledger, model_requests)
            model_plan = self._call_structured(
                completion_prompt,
                SimulationPlan,
                tool_name=COMPLETION_TOOL_NAME,
                tool_description="只提交编译器明确申请的内部仿真字段补全计划。",
                stage="simulation_completion",
                validator=lambda value: validate_simulation_plan(
                    value,
                    model_requests,
                    ledger,
                ),
            )
        plan = SimulationPlan(
            completions=[*engine_plan.completions, *model_plan.completions],
            unresolved_request_ids=[
                *engine_plan.unresolved_request_ids,
                *model_plan.unresolved_request_ids,
            ],
        )
        compilation = compile_report_ledger(ledger, plan)

        self.progress("[5/8] 执行生成前来源贴合质量门")
        pre_quality = evaluate_pre_generation(ledger, compilation, document)
        _require_quality(pre_quality)
        scenario = build_report_scenario(
            ledger,
            compilation,
            source_name=document.source_name,
        )

        safe_output.parent.mkdir(parents=True, exist_ok=True)
        temp_root = Path(
            tempfile.mkdtemp(
                prefix=f".{safe_output.name}.eforge-",
                dir=safe_output.parent,
            )
        )
        staged_output = temp_root / "publish"
        staged_scenario = temp_root / "scenario.yaml"
        try:
            staged_output.mkdir()
            staged_scenario.write_text(
                yaml.safe_dump(
                    scenario.model_dump(mode="json", exclude_none=True),
                    allow_unicode=True,
                    sort_keys=False,
                ),
                encoding="utf-8",
            )

            self.progress("[6/8] 校验 Scenario 并调用 EvidenceForge 原生生成引擎")
            self.scenario_validator(staged_scenario)
            self.dataset_generator(staged_scenario, staged_output, False)
            self._verify_required_outputs(staged_output)
            shutil.copy2(staged_scenario, staged_output / "scenario.yaml")

            self.progress("[7/8] 执行生成后 ID 链、IOC 与记录级标签质量门")
            post_quality = evaluate_post_generation(staged_output, ledger, compilation)
            _require_quality(post_quality)
            _write_quality_report(
                staged_output / QUALITY_REPORT_FILENAME,
                source_name=document.source_name,
                model=self.client.model,
                model_calls=self._model_calls,
                pre_quality=pre_quality,
                post_quality=post_quality,
            )

            self.progress("[8/8] 原子发布通过全部质量门的最终产物")
            self._publish(staged_output, safe_output, force=force)
        finally:
            shutil.rmtree(temp_root, ignore_errors=True)

        materialized_count = sum(
            event.status.value == "materialized" for event in compilation.events
        )
        return ReportPipelineResult(
            output_dir=safe_output,
            scenario_path=safe_output / "scenario.yaml",
            quality_report_path=safe_output / QUALITY_REPORT_FILENAME,
            source_name=document.source_name,
            fact_count=len(ledger.facts),
            materialized_event_count=materialized_count,
            materializable_coverage=pre_quality.metrics["materializable_behavior_coverage"].rate,
            quality_score=post_quality.score,
            model=self.client.model,
            model_calls=self._model_calls,
        )

    def _call_structured(
        self,
        prompt: PromptBundle,
        response_model: type[StructuredT],
        *,
        tool_name: str,
        tool_description: str,
        stage: str,
        validator: Callable[[StructuredT], list[str]],
    ) -> StructuredT:
        """调用一个结构化阶段，并在失败时最多定向修复一次。"""
        try:
            response = self.client.complete(
                prompt.system,
                prompt.user,
                tool_name=tool_name,
                tool_description=tool_description,
                response_model=response_model,
                stage=stage,
                prompt_version=prompt.version,
            )
        finally:
            self._model_calls += 1
        value, errors = _parse_and_validate(response, response_model, validator)
        if not errors and value is not None:
            return value

        self.progress(f"{stage} 首次响应未通过本地校验，执行一次定向修复")
        repair_prompt = build_structured_repair_prompt(
            prompt,
            invalid_response=response,
            errors=errors,
            response_model=response_model,
            tool_name=tool_name,
            stage=stage,
        )
        try:
            response = self.client.complete(
                repair_prompt.system,
                repair_prompt.user,
                tool_name=tool_name,
                tool_description=tool_description,
                response_model=response_model,
                stage=stage,
                prompt_version=repair_prompt.version,
                repair=True,
            )
        finally:
            self._model_calls += 1
        value, errors = _parse_and_validate(response, response_model, validator)
        if errors or value is None:
            detail = "；".join(errors[:20]) if errors else "未知结构错误"
            raise ReportModelOutputError(f"MiniMax {stage} 在修复后仍未通过：{detail}")
        return value

    def _validate_output_path(self, output_dir: Path, *, force: bool) -> Path:
        """拒绝过宽、符号链接或未授权覆盖的输出路径。"""
        candidate = output_dir.expanduser()
        if candidate.is_symlink():
            raise ReportPipelineError("拒绝写入符号链接输出目录")
        resolved = candidate.resolve(strict=False)
        forbidden = {Path("/").resolve(), Path.home().resolve(), self.workspace_root}
        if resolved in forbidden:
            raise ReportPipelineError("输出目录不能是根目录、用户主目录或项目根目录")
        if resolved.exists() and not resolved.is_dir():
            raise ReportPipelineError("输出路径已存在且不是目录")
        if resolved.exists() and any(resolved.iterdir()) and not force:
            raise ReportPipelineError("输出目录非空；如确认覆盖，请显式传入 --force")
        return resolved

    @staticmethod
    def _verify_required_outputs(output_dir: Path) -> None:
        """确认原生生成器产出了标准文件集。"""
        missing = [name for name in REQUIRED_OUTPUTS if not (output_dir / name).exists()]
        if missing:
            raise ReportPipelineError("生成器缺少标准产物：" + ", ".join(missing))
        data_dir = output_dir / "data"
        if not any(path.is_file() and path.stat().st_size > 0 for path in data_dir.rglob("*")):
            raise ReportPipelineError("data/ 中没有非空日志文件")

    @staticmethod
    def _publish(staged_output: Path, output_dir: Path, *, force: bool) -> None:
        """使用同文件系统重命名发布，覆盖失败时恢复旧目录。"""
        if not output_dir.exists():
            staged_output.rename(output_dir)
            return
        if any(output_dir.iterdir()) and not force:
            raise ReportPipelineError("发布时发现输出目录已非空")
        if not any(output_dir.iterdir()):
            output_dir.rmdir()
            staged_output.rename(output_dir)
            return

        backup = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.backup-", dir=output_dir.parent))
        backup.rmdir()
        output_dir.rename(backup)
        try:
            staged_output.rename(output_dir)
        except BaseException:
            if not output_dir.exists() and backup.exists():
                backup.rename(output_dir)
            raise
        shutil.rmtree(backup)


def _parse_and_validate(
    response: str,
    response_model: type[StructuredT],
    validator: Callable[[StructuredT], list[str]],
) -> tuple[StructuredT | None, list[str]]:
    try:
        value = parse_structured_json(response, response_model)
    except (json.JSONDecodeError, PydanticValidationError, TypeError, ValueError) as exc:
        return None, [_safe_parse_error(exc)]
    try:
        return value, validator(value)
    except (PydanticValidationError, TypeError, ValueError) as exc:
        return None, [_safe_parse_error(exc)]


def _audit_validation_errors(
    _audit: FactAuditResult,
    _ledger: ReportFactLedger,
    _document: ExtractedDocument,
) -> list[str]:
    """B 是顾问建议；结构解析后由本地逐条接受或拒绝。"""
    return []


def _safe_parse_error(exc: Exception) -> str:
    if isinstance(exc, PydanticValidationError):
        details = []
        for error in exc.errors()[:20]:
            location = ".".join(str(part) for part in error["loc"])
            details.append(f"{location}: {error['msg']}")
        return "; ".join(details)[:5000]
    return f"{type(exc).__name__}: {str(exc)[:2000]}"


def _candidates_for_chunk(
    candidates: list[IocCandidate],
    chunk: str,
    source_spans: list[SourceSpan],
) -> list[IocCandidate]:
    folded = chunk.casefold()
    visible_span_ids = {span.span_id for span in source_spans}
    selected: list[IocCandidate] = []
    for candidate in candidates:
        if (
            candidate.original.casefold() not in folded
            and candidate.normalized.casefold() not in folded
        ):
            continue
        occurrences = []
        for occurrence in candidate.occurrences:
            span_ids = [
                span_id for span_id in occurrence.source_span_ids if span_id in visible_span_ids
            ]
            if span_ids:
                occurrences.append(
                    occurrence.model_copy(update={"source_span_ids": span_ids}, deep=True)
                )
        if occurrences:
            selected.append(candidate.model_copy(update={"occurrences": occurrences}, deep=True))
    return selected


def _source_spans_by_chunk(
    document: ExtractedDocument,
    chunks: list[str],
) -> list[list[SourceSpan]]:
    """每个 A 阶段分块只携带与它字符区间重叠的来源目录。"""
    result: list[list[SourceSpan]] = []
    cursor = 0
    for chunk in chunks:
        start = document.text.find(chunk, max(0, cursor - DEFAULT_CHUNK_OVERLAP * 2))
        if start < 0:
            raise ReportPipelineError("无法把报告分块稳定定位回来源文本")
        end = start + len(chunk)
        visible = [
            span for span in document.spans if span.char_start < end and span.char_end > start
        ]
        if not visible:
            raise ReportPipelineError("报告分块没有可引用的来源片段")
        result.append(visible)
        cursor = end
    return result


def _require_quality(report: ReportFidelityReport) -> None:
    if report.passed:
        return
    raise ReportQualityError(
        f"{report.stage} 来源贴合质量门未通过（{report.score:.2f} 分）："
        + "；".join(report.hard_failures[:20])
    )


def _write_quality_report(
    path: Path,
    *,
    source_name: str,
    model: str,
    model_calls: int,
    pre_quality: ReportFidelityReport,
    post_quality: ReportFidelityReport,
) -> None:
    payload = {
        "schema_version": 1,
        "source_name": source_name,
        "model": model,
        "model_calls": model_calls,
        "pre_generation": pre_quality.model_dump(mode="json"),
        "post_generation": post_quality.model_dump(mode="json"),
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
