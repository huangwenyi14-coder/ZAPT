"""Helpers for report-to-dataset semantic regression tests."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _StrictModel(BaseModel):
    """Forbid accidental fixture drift caused by misspelled fields."""

    model_config = ConfigDict(extra="forbid")


class SourceFixture(_StrictModel):
    """Source metadata without embedding the original report."""

    kind: Literal["pdf", "txt"]
    display_name: str = Field(min_length=1)
    fixture: str | None = None

    @model_validator(mode="after")
    def require_fixture_for_txt(self) -> SourceFixture:
        """Keep synthetic text cases self-contained while PDFs remain external."""
        if self.kind == "txt" and self.fixture is None:
            raise ValueError("TXT 语义用例必须声明 fixture")
        return self


class IocExpectations(_StrictModel):
    """Normalized report-level indicators."""

    hashes: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)

    @field_validator("hashes", "urls", "domains", "ips")
    @classmethod
    def reject_duplicates(cls, values: list[str]) -> list[str]:
        """Reject duplicate expectations instead of hiding merge regressions."""
        if len(values) != len(set(values)):
            raise ValueError("IOC 期望中不能包含重复值")
        return values

    @model_validator(mode="after")
    def require_normalized_values(self) -> IocExpectations:
        """Keep comparisons independent from common defanging syntax."""
        all_values = [*self.hashes, *self.urls, *self.domains, *self.ips]
        if any("[.]" in value or value.startswith("hxxp") for value in all_values):
            raise ValueError("IOC 期望必须使用去除失陷标记后的规范值")
        if any(value != value.lower() for value in self.hashes):
            raise ValueError("哈希期望必须使用小写")
        return self


class ScheduledTaskExpectation(_StrictModel):
    """One report-supported scheduled task."""

    name: str = Field(min_length=1)
    binary: str = Field(min_length=1)
    interval_minutes: int | None = Field(default=None, gt=0)
    mechanism: Literal["com", "schtasks", "unspecified"] = "unspecified"


class ProcessBehaviorBinding(_StrictModel):
    """A process that is explicitly bound to one behavior."""

    process_image: str = Field(min_length=1)
    behavior: str = Field(min_length=1)


class NetworkBehaviorBinding(_StrictModel):
    """A URL bound to one behavior and optional downloaded file."""

    behavior: str = Field(min_length=1)
    url: str = Field(min_length=1)
    target_file: str | None = None


class ForbiddenSemantics(_StrictModel):
    """Known fabrication or cross-binding patterns that must never reappear."""

    process_images: list[str] = Field(default_factory=list)
    behaviors: list[str] = Field(default_factory=list)
    process_bindings: list[ProcessBehaviorBinding] = Field(default_factory=list)
    network_bindings: list[NetworkBehaviorBinding] = Field(default_factory=list)
    registry_writes: list[str] = Field(default_factory=list)
    reject_unprovenanced_exact_claims: bool = True


class ReportSemanticExpectations(_StrictModel):
    """Source-backed semantic requirements for one report."""

    case_id: str = Field(min_length=1)
    source: SourceFixture
    iocs: IocExpectations
    exact_iocs: bool = True
    required_commands: list[str] = Field(default_factory=list)
    required_files: list[str] = Field(default_factory=list)
    required_scheduled_tasks: list[ScheduledTaskExpectation] = Field(default_factory=list)
    required_behaviors: list[str] = Field(default_factory=list)
    required_process_bindings: list[ProcessBehaviorBinding] = Field(default_factory=list)
    required_network_bindings: list[NetworkBehaviorBinding] = Field(default_factory=list)
    required_registry_queries: list[str] = Field(default_factory=list)
    forbidden: ForbiddenSemantics = Field(default_factory=ForbiddenSemantics)

    @model_validator(mode="after")
    def reject_duplicate_semantics(self) -> ReportSemanticExpectations:
        """Make all list membership assertions unambiguous."""
        scalar_lists = (
            self.required_commands,
            self.required_files,
            self.required_behaviors,
            self.required_registry_queries,
        )
        if any(len(values) != len(set(values)) for values in scalar_lists):
            raise ValueError(f"用例 {self.case_id} 包含重复语义期望")

        task_keys = [(task.name, task.binary) for task in self.required_scheduled_tasks]
        if len(task_keys) != len(set(task_keys)):
            raise ValueError(f"用例 {self.case_id} 包含重复计划任务")
        return self


class ReportExpectationSuite(_StrictModel):
    """Versioned collection of report semantic cases."""

    schema_version: Literal[1]
    cases: list[ReportSemanticExpectations] = Field(min_length=1)

    @model_validator(mode="after")
    def reject_duplicate_case_ids(self) -> ReportExpectationSuite:
        """Require stable unique case identifiers."""
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("语义用例 ID 不能重复")
        return self


class ReportSemanticSnapshot(_StrictModel):
    """Normalized view built from a generated scenario and ground truth."""

    iocs: IocExpectations = Field(default_factory=IocExpectations)
    commands: list[str] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)
    scheduled_tasks: list[ScheduledTaskExpectation] = Field(default_factory=list)
    behaviors: list[str] = Field(default_factory=list)
    process_images: list[str] = Field(default_factory=list)
    process_bindings: list[ProcessBehaviorBinding] = Field(default_factory=list)
    network_bindings: list[NetworkBehaviorBinding] = Field(default_factory=list)
    registry_queries: list[str] = Field(default_factory=list)
    registry_writes: list[str] = Field(default_factory=list)
    unprovenanced_exact_claims: list[str] = Field(default_factory=list)


def load_expectation_suite(path: Path) -> ReportExpectationSuite:
    """Load one strict UTF-8 expectation suite."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    return ReportExpectationSuite.model_validate(payload)


def build_matching_snapshot(expectations: ReportSemanticExpectations) -> ReportSemanticSnapshot:
    """Build the smallest snapshot satisfying all positive expectations."""
    process_images = [binding.process_image for binding in expectations.required_process_bindings]
    return ReportSemanticSnapshot(
        iocs=expectations.iocs.model_copy(deep=True),
        commands=list(expectations.required_commands),
        files=list(expectations.required_files),
        scheduled_tasks=[
            task.model_copy(deep=True) for task in expectations.required_scheduled_tasks
        ],
        behaviors=list(expectations.required_behaviors),
        process_images=process_images,
        process_bindings=[
            binding.model_copy(deep=True) for binding in expectations.required_process_bindings
        ],
        network_bindings=[
            binding.model_copy(deep=True) for binding in expectations.required_network_bindings
        ],
        registry_queries=list(expectations.required_registry_queries),
    )


def assert_report_semantics(
    snapshot: ReportSemanticSnapshot,
    expectations: ReportSemanticExpectations,
) -> None:
    """Assert required report facts and reject known fabrication patterns."""
    _assert_iocs(snapshot.iocs, expectations.iocs, exact=expectations.exact_iocs)
    _assert_subset("命令", expectations.required_commands, snapshot.commands)
    _assert_subset("文件", expectations.required_files, snapshot.files)
    _assert_subset("行为", expectations.required_behaviors, snapshot.behaviors)
    _assert_subset(
        "注册表查询",
        expectations.required_registry_queries,
        snapshot.registry_queries,
        normalize=_windows_value,
    )
    _assert_model_subset(
        "计划任务",
        expectations.required_scheduled_tasks,
        snapshot.scheduled_tasks,
    )
    _assert_model_subset(
        "进程行为绑定",
        expectations.required_process_bindings,
        snapshot.process_bindings,
    )
    _assert_model_subset(
        "网络行为绑定",
        expectations.required_network_bindings,
        snapshot.network_bindings,
    )

    forbidden = expectations.forbidden
    _assert_disjoint(
        "禁止进程",
        forbidden.process_images,
        snapshot.process_images,
        normalize=_process_image_value,
    )
    _assert_disjoint("禁止行为", forbidden.behaviors, snapshot.behaviors)
    _assert_model_disjoint(
        "禁止进程行为绑定",
        forbidden.process_bindings,
        snapshot.process_bindings,
    )
    _assert_model_disjoint(
        "禁止网络行为绑定",
        forbidden.network_bindings,
        snapshot.network_bindings,
    )
    _assert_disjoint(
        "禁止注册表写入",
        forbidden.registry_writes,
        snapshot.registry_writes,
        normalize=_windows_value,
    )
    if forbidden.reject_unprovenanced_exact_claims:
        assert not snapshot.unprovenanced_exact_claims, "存在未标记来源的精确主张: " + ", ".join(
            snapshot.unprovenanced_exact_claims
        )


def _assert_iocs(actual: IocExpectations, expected: IocExpectations, *, exact: bool) -> None:
    for field_name in ("hashes", "urls", "domains", "ips"):
        expected_values = getattr(expected, field_name)
        actual_values = getattr(actual, field_name)
        if exact:
            assert set(actual_values) == set(expected_values), (
                f"IOC {field_name} 不一致: 期望 {expected_values!r}, 实际 {actual_values!r}"
            )
        else:
            _assert_subset(f"IOC {field_name}", expected_values, actual_values)


def _assert_subset(
    label: str,
    expected: list[str],
    actual: list[str],
    *,
    normalize: Callable[[str], str] = str,
) -> None:
    actual_values = {normalize(value) for value in actual}
    missing = [value for value in expected if normalize(value) not in actual_values]
    assert not missing, f"缺少{label}: {missing!r}"


def _assert_disjoint(
    label: str,
    forbidden: list[str],
    actual: list[str],
    *,
    normalize: Callable[[str], str] = str,
) -> None:
    actual_values = {normalize(value) for value in actual}
    found = [value for value in forbidden if normalize(value) in actual_values]
    assert not found, f"发现{label}: {found!r}"


def _assert_model_subset(label: str, expected: list[BaseModel], actual: list[BaseModel]) -> None:
    actual_values = {_model_key(value) for value in actual}
    missing = [value.model_dump() for value in expected if _model_key(value) not in actual_values]
    assert not missing, f"缺少{label}: {missing!r}"


def _assert_model_disjoint(label: str, forbidden: list[BaseModel], actual: list[BaseModel]) -> None:
    actual_values = {_model_key(value) for value in actual}
    found = [value.model_dump() for value in forbidden if _model_key(value) in actual_values]
    assert not found, f"发现{label}: {found!r}"


def _model_key(value: BaseModel) -> str:
    if isinstance(value, ScheduledTaskExpectation):
        payload = {
            "name": value.name.casefold(),
            "binary": _windows_value(value.binary),
            "interval_minutes": value.interval_minutes,
            "mechanism": value.mechanism,
        }
    elif isinstance(value, ProcessBehaviorBinding):
        payload = {
            "process_image": _process_image_value(value.process_image),
            "behavior": value.behavior,
        }
    elif isinstance(value, NetworkBehaviorBinding):
        payload = {
            "behavior": value.behavior,
            "url": value.url,
            "target_file": (
                _windows_value(value.target_file) if value.target_file is not None else None
            ),
        }
    else:
        payload = value.model_dump(mode="json")
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _windows_value(value: str) -> str:
    return value.replace("/", "\\").casefold()


def _process_image_value(value: str) -> str:
    return _windows_value(value).rsplit("\\", maxsplit=1)[-1]
