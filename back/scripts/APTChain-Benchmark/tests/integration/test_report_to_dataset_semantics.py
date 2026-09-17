"""Offline semantic baselines for report-driven dataset generation."""

import json
import re
from pathlib import Path
from urllib.parse import urlunsplit

import pytest
import yaml
from pydantic import BaseModel

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario
from evidenceforge.report_ingest.extractors import extract_document
from evidenceforge.report_ingest.pipeline import (
    QUALITY_REPORT_FILENAME,
    REQUIRED_OUTPUTS,
    ReportPipeline,
    ReportQualityError,
)
from tests.support.report_semantics import (
    IocExpectations,
    NetworkBehaviorBinding,
    ProcessBehaviorBinding,
    ReportSemanticExpectations,
    ReportSemanticSnapshot,
    ScheduledTaskExpectation,
    assert_report_semantics,
    build_matching_snapshot,
    load_expectation_suite,
)


def _load_cases(fixtures_dir: Path) -> dict[str, ReportSemanticExpectations]:
    report_dir = fixtures_dir / "report_ingest"
    suites = [
        load_expectation_suite(report_dir / "apt_c48_expectations.json"),
        load_expectation_suite(report_dir / "synthetic_txt_expectations.json"),
    ]
    return {case.case_id: case for suite in suites for case in suite.cases}


class _FixtureMiniMaxClient:
    """按阶段返回脱敏 JSON 夹具，不执行任何网络请求。"""

    model = "MiniMax-offline-fixture"

    def __init__(self, bundle: dict[str, object]) -> None:
        self.bundle = bundle
        self.calls: list[str] = []

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
        del tool_name, tool_description, response_model, prompt_version
        assert repair is False
        key = "fact_extraction" if stage.startswith("fact_extraction_") else stage
        self.calls.append(stage)
        return json.dumps(self.bundle[key], ensure_ascii=False)


def _load_minimax_bundle(fixtures_dir: Path, case_id: str) -> dict[str, object]:
    path = fixtures_dir / "report_ingest" / "minimax" / f"{case_id}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_scenario(path: Path) -> None:
    Scenario.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def _generate_native_dataset(scenario_path: Path, output_dir: Path, force: bool) -> None:
    assert force is False
    scenario = Scenario.model_validate(yaml.safe_load(scenario_path.read_text(encoding="utf-8")))
    GenerationEngine(
        scenario,
        output_dir / "data",
        ground_truth_dir=output_dir,
        artifact_dir=output_dir / "artifacts",
        scenario_root=scenario_path.parent,
    ).generate()


def _pipeline(client: _FixtureMiniMaxClient, tmp_path: Path, *, generator=None) -> ReportPipeline:
    return ReportPipeline(
        client,
        scenario_validator=_validate_scenario,
        dataset_generator=generator or _generate_native_dataset,
        workspace_root=tmp_path / "workspace",
    )


def _event_fact_id(event: dict[str, object]) -> str | None:
    metadata = event.get("source_metadata")
    if not isinstance(metadata, dict):
        return None
    fact_ids = metadata.get("fact_ids")
    if not isinstance(fact_ids, list) or not fact_ids:
        return None
    return str(fact_ids[0])


def _connection_url(event: dict[str, object]) -> str | None:
    hostname = event.get("hostname")
    if not isinstance(hostname, str):
        return None
    service = str(event.get("service") or "").lower()
    port = int(event.get("dst_port") or (443 if service == "ssl" else 80))
    scheme = "https" if service in {"ssl", "https", "tls"} or port == 443 else "http"
    netloc = hostname if port in {80, 443} else f"{hostname}:{port}"
    return urlunsplit((scheme, netloc, str(event.get("uri") or "/"), "", ""))


def _snapshot_from_output(output_dir: Path) -> ReportSemanticSnapshot:
    """只从用户最终可见的 Scenario/GT 构造规范语义视图。"""
    scenario = yaml.safe_load((output_dir / "scenario.yaml").read_text(encoding="utf-8"))
    context = scenario["report_context"]
    facts = {item["fact_id"]: item for item in context["facts"]}
    events = [event for step in scenario.get("storyline", []) for event in step["events"]]
    events_by_fact: dict[str, list[dict[str, object]]] = {}
    for event in events:
        fact_id = _event_fact_id(event)
        if fact_id is not None:
            events_by_fact.setdefault(fact_id, []).append(event)

    ioc_values: dict[str, list[str]] = {key: [] for key in ("hash", "url", "domain", "ip")}
    for indicator in context["report_iocs"]:
        ioc_values[indicator["kind"]].append(indicator["normalized_value"])

    files: list[str] = []
    tasks: list[ScheduledTaskExpectation] = []
    process_images: list[str] = []
    process_bindings: list[ProcessBehaviorBinding] = []
    network_bindings: list[NetworkBehaviorBinding] = []
    registry_queries: list[str] = []
    registry_writes: list[str] = []
    commands: list[str] = []
    unprovenanced: list[str] = []

    for fact_id, fact_events in events_by_fact.items():
        behavior = facts[fact_id]["behavior"]
        target_files = [
            str(event["path"]) for event in fact_events if event["type"] == "file_create"
        ]
        for event in fact_events:
            event_type = event["type"]
            if event.get("source_metadata") is None:
                unprovenanced.append(f"{fact_id}:{event_type}")
            if event_type == "process":
                image = str(event["process_name"])
                process_images.append(image)
                process_bindings.append(
                    ProcessBehaviorBinding(process_image=image, behavior=behavior)
                )
                if event.get("command_line"):
                    commands.append(str(event["command_line"]))
            elif event_type in {"file_create", "file_delete"}:
                files.append(str(event["path"]))
            elif event_type == "connection":
                url = _connection_url(event)
                if url is not None:
                    network_bindings.append(
                        NetworkBehaviorBinding(
                            behavior=behavior,
                            url=url,
                            target_file=target_files[0] if len(target_files) == 1 else None,
                        )
                    )
            elif event_type == "scheduled_task_created":
                binary = str(event.get("task_content") or "")
                files.append(binary)
                if binary:
                    tasks.append(
                        ScheduledTaskExpectation(
                            name=str(event["task_name"]),
                            binary=binary,
                            interval_minutes=event.get("interval_minutes"),
                            mechanism=str(event.get("creation_method") or "unspecified"),
                        )
                    )
            elif event_type == "registry_query":
                registry_queries.append(str(event["key"]))
            elif event_type == "registry_set":
                registry_writes.append(str(event["key"]))

    return ReportSemanticSnapshot(
        iocs=IocExpectations(
            hashes=ioc_values["hash"],
            urls=ioc_values["url"],
            domains=ioc_values["domain"],
            ips=ioc_values["ip"],
        ),
        commands=list(dict.fromkeys(commands)),
        files=list(dict.fromkeys(path for path in files if path)),
        scheduled_tasks=tasks,
        behaviors=_semantic_behaviors(context["facts"], events),
        process_images=list(dict.fromkeys(process_images)),
        process_bindings=process_bindings,
        network_bindings=network_bindings,
        registry_queries=registry_queries,
        registry_writes=registry_writes,
        unprovenanced_exact_claims=unprovenanced,
    )


def _semantic_behaviors(
    facts: list[dict[str, object]],
    events: list[dict[str, object]],
) -> list[str]:
    """从最终事实和来源标记事件构造报告级语义标签。"""
    labels = [str(item["behavior"]) for item in facts]
    for fact in facts:
        behavior = str(fact["behavior"])
        description = str(fact.get("description") or "").casefold()
        if behavior == "spearphishing_attachment" and any(
            marker in description for marker in ("压缩包", "archive", "zip", "rar")
        ):
            labels.append("spearphishing_archive_attachment")
        if any(
            marker in description
            for marker in ("图标", "后缀", "伪装", "masquerad", "disguis")
        ) and any(
            marker in description for marker in ("可执行文件", "pe 文件", "executable")
        ):
            labels.append("masqueraded_executable")
        if behavior == "malware_execution":
            if any(marker in description for marker in ("诱导", "打开", "执行", "user")):
                labels.append("user_execution")
        if behavior in {"host_recon", "anti_debug_anti_vm"} and any(
            marker in description for marker in ("进程列表", "遍历进程", "process list")
        ):
            labels.append("process_enumeration")
        if behavior == "anti_debug_anti_vm" and any(
            marker in description for marker in ("bios", "systembiosversion", "注册表")
        ):
            labels.append("bios_registry_query")
        if any(
            event.get("type") == "registry_query"
            and str(event.get("key") or "").casefold().endswith("systembiosversion")
            and _event_fact_id(event) == str(fact["fact_id"])
            for event in events
        ):
            labels.append("bios_registry_query")
        if behavior == "self_deletion":
            if _is_conditional_self_delete_description(description):
                labels.append("conditional_self_delete")
            else:
                labels.append("cleanup_self_delete")
        if behavior == "c2_system_info_exfil":
            labels.append("host_inventory_exfiltration")
        if behavior in {"payload_download", "payload_download_execute"}:
            labels.append("attack_component_download")
        if behavior == "persistence_scheduled_task":
            fact_id = str(fact["fact_id"])
            uses_com = "com" in description or any(
                event.get("creation_method") == "com"
                and _event_fact_id(event) == fact_id
                for event in events
            )
            if uses_com:
                labels.append("com_scheduled_task_creation")
    return list(dict.fromkeys(labels))


def _is_conditional_self_delete_description(description: str) -> bool:
    """识别中英文条件触发自删除，不把普通收尾清理误判为条件行为。"""
    if any(marker in description for marker in ("如果", "若", "一旦", "if ", "when ")):
        return True
    return bool(
        re.search(
            r"(?:检测到|发现|处于|存在).{0,80}(?:时|后).{0,40}(?:触发|自毁|删除)",
            description,
        )
    )


def test_semantic_behavior_recognizes_triggered_chinese_self_delete() -> None:
    facts = [
        {
            "fact_id": "fact-conditional-delete",
            "behavior": "self_deletion",
            "description": "样本在检测到调试环境或虚拟机时触发自毁机制并删除自身",
        },
        {
            "fact_id": "fact-cleanup-delete",
            "behavior": "self_deletion",
            "description": "样本工作完成后删除自身以清理痕迹",
        },
    ]

    labels = _semantic_behaviors(facts, [])

    assert "conditional_self_delete" in labels
    assert "cleanup_self_delete" in labels


def test_semantic_behavior_recognizes_masquerade_and_anti_analysis_enumeration() -> None:
    facts = [
        {
            "fact_id": "fact-masquerade",
            "behavior": "other",
            "description": "恶意可执行文件通过修改图标和隐藏后缀进行伪装",
        },
        {
            "fact_id": "fact-process-enumeration",
            "behavior": "anti_debug_anti_vm",
            "description": "样本遍历进程列表比对调试器进程名",
        },
    ]

    events = [
        {
            "type": "registry_query",
            "key": r"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\SystemBiosVersion",
            "source_metadata": {"fact_ids": ["fact-process-enumeration"]},
        }
    ]

    labels = _semantic_behaviors(facts, events)

    assert "masqueraded_executable" in labels
    assert "process_enumeration" in labels
    assert "bios_registry_query" in labels


def test_report_semantic_expectation_fixtures_are_strict_and_complete(
    fixtures_dir: Path,
) -> None:
    cases = _load_cases(fixtures_dir)

    assert set(cases) == {
        "apt-c48-2024-11-26",
        "minimal-no-ioc",
        "network-only",
        "multi-artifact",
    }
    assert len(cases["apt-c48-2024-11-26"].iocs.hashes) == 3
    assert len(cases["apt-c48-2024-11-26"].iocs.urls) == 4
    assert len(cases["apt-c48-2024-11-26"].required_scheduled_tasks) == 2
    assert len(cases["multi-artifact"].required_network_bindings) == 2


def test_synthetic_text_cases_are_self_contained(fixtures_dir: Path) -> None:
    cases = _load_cases(fixtures_dir)
    report_dir = fixtures_dir / "report_ingest"

    for case in cases.values():
        if case.source.kind != "txt":
            continue
        source_path = report_dir / str(case.source.fixture)
        text = source_path.read_text(encoding="utf-8")
        extracted = extract_document(source_path)
        assert source_path.is_file()
        assert text.strip()
        assert len(text) < 1000
        assert extracted.source_type == "txt"
        assert extracted.text == text.strip()


@pytest.mark.parametrize(
    "case_id",
    ["apt-c48-2024-11-26", "minimal-no-ioc", "network-only", "multi-artifact"],
)
def test_matching_semantic_snapshots_pass(fixtures_dir: Path, case_id: str) -> None:
    expectations = _load_cases(fixtures_dir)[case_id]
    snapshot = build_matching_snapshot(expectations)

    assert_report_semantics(snapshot, expectations)


def test_baseline_rejects_invented_powershell(fixtures_dir: Path) -> None:
    expectations = _load_cases(fixtures_dir)["apt-c48-2024-11-26"]
    snapshot = build_matching_snapshot(expectations).model_copy(
        update={
            "process_images": ["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"]
        }
    )

    with pytest.raises(AssertionError, match="禁止进程"):
        assert_report_semantics(snapshot, expectations)


def test_baseline_rejects_cmd_owning_later_attack_behavior(fixtures_dir: Path) -> None:
    expectations = _load_cases(fixtures_dir)["apt-c48-2024-11-26"]
    snapshot = build_matching_snapshot(expectations)
    invalid_binding = ProcessBehaviorBinding(
        process_image="C:\\Windows\\System32\\cmd.exe",
        behavior="attack_component_download",
    )
    snapshot = snapshot.model_copy(
        update={"process_bindings": [*snapshot.process_bindings, invalid_binding]}
    )

    with pytest.raises(AssertionError, match="禁止进程行为绑定"):
        assert_report_semantics(snapshot, expectations)


def test_baseline_rejects_decoy_uri_inherited_by_checkin(fixtures_dir: Path) -> None:
    expectations = _load_cases(fixtures_dir)["apt-c48-2024-11-26"]
    snapshot = build_matching_snapshot(expectations)
    invalid_binding = expectations.forbidden.network_bindings[0]
    snapshot = snapshot.model_copy(
        update={"network_bindings": [*snapshot.network_bindings, invalid_binding]}
    )

    with pytest.raises(AssertionError, match="禁止网络行为绑定"):
        assert_report_semantics(snapshot, expectations)


def test_baseline_rejects_registry_query_rendered_as_write(fixtures_dir: Path) -> None:
    expectations = _load_cases(fixtures_dir)["apt-c48-2024-11-26"]
    snapshot = build_matching_snapshot(expectations).model_copy(
        update={"registry_writes": expectations.required_registry_queries}
    )

    with pytest.raises(AssertionError, match="禁止注册表写入"):
        assert_report_semantics(snapshot, expectations)


def test_minimal_report_rejects_invented_ioc(fixtures_dir: Path) -> None:
    expectations = _load_cases(fixtures_dir)["minimal-no-ioc"]
    snapshot = build_matching_snapshot(expectations)
    snapshot.iocs.domains.append("invented.example")

    with pytest.raises(AssertionError, match="IOC domains 不一致"):
        assert_report_semantics(snapshot, expectations)


@pytest.mark.parametrize("case_id", ["minimal-no-ioc", "network-only", "multi-artifact"])
def test_offline_minimax_pipeline_generates_semantically_faithful_dataset(
    fixtures_dir: Path,
    tmp_path: Path,
    case_id: str,
) -> None:
    """A/B/C 假响应必须完整走到原生日志和生成后质量门。"""
    expectations = _load_cases(fixtures_dir)[case_id]
    source = fixtures_dir / "report_ingest" / str(expectations.source.fixture)
    client = _FixtureMiniMaxClient(_load_minimax_bundle(fixtures_dir, case_id))
    output = tmp_path / case_id

    result = _pipeline(client, tmp_path).run(source, output)
    snapshot = _snapshot_from_output(output)

    assert client.calls == ["fact_extraction_1", "fact_audit"]
    assert result.model_calls == 2
    assert result.materializable_coverage == 1.0
    assert result.quality_score == 100.0
    assert all((output / name).exists() for name in REQUIRED_OUTPUTS)
    assert (output / QUALITY_REPORT_FILENAME).is_file()
    assert any(path.stat().st_size > 0 for path in (output / "data").rglob("*"))
    assert_report_semantics(snapshot, expectations)
    if case_id == "multi-artifact":
        ground_truth = json.loads((output / "GROUND_TRUTH.json").read_text(encoding="utf-8"))
        task_attributes = [
            event["attributes"]
            for event in ground_truth["events"]
            if event["kind"] == "scheduled_task_created"
        ]
        assert {item["interval_minutes"] for item in task_attributes} == {20, 30}
        assert {item["task_name"] for item in task_attributes} == {
            "UpdaterTelemetry",
            "UserCacheRefresh",
        }
        assert any("<Interval>PT20M</Interval>" in item["task_content"] for item in task_attributes)
        assert any("<Interval>PT30M</Interval>" in item["task_content"] for item in task_attributes)


def test_offline_pipeline_semantics_are_stable_for_same_input(
    fixtures_dir: Path,
    tmp_path: Path,
) -> None:
    """同一输入和固定场景配置不得改变事实、绑定或最终 Scenario。"""
    case_id = "multi-artifact"
    source = fixtures_dir / "report_ingest" / "multi_artifact.txt"
    bundle = _load_minimax_bundle(fixtures_dir, case_id)
    first = tmp_path / "first"
    second = tmp_path / "second"

    _pipeline(_FixtureMiniMaxClient(bundle), tmp_path).run(source, first)
    _pipeline(_FixtureMiniMaxClient(bundle), tmp_path).run(source, second)

    assert _snapshot_from_output(first) == _snapshot_from_output(second)
    assert (first / "scenario.yaml").read_text(encoding="utf-8") == (
        second / "scenario.yaml"
    ).read_text(encoding="utf-8")


def test_offline_pipeline_quality_failure_leaves_no_partial_output(
    fixtures_dir: Path,
    tmp_path: Path,
) -> None:
    """原生生成完成后若来源链被破坏，临时产物也不能发布。"""
    case_id = "network-only"
    source = fixtures_dir / "report_ingest" / "network_only.txt"
    output = tmp_path / "must-not-publish"

    def tampering_generator(scenario_path: Path, output_dir: Path, force: bool) -> None:
        _generate_native_dataset(scenario_path, output_dir, force)
        ground_truth_path = output_dir / "GROUND_TRUTH.json"
        ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
        ground_truth["report_context"]["report_iocs"] = []
        ground_truth_path.write_text(
            json.dumps(ground_truth, ensure_ascii=False),
            encoding="utf-8",
        )

    client = _FixtureMiniMaxClient(_load_minimax_bundle(fixtures_dir, case_id))
    with pytest.raises(ReportQualityError, match="post_generation"):
        _pipeline(client, tmp_path, generator=tampering_generator).run(source, output)

    assert not output.exists()
    assert not list(tmp_path.glob(".must-not-publish.eforge-*"))
