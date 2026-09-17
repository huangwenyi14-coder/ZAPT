# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Deterministic compilation from report facts to EvidenceForge event intents."""

import hashlib
import logging
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.models.scenario import Scenario
from evidenceforge.report_ingest.models import (
    CompilationStatus,
    CompiledEventType,
    CompiledField,
    CompiledScenarioEvent,
    CompletionRequest,
    EntityType,
    ExpectedVisibility,
    FieldOrigin,
    FieldProvenance,
    ReportEntity,
    ReportFact,
    ReportFactLedger,
    ReportRelation,
    ReportScenarioCompilation,
    SimulationCompletion,
    SimulationPlan,
    SourceCategory,
    SourceSpan,
    validate_simulation_plan,
)

LOG = logging.getLogger(__name__)

_OWNER_PREDICATES = {
    "executed_by",
    "performed_by",
    "runs_in",
    "source_process",
    "uses_process",
}
_COMMAND_PREDICATES = {"executes", "runs", "uses_command"}
_DOMAIN_IP_PREDICATES = {"maps_to", "points_to", "resolves_to"}

_PROCESS_BEHAVIORS = {
    "anti_debug_anti_vm",
    "browser_history_theft",
    "clipboard_theft",
    "credential_theft_chrome",
    "credential_theft_firefox",
    "decoy_document_open",
    "document_filename_collection",
    "host_recon",
    "malware_execution",
    "payload_download_execute",
    "remote_command_execution",
    "screen_capture",
}
_PROCESS_COMPLETION_BEHAVIORS = _PROCESS_BEHAVIORS - {"anti_debug_anti_vm"}
_NETWORK_BEHAVIORS = {
    "c2_beacon_https",
    "c2_checkin",
    "c2_command_fetch",
    "c2_system_info_exfil",
    "data_exfiltration",
    "network_connectivity_check",
    "payload_download",
}
_DOWNLOAD_BEHAVIORS = {"decoy_document_download", "payload_download"}
_EXFILTRATION_BEHAVIORS = {"c2_system_info_exfil", "data_exfiltration"}
_TASK_BEHAVIORS = {"persistence_scheduled_task"}
_SERVICE_BEHAVIORS = {"service_installation"}
_REGISTRY_QUERY_BEHAVIORS = {"bios_registry_query", "registry_query", "registry_read"}
_REGISTRY_SET_BEHAVIORS = {"registry_run_persistence", "registry_set", "registry_write"}
_FILE_CREATE_BEHAVIORS = {"file_create"}
_DELETE_BEHAVIORS = {"self_deletion"}
_DNS_BEHAVIORS = {"c2_dns_resolution"}
_EMAIL_BEHAVIORS = {"spearphishing_attachment"}
_ANTI_ANALYSIS_TARGET_PREDICATES = {"checks", "detects", "inspects", "targets"}
_SIMULATION_RECIPIENT = "report.user@report-lab.local"

_PROCESS_IMAGE_BY_TOKEN = {
    "cmd": r"C:\Windows\System32\cmd.exe",
    "cmd.exe": r"C:\Windows\System32\cmd.exe",
    "powershell": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "powershell.exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "pwsh": r"C:\Program Files\PowerShell\7\pwsh.exe",
    "pwsh.exe": r"C:\Program Files\PowerShell\7\pwsh.exe",
    "reg": r"C:\Windows\System32\reg.exe",
    "reg.exe": r"C:\Windows\System32\reg.exe",
    "rundll32": r"C:\Windows\System32\rundll32.exe",
    "rundll32.exe": r"C:\Windows\System32\rundll32.exe",
    "schtasks": r"C:\Windows\System32\schtasks.exe",
    "schtasks.exe": r"C:\Windows\System32\schtasks.exe",
}


class ReportCompilerError(EvidenceForgeError):
    """The accepted report facts cannot be compiled without violating provenance."""


@dataclass(frozen=True)
class _BoundEntity:
    """One entity directly connected to a fact."""

    entity: ReportEntity
    predicate: str
    relation: ReportRelation


@dataclass(frozen=True)
class _OwnerResolution:
    """A direct, derived, completed, pending, or unresolved process owner."""

    entity: ReportEntity | None
    request: CompletionRequest | None = None
    unresolved: bool = False


def compile_report_ledger(
    ledger: ReportFactLedger,
    simulation_plan: SimulationPlan | None = None,
) -> ReportScenarioCompilation:
    """Compile accepted report facts without cross-fact process or network fallbacks."""
    compiler = _ReportCompiler(ledger, simulation_plan)
    return compiler.compile()


def resolve_engine_completion_requests(
    requests: list[CompletionRequest],
    ledger: ReportFactLedger,
) -> tuple[SimulationPlan, list[CompletionRequest]]:
    """Resolve mechanical process placeholders locally and return remaining AI work."""
    facts = {fact.fact_id: fact for fact in ledger.facts}
    completions: list[SimulationCompletion] = []
    remaining: list[CompletionRequest] = []
    for request in requests:
        if (
            request.field_path != "process.image"
            or FieldOrigin.ENGINE_GENERATED not in request.allowed_origins
            or request.target_id not in facts
        ):
            remaining.append(request)
            continue
        fact = facts[request.target_id]
        behavior = _safe_token(fact.behavior)[:40] or "behavior"
        digest = hashlib.sha256(f"{fact.fact_id}|{fact.behavior}".encode()).hexdigest()[:10]
        completions.append(
            SimulationCompletion(
                request_id=request.request_id,
                target_id=request.target_id,
                field_path=request.field_path,
                value=rf"C:\ProgramData\EvidenceForge\ReportSim\{behavior}-{digest}.exe",
                origin=FieldOrigin.ENGINE_GENERATED,
                reason="为物化来源行为生成稳定的内部仿真进程，不代表原文进程名",
                compatible=True,
                compatibility_explanation="只建立事件所有权，不新增命令、攻击行为或外部 IOC",
            )
        )
    return SimulationPlan(completions=completions), remaining


def build_report_scenario(
    ledger: ReportFactLedger,
    compilation: ReportScenarioCompilation,
    *,
    source_name: str,
) -> Scenario:
    """把确定性编译结果适配为原项目可直接生成的 Scenario。"""
    pending = [
        event.event_id
        for event in compilation.events
        if event.status == CompilationStatus.NEEDS_COMPLETION
    ]
    if pending:
        raise ReportCompilerError("存在未解决的补全事件：" + ", ".join(pending))

    span_by_id = {span.span_id: span for span in ledger.source_spans}
    fact_by_id = {fact.fact_id: fact for fact in ledger.facts}
    storyline: list[dict[str, object]] = []
    for index, event in enumerate(
        item for item in compilation.events if item.status == CompilationStatus.MATERIALIZED
    ):
        if event.event_type is None:
            raise ReportCompilerError(f"已物化事件 {event.event_id} 缺少类型")
        event_fields = {
            name: field.value
            for name, field in event.fields.items()
            if name in _SCENARIO_FIELDS_BY_EVENT[event.event_type]
        }
        missing_fields = _REQUIRED_SCENARIO_FIELDS[event.event_type] - event_fields.keys()
        if missing_fields:
            raise ReportCompilerError(
                f"事件 {event.event_id} 缺少 Scenario 必填字段：{sorted(missing_fields)}"
            )
        source_span_ids = list(
            dict.fromkeys(
                [
                    *fact_by_id[event.fact_id].provenance.source_span_ids,
                    *(
                        span_id
                        for field in event.fields.values()
                        for span_id in field.provenance.source_span_ids
                    ),
                ]
            )
        )
        field_sources = {
            name: _storyline_field_source(event.fact_id, field.provenance, fact_by_id)
            for name, field in event.fields.items()
        }
        field_sources.update(
            {
                "actor": _engine_storyline_field_source(
                    event.fact_id, "报告未定义可直接使用的本地账号"
                ),
                "system": _engine_storyline_field_source(
                    event.fact_id, "报告未定义可直接使用的实验终端"
                ),
                "time": _engine_storyline_field_source(
                    event.fact_id, "按来源事实顺序生成确定性仿真时间"
                ),
            }
        )
        event_spec = {
            "type": event.event_type.value,
            **event_fields,
            "description": event.activity,
            "source_metadata": {
                "category": event.source_category.value,
                "fact_ids": [event.fact_id],
                "source_locations": _source_locations(span_by_id, source_span_ids),
                "field_sources": field_sources,
                "expected_visibility": [item.value for item in event.expected_visibility],
                "degradation_reason": event.degradation_reason,
                "necessity_reason": event.necessity_reason,
            },
        }
        storyline.append(
            {
                "id": event.event_id,
                "time": f"+{60 + index}m",
                "actor": "report_user",
                "system": "REPORT-WS-01",
                "activity": event.activity,
                "events": [event_spec],
            }
        )

    report_facts: list[dict[str, object]] = []
    for fact in sorted(ledger.facts, key=lambda item: (item.order, item.fact_id)):
        fact_events = [event for event in compilation.events if event.fact_id == fact.fact_id]
        materialized_ids = [
            event.event_id
            for event in fact_events
            if event.status == CompilationStatus.MATERIALIZED
        ]
        degradation_reasons = list(
            dict.fromkeys(
                event.degradation_reason for event in fact_events if event.degradation_reason
            )
        )
        status = "materialized" if materialized_ids else "ground_truth_only"
        report_facts.append(
            {
                "fact_id": fact.fact_id,
                "behavior": fact.behavior,
                "description": fact.description,
                "status": status,
                "event_ids": materialized_ids,
                "source_locations": _source_locations(span_by_id, fact.provenance.source_span_ids),
                "degradation_reason": (
                    None
                    if status == "materialized"
                    else "; ".join(degradation_reasons) or "编译器无可执行事件映射"
                ),
            }
        )

    report_iocs = [
        {
            "indicator_id": indicator.indicator_id,
            "kind": indicator.kind.value,
            "value": indicator.value,
            "normalized_value": indicator.normalized_value,
            "source_locations": _source_locations(span_by_id, indicator.provenance.source_span_ids),
        }
        for indicator in ledger.report_iocs
    ]
    scenario_token = hashlib.sha256(
        f"{source_name}|{ledger.source_metadata.report_name}".encode()
    ).hexdigest()[:12]
    return Scenario.model_validate(
        {
            "version": "1.0",
            "name": f"report_{scenario_token}",
            "description": f"根据威胁报告《{ledger.source_metadata.report_name}》生成的可追溯终端与网络数据集。",
            "environment": {
                "description": "报告驱动的隔离实验环境",
                "domain": "report-lab.local",
                "users": [
                    {
                        "username": "report_user",
                        "full_name": "Report Lab User",
                        "email": "report.user@report-lab.local",
                        "primary_system": "REPORT-WS-01",
                    }
                ],
                "systems": [
                    {
                        "hostname": "REPORT-WS-01",
                        "ip": "10.77.0.10",
                        "os": "Windows 11",
                        "type": "workstation",
                        "assigned_user": "report_user",
                    },
                    {
                        "hostname": "REPORT-MAIL-01",
                        "ip": "10.77.0.20",
                        "os": "Linux Ubuntu 22.04",
                        "type": "server",
                        "services": ["postfix"],
                        "roles": ["mail_server"],
                    },
                ],
                "network": {
                    "segments": [
                        {
                            "name": "report_lab",
                            "cidr": "10.77.0.0/24",
                            "description": "报告仿真终端与支撑服务",
                            "systems": ["REPORT-WS-01", "REPORT-MAIL-01"],
                            "exposure": "internal",
                        }
                    ],
                    "sensors": [
                        {
                            "type": "network",
                            "name": "report-lab-zeek",
                            "monitoring_segments": ["report_lab"],
                            "direction": "bidirectional",
                            "placement": "span",
                            "log_formats": ["zeek"],
                        }
                    ],
                },
                "email": {
                    "accepted_domains": ["report-lab.local"],
                    "mail_servers": [
                        {
                            "name": "mail-1",
                            "hostname": "mail.report-lab.local",
                            "system": "REPORT-MAIL-01",
                            "platform": "generic_smtp",
                        }
                    ],
                    "default_mailbox_servers": ["mail-1"],
                    "outbound_routes": [{"name": "default", "servers": ["mail-1"]}],
                    "inbound_route": ["mail-1"],
                    "artifacts": {"mode": "storyline"},
                    "background_messages_per_user_per_day": 0,
                },
            },
            "personas": [],
            "time_window": {
                "start": "2024-01-15T08:00:00Z",
                "duration": "8h",
                "warmup": "1h",
            },
            "baseline_activity": {
                "description": "低强度背景活动，突出报告来源行为",
                "intensity": "low",
                "variation": "low",
                "suspicious_noise": "low",
            },
            "observation_profile": "complete",
            "report_context": {
                "source_name": source_name,
                "report_name": ledger.source_metadata.report_name,
                "report_iocs": report_iocs,
                "facts": report_facts,
            },
            "storyline": storyline,
            "red_herrings": [],
            "output": {
                "logs": [
                    {"format": "windows"},
                    {"format": "zeek"},
                    {"format": "ecar"},
                    {"format": "syslog"},
                ],
                "destination": "./data",
                "compression": False,
            },
        }
    )


_SCENARIO_FIELDS_BY_EVENT: dict[CompiledEventType, frozenset[str]] = {
    CompiledEventType.PROCESS: frozenset(
        {"process_name", "command_line", "process_ref", "persistent"}
    ),
    CompiledEventType.CONNECTION: frozenset(
        {
            "dst_ip",
            "dst_port",
            "hostname",
            "service",
            "source_ip",
            "source_process_ref",
            "source_file",
            "method",
            "uri",
            "status_code",
            "orig_bytes",
            "resp_bytes",
        }
    ),
    CompiledEventType.DNS_QUERY: frozenset(
        {"query", "qtype", "rcode", "ttl", "answer", "source_ip"}
    ),
    CompiledEventType.FILE_CREATE: frozenset({"process_ref", "path", "size_bytes"}),
    CompiledEventType.FILE_DELETE: frozenset({"process_ref", "path"}),
    CompiledEventType.FILE_COLLECTION: frozenset({"process_ref", "files", "file_sizes"}),
    CompiledEventType.SCHEDULED_TASK_CREATED: frozenset(
        {
            "task_name",
            "task_content",
            "source_process_ref",
            "interval_minutes",
            "creation_method",
        }
    ),
    CompiledEventType.SERVICE_INSTALLED: frozenset(
        {"service_name", "service_file_name", "service_account"}
    ),
    CompiledEventType.REGISTRY_QUERY: frozenset({"process_ref", "key", "value_name"}),
    CompiledEventType.REGISTRY_SET: frozenset({"process_ref", "key", "value_name", "value_data"}),
    CompiledEventType.EMAIL_MESSAGE: frozenset(
        {"sender", "to", "cc", "bcc", "subject", "body", "verdict", "mail_action"}
    ),
    CompiledEventType.PROCESS_ACCESS: frozenset({"target_process", "access_mask"}),
    CompiledEventType.IMAGE_LOAD: frozenset(
        {"process_ref", "image_loaded", "signed", "signature", "signature_status"}
    ),
}

_REQUIRED_SCENARIO_FIELDS: dict[CompiledEventType, frozenset[str]] = {
    CompiledEventType.PROCESS: frozenset({"process_name"}),
    CompiledEventType.CONNECTION: frozenset({"dst_ip"}),
    CompiledEventType.DNS_QUERY: frozenset({"query", "answer"}),
    CompiledEventType.FILE_CREATE: frozenset({"process_ref", "path"}),
    CompiledEventType.FILE_DELETE: frozenset({"process_ref", "path"}),
    CompiledEventType.FILE_COLLECTION: frozenset({"process_ref", "files"}),
    CompiledEventType.SCHEDULED_TASK_CREATED: frozenset({"task_name"}),
    CompiledEventType.SERVICE_INSTALLED: frozenset({"service_name", "service_file_name"}),
    CompiledEventType.REGISTRY_QUERY: frozenset({"process_ref", "key"}),
    CompiledEventType.REGISTRY_SET: frozenset({"process_ref", "key", "value_name", "value_data"}),
    CompiledEventType.EMAIL_MESSAGE: frozenset({"to"}),
    CompiledEventType.PROCESS_ACCESS: frozenset({"target_process"}),
    CompiledEventType.IMAGE_LOAD: frozenset({"process_ref", "image_loaded"}),
}


def _source_locations(
    span_by_id: dict[str, SourceSpan],
    source_span_ids: list[str],
) -> list[dict[str, object]]:
    locations: list[dict[str, object]] = []
    for span_id in dict.fromkeys(source_span_ids):
        span = span_by_id.get(span_id)
        if span is None:
            raise ReportCompilerError(f"Scenario 适配器引用了未知片段 {span_id}")
        locations.append(
            {
                "span_id": span.span_id,
                "page_number": span.page_number,
                "paragraph_number": span.paragraph_number,
            }
        )
    return locations


def _storyline_field_source(
    fact_id: str,
    provenance: FieldProvenance,
    fact_by_id: dict[str, ReportFact],
) -> dict[str, object]:
    source_fact_ids = [
        fact_id,
        *(source_id for source_id in provenance.source_ids if source_id in fact_by_id),
    ]
    return {
        "origin": provenance.origin.value,
        "source_fact_ids": list(dict.fromkeys(source_fact_ids)),
        "source_span_ids": provenance.source_span_ids,
        "reason": provenance.reason,
    }


def _engine_storyline_field_source(fact_id: str, reason: str) -> dict[str, object]:
    return {
        "origin": FieldOrigin.ENGINE_GENERATED.value,
        "source_fact_ids": [fact_id],
        "source_span_ids": [],
        "reason": reason,
    }


class _ReportCompiler:
    """Stateful single-pass compiler with stable, fact-scoped identities."""

    def __init__(
        self,
        ledger: ReportFactLedger,
        simulation_plan: SimulationPlan | None,
    ) -> None:
        self.ledger = ledger
        self.simulation_plan = simulation_plan
        self.entities = {entity.entity_id: entity for entity in ledger.entities}
        self.facts = {fact.fact_id: fact for fact in ledger.facts}
        self.bound_entities = self._index_fact_bindings()
        self.entity_relations = self._index_entity_relations()
        self.events: list[CompiledScenarioEvent] = []
        self.generated_entities: dict[str, ReportEntity] = {}
        self.completion_requests: dict[str, CompletionRequest] = {}
        self.established_processes: set[str] = set()
        self.completions = {
            completion.request_id: completion
            for completion in (simulation_plan.completions if simulation_plan else [])
        }
        self.unresolved_request_ids = set(
            simulation_plan.unresolved_request_ids if simulation_plan else []
        )

    def compile(self) -> ReportScenarioCompilation:
        """Compile facts in source order and validate the optional completion plan."""
        for fact in sorted(self.ledger.facts, key=lambda item: (item.order, item.fact_id)):
            self._compile_fact(fact)

        requests = list(self.completion_requests.values())
        if self.simulation_plan is not None:
            errors = validate_simulation_plan(self.simulation_plan, requests, self.ledger)
            if errors:
                raise ReportCompilerError("受控补全计划未通过编译器校验：" + "; ".join(errors))

        compilation = ReportScenarioCompilation(
            events=self.events,
            generated_entities=list(self.generated_entities.values()),
            completion_requests=requests,
        )
        self._validate_entity_references(compilation)
        return compilation

    def _compile_fact(self, fact: ReportFact) -> None:
        behavior = fact.behavior
        if behavior == "anti_debug_anti_vm":
            self._compile_anti_analysis(fact)
        elif behavior in _PROCESS_BEHAVIORS:
            self._compile_process(fact)
        elif behavior in _NETWORK_BEHAVIORS or behavior in _DOWNLOAD_BEHAVIORS:
            self._compile_network(fact)
        elif behavior in _TASK_BEHAVIORS:
            self._compile_scheduled_tasks(fact)
        elif behavior in _SERVICE_BEHAVIORS:
            self._compile_services(fact)
        elif behavior in _REGISTRY_QUERY_BEHAVIORS:
            self._compile_registry(fact, CompiledEventType.REGISTRY_QUERY)
        elif behavior in _REGISTRY_SET_BEHAVIORS:
            self._compile_registry(fact, CompiledEventType.REGISTRY_SET)
        elif behavior in _FILE_CREATE_BEHAVIORS:
            self._compile_file_creation(fact)
        elif behavior in _DELETE_BEHAVIORS:
            self._compile_file_deletion(fact)
        elif behavior in _DNS_BEHAVIORS:
            self._compile_dns(fact)
        elif behavior in _EMAIL_BEHAVIORS:
            self._compile_email(fact)
        else:
            self._ground_truth_only(fact, f"编译器尚无 {behavior} 的无损事件映射")

    def _compile_process(self, fact: ReportFact) -> None:
        command = self._single_bound_entity(fact, EntityType.COMMAND, _COMMAND_PREDICATES)
        owner = self._resolve_owner(
            fact,
            allow_completion=fact.behavior in _PROCESS_COMPLETION_BEHAVIORS,
        )
        if owner.entity is None:
            if owner.request is not None and not owner.unresolved:
                fields: dict[str, CompiledField] = {}
                if command is not None:
                    fields["command_line"] = self._source_field(command)
                self._pending_event(
                    fact,
                    CompiledEventType.PROCESS,
                    owner.request,
                    fields=fields,
                    visibility=[ExpectedVisibility.ENDPOINT_PROCESS],
                )
                return
            reason = (
                "受控补全拒绝或未解决进程主体"
                if owner.unresolved
                else "报告只描述行为概念，没有进程或精确命令可供主机事件物化"
            )
            self._ground_truth_only(fact, reason)
            return

        process = owner.entity
        fields = self._process_fields(process)
        fields["persistent"] = self._engine_field(
            True,
            [process.entity_id],
            "保持报告进程存活，便于后续来源事实继续引用稳定 process_ref",
        )
        if command is not None:
            fields["command_line"] = self._source_field(command)
        event = self._new_event(
            fact=fact,
            event_type=CompiledEventType.PROCESS,
            fields=fields,
            source_category=self._source_category(process, fields),
            status=CompilationStatus.MATERIALIZED,
            visibility=[ExpectedVisibility.ENDPOINT_PROCESS],
            subject_entity_id=process.entity_id,
            object_entity_ids=[command.entity_id] if command else [],
            completion_request_ids=[owner.request.request_id] if owner.request else [],
        )
        self.events.append(event)
        self.established_processes.add(process.entity_id)

    def _compile_network(self, fact: ReportFact) -> None:
        channels = self._network_channels(fact)
        owner = self._resolve_owner(fact, allow_completion=True)
        if owner.entity is None:
            if owner.request is not None and not owner.unresolved:
                pending_channels: list[ReportEntity | None] = channels or [None]
                for channel in pending_channels:
                    self._pending_event(
                        fact,
                        CompiledEventType.CONNECTION,
                        owner.request,
                        fields=(
                            self._network_fields(fact, channel, channels)
                            if channel is not None
                            else self._synthetic_network_fields(fact)
                        ),
                        visibility=[ExpectedVisibility.NETWORK_FLOW],
                        channel_entity_ids=[channel.entity_id] if channel is not None else [],
                    )
                return
            self._ground_truth_only(fact, "网络行为缺少独立主体，且受控补全未提供进程")
            return

        process = owner.entity
        self._ensure_process_prerequisite(fact, process, owner.request)
        files = self._bound_entities_of_type(fact, EntityType.FILE)
        event_files = (
            files
            if fact.behavior in _DOWNLOAD_BEHAVIORS or fact.behavior == "data_exfiltration"
            else []
        )
        event_channels: list[ReportEntity | None] = channels or [None]
        for channel in event_channels:
            fields = (
                self._network_fields(fact, channel, channels)
                if channel is not None
                else self._synthetic_network_fields(fact)
            )
            fields["source_process_ref"] = self._process_ref_field(process)
            if fact.behavior == "data_exfiltration" and len(event_files) == 1:
                fields["source_file"] = self._source_field(event_files[0])
            event = self._new_event(
                fact=fact,
                event_type=CompiledEventType.CONNECTION,
                fields=fields,
                source_category=self._source_category(process, fields),
                status=CompilationStatus.MATERIALIZED,
                visibility=[ExpectedVisibility.NETWORK_FLOW],
                subject_entity_id=process.entity_id,
                object_entity_ids=[item.entity_id for item in event_files],
                channel_entity_ids=[channel.entity_id] if channel is not None else [],
                completion_request_ids=[owner.request.request_id] if owner.request else [],
            )
            self.events.append(event)
        if fact.behavior in _DOWNLOAD_BEHAVIORS:
            self._append_file_create_events(fact, process, files, owner.request)

    def _compile_anti_analysis(self, fact: ReportFact) -> None:
        """Materialize exact anti-analysis targets without inventing a command."""
        targets = [
            item.entity
            for item in self.bound_entities.get(fact.fact_id, [])
            if item.entity.entity_type == EntityType.PROCESS
            and item.predicate in _ANTI_ANALYSIS_TARGET_PREDICATES
        ]
        registry_keys = self._bound_entities_of_type(fact, EntityType.REGISTRY)
        if not targets and not registry_keys:
            self._ground_truth_only(fact, "反分析行为没有可证的目标进程或注册表键")
            return

        owner = self._resolve_owner(fact, allow_completion=True)
        if owner.entity is None:
            if owner.request is not None and not owner.unresolved:
                for target in targets:
                    self._pending_event(
                        fact,
                        CompiledEventType.PROCESS_ACCESS,
                        owner.request,
                        fields={"target_process": self._source_field(target)},
                        visibility=[ExpectedVisibility.ENDPOINT_PROCESS],
                        object_entity_ids=[target.entity_id],
                    )
                for key in registry_keys:
                    self._pending_event(
                        fact,
                        CompiledEventType.REGISTRY_QUERY,
                        owner.request,
                        fields=self._registry_fields(key, CompiledEventType.REGISTRY_QUERY),
                        visibility=[ExpectedVisibility.ENDPOINT_REGISTRY],
                        object_entity_ids=[key.entity_id],
                    )
                return
            self._ground_truth_only(fact, "反分析行为缺少执行进程，且受控补全未解决")
            return

        process = owner.entity
        # Establish every inspected process before the inspecting process.  The
        # native storyline engine uses the most recently started process as
        # the Process Access source, so keeping the owner last preserves both
        # a live target PID and the correct source-process role.
        for target in targets:
            self._ensure_process_prerequisite(fact, target, None)
        self._ensure_process_prerequisite(fact, process, owner.request)
        request_ids = [owner.request.request_id] if owner.request else []
        for target in targets:
            fields = {
                "target_process": self._source_field(target),
                "access_mask": self._engine_field(
                    "0x1000",
                    [fact.fact_id, target.entity_id],
                    "使用最小查询权限以物化报告中的进程检测，不表示原文权限值",
                ),
            }
            self.events.append(
                self._new_event(
                    fact=fact,
                    event_type=CompiledEventType.PROCESS_ACCESS,
                    fields=fields,
                    source_category=self._source_category(process, fields),
                    status=CompilationStatus.MATERIALIZED,
                    visibility=[ExpectedVisibility.ENDPOINT_PROCESS],
                    subject_entity_id=process.entity_id,
                    object_entity_ids=[target.entity_id],
                    completion_request_ids=request_ids,
                )
            )
        for key in registry_keys:
            fields = self._registry_fields(key, CompiledEventType.REGISTRY_QUERY)
            fields["process_ref"] = self._process_ref_field(process)
            self.events.append(
                self._new_event(
                    fact=fact,
                    event_type=CompiledEventType.REGISTRY_QUERY,
                    fields=fields,
                    source_category=self._source_category(process, fields),
                    status=CompilationStatus.MATERIALIZED,
                    visibility=[ExpectedVisibility.ENDPOINT_REGISTRY],
                    subject_entity_id=process.entity_id,
                    object_entity_ids=[key.entity_id],
                    completion_request_ids=request_ids,
                )
            )

    def _compile_scheduled_tasks(self, fact: ReportFact) -> None:
        tasks = self._bound_entities_of_type(fact, EntityType.SCHEDULED_TASK)
        if not tasks:
            tasks = [self._engine_task_entity(fact)]
        owner = self._resolve_owner(fact, allow_completion=True)
        if owner.entity is None:
            if owner.request is not None and not owner.unresolved:
                for task in tasks:
                    self._pending_event(
                        fact,
                        CompiledEventType.SCHEDULED_TASK_CREATED,
                        owner.request,
                        fields=self._task_fields(task),
                        visibility=[ExpectedVisibility.ENDPOINT_PROCESS],
                        object_entity_ids=[task.entity_id],
                    )
                return
            self._ground_truth_only(fact, "计划任务缺少创建进程，且受控补全未解决")
            return

        process = owner.entity
        self._ensure_process_prerequisite(fact, process, owner.request)
        for task in tasks:
            fields = self._task_fields(task)
            fields["source_process_ref"] = self._process_ref_field(process)
            self.events.append(
                self._new_event(
                    fact=fact,
                    event_type=CompiledEventType.SCHEDULED_TASK_CREATED,
                    fields=fields,
                    source_category=self._source_category(process, fields),
                    status=CompilationStatus.MATERIALIZED,
                    visibility=[ExpectedVisibility.ENDPOINT_PROCESS],
                    subject_entity_id=process.entity_id,
                    object_entity_ids=[task.entity_id],
                    completion_request_ids=[owner.request.request_id] if owner.request else [],
                )
            )

    def _compile_services(self, fact: ReportFact) -> None:
        services = [
            item
            for item in self._bound_entities_of_type(fact, EntityType.SERVICE)
            if item.attributes.get("service_name") or item.attributes.get("binary")
        ]
        if not services:
            self._ground_truth_only(fact, "服务安装行为缺少服务名或服务二进制实体")
            return
        owner = self._resolve_owner(fact, allow_completion=True)
        if owner.entity is None:
            if owner.request is not None and not owner.unresolved:
                self._pending_event(
                    fact,
                    CompiledEventType.SERVICE_INSTALLED,
                    owner.request,
                    visibility=[ExpectedVisibility.ENDPOINT_PROCESS],
                )
                return
            self._ground_truth_only(fact, "服务安装缺少创建进程，且受控补全未解决")
            return
        process = owner.entity
        self._ensure_process_prerequisite(fact, process, owner.request)
        for service in services:
            service_name = str(service.attributes.get("service_name") or service.value)
            binary = service.attributes.get("binary")
            if not isinstance(binary, str) or not binary.strip():
                self._ground_truth_only(fact, f"服务 {service_name} 缺少来源支持的二进制路径")
                continue
            fields = {
                "service_name": self._source_attribute_field(service, service_name),
                "service_file_name": self._source_attribute_field(service, binary),
            }
            self.events.append(
                self._new_event(
                    fact=fact,
                    event_type=CompiledEventType.SERVICE_INSTALLED,
                    fields=fields,
                    source_category=self._source_category(process, fields),
                    status=CompilationStatus.MATERIALIZED,
                    visibility=[ExpectedVisibility.ENDPOINT_PROCESS],
                    subject_entity_id=process.entity_id,
                    object_entity_ids=[service.entity_id],
                    completion_request_ids=[owner.request.request_id] if owner.request else [],
                )
            )

    def _compile_registry(self, fact: ReportFact, event_type: CompiledEventType) -> None:
        keys = self._bound_entities_of_type(fact, EntityType.REGISTRY)
        if not keys:
            self._ground_truth_only(fact, "注册表行为没有关联注册表键实体")
            return
        owner = self._resolve_owner(fact, allow_completion=True)
        if owner.entity is None:
            if owner.request is not None and not owner.unresolved:
                for key in keys:
                    self._pending_event(
                        fact,
                        event_type,
                        owner.request,
                        fields=self._registry_fields(key, event_type),
                        visibility=[ExpectedVisibility.ENDPOINT_REGISTRY],
                        object_entity_ids=[key.entity_id],
                    )
                return
            self._ground_truth_only(fact, "注册表行为缺少执行进程，且受控补全未解决")
            return

        process = owner.entity
        self._ensure_process_prerequisite(fact, process, owner.request)
        for key in keys:
            fields = self._registry_fields(key, event_type)
            if (
                event_type == CompiledEventType.REGISTRY_SET
                and not {
                    "value_name",
                    "value_data",
                }
                <= fields.keys()
            ):
                self._ground_truth_only(fact, f"注册表写入 {key.value} 缺少值名或值数据")
                continue
            fields["process_ref"] = self._process_ref_field(process)
            self.events.append(
                self._new_event(
                    fact=fact,
                    event_type=event_type,
                    fields=fields,
                    source_category=self._source_category(process, fields),
                    status=CompilationStatus.MATERIALIZED,
                    visibility=[ExpectedVisibility.ENDPOINT_REGISTRY],
                    subject_entity_id=process.entity_id,
                    object_entity_ids=[key.entity_id],
                    completion_request_ids=[owner.request.request_id] if owner.request else [],
                )
            )

    def _compile_file_deletion(self, fact: ReportFact) -> None:
        files = self._bound_entities_of_type(fact, EntityType.FILE)
        owner = self._resolve_owner(
            fact,
            allow_completion=True,
            use_command=bool(files),
        )
        if owner.entity is None:
            if owner.request is not None and not owner.unresolved:
                self._pending_event(
                    fact,
                    CompiledEventType.FILE_DELETE,
                    owner.request,
                    visibility=[ExpectedVisibility.ENDPOINT_FILE],
                    object_entity_ids=[item.entity_id for item in files],
                )
                return
            self._ground_truth_only(fact, "文件删除缺少执行进程，且受控补全未解决")
            return
        process = owner.entity
        self._ensure_process_prerequisite(fact, process, owner.request)
        deletion_targets: list[ReportEntity] = files or [process]
        for file_entity in deletion_targets:
            fields = {
                "process_ref": self._process_ref_field(process),
                "path": self._source_field(file_entity),
            }
            self.events.append(
                self._new_event(
                    fact=fact,
                    event_type=CompiledEventType.FILE_DELETE,
                    fields=fields,
                    source_category=self._source_category(process, fields),
                    status=CompilationStatus.MATERIALIZED,
                    visibility=[ExpectedVisibility.ENDPOINT_FILE],
                    subject_entity_id=process.entity_id,
                    object_entity_ids=[file_entity.entity_id],
                    completion_request_ids=[owner.request.request_id] if owner.request else [],
                )
            )

    def _compile_file_creation(self, fact: ReportFact) -> None:
        files = self._bound_entities_of_type(fact, EntityType.FILE)
        if not files:
            self._ground_truth_only(fact, "文件创建行为没有关联具体文件")
            return
        owner = self._resolve_owner(fact, allow_completion=True)
        if owner.entity is None:
            if owner.request is not None and not owner.unresolved:
                for file_entity in files:
                    self._pending_event(
                        fact,
                        CompiledEventType.FILE_CREATE,
                        owner.request,
                        fields={"path": self._source_field(file_entity)},
                        visibility=[ExpectedVisibility.ENDPOINT_FILE],
                        object_entity_ids=[file_entity.entity_id],
                    )
                return
            self._ground_truth_only(fact, "文件创建缺少执行进程，且受控补全未提供主体")
            return
        process = owner.entity
        self._ensure_process_prerequisite(fact, process, owner.request)
        self._append_file_create_events(fact, process, files, owner.request)

    def _append_file_create_events(
        self,
        fact: ReportFact,
        process: ReportEntity,
        files: list[ReportEntity],
        request: CompletionRequest | None,
    ) -> None:
        """Materialize source-bound local files once for one create/download fact."""
        for file_entity in files:
            fields = {
                "process_ref": self._process_ref_field(process),
                "path": self._source_field(file_entity),
            }
            self.events.append(
                self._new_event(
                    fact=fact,
                    event_type=CompiledEventType.FILE_CREATE,
                    fields=fields,
                    source_category=self._source_category(process, fields),
                    status=CompilationStatus.MATERIALIZED,
                    visibility=[ExpectedVisibility.ENDPOINT_FILE],
                    subject_entity_id=process.entity_id,
                    object_entity_ids=[file_entity.entity_id],
                    completion_request_ids=[request.request_id] if request else [],
                )
            )

    def _compile_dns(self, fact: ReportFact) -> None:
        domains = self._bound_entities_of_type(fact, EntityType.DOMAIN)
        if not domains:
            self._ground_truth_only(fact, "DNS 行为没有关联域名实体")
            return
        for domain in domains:
            fields = {
                "query": self._materialized_network_value_field(domain),
                "qtype": self._engine_field("A", [domain.entity_id], "生成 A 查询以物化域名解析"),
                "rcode": self._engine_field(
                    "NOERROR",
                    [domain.entity_id],
                    "报告描述成功使用该域名，生成成功解析结果",
                ),
            }
            ip = self._mapped_ip(domain, fact, domains)
            if ip is not None:
                fields["answer"] = self._materialized_network_value_field(ip)
            else:
                fields["answer"] = self._synthetic_ip_field(domain)
            self.events.append(
                self._new_event(
                    fact=fact,
                    event_type=CompiledEventType.DNS_QUERY,
                    fields=fields,
                    source_category=self._field_source_category(fields),
                    status=CompilationStatus.MATERIALIZED,
                    visibility=[ExpectedVisibility.DNS],
                    channel_entity_ids=[domain.entity_id],
                )
            )

    def _compile_email(self, fact: ReportFact) -> None:
        emails = self._bound_entities_of_type(fact, EntityType.EMAIL)
        recipients = [
            item
            for item in emails
            if self._predicate_for(fact, item.entity_id) in {"delivered_to", "sent_to", "targets"}
        ]
        senders = [
            item
            for item in emails
            if self._predicate_for(fact, item.entity_id) in {"from", "sent_by"}
        ]
        recipient_field = (
            CompiledField(
                value=[item.value for item in recipients],
                provenance=self._merged_source_provenance(recipients),
            )
            if recipients
            else self._field(
                [_SIMULATION_RECIPIENT],
                FieldProvenance(
                    origin=FieldOrigin.ENGINE_GENERATED,
                    source_ids=[fact.fact_id],
                    reason="报告未披露收件人；使用隔离实验环境内部邮箱物化投递",
                ),
            )
        )
        fields: dict[str, CompiledField] = {
            "to": recipient_field,
            "verdict": self._engine_field(
                "phishing",
                [fact.fact_id],
                "来源事实将该邮件描述为鱼叉钓鱼投递",
            ),
        }
        if len(senders) == 1:
            fields["sender"] = self._source_field(senders[0])
        self.events.append(
            self._new_event(
                fact=fact,
                event_type=CompiledEventType.EMAIL_MESSAGE,
                fields=fields,
                source_category=self._field_source_category(fields),
                status=CompilationStatus.MATERIALIZED,
                visibility=[ExpectedVisibility.EMAIL],
                object_entity_ids=[item.entity_id for item in recipients],
            )
        )

    def _resolve_owner(
        self,
        fact: ReportFact,
        *,
        allow_completion: bool,
        use_command: bool = True,
    ) -> _OwnerResolution:
        bound = self.bound_entities.get(fact.fact_id, [])
        explicit = [
            item.entity
            for item in bound
            if item.entity.entity_type == EntityType.PROCESS and item.predicate in _OWNER_PREDICATES
        ]
        if len(explicit) == 1:
            return _OwnerResolution(explicit[0])
        if len(explicit) > 1:
            return _OwnerResolution(None)

        command = (
            self._single_bound_entity(fact, EntityType.COMMAND, _COMMAND_PREDICATES)
            if use_command
            else None
        )
        if command is not None:
            process_image = _process_image_from_command(command.value)
            if process_image:
                entity_id = f"derived-process-{_safe_token(fact.fact_id)}"
                process = self.generated_entities.get(entity_id)
                if process is None:
                    process = ReportEntity(
                        entity_id=entity_id,
                        entity_type=EntityType.PROCESS,
                        value=process_image,
                        provenance=FieldProvenance(
                            origin=FieldOrigin.DERIVED,
                            source_ids=[command.entity_id],
                            reason="从来源命令行的首个可执行文件确定进程镜像",
                        ),
                    )
                    self.generated_entities[entity_id] = process
                return _OwnerResolution(process)

        if not allow_completion:
            return _OwnerResolution(None)
        request = self._process_completion_request(fact)
        completion = self.completions.get(request.request_id)
        if completion is not None:
            return _OwnerResolution(
                self._process_from_completion(fact, completion),
                request=request,
            )
        return _OwnerResolution(
            None,
            request=request,
            unresolved=request.request_id in self.unresolved_request_ids,
        )

    def _process_completion_request(self, fact: ReportFact) -> CompletionRequest:
        request_id = f"complete-{_safe_token(fact.fact_id)}-process-image"
        request = self.completion_requests.get(request_id)
        if request is None:
            request = CompletionRequest(
                request_id=request_id,
                target_id=fact.fact_id,
                field_path="process.image",
                description="为报告明确的行为补全一个仿真内部进程镜像",
                allowed_origins=[FieldOrigin.ENGINE_GENERATED, FieldOrigin.AI_COMPLETED],
                source_ids=[fact.fact_id],
                constraints=[
                    "不得新增攻击行为",
                    "不得新增或修改外部 IOC",
                    "不得在报告未提及解释器时选择 PowerShell、CMD、WScript 或 CScript",
                ],
            )
            self.completion_requests[request_id] = request
        return request

    def _process_from_completion(
        self,
        fact: ReportFact,
        completion: SimulationCompletion,
    ) -> ReportEntity:
        if not isinstance(completion.value, str) or not completion.value.strip():
            raise ReportCompilerError(f"补全 {completion.request_id} 必须返回非空进程路径")
        normalized_value = completion.value.strip().casefold()
        forbidden_interpreters = ("cmd.exe", "cscript", "powershell", "pwsh", "wscript")
        if "://" in normalized_value:
            raise ReportCompilerError(f"补全 {completion.request_id} 不能把网络地址作为进程镜像")
        if any(token in normalized_value for token in forbidden_interpreters):
            raise ReportCompilerError(
                f"补全 {completion.request_id} 不能为来源未披露的进程指定命令解释器"
            )
        prefix = "engine" if completion.origin == FieldOrigin.ENGINE_GENERATED else "ai"
        entity_id = f"{prefix}-process-{_safe_token(fact.fact_id)}"
        entity = self.generated_entities.get(entity_id)
        if entity is None:
            entity = ReportEntity(
                entity_id=entity_id,
                entity_type=EntityType.PROCESS,
                value=completion.value,
                provenance=FieldProvenance(
                    origin=completion.origin,
                    source_ids=[fact.fact_id],
                    reason=completion.reason,
                ),
            )
            self.generated_entities[entity_id] = entity
        return entity

    def _ensure_process_prerequisite(
        self,
        fact: ReportFact,
        process: ReportEntity,
        request: CompletionRequest | None,
    ) -> None:
        if process.entity_id in self.established_processes:
            return
        fields = self._process_fields(process)
        fields["persistent"] = self._engine_field(
            True,
            [process.entity_id],
            "后续来源行为显式引用该进程，需在仿真状态中保持进程存活",
        )
        self.events.append(
            self._new_event(
                fact=fact,
                event_type=CompiledEventType.PROCESS,
                fields=fields,
                source_category=SourceCategory.FULLY_SYNTHETIC,
                status=CompilationStatus.MATERIALIZED,
                visibility=[ExpectedVisibility.ENDPOINT_PROCESS],
                subject_entity_id=process.entity_id,
                completion_request_ids=[request.request_id] if request else [],
                necessity_reason="在 EvidenceForge 状态中建立该行为明确绑定的进程主体",
            )
        )
        self.established_processes.add(process.entity_id)

    def _network_channels(self, fact: ReportFact) -> list[ReportEntity]:
        urls = self._bound_entities_of_type(fact, EntityType.URL)
        url_hosts = {urlsplit(item.canonical_value or item.value).hostname for item in urls}
        domains = [
            item
            for item in self._bound_entities_of_type(fact, EntityType.DOMAIN)
            if item.canonical_value not in url_hosts
        ]
        channels = [*urls, *domains]
        if not channels:
            channels.extend(self._bound_entities_of_type(fact, EntityType.IP))
        return channels

    def _network_fields(
        self,
        fact: ReportFact,
        channel: ReportEntity,
        channels: list[ReportEntity],
    ) -> dict[str, CompiledField]:
        fields: dict[str, CompiledField] = {}
        if channel.entity_type == EntityType.URL:
            parts = urlsplit(channel.canonical_value or channel.value)
            if not parts.hostname:
                raise ReportCompilerError(f"URL 实体 {channel.entity_id} 缺少主机名")
            fields["hostname"] = self._derived_field(
                parts.hostname,
                [channel.entity_id],
                "从当前行为绑定的 URL 拆分主机名",
            )
            port = parts.port or (443 if parts.scheme == "https" else 80)
            fields["dst_port"] = self._derived_field(
                port,
                [channel.entity_id],
                "从当前 URL 协议或显式端口确定目标端口",
            )
            service = "ssl" if parts.scheme == "https" else "http"
            fields["service"] = self._derived_field(
                service,
                [channel.entity_id],
                "从当前 URL 协议确定连接服务",
            )
            uri = parts.path or "/"
            if parts.query:
                uri = f"{uri}?{parts.query}"
            fields["uri"] = self._derived_field(
                uri,
                [channel.entity_id],
                "从当前行为绑定的 URL 拆分 URI，不跨行为复用",
            )
            if fact.behavior in _DOWNLOAD_BEHAVIORS:
                fields["method"] = self._derived_field(
                    "GET",
                    [fact.fact_id, channel.entity_id],
                    "报告明确描述从该 URL 下载",
                )
            elif fact.behavior in _EXFILTRATION_BEHAVIORS:
                fields["method"] = self._derived_field(
                    "POST",
                    [fact.fact_id, channel.entity_id],
                    "报告明确描述向该 URL 上传或外传",
                )
        elif channel.entity_type == EntityType.DOMAIN:
            fields["hostname"] = self._materialized_network_value_field(channel)
            protocol = str(channel.attributes.get("protocol") or "").lower()
            if protocol in {"https", "tls"} or fact.behavior == "c2_beacon_https":
                fields["dst_port"] = self._derived_field(
                    443,
                    [fact.fact_id, channel.entity_id],
                    "HTTPS/TLS 行为确定使用 443 端口",
                )
                fields["service"] = self._derived_field(
                    "ssl",
                    [fact.fact_id, channel.entity_id],
                    "HTTPS/TLS 行为确定连接服务",
                )
            else:
                port = channel.attributes.get("port")
                if isinstance(port, int) and 0 < port <= 65535:
                    fields["dst_port"] = self._source_attribute_field(channel, port)
        elif channel.entity_type == EntityType.IP:
            fields["dst_ip"] = self._materialized_network_value_field(channel)
            if fact.behavior == "c2_beacon_https":
                fields["dst_port"] = self._derived_field(
                    443,
                    [fact.fact_id, channel.entity_id],
                    "HTTPS 行为确定使用 443 端口",
                )
                fields["service"] = self._derived_field(
                    "ssl",
                    [fact.fact_id, channel.entity_id],
                    "HTTPS 行为确定连接服务",
                )

        if "dst_ip" not in fields:
            mapped_ip = self._mapped_ip(channel, fact, channels)
            fields["dst_ip"] = (
                self._materialized_network_value_field(mapped_ip)
                if mapped_ip is not None
                else self._synthetic_ip_field(channel)
            )
        return fields

    def _synthetic_network_fields(self, fact: ReportFact) -> dict[str, CompiledField]:
        """Build a reserved lab endpoint when the report omits or ambiguously binds an IOC."""
        fields = {
            "dst_ip": self._engine_field(
                _simulation_ip(f"network|{fact.fact_id}"),
                [fact.fact_id],
                "报告网络行为缺少唯一可绑定的端点；使用 RFC 5737 保留地址仅供仿真",
            ),
            "dst_port": self._engine_field(
                443,
                [fact.fact_id],
                "使用实验网络的 HTTPS 默认端口，不代表原文端口",
            ),
            "service": self._engine_field(
                "ssl",
                [fact.fact_id],
                "使用实验网络的 HTTPS 默认服务，不代表原文协议",
            ),
        }
        if fact.behavior in _DOWNLOAD_BEHAVIORS:
            fields["method"] = self._engine_field(
                "GET",
                [fact.fact_id],
                "为报告明确的下载行为生成实验 HTTP 方法",
            )
        elif fact.behavior in _EXFILTRATION_BEHAVIORS:
            fields["method"] = self._engine_field(
                "POST",
                [fact.fact_id],
                "为报告明确的外传行为生成实验 HTTP 方法",
            )
        return fields

    def _mapped_ip(
        self,
        channel: ReportEntity,
        fact: ReportFact,
        channels: list[ReportEntity],
    ) -> ReportEntity | None:
        candidate_ids = {channel.entity_id}
        if channel.entity_type == EntityType.URL:
            hostname = urlsplit(channel.canonical_value or channel.value).hostname
            candidate_ids.update(
                entity.entity_id
                for entity in self.entities.values()
                if entity.entity_type == EntityType.DOMAIN and entity.canonical_value == hostname
            )
        for entity_id in candidate_ids:
            for relation in self.entity_relations.get(entity_id, []):
                if relation.predicate not in _DOMAIN_IP_PREDICATES:
                    continue
                other_id = (
                    relation.target_id if relation.source_id == entity_id else relation.source_id
                )
                other = self.entities.get(other_id)
                if other is not None and other.entity_type == EntityType.IP:
                    return other

        direct_ips = self._bound_entities_of_type(fact, EntityType.IP)
        if len(channels) == 1 and len(direct_ips) == 1:
            return direct_ips[0]
        return None

    def _task_fields(self, task: ReportEntity) -> dict[str, CompiledField]:
        fields = {"task_name": self._source_field(task)}
        binary = task.attributes.get("binary")
        if isinstance(binary, str) and binary.strip():
            fields["task_content"] = self._source_attribute_field(task, binary)
        trigger = task.attributes.get("trigger")
        if isinstance(trigger, str) and trigger.strip():
            fields["trigger"] = self._source_attribute_field(task, trigger)
            interval_minutes = _trigger_interval_minutes(trigger)
            if interval_minutes is not None:
                fields["interval_minutes"] = self._derived_field(
                    interval_minutes,
                    [task.entity_id],
                    "从来源计划任务触发描述解析重复周期（分钟）",
                )
        creation_method = task.attributes.get("creation_method")
        if isinstance(creation_method, str) and creation_method.strip():
            normalized_method = creation_method.casefold()
            if "com" in normalized_method:
                fields["creation_method"] = self._derived_field(
                    "com",
                    [task.entity_id],
                    "从来源中明确的 COM 组件创建方式归一化",
                )
            elif "schtasks" in normalized_method:
                fields["creation_method"] = self._derived_field(
                    "schtasks",
                    [task.entity_id],
                    "从来源中明确的 schtasks 创建方式归一化",
                )
        return fields

    def _engine_task_entity(self, fact: ReportFact) -> ReportEntity:
        """Create a stable lab-only task when the report omits its exact name."""
        entity_id = f"engine-task-{_safe_token(fact.fact_id)}"
        existing = self.generated_entities.get(entity_id)
        if existing is not None:
            return existing
        digest = hashlib.sha256(f"task|{fact.fact_id}".encode()).hexdigest()[:10]
        task = ReportEntity(
            entity_id=entity_id,
            entity_type=EntityType.SCHEDULED_TASK,
            value=f"EvidenceForge_ReportTask_{digest}",
            provenance=FieldProvenance(
                origin=FieldOrigin.ENGINE_GENERATED,
                source_ids=[fact.fact_id],
                reason="报告明确存在计划任务行为，但未提供可唯一绑定的任务名；生成隔离实验任务名",
            ),
        )
        self.generated_entities[entity_id] = task
        return task

    def _registry_fields(
        self,
        key: ReportEntity,
        event_type: CompiledEventType,
    ) -> dict[str, CompiledField]:
        fields = {"key": self._source_field(key)}
        value_name = key.attributes.get("value_name")
        if isinstance(value_name, str) and value_name.strip():
            fields["value_name"] = self._source_attribute_field(key, value_name)
        value_data = key.attributes.get("value_data")
        if event_type == CompiledEventType.REGISTRY_SET and isinstance(value_data, str):
            fields["value_data"] = self._source_attribute_field(key, value_data)
        return fields

    def _process_fields(self, process: ReportEntity) -> dict[str, CompiledField]:
        return {
            "process_name": self._field(process.value, process.provenance),
            "process_ref": self._process_ref_field(process),
        }

    def _process_ref_field(self, process: ReportEntity) -> CompiledField:
        if process.provenance.origin == FieldOrigin.AI_COMPLETED:
            return self._field(
                f"proc-{_safe_token(process.entity_id)}",
                FieldProvenance(
                    origin=FieldOrigin.AI_COMPLETED,
                    source_ids=[process.entity_id],
                    reason="从 AI 补全的内部进程实体生成稳定 process_ref",
                ),
            )
        return self._derived_field(
            f"proc-{_safe_token(process.entity_id)}",
            [process.entity_id],
            "从稳定进程实体 ID 生成 EvidenceForge process_ref",
        )

    def _source_field(self, entity: ReportEntity) -> CompiledField:
        return self._field(entity.value, entity.provenance)

    def _materialized_network_value_field(self, entity: ReportEntity) -> CompiledField:
        """为可执行网络字段还原常见 IOC 去武器化写法。"""
        value = entity.canonical_value or entity.value
        if value == entity.value:
            return self._source_field(entity)
        return self._derived_field(
            value,
            [entity.entity_id],
            "仅将来源 IOC 的常见去武器化和大小写恢复为可执行网络值；原文展示值仍保留在报告账本",
        )

    def _source_attribute_field(
        self,
        entity: ReportEntity,
        value: str | int | float | bool,
    ) -> CompiledField:
        return self._field(value, entity.provenance)

    def _derived_field(
        self,
        value: str | int | float | bool,
        source_ids: list[str],
        reason: str,
    ) -> CompiledField:
        return self._field(
            value,
            FieldProvenance(
                origin=FieldOrigin.DERIVED,
                source_ids=source_ids,
                reason=reason,
            ),
        )

    def _engine_field(
        self,
        value: str | int | float | bool,
        source_ids: list[str],
        reason: str,
    ) -> CompiledField:
        return self._field(
            value,
            FieldProvenance(
                origin=FieldOrigin.ENGINE_GENERATED,
                source_ids=source_ids,
                reason=reason,
            ),
        )

    def _synthetic_ip_field(self, channel: ReportEntity) -> CompiledField:
        return self._engine_field(
            _simulation_ip(channel.canonical_value or channel.value),
            [channel.entity_id],
            "报告只给出外部主机名；使用 RFC 5737 仿真地址满足连接渲染，不登记为报告 IOC",
        )

    def _field(
        self,
        value: str | int | float | bool | list[str],
        provenance: FieldProvenance,
    ) -> CompiledField:
        return CompiledField(value=value, provenance=provenance.model_copy(deep=True))

    def _merged_source_provenance(self, entities: list[ReportEntity]) -> FieldProvenance:
        return FieldProvenance(
            origin=FieldOrigin.SOURCE,
            source_span_ids=list(
                dict.fromkeys(
                    span_id for entity in entities for span_id in entity.provenance.source_span_ids
                )
            ),
        )

    def _source_category(
        self,
        process: ReportEntity,
        fields: dict[str, CompiledField],
    ) -> SourceCategory:
        if process.provenance.origin == FieldOrigin.AI_COMPLETED or any(
            field.provenance.origin == FieldOrigin.AI_COMPLETED for field in fields.values()
        ):
            return SourceCategory.PARTIALLY_AI_COMPLETED
        if process.provenance.origin == FieldOrigin.ENGINE_GENERATED or any(
            field.provenance.origin == FieldOrigin.ENGINE_GENERATED for field in fields.values()
        ):
            return SourceCategory.PARTIALLY_ENGINE_GENERATED
        return SourceCategory.SOURCE_FACT

    def _field_source_category(
        self,
        fields: dict[str, CompiledField],
    ) -> SourceCategory:
        if any(field.provenance.origin == FieldOrigin.AI_COMPLETED for field in fields.values()):
            return SourceCategory.PARTIALLY_AI_COMPLETED
        if any(
            field.provenance.origin == FieldOrigin.ENGINE_GENERATED for field in fields.values()
        ):
            return SourceCategory.PARTIALLY_ENGINE_GENERATED
        return SourceCategory.SOURCE_FACT

    def _pending_event(
        self,
        fact: ReportFact,
        event_type: CompiledEventType,
        request: CompletionRequest,
        *,
        fields: dict[str, CompiledField] | None = None,
        visibility: list[ExpectedVisibility],
        object_entity_ids: list[str] | None = None,
        channel_entity_ids: list[str] | None = None,
    ) -> None:
        self.events.append(
            self._new_event(
                fact=fact,
                event_type=event_type,
                fields=fields or {},
                source_category=SourceCategory.SOURCE_FACT,
                status=CompilationStatus.NEEDS_COMPLETION,
                visibility=visibility,
                object_entity_ids=object_entity_ids or [],
                channel_entity_ids=channel_entity_ids or [],
                completion_request_ids=[request.request_id],
            )
        )

    def _ground_truth_only(self, fact: ReportFact, reason: str) -> None:
        self.events.append(
            self._new_event(
                fact=fact,
                event_type=None,
                fields={},
                source_category=SourceCategory.SOURCE_FACT,
                status=CompilationStatus.GROUND_TRUTH_ONLY,
                visibility=[ExpectedVisibility.GROUND_TRUTH],
                degradation_reason=reason,
            )
        )

    def _new_event(
        self,
        *,
        fact: ReportFact,
        event_type: CompiledEventType | None,
        fields: dict[str, CompiledField],
        source_category: SourceCategory,
        status: CompilationStatus,
        visibility: list[ExpectedVisibility],
        subject_entity_id: str | None = None,
        object_entity_ids: list[str] | None = None,
        channel_entity_ids: list[str] | None = None,
        completion_request_ids: list[str] | None = None,
        degradation_reason: str | None = None,
        necessity_reason: str | None = None,
    ) -> CompiledScenarioEvent:
        sequence = len(self.events) + 1
        return CompiledScenarioEvent(
            event_id=f"event-{sequence:04d}-{_safe_token(fact.fact_id)}",
            fact_id=fact.fact_id,
            order=sequence,
            event_type=event_type,
            activity=fact.description,
            subject_entity_id=subject_entity_id,
            object_entity_ids=object_entity_ids or [],
            channel_entity_ids=channel_entity_ids or [],
            fields=fields,
            source_category=source_category,
            status=status,
            expected_visibility=visibility,
            completion_request_ids=completion_request_ids or [],
            degradation_reason=degradation_reason,
            necessity_reason=necessity_reason,
        )

    def _single_bound_entity(
        self,
        fact: ReportFact,
        entity_type: EntityType,
        predicates: set[str],
    ) -> ReportEntity | None:
        candidates = [
            item.entity
            for item in self.bound_entities.get(fact.fact_id, [])
            if item.entity.entity_type == entity_type and item.predicate in predicates
        ]
        return candidates[0] if len(candidates) == 1 else None

    def _bound_entities_of_type(
        self,
        fact: ReportFact,
        entity_type: EntityType,
    ) -> list[ReportEntity]:
        return list(
            {
                item.entity.entity_id: item.entity
                for item in self.bound_entities.get(fact.fact_id, [])
                if item.entity.entity_type == entity_type
            }.values()
        )

    def _predicate_for(self, fact: ReportFact, entity_id: str) -> str:
        for item in self.bound_entities.get(fact.fact_id, []):
            if item.entity.entity_id == entity_id:
                return item.predicate
        return ""

    def _index_fact_bindings(self) -> dict[str, list[_BoundEntity]]:
        result: dict[str, list[_BoundEntity]] = {fact_id: [] for fact_id in self.facts}
        for relation in self.ledger.relations:
            if relation.source_id in self.facts and relation.target_id in self.entities:
                result[relation.source_id].append(
                    _BoundEntity(
                        entity=self.entities[relation.target_id],
                        predicate=relation.predicate,
                        relation=relation,
                    )
                )
            elif relation.target_id in self.facts and relation.source_id in self.entities:
                result[relation.target_id].append(
                    _BoundEntity(
                        entity=self.entities[relation.source_id],
                        predicate=relation.predicate,
                        relation=relation,
                    )
                )
        return result

    def _index_entity_relations(self) -> dict[str, list[ReportRelation]]:
        result: dict[str, list[ReportRelation]] = {}
        for relation in self.ledger.relations:
            if relation.source_id in self.entities and relation.target_id in self.entities:
                result.setdefault(relation.source_id, []).append(relation)
                result.setdefault(relation.target_id, []).append(relation)
        return result

    def _validate_entity_references(self, compilation: ReportScenarioCompilation) -> None:
        valid_ids = set(self.entities) | {
            entity.entity_id for entity in compilation.generated_entities
        }
        errors: list[str] = []
        for event in compilation.events:
            references = {
                *event.object_entity_ids,
                *event.channel_entity_ids,
            }
            if event.subject_entity_id:
                references.add(event.subject_entity_id)
            missing = references - valid_ids
            if missing:
                errors.append(f"{event.event_id} 包含未知实体 {sorted(missing)}")
        if errors:
            raise ReportCompilerError("编译结果实体引用无效：" + "; ".join(errors))


def _process_image_from_command(command_line: str) -> str | None:
    """Derive only an executable explicitly present as the first command token."""
    match = re.match(r'^\s*(?:"([^"]+)"|(\S+))', command_line)
    if match is None:
        return None
    token = (match.group(1) or match.group(2) or "").strip()
    if not token:
        return None
    mapped = _PROCESS_IMAGE_BY_TOKEN.get(token.casefold())
    if mapped:
        return mapped
    if "\\" in token or "/" in token or token.casefold().endswith((".exe", ".com", ".bat")):
        return token
    return None


def _trigger_interval_minutes(trigger: str) -> int | None:
    """Parse an explicit repeated minute/hour interval without inventing a schedule."""
    text = trigger.strip().lower()
    minute_match = re.search(
        r"(?:每\s*隔?\s*|every\s+)(\d{1,6})\s*(?:分钟|分|minutes?|mins?)",
        text,
    )
    if minute_match:
        minutes = int(minute_match.group(1))
        return minutes if 0 < minutes <= 525_600 else None
    hour_match = re.search(
        r"(?:每\s*隔?\s*|every\s+)(\d{1,4})\s*(?:小时|hours?|hrs?)",
        text,
    )
    if hour_match:
        minutes = int(hour_match.group(1)) * 60
        return minutes if 0 < minutes <= 525_600 else None
    iso_match = re.fullmatch(r"pt(\d{1,6})m", text)
    if iso_match:
        minutes = int(iso_match.group(1))
        return minutes if 0 < minutes <= 525_600 else None
    return None


def _simulation_ip(seed: str) -> str:
    """Return a stable RFC 5737 address used only as a simulation-layer endpoint."""
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    prefixes = ("192.0.2", "198.51.100", "203.0.113")
    prefix = prefixes[digest[0] % len(prefixes)]
    return f"{prefix}.{10 + int.from_bytes(digest[1:3], 'big') % 240}"


def _safe_token(value: str) -> str:
    """Return a stable identifier component without using report prose."""
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.")
    if normalized and normalized[0].isalpha():
        return normalized[:80]
    return f"id-{hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]}"
