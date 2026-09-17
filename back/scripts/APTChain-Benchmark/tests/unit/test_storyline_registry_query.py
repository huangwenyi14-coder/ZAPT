# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Regression tests for report-driven registry-read storyline events."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

from evidenceforge.events.contexts import HostContext
from evidenceforge.generation.engine.storyline import StorylineMixin
from evidenceforge.models import System, User
from evidenceforge.models.scenario import RegistryQueryEventSpec


def test_registry_query_executes_as_canonical_read_and_keeps_source_metadata() -> None:
    """Execution must preserve query semantics and report provenance end to end."""
    event_time = datetime(2024, 11, 26, 10, 0, tzinfo=UTC)
    process_start = event_time - timedelta(minutes=1)
    process_image = r"C:\ProgramData\agent.exe"
    system = System(
        hostname="WS-01",
        ip="10.0.0.10",
        os="Windows 11",
        type="workstation",
    )
    actor = User(
        username="victim",
        full_name="Victim User",
        email="victim@example.com",
    )
    running = SimpleNamespace(
        username=actor.username,
        logon_id="0x123",
        parent_pid=4,
        image=process_image,
        command_line=process_image,
        start_time=process_start,
    )
    engine_type = type("RegistryQueryEngine", (StorylineMixin,), {})
    engine = engine_type.__new__(engine_type)
    engine.dispatcher = Mock()
    engine.state_manager = Mock()
    engine.state_manager.get_process.return_value = running
    engine.state_manager.get_process_object_id.return_value = "process-object-1"
    engine.activity_generator = Mock()
    engine.activity_generator._build_host_context.return_value = HostContext(
        hostname=system.hostname,
        ip=system.ip,
        os=system.os,
        os_category="windows",
        system_type=system.type,
    )
    engine._storyline_process_for_ref = Mock(return_value=(4321, process_image))
    engine._clamp_after_storyline_process_source_create = Mock(return_value=event_time)
    spec = RegistryQueryEventSpec.model_validate(
        {
            "process_ref": "agent",
            "key": r"HKLM\HARDWARE\DESCRIPTION\System\BIOS",
            "value_name": "BIOSVendor",
            "source_metadata": {
                "category": "source_fact",
                "fact_ids": ["fact-bios-query"],
                "source_locations": [{"span_id": "span-0003-0123456789ab", "page_number": 3}],
                "field_sources": {
                    "key": {
                        "origin": "source",
                        "source_fact_ids": ["fact-bios-query"],
                        "source_span_ids": ["span-0003-0123456789ab"],
                    }
                },
                "expected_visibility": ["ecar"],
            },
        }
    )

    result = engine._execute_typed_event(
        spec=spec,
        actor=actor,
        system=system,
        time=event_time,
        activity="读取 BIOS 厂商信息",
        explicit_types={"registry_query"},
    )

    canonical_event = engine.dispatcher.dispatch.call_args.args[0]
    assert canonical_event.event_type == "registry_read"
    assert canonical_event.registry.action == "read"
    assert canonical_event.registry.key.endswith(r"BIOS\BIOSVendor")
    assert canonical_event.registry.value == ""
    assert result["type"] == "registry_query"
    assert result["registry_key"].endswith(r"BIOS\BIOSVendor")
    assert "registry_value" not in result
    assert result["source_metadata"]["fact_ids"] == ["fact-bios-query"]
