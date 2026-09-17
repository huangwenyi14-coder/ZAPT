"""Top-level scenario loader.

`load_scenario(scenario_dir)` walks `scenario_dir/data/*` and dispatches each
file to its parser based on filename. Returns:
- canonical_events: List[CanonicalEvent] (chronologically sorted)
- scenario_name: str
- host_dirs: List[Path]
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from .base import CanonicalEvent
from .ecar import parse_ecar
from .syslog_linux import parse_syslog
from .windows_security import parse_windows_xml
from .zeek import parse_zeek_file


def _is_hidden(p: Path) -> bool:
    return any(part.startswith(".") for part in p.parts)


def _iter_data_files(scenario_dir: Path) -> Iterator[tuple[str, Path]]:
    """Yield (subdir_host, file_path) for every parser-supported file under data/.

    `subdir_host` is the immediate parent directory name under data/, used only for logging.
    """
    data_dir = scenario_dir / "data"
    if not data_dir.exists():
        return
    for host_dir in sorted(data_dir.iterdir()):
        if not host_dir.is_dir() or _is_hidden(host_dir):
            continue
        for f in sorted(host_dir.iterdir()):
            if not f.is_file() or _is_hidden(f):
                continue
            yield (host_dir.name, f)


def _parse_file(host: str, path: Path) -> Iterator[CanonicalEvent]:
    name = path.name
    if name == "ecar.json":
        yield from parse_ecar(path)
    elif name == "syslog.log":
        yield from parse_syslog(path)
    elif name in ("windows_event_security.xml", "windows_event_sysmon.xml"):
        yield from parse_windows_xml(path)
    elif name.startswith("zeek_") or name in (
        "conn.json", "dns.json", "http.json", "files.json",
        "ssl.json", "x509.json", "dhcp.json", "ntp.json", "ocsp.json", "pe.json",
    ):
        yield from parse_zeek_file(path)


def load_scenario(scenario_dir: str | Path) -> tuple[str, list[CanonicalEvent]]:
    """Load all canonical events for a scenario, sorted by timestamp."""
    sd = Path(scenario_dir)
    name = sd.name
    events: list[CanonicalEvent] = []
    for host_dir_name, f in _iter_data_files(sd):
        for ev in _parse_file(host_dir_name, f):
            # Some parsers don't always set host; fall back to host_dir
            if not ev.host:
                ev = ev.with_extra(host=host_dir_name)
            events.append(ev)
    events.sort(key=lambda e: (e.timestamp or _epoch_zero()))
    return name, events


def _epoch_zero():
    from datetime import datetime, timezone
    return datetime(1970, 1, 1, tzinfo=timezone.utc)