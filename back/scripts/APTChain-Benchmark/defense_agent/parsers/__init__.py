"""Parsers package — multi-source heterogeneous log → CanonicalEvent."""

from .base import CanonicalEvent, parse_timestamp
from .ecar import parse_ecar
from .loader import load_scenario
from .syslog_linux import parse_syslog
from .windows_security import parse_windows_xml
from .zeek import parse_zeek_file

__all__ = [
    "CanonicalEvent",
    "parse_timestamp",
    "parse_ecar",
    "parse_syslog",
    "parse_windows_xml",
    "parse_zeek_file",
    "load_scenario",
]