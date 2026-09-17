"""Fail-closed quality gates for report-derived scenario corpora.

Schema validation answers whether a scenario can be rendered.  These checks
answer a different question: whether high-confidence anti-patterns make the
scenario unsuitable for a contestant-facing quality corpus.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path, PureWindowsPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.utils import load_scenario_yaml

QUALITY_STANDARD_VERSION = "1.1"

ROLE_BEARING_TOKENS = (
    "ATK",
    "ATTACKER",
    "C2",
    "CNC",
    "VICTIM",
    "THREAT-ACTOR",
)
OPTIONAL_DETECTION_FORMATS = {
    "cisco_asa",
    "snort_alert",
    "suricata",
}
NON_EXECUTABLE_PROCESS_SUFFIXES = {
    ".aspx",
    ".cs",
    ".dll",
    ".doc",
    ".docm",
    ".docx",
    ".hta",
    ".js",
    ".lnk",
    ".pdf",
    ".ps1",
    ".rtf",
    ".swf",
    ".vba",
    ".vbs",
    ".xls",
    ".xlsm",
    ".xlsx",
}
EXECUTABLE_SUFFIXES = {
    ".bat",
    ".cmd",
    ".com",
    ".exe",
}
ARGUMENT_REQUIRED_INTERPRETERS = {
    "bitsadmin.exe",
    "certutil.exe",
    "cmd.exe",
    "cscript.exe",
    "mshta.exe",
    "powershell.exe",
    "pwsh.exe",
    "reg.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "sc.exe",
    "schtasks.exe",
    "wmic.exe",
    "wscript.exe",
}
PROCESS_REFERENCE_FIELDS = (
    "parent_ref",
    "process_ref",
    "source_process_ref",
)
MANUAL_REVIEW_RULES = (
    (
        "EFQ-M01",
        "verify source facts, activity, typed events, and actual log rows agree field by field",
        "storyline",
    ),
    (
        "EFQ-M02",
        "verify unknown facts were omitted or marked as training parameters, never invented",
        "storyline",
    ),
    (
        "EFQ-M03",
        "verify delivery, save, open, exploit, and execution are not collapsed into one action",
        "storyline.initial_access",
    ),
    (
        "EFQ-M04",
        "verify process image, full command line, references, and side effects describe one action",
        "storyline.process_tree",
    ),
    (
        "EFQ-M05",
        "verify asset roles, network direction, and endpoint purposes are correct",
        "storyline.network",
    ),
    (
        "EFQ-M06",
        "verify file, registry, image, service, and task owners and lifecycles are correct",
        "storyline.side_effects",
    ),
    (
        "EFQ-M07",
        "verify report, research, scenario-parameter, and engine-derived provenance is complete",
        "source_fact_matrix",
    ),
    (
        "EFQ-M08",
        "verify mutually exclusive report alternatives were not merged into one attack episode",
        "source_fact_matrix.alternatives",
    ),
    (
        "EFQ-M09",
        "join representative endpoint, network, mail, and web rows back to Ground Truth",
        "generated_evidence",
    ),
    (
        "EFQ-M10",
        "verify the contestant package contains only the agreed victim-side observables",
        "contestant_package",
    ),
)
PUBLIC_EXPLOIT_TECHNIQUE = "T1190"
_EXECUTABLE_IN_COMMAND = re.compile(
    r'(?i)^\s*(?:"([^"]+\.(?:bat|cmd|com|exe))"|(.+?\.(?:bat|cmd|com|exe)))'
    r"(?:\s|$)"
)
_ROLE_TOKEN_PATTERN = re.compile(
    r"(?:^|[-_.])(?:" + "|".join(re.escape(token) for token in ROLE_BEARING_TOKENS) + r")"
    r"(?:[-_.0-9]|$)",
    re.IGNORECASE,
)


class ScenarioQualityIssue(BaseModel):
    """One stable, actionable scenario-quality finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    severity: Literal["error", "warning", "manual"]
    message: str
    location: str


class ScenarioQualityResult(BaseModel):
    """Quality result for one scenario."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario: str
    path: str
    accepted: bool
    issues: list[ScenarioQualityIssue] = Field(default_factory=list)


class CorpusQualityReport(BaseModel):
    """Machine-readable preflight report for a scenario corpus."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.0"
    quality_standard_version: str = QUALITY_STANDARD_VERSION
    scenario_count: int
    accepted: bool
    blocking_issue_count: int
    warning_issue_count: int
    manual_review_item_count: int
    corpus_issues: list[ScenarioQualityIssue] = Field(default_factory=list)
    scenarios: list[ScenarioQualityResult] = Field(default_factory=list)


class GeneratedScenarioCommandStats(BaseModel):
    """Command-line diversity statistics for one generated scenario."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario: str
    process_create_count: int
    powershell_process_create_count: int
    unique_powershell_command_count: int
    bare_interpreter_count: int


class GeneratedCommandQualityReport(BaseModel):
    """Post-generation command-line quality report for a corpus."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.0"
    quality_standard_version: str = QUALITY_STANDARD_VERSION
    scenario_count: int
    accepted: bool
    blocking_issue_count: int
    powershell_process_create_count: int
    unique_powershell_command_count: int
    issues: list[ScenarioQualityIssue] = Field(default_factory=list)
    scenarios: list[GeneratedScenarioCommandStats] = Field(default_factory=list)


def _issue(
    rule_id: str,
    severity: Literal["error", "warning", "manual"],
    message: str,
    location: str,
) -> ScenarioQualityIssue:
    return ScenarioQualityIssue(
        rule_id=rule_id,
        severity=severity,
        message=message,
        location=location,
    )


def _has_role_bearing_token(value: str) -> bool:
    return bool(_ROLE_TOKEN_PATTERN.search(value))


def _windows_basename(value: str) -> str:
    return PureWindowsPath(value.strip().strip('"')).name.lower()


def _first_command_executable(command_line: str) -> str | None:
    stripped = command_line.strip()
    if not stripped:
        return None
    if stripped.startswith('"'):
        end_quote = stripped.find('"', 1)
        if end_quote > 1:
            return _windows_basename(stripped[1:end_quote])
    first_token = stripped.split(maxsplit=1)[0].strip('"')
    if not re.match(r"(?i)^[a-z]:\\", stripped):
        return _windows_basename(first_token)
    match = _EXECUTABLE_IN_COMMAND.match(stripped)
    if match is None:
        return _windows_basename(first_token)
    return _windows_basename(match.group(1) or match.group(2))


def is_bare_argument_required_interpreter(process_name: str, command_line: str) -> bool:
    """Return whether an interpreter/LOLBin command contains no action arguments."""
    process_basename = _windows_basename(process_name)
    if process_basename not in ARGUMENT_REQUIRED_INTERPRETERS:
        return False
    normalized_command = " ".join(command_line.split()).strip().strip('"').casefold()
    normalized_image = process_name.strip().strip('"').casefold()
    process_stem = PureWindowsPath(process_basename).stem.casefold()
    return normalized_command in {
        normalized_image,
        process_basename,
        process_stem,
    }


def _iter_storyline(
    scenario: dict[str, Any],
) -> list[tuple[int, dict[str, Any], int, dict[str, Any]]]:
    rows: list[tuple[int, dict[str, Any], int, dict[str, Any]]] = []
    for step_index, step in enumerate(scenario.get("storyline") or []):
        if not isinstance(step, dict):
            continue
        for event_index, event in enumerate(step.get("events") or []):
            if isinstance(event, dict):
                rows.append((step_index, step, event_index, event))
    return rows


def _event_location(step_index: int, event_index: int, event: dict[str, Any]) -> str:
    event_type = event.get("type", "unknown")
    return f"storyline[{step_index}].events[{event_index}]<{event_type}>"


def _audit_topology(scenario: dict[str, Any]) -> list[ScenarioQualityIssue]:
    issues: list[ScenarioQualityIssue] = []
    environment = scenario.get("environment") or {}
    systems = environment.get("systems") or []
    system_ips: dict[str, str] = {}
    for index, system in enumerate(systems):
        if not isinstance(system, dict):
            continue
        hostname = str(system.get("hostname") or "")
        if hostname and _has_role_bearing_token(hostname):
            issues.append(
                _issue(
                    "EFQ001",
                    "error",
                    f"enterprise system hostname reveals its answer-side role: {hostname!r}",
                    f"environment.systems[{index}].hostname",
                )
            )
        ip = str(system.get("ip") or "")
        if ip:
            system_ips[ip] = hostname

    external_ips: dict[str, str] = {}
    for index, identity in enumerate(environment.get("network_identities") or []):
        if not isinstance(identity, dict):
            continue
        tags = {str(tag).lower() for tag in identity.get("tags") or []}
        if not tags.intersection({"external", "c2", "attacker", "threat-actor"}):
            continue
        identity_id = str(identity.get("id") or f"network_identities[{index}]")
        for ip in identity.get("ips") or []:
            external_ips[str(ip)] = identity_id

    for ip in sorted(set(system_ips).intersection(external_ips)):
        issues.append(
            _issue(
                "EFQ002",
                "error",
                (
                    f"external identity {external_ips[ip]!r} reuses enterprise system IP {ip} "
                    f"({system_ips[ip]!r})"
                ),
                "environment",
            )
        )

    sensors = (environment.get("network") or {}).get("sensors") or []
    for index, sensor in enumerate(sensors):
        if not isinstance(sensor, dict):
            continue
        formats = {str(item).lower() for item in sensor.get("log_formats") or []}
        excluded = sorted(formats.intersection(OPTIONAL_DETECTION_FORMATS))
        if excluded:
            issues.append(
                _issue(
                    "EFQ003",
                    "error",
                    (
                        "contestant quality corpus enables optional firewall/detection sources: "
                        + ", ".join(excluded)
                    ),
                    f"environment.network.sensors[{index}].log_formats",
                )
            )

    output_formats = {
        str(log.get("format")).lower()
        for log in (scenario.get("output") or {}).get("logs") or []
        if isinstance(log, dict) and log.get("format")
    }
    excluded_output = sorted(output_formats.intersection(OPTIONAL_DETECTION_FORMATS))
    if excluded_output:
        issues.append(
            _issue(
                "EFQ003",
                "error",
                (
                    "contestant quality corpus requests optional firewall/detection output: "
                    + ", ".join(excluded_output)
                ),
                "output.logs",
            )
        )
    return issues


def _audit_storyline(scenario: dict[str, Any]) -> list[ScenarioQualityIssue]:
    issues: list[ScenarioQualityIssue] = []
    environment = scenario.get("environment") or {}
    system_types = {
        str(system.get("hostname")): str(system.get("type") or "").lower()
        for system in environment.get("systems") or []
        if isinstance(system, dict) and system.get("hostname")
    }
    process_definitions: dict[tuple[str, str], str] = {}
    reference_uses: list[tuple[str, str, str, str]] = []

    for step_index, step, event_index, event in _iter_storyline(scenario):
        location = _event_location(step_index, event_index, event)
        event_type = str(event.get("type") or "")
        system = str(step.get("system") or "")
        description = str(event.get("description") or "").strip()
        if not description:
            issues.append(
                _issue(
                    "EFQ004",
                    "error",
                    "typed event lacks an event-specific description",
                    f"{location}.description",
                )
            )

        serialized = " ".join(
            str(value)
            for key, value in event.items()
            if key in {"description", "process_name", "command_line", "process_ref"}
        ).lower()
        if "synthetic owner" in serialized or "synthetic anchor" in serialized:
            issues.append(
                _issue(
                    "EFQ005",
                    "error",
                    "synthetic process owner is rendered as malicious endpoint evidence",
                    location,
                )
            )

        process_name = str(event.get("process_name") or "")
        command_line = str(event.get("command_line") or "")
        if event_type == "process" and process_name:
            suffix = PureWindowsPath(process_name).suffix.lower()
            if suffix in NON_EXECUTABLE_PROCESS_SUFFIXES:
                issues.append(
                    _issue(
                        "EFQ006",
                        "error",
                        f"non-executable artifact is used as process image: {process_name!r}",
                        f"{location}.process_name",
                    )
                )

            process_basename = _windows_basename(process_name)
            command_executable = _first_command_executable(command_line)
            process_stem = PureWindowsPath(process_basename).stem
            command_stem = PureWindowsPath(command_executable).stem if command_executable else None
            if suffix in EXECUTABLE_SUFFIXES and command_line and command_executable is None:
                issues.append(
                    _issue(
                        "EFQ007",
                        "error",
                        (
                            "process command line does not start with an executable image; "
                            f"process={process_basename!r}, command_line={command_line!r}"
                        ),
                        f"{location}.command_line",
                    )
                )
            elif (
                suffix in EXECUTABLE_SUFFIXES
                and command_executable is not None
                and command_stem != process_stem
            ):
                issues.append(
                    _issue(
                        "EFQ007",
                        "error",
                        (
                            "process image and command-line executable disagree; "
                            f"process={process_basename!r}, command={command_executable!r}"
                        ),
                        f"{location}.command_line",
                    )
                )

            command_lower = command_line.lower()
            if process_basename == "outlook.exe" and (
                "/c ipm.note" in command_lower or "/a " in command_lower
            ):
                issues.append(
                    _issue(
                        "EFQ008",
                        "error",
                        "Outlook compose switches cannot represent phishing-email delivery",
                        f"{location}.command_line",
                    )
                )

            if is_bare_argument_required_interpreter(process_name, command_line):
                issues.append(
                    _issue(
                        "EFQ029",
                        "error",
                        (
                            "argument-requiring interpreter/LOLBin has no action arguments; "
                            f"process={process_basename!r}, command_line={command_line!r}"
                        ),
                        f"{location}.command_line",
                    )
                )

            process_ref = str(event.get("process_ref") or "")
            if process_ref:
                key = (system, process_ref)
                if key in process_definitions:
                    issues.append(
                        _issue(
                            "EFQ009",
                            "error",
                            (
                                f"process_ref {process_ref!r} is defined more than once on "
                                f"{system!r}"
                            ),
                            f"{location}.process_ref",
                        )
                    )
                else:
                    process_definitions[key] = location

        technique = str(event.get("technique") or "")
        if technique.startswith(PUBLIC_EXPLOIT_TECHNIQUE) and system_types.get(system) in {
            "workstation",
            "desktop",
            "laptop",
        }:
            issues.append(
                _issue(
                    "EFQ010",
                    "error",
                    (
                        f"public-facing exploit T1190 is assigned to workstation {system!r}; "
                        "model the public service target and inbound direction"
                    ),
                    location,
                )
            )

        for field in PROCESS_REFERENCE_FIELDS:
            ref = str(event.get(field) or "")
            if not ref:
                continue
            if event_type == "process" and field == "process_ref":
                continue
            reference_uses.append((system, ref, location, field))

    for system, ref, location, field in reference_uses:
        if (system, ref) not in process_definitions:
            issues.append(
                _issue(
                    "EFQ011",
                    "error",
                    f"{field} {ref!r} has no process definition on system {system!r}",
                    f"{location}.{field}",
                )
            )

    issues.extend(
        _issue(rule_id, "manual", message, location)
        for rule_id, message, location in MANUAL_REVIEW_RULES
    )
    return issues


def audit_scenario_definition(path: Path) -> ScenarioQualityResult:
    """Audit one scenario definition using high-confidence release rules."""
    resolved = path.resolve()
    scenario = load_scenario_yaml(resolved)
    issues = _audit_topology(scenario)
    issues.extend(_audit_storyline(scenario))
    issues.sort(key=lambda item: (item.location, item.rule_id, item.message))
    return ScenarioQualityResult(
        scenario=str(scenario.get("name") or resolved.parent.name),
        path=str(resolved),
        accepted=not any(issue.severity == "error" for issue in issues),
        issues=issues,
    )


def _parse_relative_minutes(value: object) -> float | None:
    if not isinstance(value, str) or not value.startswith("+"):
        return None
    match = re.fullmatch(r"\+(\d+(?:\.\d+)?)([smhd])", value.strip())
    if match is None:
        return None
    amount = float(match.group(1))
    return amount * {"s": 1 / 60, "m": 1, "h": 60, "d": 1440}[match.group(2)]


def _audit_corpus_patterns(
    paths: list[Path],
    loaded: dict[Path, dict[str, Any]],
) -> tuple[list[ScenarioQualityIssue], dict[str, list[ScenarioQualityIssue]]]:
    corpus_issues: list[ScenarioQualityIssue] = []
    scenario_issues: dict[str, list[ScenarioQualityIssue]] = defaultdict(list)
    process_count = 0
    powershell_count = 0
    process_commands: Counter[str] = Counter()
    storyline_systems: Counter[str] = Counter()
    beacon_profiles: Counter[tuple[str, str, str]] = Counter()
    beacon_owners: dict[tuple[str, str, str], set[str]] = defaultdict(set)

    for path in paths:
        scenario = loaded[path]
        name = str(scenario.get("name") or path.parent.name)
        relative_times: list[float] = []
        for _, step, _, event in _iter_storyline(scenario):
            system = str(step.get("system") or "")
            if system:
                storyline_systems[system] += 1
            if event.get("type") == "process":
                process_count += 1
                process_name = _windows_basename(str(event.get("process_name") or ""))
                if process_name in {"powershell.exe", "pwsh.exe"}:
                    powershell_count += 1
                command = " ".join(str(event.get("command_line") or "").lower().split())
                if command:
                    process_commands[command] += 1
            if event.get("type") == "beacon":
                profile = (
                    str(event.get("interval") or ""),
                    str(event.get("duration") or ""),
                    str(event.get("jitter") or ""),
                )
                beacon_profiles[profile] += 1
                beacon_owners[profile].add(name)
        for step in scenario.get("storyline") or []:
            if not isinstance(step, dict):
                continue
            minute = _parse_relative_minutes(step.get("time"))
            if minute is not None:
                relative_times.append(minute)
        deltas = [
            current - previous
            for previous, current in zip(relative_times, relative_times[1:], strict=False)
        ]
        if len(deltas) >= 3:
            six_minute_count = sum(abs(delta - 6) < 1e-9 for delta in deltas)
            if six_minute_count / len(deltas) >= 0.6:
                scenario_issues[name].append(
                    _issue(
                        "EFQ012",
                        "error",
                        (
                            f"{six_minute_count}/{len(deltas)} adjacent storyline gaps are "
                            "exactly six minutes; timing is compiler cadence, not causal timing"
                        ),
                        "storyline[*].time",
                    )
                )

    if process_count >= 20 and powershell_count / process_count > 0.35:
        corpus_issues.append(
            _issue(
                "EFQ013",
                "error",
                (
                    f"PowerShell owns {powershell_count}/{process_count} process events "
                    "(>35% corpus ceiling)"
                ),
                "corpus.storyline.process",
            )
        )

    if process_count >= 20 and process_commands:
        command, count = process_commands.most_common(1)[0]
        if count / process_count > 0.1:
            corpus_issues.append(
                _issue(
                    "EFQ014",
                    "error",
                    (
                        f"one command line owns {count}/{process_count} process events "
                        f"(>10% corpus ceiling): {command!r}"
                    ),
                    "corpus.storyline.process.command_line",
                )
            )

    total_storyline_placements = sum(storyline_systems.values())
    if total_storyline_placements >= 50 and storyline_systems:
        system, count = storyline_systems.most_common(1)[0]
        if count / total_storyline_placements > 0.75:
            corpus_issues.append(
                _issue(
                    "EFQ015",
                    "error",
                    (
                        f"system {system!r} owns {count}/{total_storyline_placements} typed "
                        "events (>75% corpus ceiling)"
                    ),
                    "corpus.storyline.system",
                )
            )

    beacon_total = sum(beacon_profiles.values())
    if beacon_total >= 5 and beacon_profiles:
        profile, count = beacon_profiles.most_common(1)[0]
        if count / beacon_total > 0.5:
            issue = _issue(
                "EFQ016",
                "error",
                (
                    f"beacon profile interval/duration/jitter={profile!r} owns "
                    f"{count}/{beacon_total} beacons (>50% corpus ceiling)"
                ),
                "corpus.storyline.beacon",
            )
            corpus_issues.append(issue)
            for name in beacon_owners[profile]:
                scenario_issues[name].append(issue)

    return corpus_issues, scenario_issues


def audit_scenario_corpus(paths: list[Path]) -> CorpusQualityReport:
    """Audit scenario definitions and corpus-level concentration patterns."""
    stable_paths = sorted((path.resolve() for path in paths), key=lambda item: str(item))
    loaded = {path: load_scenario_yaml(path) for path in stable_paths}
    results = [audit_scenario_definition(path) for path in stable_paths]
    corpus_issues, per_scenario = _audit_corpus_patterns(stable_paths, loaded)

    merged_results: list[ScenarioQualityResult] = []
    for result in results:
        extra = per_scenario.get(result.scenario, [])
        issues = sorted(
            [*result.issues, *extra],
            key=lambda item: (item.location, item.rule_id, item.message),
        )
        merged_results.append(
            result.model_copy(
                update={
                    "accepted": not any(issue.severity == "error" for issue in issues),
                    "issues": issues,
                }
            )
        )

    all_issues = [*corpus_issues]
    all_issues.extend(issue for result in merged_results for issue in result.issues)
    blocking = sum(issue.severity == "error" for issue in all_issues)
    warnings = sum(issue.severity == "warning" for issue in all_issues)
    manual = sum(issue.severity == "manual" for issue in all_issues)
    return CorpusQualityReport(
        scenario_count=len(merged_results),
        accepted=blocking == 0,
        blocking_issue_count=blocking,
        warning_issue_count=warnings,
        manual_review_item_count=manual,
        corpus_issues=sorted(
            corpus_issues,
            key=lambda item: (item.location, item.rule_id, item.message),
        ),
        scenarios=merged_results,
    )


def audit_generated_command_corpus(
    scenario_output_dirs: list[Path],
) -> GeneratedCommandQualityReport:
    """Audit final eCAR PROCESS/CREATE rows for bare and concentrated commands."""
    stable_dirs = sorted(
        (path.resolve() for path in scenario_output_dirs if (path / "data").is_dir()),
        key=lambda item: str(item),
    )
    issues: list[ScenarioQualityIssue] = []
    scenario_stats: list[GeneratedScenarioCommandStats] = []
    powershell_commands: Counter[str] = Counter()
    command_owners: dict[str, set[str]] = defaultdict(set)

    for output_dir in stable_dirs:
        process_create_count = 0
        powershell_process_create_count = 0
        bare_interpreter_count = 0
        scenario_powershell_commands: set[str] = set()
        examples: list[str] = []
        for path in sorted((output_dir / "data").glob("*/ecar.json")):
            with path.open(encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, start=1):
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if event.get("object") != "PROCESS" or event.get("action") != "CREATE":
                        continue
                    process_create_count += 1
                    properties = event.get("properties") or {}
                    image = str(properties.get("image_path") or "")
                    command = " ".join(str(properties.get("command_line") or "").split())
                    image_basename = _windows_basename(image)
                    if image_basename in {"powershell.exe", "pwsh.exe"}:
                        powershell_process_create_count += 1
                        scenario_powershell_commands.add(command)
                        powershell_commands[command] += 1
                        command_owners[command].add(output_dir.name)
                    if is_bare_argument_required_interpreter(image, command):
                        bare_interpreter_count += 1
                        if len(examples) < 3:
                            examples.append(f"{path.name}:{line_number} {command!r}")

        if bare_interpreter_count:
            issues.append(
                _issue(
                    "EFQ029",
                    "error",
                    (
                        f"{output_dir.name!r} contains {bare_interpreter_count} bare "
                        "argument-requiring interpreter PROCESS/CREATE rows; examples: "
                        + "; ".join(examples)
                    ),
                    str(output_dir / "data"),
                )
            )
        scenario_stats.append(
            GeneratedScenarioCommandStats(
                scenario=output_dir.name,
                process_create_count=process_create_count,
                powershell_process_create_count=powershell_process_create_count,
                unique_powershell_command_count=len(scenario_powershell_commands),
                bare_interpreter_count=bare_interpreter_count,
            )
        )

    powershell_total = sum(powershell_commands.values())
    if len(stable_dirs) >= 3 and powershell_total >= 50 and powershell_commands:
        command, count = powershell_commands.most_common(1)[0]
        minimum_owners = math.ceil(len(stable_dirs) / 2)
        owners = command_owners[command]
        if count / powershell_total > 0.1 and len(owners) >= minimum_owners:
            issues.append(
                _issue(
                    "EFQ030",
                    "error",
                    (
                        f"one exact PowerShell command owns {count}/{powershell_total} "
                        f"PROCESS/CREATE rows across {len(owners)}/{len(stable_dirs)} scenarios: "
                        f"{command!r}"
                    ),
                    "generated_corpus.data/*/ecar.json",
                )
            )

    issues.sort(key=lambda item: (item.location, item.rule_id, item.message))
    blocking = sum(issue.severity == "error" for issue in issues)
    return GeneratedCommandQualityReport(
        scenario_count=len(stable_dirs),
        accepted=blocking == 0,
        blocking_issue_count=blocking,
        powershell_process_create_count=powershell_total,
        unique_powershell_command_count=len(powershell_commands),
        issues=issues,
        scenarios=scenario_stats,
    )
