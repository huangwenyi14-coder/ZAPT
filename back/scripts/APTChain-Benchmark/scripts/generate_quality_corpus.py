#!/usr/bin/env python3
"""Generate a validated scenario corpus with resumable per-scenario jobs.

Each scenario is generated into its own output directory. EvidenceForge's
transactional writer keeps the old result intact until a new run succeeds, and
this runner records a completion marker only after generation plus leakage
checks both pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import signal
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

from evidenceforge.validation.scenario_quality import (
    QUALITY_STANDARD_VERSION,
    audit_generated_command_corpus,
    audit_scenario_corpus,
)

FORBIDDEN_PUBLIC_TOKENS = (
    "ATK-LNX-01",
    "C2-SERVER-01",
    "WS-VICTIM-01",
    "LNX-VICTIM-01",
    "external-threat-actor.example",
    "victim@target-org.example",
    "attachment.bin",
)
FORBIDDEN_PUBLIC_FILENAMES = {
    "cisco_asa.log",
    "snort_alert.log",
}
COMPLETION_MARKER = ".quality-generation.json"
_ACTIVE_PROCESSES: set[subprocess.Popen[str]] = set()
_ACTIVE_PROCESSES_LOCK = threading.Lock()
_STOP_EVENT = threading.Event()


def discover_scenarios(root: Path) -> list[Path]:
    """Return direct child scenario files in stable slug order."""
    return sorted(root.glob("*/scenario.yaml"), key=lambda path: path.parent.name)


def audit_generated_data(data_dir: Path) -> list[str]:
    """Return leakage errors found in one generated ``data/`` directory."""
    issues: list[str] = []
    if not data_dir.is_dir():
        return [f"missing generated data directory: {data_dir}"]

    forbidden_names = {
        "GROUND_TRUTH.md",
        "GROUND_TRUTH.json",
        "GOLD_LABEL.json",
        "RECORD_GROUND_TRUTH.jsonl",
    }
    for path in sorted(data_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name.lower() in FORBIDDEN_PUBLIC_FILENAMES:
            issues.append(f"excluded optional firewall/IDS source inside data/: {path}")
            continue
        if path.name in forbidden_names or path.name.endswith(".labels.json"):
            issues.append(f"private label/ground-truth artifact inside data/: {path}")
            continue
        encoded_tokens = tuple(token.encode() for token in FORBIDDEN_PUBLIC_TOKENS)
        overlap_size = max(map(len, encoded_tokens)) - 1
        overlap = b""
        found_tokens: set[str] = set()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                payload = overlap + chunk
                for token, encoded in zip(FORBIDDEN_PUBLIC_TOKENS, encoded_tokens, strict=True):
                    if token not in found_tokens and encoded in payload:
                        issues.append(f"forbidden token {token!r} in {path}")
                        found_tokens.add(token)
                if len(found_tokens) == len(FORBIDDEN_PUBLIC_TOKENS):
                    break
                overlap = payload[-overlap_size:] if overlap_size else b""
    return issues


def _write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _is_complete(output_dir: Path, scenario_path: Path) -> bool:
    marker = output_dir / COMPLETION_MARKER
    if not marker.is_file():
        return False
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    return (
        payload.get("status") == "complete"
        and payload.get("scenario") == scenario_path.parent.name
        and payload.get("scenario_sha256") == _scenario_digest(scenario_path)
        and payload.get("quality_standard_version") == QUALITY_STANDARD_VERSION
        and (output_dir / "data").is_dir()
    )


def _scenario_digest(scenario_path: Path) -> str:
    """Return the scenario source digest recorded by completion markers."""
    return hashlib.sha256(scenario_path.read_bytes()).hexdigest()


def generate_one(
    scenario_path: Path,
    output_root: Path,
    log_root: Path,
    *,
    resume: bool,
) -> dict:
    """Generate and audit one scenario, returning a serializable status row."""
    slug = scenario_path.parent.name
    output_dir = output_root / slug
    started_at = datetime.now(UTC)
    if resume and _is_complete(output_dir, scenario_path):
        return {
            "scenario": slug,
            "status": "skipped_complete",
            "started_at": started_at.isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
        }

    eforge = Path(sys.executable).parent / "eforge"
    command = [
        str(eforge),
        "generate",
        str(scenario_path),
        "--output",
        str(output_dir),
        "--force",
    ]
    if _STOP_EVENT.is_set():
        return {
            "scenario": slug,
            "status": "cancelled",
            "started_at": started_at.isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
        }
    process = subprocess.Popen(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    with _ACTIVE_PROCESSES_LOCK:
        _ACTIVE_PROCESSES.add(process)
    try:
        stdout, stderr = process.communicate()
    finally:
        with _ACTIVE_PROCESSES_LOCK:
            _ACTIVE_PROCESSES.discard(process)
    log_root.mkdir(parents=True, exist_ok=True)
    log_path = log_root / f"{slug}.log"
    log_path.write_text(stdout + stderr, encoding="utf-8")

    completed_at = datetime.now(UTC)
    if process.returncode != 0:
        return {
            "scenario": slug,
            "status": "generation_failed",
            "returncode": process.returncode,
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "log": str(log_path),
        }

    leakage_issues = audit_generated_data(output_dir / "data")
    if leakage_issues:
        return {
            "scenario": slug,
            "status": "leakage_audit_failed",
            "issues": leakage_issues[:100],
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "log": str(log_path),
        }

    marker_payload = {
        "schema_version": "1.0",
        "scenario": slug,
        "status": "complete",
        "quality_standard_version": QUALITY_STANDARD_VERSION,
        "scenario_file": str(scenario_path.resolve()),
        "scenario_sha256": _scenario_digest(scenario_path),
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
    }
    _write_json_atomic(output_dir / COMPLETION_MARKER, marker_payload)
    return {
        **marker_payload,
        "log": str(log_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenarios_root", type=Path)
    parser.add_argument("output_root", type=Path)
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Concurrent generators (default: 4; long scenarios can approach 2-3 GB RAM each).",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Regenerate scenarios even when a valid completion marker exists.",
    )
    args = parser.parse_args()

    scenarios_root = args.scenarios_root.resolve()
    output_root = args.output_root.resolve()
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    scenarios = discover_scenarios(scenarios_root)
    if not scenarios:
        parser.error(f"no direct child scenario.yaml files found under {scenarios_root}")

    batch_root = output_root / "_batch"
    log_root = batch_root / "logs"
    state_path = batch_root / "state.json"
    quality_preflight_path = batch_root / "quality-preflight.json"
    output_root.mkdir(parents=True, exist_ok=True)

    quality_report = audit_scenario_corpus(scenarios)
    _write_json_atomic(
        quality_preflight_path,
        quality_report.model_dump(mode="json"),
    )
    print(f"quality preflight: {quality_preflight_path}")
    if not quality_report.accepted:
        print(
            "quality preflight failed: "
            f"{quality_report.blocking_issue_count} blocking issue(s); generation not started"
        )
        return 1

    rows: list[dict] = []
    rows_lock = threading.Lock()
    executor = ThreadPoolExecutor(max_workers=args.workers)
    interrupted = False
    try:
        futures = {
            executor.submit(
                generate_one,
                scenario,
                output_root,
                log_root,
                resume=not args.no_resume,
            ): scenario
            for scenario in scenarios
        }
        for future in as_completed(futures):
            row = future.result()
            with rows_lock:
                rows.append(row)
                rows.sort(key=lambda item: item["scenario"])
                state = {
                    "schema_version": "1.0",
                    "scenario_count": len(scenarios),
                    "finished_count": len(rows),
                    "complete_count": sum(
                        item["status"] in {"complete", "skipped_complete"} for item in rows
                    ),
                    "failed_count": sum(
                        item["status"] not in {"complete", "skipped_complete"} for item in rows
                    ),
                    "updated_at": datetime.now(UTC).isoformat(),
                    "scenarios": rows,
                }
                _write_json_atomic(state_path, state)
            print(
                f"[{len(rows):03d}/{len(scenarios):03d}] {row['scenario']}: {row['status']}",
                flush=True,
            )
    except KeyboardInterrupt:
        interrupted = True
        _STOP_EVENT.set()
        with _ACTIVE_PROCESSES_LOCK:
            active_processes = list(_ACTIVE_PROCESSES)
        for process in active_processes:
            if process.poll() is None:
                try:
                    process.send_signal(signal.SIGTERM)
                except ProcessLookupError:
                    pass
        executor.shutdown(wait=False, cancel_futures=True)
        print("interrupted: active generators terminated; rerun to resume", flush=True)
    finally:
        if not interrupted:
            executor.shutdown(wait=True)

    if interrupted:
        return 130

    failed = [row for row in rows if row["status"] not in {"complete", "skipped_complete"}]
    if not failed:
        generated_command_report = audit_generated_command_corpus(
            [output_root / scenario.parent.name for scenario in scenarios]
        )
        generated_command_path = batch_root / "generated-command-quality.json"
        _write_json_atomic(
            generated_command_path,
            generated_command_report.model_dump(mode="json"),
        )
        print(f"generated command quality: {generated_command_path}")
        if not generated_command_report.accepted:
            print(
                "generated command quality failed: "
                f"{generated_command_report.blocking_issue_count} blocking issue(s)"
            )
            return 1
    print(f"state: {state_path}")
    print(f"complete: {len(rows) - len(failed)}/{len(rows)}")
    print(f"failed: {len(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
