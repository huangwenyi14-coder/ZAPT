"""Run reproducible, isolated smoke tests against each locked upstream source tree."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parent
NATIVE_ENVIRONMENTS_ROOT = ROOT / "envs" / "native"


class MethodConfig(BaseModel):
    """Native source probe configuration."""

    model_config = ConfigDict(extra="forbid")

    id: str
    python_version: str
    source_subdir: str
    workdir: str
    probe: list[str]
    dependency_source: str
    native_platform: str
    requirements: str | None = None
    compile_excludes: list[str] = Field(default_factory=list)


class MethodCatalog(BaseModel):
    """Catalog of upstream methods to test."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str
    methods: list[MethodConfig]


def run_command(command: list[str], cwd: Path, timeout_seconds: int) -> dict[str, Any]:
    """Run one command and retain its exact evidence without raising."""
    started = time.monotonic()
    try:
        process = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        return {
            "command": command,
            "cwd": str(cwd),
            "exit_code": process.returncode,
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout": process.stdout,
            "stderr": process.stderr,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "cwd": str(cwd),
            "exit_code": None,
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "timed_out": True,
        }


def native_environment(method_id: str) -> Path:
    """Return the isolated source-native probe environment path."""
    return NATIVE_ENVIRONMENTS_ROOT / method_id


def create_environment(method: MethodConfig) -> dict[str, Any]:
    """Create the method's own empty uv environment using its documented Python."""
    environment = native_environment(method.id)
    command = [
        "uv",
        "venv",
        "--python",
        method.python_version,
        "--clear",
        str(environment),
    ]
    result = run_command(command, REPOSITORY_ROOT, timeout_seconds=300)
    result["environment"] = str(environment)
    return result


def compile_source(method: MethodConfig, python: Path) -> dict[str, Any]:
    """Compile first-party Python files while excluding explicitly vendored trees."""
    source = ROOT / "third_party" / method.source_subdir
    candidates = [
        path
        for path in source.rglob("*.py")
        if ".git" not in path.parts
        and not any(excluded in path.parts for excluded in method.compile_excludes)
    ]
    command = [str(python), "-m", "py_compile", *[str(path) for path in candidates]]
    return run_command(command, source, timeout_seconds=300)


def resolve_requirements(method: MethodConfig, python: Path) -> dict[str, Any] | None:
    """Ask uv to resolve the unmodified upstream requirements for this host."""
    if method.requirements is None:
        return None
    source = ROOT / "third_party" / method.source_subdir
    requirements = source / method.requirements
    command = [
        "uv",
        "pip",
        "install",
        "--dry-run",
        "--python",
        str(python),
        "--requirements",
        str(requirements),
    ]
    return run_command(command, source, timeout_seconds=300)


def probe_source(method: MethodConfig, python: Path) -> dict[str, Any]:
    """Execute the upstream entry point without modifying the checkout."""
    source = ROOT / "third_party" / method.source_subdir
    workdir = (source / method.workdir).resolve()
    return run_command([str(python), *method.probe], workdir, timeout_seconds=60)


def load_catalog() -> MethodCatalog:
    """Load and validate the native method catalog."""
    raw = json.loads((ROOT / "native_methods.json").read_text(encoding="utf-8"))
    return MethodCatalog.model_validate(raw)


def load_locked_refs() -> dict[str, str]:
    """Return expected commit IDs keyed by method ID."""
    raw = json.loads((ROOT / "source_lock.json").read_text(encoding="utf-8"))
    return {item["id"]: item["ref"] for item in raw["sources"]}


def test_method(method: MethodConfig, expected_ref: str) -> dict[str, Any]:
    """Run source-integrity, syntax, dependency, and entry-point probes."""
    source = ROOT / "third_party" / method.source_subdir
    environment_result = create_environment(method)
    python = native_environment(method.id) / "bin" / "python"
    revision = run_command(["git", "rev-parse", "HEAD"], source, timeout_seconds=30)
    current_ref = revision["stdout"].strip()
    result: dict[str, Any] = {
        "method": method.id,
        "source": str(source),
        "expected_ref": expected_ref,
        "current_ref": current_ref,
        "ref_matches": revision["exit_code"] == 0 and current_ref == expected_ref,
        "dependency_source": method.dependency_source,
        "native_platform": method.native_platform,
        "environment": environment_result,
        "revision": revision,
    }
    if environment_result["exit_code"] != 0 or not python.exists():
        result["syntax"] = None
        result["dependency_resolution"] = None
        result["entrypoint_probe"] = None
        result["status"] = "environment_failed"
        return result
    result["syntax"] = compile_source(method, python)
    result["dependency_resolution"] = resolve_requirements(method, python)
    result["entrypoint_probe"] = probe_source(method, python)
    if result["entrypoint_probe"]["exit_code"] == 0:
        result["status"] = "entrypoint_ready"
    elif result["dependency_resolution"] is None:
        result["status"] = "dependency_manifest_missing"
    elif result["dependency_resolution"]["exit_code"] != 0:
        result["status"] = "native_dependencies_incompatible"
    else:
        result["status"] = "dependencies_resolve_but_not_installed"
    return result


def write_markdown(results: list[dict[str, Any]], target: Path) -> None:
    """Write a compact human-readable source smoke-test table."""
    lines = [
        "# Native Source Smoke Tests",
        "",
        f"Host: `{platform.platform()}` / `{platform.machine()}`.",
        "",
        "These are unmodified-source tests. A successful syntax check is not a detector run; "
        "the entry-point and seven-dataset stages are tracked separately.",
        "",
        "| Method | Locked ref | Syntax | Native requirements | Entry point | Status |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for result in results:
        syntax = result.get("syntax")
        dependency = result.get("dependency_resolution")
        probe = result.get("entrypoint_probe")
        lines.append(
            "| {method} | {ref} | {syntax} | {dependency} | {probe} | `{status}` |".format(
                method=result["method"],
                ref="yes" if result["ref_matches"] else "no",
                syntax="pass" if syntax and syntax["exit_code"] == 0 else "fail",
                dependency=(
                    "missing manifest"
                    if dependency is None
                    else ("resolves" if dependency["exit_code"] == 0 else "incompatible")
                ),
                probe="pass" if probe and probe["exit_code"] == 0 else "fail",
                status=result["status"],
            )
        )
    lines.extend(
        [
            "",
            "Exact commands, stdout, stderr, exit codes, and timings are retained in "
            "`native_smoke.json`.",
            "",
        ]
    )
    target.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    """Run selected native source probes and write auditable results."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--method", action="append", dest="methods")
    args = parser.parse_args()

    catalog = load_catalog()
    locked_refs = load_locked_refs()
    selected = set(args.methods or [method.id for method in catalog.methods])
    unknown = selected - {method.id for method in catalog.methods}
    if unknown:
        parser.error(f"unknown methods: {', '.join(sorted(unknown))}")

    new_results = [
        test_method(method, locked_refs[method.id])
        for method in catalog.methods
        if method.id in selected
    ]
    result_dir = ROOT / "results" / "source_native"
    result_dir.mkdir(parents=True, exist_ok=True)
    result_path = result_dir / "native_smoke.json"
    if args.methods and result_path.exists():
        previous = json.loads(result_path.read_text(encoding="utf-8"))
        results_by_method = {
            str(result["method"]): result for result in previous.get("results", [])
        }
        results_by_method.update({str(result["method"]): result for result in new_results})
        results = [
            results_by_method[method.id]
            for method in catalog.methods
            if method.id in results_by_method
        ]
    else:
        results = new_results
    output = {
        "schema_version": "1.0",
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": sys.version,
        },
        "results": results,
    }
    result_path.write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    write_markdown(results, result_dir / "README.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
