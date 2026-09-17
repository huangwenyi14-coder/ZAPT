"""Rebuild the portable EvidenceForge provenance-baseline environments."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

BASELINES_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = BASELINES_ROOT.parent
MANIFEST_PATH = BASELINES_ROOT / "adapter_environments.json"
SOURCE_LOCK_PATH = BASELINES_ROOT / "source_lock.json"
DEFAULT_REPORT = BASELINES_ROOT / "work" / "environment-reset" / "report.json"


@dataclass(frozen=True)
class ArtifactSpec:
    """One external file required by an adapted detector."""

    path: str
    sha256: str


@dataclass(frozen=True)
class MethodSpec:
    """Portable environment and source contract for one detector adapter."""

    id: str
    python_version: str
    environment: str
    requirements: str
    module: str
    sources: tuple[str, ...]
    patches: tuple[str, ...]
    probe: str
    artifacts: tuple[ArtifactSpec, ...] = ()


@dataclass
class CommandRecord:
    """Auditable result of one external command."""

    command: list[str]
    cwd: str
    exit_code: int | None
    duration_seconds: float
    dry_run: bool
    stdout: str = ""
    stderr: str = ""


@dataclass
class MethodResult:
    """Environment readiness result for one detector."""

    id: str
    environment: str
    status: str = "pending"
    errors: list[str] = field(default_factory=list)
    python_version: str | None = None


class CommandRunner:
    """Run commands while retaining a compact machine-readable audit trail."""

    def __init__(self, *, dry_run: bool) -> None:
        self.dry_run = dry_run
        self.records: list[CommandRecord] = []

    def run(
        self,
        command: list[str],
        *,
        cwd: Path = REPOSITORY_ROOT,
        environment: dict[str, str] | None = None,
        capture_output: bool = False,
    ) -> CommandRecord:
        """Run one command and return its non-raising result."""
        print(f"$ {shlex.join(command)}", flush=True)
        if self.dry_run:
            record = CommandRecord(command, str(cwd), 0, 0.0, True)
            self.records.append(record)
            return record

        started = time.monotonic()
        process = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            check=False,
            text=True,
            capture_output=capture_output,
        )
        record = CommandRecord(
            command=command,
            cwd=str(cwd),
            exit_code=process.returncode,
            duration_seconds=round(time.monotonic() - started, 3),
            dry_run=False,
            stdout=process.stdout if capture_output else "",
            stderr=process.stderr if capture_output else "",
        )
        self.records.append(record)
        return record


def resolve_inside(root: Path, relative: str) -> Path:
    """Resolve a manifest path and reject traversal outside its owning root."""
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ValueError(f"path escapes {root}: {relative}")
    return candidate


def load_manifest(path: Path = MANIFEST_PATH) -> list[MethodSpec]:
    """Load and validate the adapter environment manifest."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != "1.0":
        raise ValueError(f"unsupported adapter environment schema: {payload.get('schema_version')}")

    methods: list[MethodSpec] = []
    for raw in payload.get("methods", []):
        artifacts = tuple(ArtifactSpec(**item) for item in raw.get("artifacts", []))
        method = MethodSpec(
            id=str(raw["id"]),
            python_version=str(raw["python_version"]),
            environment=str(raw["environment"]),
            requirements=str(raw["requirements"]),
            module=str(raw["module"]),
            sources=tuple(str(item) for item in raw.get("sources", [])),
            patches=tuple(str(item) for item in raw.get("patches", [])),
            probe=str(raw["probe"]),
            artifacts=artifacts,
        )
        if Path(method.environment).name != method.environment:
            raise ValueError(f"environment must be one directory name: {method.environment}")
        requirements = resolve_inside(BASELINES_ROOT, method.requirements)
        if not requirements.is_file():
            raise FileNotFoundError(f"requirements file is missing: {requirements}")
        for patch in method.patches:
            patch_path = resolve_inside(BASELINES_ROOT, patch)
            if not patch_path.is_file():
                raise FileNotFoundError(f"compatibility patch is missing: {patch_path}")
        for artifact in method.artifacts:
            resolve_inside(BASELINES_ROOT, artifact.path)
        methods.append(method)

    method_ids = [method.id for method in methods]
    environments = [method.environment for method in methods]
    if not methods or len(method_ids) != len(set(method_ids)):
        raise ValueError("adapter environment manifest has missing or duplicate method IDs")
    if len(environments) != len(set(environments)):
        raise ValueError("adapter environment manifest has duplicate environment directories")
    known_sources = set(load_source_refs())
    unknown_sources = sorted(
        {source for method in methods for source in method.sources} - known_sources
    )
    if unknown_sources:
        raise ValueError(
            f"adapter manifest contains unlocked sources: {', '.join(unknown_sources)}"
        )
    return methods


def load_source_refs(path: Path = SOURCE_LOCK_PATH) -> dict[str, str]:
    """Return expected upstream commit IDs keyed by source ID."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {str(item["id"]): str(item["ref"]) for item in payload["sources"]}


def environment_python(environment: Path) -> Path:
    """Return the interpreter path for a uv environment on this platform."""
    if os.name == "nt":
        return environment / "Scripts" / "python.exe"
    return environment / "bin" / "python"


def digest_file(path: Path) -> str:
    """Return the SHA-256 digest of a file without loading it into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_errors(method: MethodSpec) -> list[str]:
    """Return missing or checksum-invalid artifact descriptions."""
    errors: list[str] = []
    for artifact in method.artifacts:
        path = resolve_inside(BASELINES_ROOT, artifact.path)
        if not path.is_file():
            errors.append(f"missing artifact: {path}")
        elif digest_file(path) != artifact.sha256:
            errors.append(f"artifact checksum mismatch: {path}")
    return errors


def find_tapas_source(base: Path, artifact: ArtifactSpec) -> Path | None:
    """Find one extracted TAPAS member under common transfer-root layouts."""
    artifact_path = Path(artifact.path)
    marker_index = artifact_path.parts.index("TAPAS-artifact")
    member_inside_artifact = Path(*artifact_path.parts[marker_index + 1 :])
    candidates = (
        base / artifact_path,
        base / Path(*artifact_path.parts[marker_index:]),
        base / member_inside_artifact,
    )
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def import_tapas_artifacts(
    method: MethodSpec,
    source_root: Path,
    *,
    dry_run: bool,
) -> list[str]:
    """Copy the two small extracted TAPAS files from another machine."""
    errors: list[str] = []
    for artifact in method.artifacts:
        source = find_tapas_source(source_root.resolve(), artifact)
        destination = resolve_inside(BASELINES_ROOT, artifact.path)
        if source is None:
            errors.append(f"TAPAS transfer source does not contain {Path(artifact.path).name}")
            continue
        if digest_file(source) != artifact.sha256:
            errors.append(f"TAPAS transfer checksum mismatch: {source}")
            continue
        print(f"COPY {source} -> {destination}", flush=True)
        if not dry_run:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
    return errors


def source_is_locked(source_id: str, expected_ref: str, runner: CommandRunner) -> bool:
    """Check that an ignored upstream checkout is at its reviewed commit."""
    if runner.dry_run:
        runner.run(
            ["git", "rev-parse", "HEAD"],
            cwd=BASELINES_ROOT / "third_party" / source_id,
            capture_output=True,
        )
        return True
    source = BASELINES_ROOT / "third_party" / source_id
    if not (source / ".git").is_dir():
        return False
    result = runner.run(["git", "rev-parse", "HEAD"], cwd=source, capture_output=True)
    return result.exit_code == 0 and result.stdout.strip() == expected_ref


def patch_source(method: MethodSpec, runner: CommandRunner, *, check_only: bool) -> list[str]:
    """Apply each reviewed compatibility patch exactly once."""
    if not method.patches:
        return []
    if len(method.sources) != 1:
        return [f"{method.id} patches require exactly one source checkout"]

    source = BASELINES_ROOT / "third_party" / method.sources[0]
    if not (source / ".git").is_dir():
        return [f"source checkout is missing for compatibility patch: {source}"]
    errors: list[str] = []
    for relative_patch in method.patches:
        patch = resolve_inside(BASELINES_ROOT, relative_patch)
        reverse = runner.run(
            ["git", "apply", "--reverse", "--check", str(patch)],
            cwd=source,
            capture_output=True,
        )
        if reverse.exit_code == 0:
            continue
        if check_only:
            errors.append(f"compatibility patch is not applied: {patch}")
            continue
        forward = runner.run(
            ["git", "apply", "--check", str(patch)], cwd=source, capture_output=True
        )
        if forward.exit_code != 0:
            errors.append(f"compatibility patch cannot be applied: {patch}")
            continue
        applied = runner.run(["git", "apply", str(patch)], cwd=source)
        if applied.exit_code != 0:
            errors.append(f"failed to apply compatibility patch: {patch}")
    return errors


def fetch_source(source_id: str, runner: CommandRunner) -> bool:
    """Fetch one ignored official checkout through the pinned-source helper."""
    result = runner.run([sys.executable, "-m", "baselines.fetch_sources", "--source", source_id])
    return result.exit_code == 0


def prepare_large_tapas(
    runner: CommandRunner,
    *,
    include_download: bool,
    unrar: Path | None,
) -> bool:
    """Reuse or explicitly download and extract the official TAPAS artifact."""
    archive_candidates = (
        BASELINES_ROOT / "artifacts" / "tapas.rar",
        BASELINES_ROOT / "artifacts" / "TAPAS-artifact.rar",
    )
    archive = next((candidate for candidate in archive_candidates if candidate.is_file()), None)
    if archive is None and include_download:
        fetched = runner.run(
            [
                sys.executable,
                "-m",
                "baselines.fetch_sources",
                "--source",
                "tapas",
                "--include-large",
            ]
        )
        if fetched.exit_code != 0:
            return False
        archive = BASELINES_ROOT / "artifacts" / "tapas.rar"
    if archive is None:
        return False

    command = [
        sys.executable,
        "-m",
        "baselines.prepare_tapas",
        "--archive",
        str(archive),
    ]
    if unrar is not None:
        command.extend(["--unrar", str(unrar.resolve())])
    return runner.run(command).exit_code == 0


def reset_environment(
    method: MethodSpec,
    runner: CommandRunner,
    *,
    uv: str,
    torch_backend: str,
) -> tuple[bool, Path]:
    """Clear and recreate one exact adapter environment."""
    environment = resolve_inside(BASELINES_ROOT / "envs", method.environment)
    python = environment_python(environment)
    created = runner.run(
        [
            uv,
            "venv",
            "--python",
            method.python_version,
            "--clear",
            str(environment),
        ]
    )
    if created.exit_code != 0:
        return False, python
    requirements = resolve_inside(BASELINES_ROOT, method.requirements)
    installed = runner.run(
        [
            uv,
            "pip",
            "install",
            "--python",
            str(python),
            "--torch-backend",
            torch_backend,
            "--requirements",
            str(requirements),
        ]
    )
    return installed.exit_code == 0, python


def verify_environment(
    method: MethodSpec,
    runner: CommandRunner,
    *,
    uv: str,
) -> tuple[list[str], str | None]:
    """Run dependency and official-model import checks for one adapter."""
    environment = resolve_inside(BASELINES_ROOT / "envs", method.environment)
    python = environment_python(environment)
    if not runner.dry_run and not python.is_file():
        return [f"environment interpreter is missing: {python}"], None

    errors: list[str] = []
    version = runner.run([str(python), "--version"], capture_output=True)
    python_version = (version.stdout or version.stderr).strip() or None
    if version.exit_code != 0:
        errors.append(f"Python interpreter failed: {python}")
    dependency_check = runner.run(
        [uv, "pip", "check", "--python", str(python)], capture_output=True
    )
    if dependency_check.exit_code != 0:
        errors.append(f"dependency check failed for {method.id}")
    environment_variables = os.environ.copy()
    environment_variables["PYTHONPATH"] = str(REPOSITORY_ROOT)
    probe = runner.run(
        [str(python), "-c", method.probe],
        environment=environment_variables,
        capture_output=True,
    )
    if probe.exit_code != 0:
        detail = probe.stderr.strip().splitlines()[-1] if probe.stderr.strip() else "unknown error"
        errors.append(f"model import probe failed for {method.id}: {detail}")
    return errors, python_version


def parse_args() -> argparse.Namespace:
    """Parse the portable reset command line."""
    methods = load_manifest()
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--reset", action="store_true", help="Clear and rebuild selected envs.")
    mode.add_argument("--check", action="store_true", help="Verify without changing envs.")
    parser.add_argument("--method", action="append", choices=[item.id for item in methods])
    parser.add_argument(
        "--without-tapas",
        action="store_true",
        help="Build only the seven clean-prefix methods.",
    )
    parser.add_argument("--skip-sources", action="store_true")
    parser.add_argument("--torch-backend", default="cpu")
    parser.add_argument(
        "--tapas-from",
        type=Path,
        help="Copy the two extracted TAPAS files from another machine or mounted directory.",
    )
    parser.add_argument(
        "--include-large-tapas",
        action="store_true",
        help="Download the 24.3 GB official archive only when extracted files are absent.",
    )
    parser.add_argument("--unrar", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser.parse_args()


def write_report(
    path: Path,
    *,
    arguments: argparse.Namespace,
    results: list[MethodResult],
    runner: CommandRunner,
) -> None:
    """Write the portable environment reset audit report."""
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "repository_root": str(REPOSITORY_ROOT),
        "mode": "reset" if arguments.reset else "check",
        "torch_backend": arguments.torch_backend,
        "methods": [asdict(result) for result in results],
        "commands": [asdict(record) for record in runner.records],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    """Rebuild or verify the portable adapter environments."""
    args = parse_args()
    manifest = load_manifest()
    selected_ids = set(args.method or [method.id for method in manifest])
    if args.without_tapas:
        selected_ids.discard("tapas")
    selected = [method for method in manifest if method.id in selected_ids]
    if not selected:
        raise ValueError("no baseline methods selected")

    uv = shutil.which("uv")
    git = shutil.which("git")
    if uv is None:
        raise FileNotFoundError("uv is required but was not found on PATH")
    if git is None:
        raise FileNotFoundError("git is required but was not found on PATH")

    runner = CommandRunner(dry_run=args.dry_run)
    source_refs = load_source_refs()
    required_sources = sorted({source for method in selected for source in method.sources})
    source_ready: dict[str, bool] = {}
    for source_id in required_sources:
        if source_id not in source_refs:
            source_ready[source_id] = False
            continue
        if args.reset and not args.skip_sources:
            fetch_source(source_id, runner)
        source_ready[source_id] = source_is_locked(source_id, source_refs[source_id], runner)

    tapas = next((method for method in selected if method.id == "tapas"), None)
    tapas_transfer_errors: list[str] = []
    if tapas is not None and args.tapas_from is not None:
        tapas_transfer_errors = import_tapas_artifacts(tapas, args.tapas_from, dry_run=args.dry_run)
    tapas_archives = (
        BASELINES_ROOT / "artifacts" / "tapas.rar",
        BASELINES_ROOT / "artifacts" / "TAPAS-artifact.rar",
    )
    if (
        tapas is not None
        and artifact_errors(tapas)
        and (args.include_large_tapas or any(path.is_file() for path in tapas_archives))
    ):
        prepare_large_tapas(
            runner,
            include_download=args.include_large_tapas,
            unrar=args.unrar,
        )

    results: list[MethodResult] = []
    for method in selected:
        result = MethodResult(
            id=method.id,
            environment=str(BASELINES_ROOT / "envs" / method.environment),
        )
        for source_id in method.sources:
            if not source_ready.get(source_id, False):
                result.errors.append(f"source is missing or not at locked commit: {source_id}")
        result.errors.extend(patch_source(method, runner, check_only=args.check))
        if method.id == "tapas":
            result.errors.extend(tapas_transfer_errors)
            if not args.dry_run:
                result.errors.extend(artifact_errors(method))

        if args.reset:
            installed, _ = reset_environment(
                method,
                runner,
                uv=uv,
                torch_backend=args.torch_backend,
            )
            if not installed:
                result.errors.append(f"dependency installation failed for {method.id}")

        if not result.errors or args.dry_run:
            verification_errors, python_version = verify_environment(method, runner, uv=uv)
            result.errors.extend(verification_errors)
            result.python_version = python_version
        result.status = "planned" if args.dry_run else ("ready" if not result.errors else "failed")
        results.append(result)
        print(f"[{result.status.upper()}] {method.id}", flush=True)
        for error in result.errors:
            print(f"  - {error}", file=sys.stderr, flush=True)

    if not args.dry_run:
        write_report(args.report.resolve(), arguments=args, results=results, runner=runner)
        print(f"Report: {args.report.resolve()}", flush=True)
    if args.dry_run:
        print(f"Baseline environments planned: {len(results)}/{len(results)}", flush=True)
        return 0
    ready = sum(result.status == "ready" for result in results)
    print(f"Baseline environments ready: {ready}/{len(results)}", flush=True)
    return 0 if ready == len(results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
