"""Probe locked upstream sources after explicitly documented host compatibility work."""

from __future__ import annotations

import hashlib
import json
import platform
from pathlib import Path
from typing import Any

from baselines.native_smoke import ROOT, load_catalog, load_locked_refs, run_command

REPOSITORY_ROOT = ROOT.parent
PATCHES: dict[str, list[str]] = {
    "threatrace": ["patches/threatrace-pyg-import.patch"],
    "magic": ["patches/magic-small-graph-sampling.patch"],
    "nodlink": ["patches/nodlink-scipy-import.patch"],
}


def probe_command(method_id: str, python: Path) -> list[str]:
    """Return the compatibility probe command for one method."""
    if method_id == "pidsmaker":
        return [str(python), "-m", "pidsmaker.main", "--help"]
    catalog = load_catalog()
    method = next(item for item in catalog.methods if item.id == method_id)
    return [str(python), *method.probe]


def probe_environment(method_id: str) -> dict[str, Any]:
    """Capture the isolated interpreter and installed dependency set."""
    python = ROOT / "envs" / method_id / "bin" / "python"
    version = run_command([str(python), "--version"], REPOSITORY_ROOT, timeout_seconds=30)
    packages = run_command(
        ["uv", "pip", "freeze", "--python", str(python)],
        REPOSITORY_ROOT,
        timeout_seconds=60,
    )
    return {"python": str(python), "version": version, "packages": packages}


def source_diff(source: Path) -> dict[str, Any]:
    """Capture and hash any explicit compatibility diff in an ignored checkout."""
    diff = run_command(["git", "diff", "--no-ext-diff"], source, timeout_seconds=30)
    payload = diff["stdout"].encode("utf-8")
    return {
        "sha256": hashlib.sha256(payload).hexdigest(),
        "text": diff["stdout"],
        "stderr": diff["stderr"],
    }


def classify_probe(method_id: str, probe: dict[str, Any]) -> str:
    """Distinguish a loaded entry point from dependency and dataset failures."""
    combined = f"{probe['stdout']}\n{probe['stderr']}"
    if probe["timed_out"]:
        return "timed_out"
    if probe["exit_code"] == 0 or "usage:" in combined:
        return "entrypoint_loaded"
    if method_id == "kairos" and "graph_4_2.TemporalData.simple" in combined:
        return "entrypoint_loaded_dataset_missing"
    if "ModuleNotFoundError" in combined:
        return "dependency_failed"
    return "entrypoint_failed"


def run_method(method_id: str, source_subdir: str, workdir: str) -> dict[str, Any]:
    """Run and classify one method's compatibility probe."""
    source = ROOT / "third_party" / source_subdir
    python = ROOT / "envs" / method_id / "bin" / "python"
    probe_cwd = (source / workdir).resolve()
    command = probe_command(method_id, python)
    if method_id == "pidsmaker":
        command = ["env", "PYTHONPATH=.", *command]
    probe = run_command(command, probe_cwd, timeout_seconds=120)
    return {
        "method": method_id,
        "status": classify_probe(method_id, probe),
        "environment": probe_environment(method_id),
        "patch_files": PATCHES.get(method_id, []),
        "source_diff": source_diff(source),
        "probe": probe,
    }


def write_markdown(results: list[dict[str, Any]], path: Path) -> None:
    """Write a concise compatibility result table."""
    lines = [
        "# Host-compatible upstream source probes",
        "",
        f"Host: `{platform.platform()}` / `{platform.machine()}`.",
        "",
        "| Method | Entrypoint status | Compatibility patch |",
        "|---|---|---|",
    ]
    for result in results:
        patches = ", ".join(result["patch_files"]) or "none"
        lines.append(f"| {result['method']} | `{result['status']}` | {patches} |")
    lines.extend(
        [
            "",
            "`entrypoint_loaded_dataset_missing` means imports and model definitions loaded, then "
            "the untouched source requested its original preprocessed DARPA artifact. It is not a "
            "successful detector benchmark.",
            "",
            "Full commands, dependency freezes, diffs, stdout, and stderr are in "
            "`compat_smoke.json`.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    """Run compatibility probes for every downloaded GitHub source."""
    catalog = load_catalog()
    locked_refs = load_locked_refs()
    results = [
        run_method(method.id, method.source_subdir, method.workdir) for method in catalog.methods
    ]
    result_dir = ROOT / "results" / "source_compat"
    result_dir.mkdir(parents=True, exist_ok=True)
    output = {
        "schema_version": "1.0",
        "host": {"platform": platform.platform(), "machine": platform.machine()},
        "locked_refs": locked_refs,
        "results": results,
    }
    (result_dir / "compat_smoke.json").write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    write_markdown(results, result_dir / "README.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
