"""Tests for portable provenance-baseline environment rebuilding."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from baselines.native_smoke import native_environment
from baselines.reset_baselines import (
    BASELINES_ROOT,
    ArtifactSpec,
    CommandRunner,
    MethodSpec,
    import_tapas_artifacts,
    load_manifest,
    patch_source,
    reset_environment,
    resolve_inside,
    source_is_locked,
)


def test_adapter_manifest_defines_all_scored_methods() -> None:
    methods = load_manifest()

    assert [method.id for method in methods] == [
        "velox",
        "nodlink",
        "magic",
        "threatrace",
        "shadewatcher",
        "kairos",
        "orthrus",
        "tapas",
    ]
    assert {method.id: method.environment for method in methods} == {
        "velox": "velox",
        "nodlink": "nodlink",
        "magic": "magic_adapter",
        "threatrace": "threatrace_adapter",
        "shadewatcher": "shadewatcher_adapter",
        "kairos": "kairos_adapter",
        "orthrus": "orthrus_adapter",
        "tapas": "tapas_adapter",
    }
    assert all(resolve_inside(BASELINES_ROOT, method.requirements).is_file() for method in methods)


def test_resolve_inside_rejects_path_traversal(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="path escapes"):
        resolve_inside(tmp_path, "../outside")


def test_reset_environment_dry_run_does_not_create_directory() -> None:
    environment_name = "test-dry-run-environment-never-created"
    environment = BASELINES_ROOT / "envs" / environment_name
    assert not environment.exists()
    method = MethodSpec(
        id="dry-run",
        python_version="3.11",
        environment=environment_name,
        requirements="requirements-velox.txt",
        module="baselines.velox_adapter",
        sources=(),
        patches=(),
        probe="import baselines.velox_adapter",
    )
    runner = CommandRunner(dry_run=True)

    installed, _ = reset_environment(method, runner, uv="uv", torch_backend="cpu")

    assert installed
    assert not environment.exists()
    assert len(runner.records) == 2


def test_dry_run_treats_locked_source_check_as_planned() -> None:
    runner = CommandRunner(dry_run=True)

    assert source_is_locked("not-downloaded-in-dry-run", "a" * 40, runner)


def test_missing_patch_source_is_reported_without_subprocess_failure() -> None:
    method = MethodSpec(
        id="missing-source",
        python_version="3.11",
        environment="missing-source",
        requirements="requirements-velox.txt",
        module="baselines.velox_adapter",
        sources=("source-that-does-not-exist",),
        patches=("patches/magic-small-graph-sampling.patch",),
        probe="import baselines.velox_adapter",
    )

    errors = patch_source(method, CommandRunner(dry_run=False), check_only=False)

    assert len(errors) == 1
    assert "source checkout is missing" in errors[0]


def test_tapas_transfer_validates_without_writing_in_dry_run(tmp_path: Path) -> None:
    content = b"official-test-member"
    source = tmp_path / "TAPAS-artifact" / "darpa.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(content)
    target = BASELINES_ROOT / "artifacts" / "unit-test" / "TAPAS-artifact" / "darpa.py"
    assert not target.exists()
    method = MethodSpec(
        id="tapas",
        python_version="3.11",
        environment="tapas_adapter",
        requirements="compat_requirements/tapas_adapter.txt",
        module="baselines.tapas_adapter",
        sources=(),
        patches=(),
        probe="import baselines.tapas_adapter",
        artifacts=(
            ArtifactSpec(
                path="artifacts/unit-test/TAPAS-artifact/darpa.py",
                sha256=hashlib.sha256(content).hexdigest(),
            ),
        ),
    )

    errors = import_tapas_artifacts(method, tmp_path, dry_run=True)

    assert errors == []
    assert not target.exists()


def test_native_smoke_environment_cannot_clear_adapter_environment() -> None:
    assert native_environment("nodlink") == BASELINES_ROOT / "envs" / "native" / "nodlink"
    assert native_environment("nodlink") != BASELINES_ROOT / "envs" / "nodlink"
