"""Extract only the TAPAS source and checkpoint needed by its adapter."""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ARTIFACT_ROOT = ROOT / "artifacts"
DEFAULT_OUTPUT = ARTIFACT_ROOT / "tapas-inspection"
MEMBERS = (
    "TAPAS-artifact/darpa.py",
    "TAPAS-artifact/model/stackedlstm_tc.pt",
)


def find_archive(explicit: Path | None) -> Path:
    """Resolve the official archive downloaded by either supported command."""
    candidates = [
        explicit,
        ARTIFACT_ROOT / "tapas.rar",
        ARTIFACT_ROOT / "TAPAS-artifact.rar",
    ]
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "TAPAS RAR is missing; run `uv run python -m baselines.fetch_sources "
        "--source tapas --include-large` first"
    )


def find_unrar(explicit: Path | None) -> Path:
    """Resolve RARLab unrar, which supports the artifact's RAR5 method."""
    if explicit is not None:
        if not explicit.is_file():
            raise FileNotFoundError(f"unrar executable does not exist: {explicit}")
        return explicit
    executable = shutil.which("unrar")
    if executable is None:
        raise FileNotFoundError(
            "RARLab unrar is required because 7-Zip cannot decode this artifact's "
            "compression method; pass its path with --unrar"
        )
    return Path(executable)


def main() -> int:
    """Extract and validate the two official TAPAS files used for benchmarking."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--unrar", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    archive = find_archive(args.archive)
    unrar = find_unrar(args.unrar)
    args.output.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            str(unrar),
            "x",
            "-o+",
            str(archive),
            *MEMBERS,
            f"{args.output}/",
        ],
        check=True,
    )
    missing = [member for member in MEMBERS if not (args.output / member).is_file()]
    if missing:
        raise FileNotFoundError(f"TAPAS extraction did not produce: {', '.join(missing)}")
    for member in MEMBERS:
        path = args.output / member
        print(f"{path}: {path.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
