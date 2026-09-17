"""Fetch provenance engineering tools at reviewed, pinned revisions."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
LOCK_PATH = ROOT / "tool_lock.json"


def run(*args: str, cwd: Path | None = None) -> None:
    """Run one checked subprocess."""
    subprocess.run(args, cwd=cwd, check=True)


def fetch_tool(tool: dict[str, Any], destination_root: Path) -> None:
    """Clone or update one tool and detach it at its locked revision."""
    destination = destination_root / str(tool["id"])
    url = str(tool["url"])
    revision = str(tool["ref"])
    if not (destination / ".git").is_dir():
        run("git", "clone", "--filter=blob:none", "--no-checkout", url, str(destination))
    run("git", "fetch", "--depth", "1", "origin", revision, cwd=destination)
    run("git", "checkout", "--detach", revision, cwd=destination)


def main() -> int:
    """Fetch every locked provenance tool."""
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    destination_root = ROOT / "third_party"
    destination_root.mkdir(parents=True, exist_ok=True)
    for tool in lock["tools"]:
        fetch_tool(tool, destination_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
