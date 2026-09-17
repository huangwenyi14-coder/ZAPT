"""Fetch published implementations at the reviewed, pinned commits."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
LOCK_PATH = ROOT / "source_lock.json"


def run(*args: str, cwd: Path | None = None) -> None:
    """Run one checked subprocess and surface its command on failure."""
    subprocess.run(args, cwd=cwd, check=True)


def fetch_git_source(source: dict[str, Any], destination_root: Path) -> None:
    """Clone or update one repository and detach it at its locked commit."""
    destination = destination_root / str(source["id"])
    url = str(source["url"])
    ref = str(source["ref"])
    if not (destination / ".git").is_dir():
        run("git", "clone", "--filter=blob:none", "--no-checkout", url, str(destination))
    run("git", "fetch", "--depth", "1", "origin", ref, cwd=destination)
    run("git", "checkout", "--detach", ref, cwd=destination)


def fetch_large_artifact(artifact: dict[str, Any], destination_root: Path) -> None:
    """Download an explicitly requested large artifact with safe range resumption."""
    destination_root.mkdir(parents=True, exist_ok=True)
    destination = destination_root / f"{artifact['id']}.rar"
    expected_size = int(artifact["size_bytes"])
    current_size = destination.stat().st_size if destination.exists() else 0
    if current_size > expected_size:
        raise ValueError(
            f"artifact is larger than expected for {artifact['id']}: "
            f"expected {expected_size}, got {current_size}"
        )

    retry_count = 0
    while current_size < expected_size:
        headers = {"Range": f"bytes={current_size}-"} if current_size else {}
        request = urllib.request.Request(str(artifact["url"]), headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                if current_size:
                    content_range = response.headers.get("Content-Range", "")
                    if response.status != 206 or not content_range.startswith(
                        f"bytes {current_size}-"
                    ):
                        raise ValueError(
                            "server did not honor the requested byte range; refusing to "
                            "overwrite partial artifact"
                        )
                with destination.open("ab") as output:
                    while chunk := response.read(1024 * 1024):
                        output.write(chunk)
            retry_count = 0
        except (
            ConnectionError,
            TimeoutError,
            http.client.IncompleteRead,
            urllib.error.URLError,
        ) as error:
            retry_count += 1
            if retry_count > 100:
                raise RuntimeError(
                    f"artifact download failed after {retry_count} resumptions"
                ) from error
            time.sleep(5)
        current_size = destination.stat().st_size if destination.exists() else 0

    if current_size != expected_size:
        raise ValueError(
            f"artifact size mismatch for {artifact['id']}: "
            f"expected {expected_size}, got {current_size}"
        )
    expected_md5 = artifact.get("md5")
    if expected_md5:
        digest = hashlib.md5(usedforsecurity=False)
        with destination.open("rb") as input_file:
            while chunk := input_file.read(8 * 1024 * 1024):
                digest.update(chunk)
        if digest.hexdigest() != expected_md5:
            raise ValueError(
                f"artifact checksum mismatch for {artifact['id']}: "
                f"expected {expected_md5}, got {digest.hexdigest()}"
            )


def main() -> None:
    """Fetch locked repositories and, only when requested, very large artifacts."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", action="append", help="Fetch only named source(s).")
    parser.add_argument(
        "--include-large",
        action="store_true",
        help="Also download large external artifacts (TAPAS is 24.3 GB).",
    )
    args = parser.parse_args()

    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    requested = set(args.source or [])
    destination_root = ROOT / "third_party"
    destination_root.mkdir(parents=True, exist_ok=True)
    for source in lock["sources"]:
        if requested and source["id"] not in requested:
            continue
        fetch_git_source(source, destination_root)

    if args.include_large:
        for artifact in lock["large_artifacts"]:
            if requested and artifact["id"] not in requested:
                continue
            fetch_large_artifact(artifact, ROOT / "artifacts")


if __name__ == "__main__":
    main()
