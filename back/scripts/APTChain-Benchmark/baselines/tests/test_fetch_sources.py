"""Unit tests for pinned-source fetching helpers."""

from __future__ import annotations

import hashlib
import io
import urllib.request
from pathlib import Path
from typing import Any

from pytest import MonkeyPatch

from baselines.fetch_sources import fetch_large_artifact


class _PartialResponse(io.BytesIO):
    """Minimal context-managed HTTP 206 response for a resumed download."""

    status = 206
    headers = {"Content-Range": "bytes 3-5/6"}

    def __enter__(self) -> _PartialResponse:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


def test_fetch_large_artifact_resumes_and_checks_md5(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    destination = tmp_path / "sample.rar"
    destination.write_bytes(b"abc")

    def fake_urlopen(request: urllib.request.Request, timeout: int) -> _PartialResponse:
        assert request.headers["Range"] == "bytes=3-"
        assert timeout == 300
        return _PartialResponse(b"def")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    artifact = {
        "id": "sample",
        "url": "https://example.invalid/sample.rar",
        "size_bytes": 6,
        "md5": hashlib.md5(b"abcdef", usedforsecurity=False).hexdigest(),
    }

    fetch_large_artifact(artifact, tmp_path)

    assert destination.read_bytes() == b"abcdef"
