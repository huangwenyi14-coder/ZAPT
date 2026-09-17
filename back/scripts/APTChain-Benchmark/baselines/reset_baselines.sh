#!/usr/bin/env bash
set -euo pipefail

EFORGE_BASELINES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EFORGE_REPO_ROOT="$(cd "${EFORGE_BASELINES_DIR}/.." && pwd)"

if ! command -v uv >/dev/null 2>&1; then
    echo "error: uv is required; install it before rebuilding the baseline environments" >&2
    exit 127
fi

if ! command -v git >/dev/null 2>&1; then
    echo "error: git is required; install it before rebuilding the baseline environments" >&2
    exit 127
fi

cd "${EFORGE_REPO_ROOT}"
exec uv run --project "${EFORGE_REPO_ROOT}" python -m baselines.reset_baselines --reset "$@"
