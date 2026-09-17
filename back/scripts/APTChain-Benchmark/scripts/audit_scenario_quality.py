#!/usr/bin/env python3
"""Audit scenario definitions against the contestant-corpus quality contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from evidenceforge.validation.scenario_quality import audit_scenario_corpus


def discover_scenario_paths(targets: list[Path]) -> list[Path]:
    """Resolve scenario files from explicit files or corpus directories."""
    paths: set[Path] = set()
    for target in targets:
        resolved = target.resolve()
        if resolved.is_file():
            paths.add(resolved)
            continue
        paths.update(resolved.glob("*/scenario.yaml"))
    return sorted(paths)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="+", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        help="Write the complete JSON report to this path (stdout when omitted).",
    )
    args = parser.parse_args()

    paths = discover_scenario_paths(args.targets)
    if not paths:
        parser.error("no scenario.yaml files found")
    report = audit_scenario_corpus(paths)
    payload = json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n"
    if args.output is None:
        print(payload, end="")
    else:
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(output.suffix + ".tmp")
        temporary.write_text(payload, encoding="utf-8")
        temporary.replace(output)
        print(f"quality report: {output}")
    print(
        "accepted="
        f"{str(report.accepted).lower()} "
        f"blocking={report.blocking_issue_count} "
        f"warnings={report.warning_issue_count} "
        f"manual={report.manual_review_item_count}"
    )
    return 0 if report.accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
