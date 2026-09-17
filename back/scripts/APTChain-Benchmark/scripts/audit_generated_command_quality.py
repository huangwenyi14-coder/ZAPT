#!/usr/bin/env python3
"""Audit command-line realism in already generated scenario outputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from evidenceforge.validation.scenario_quality import audit_generated_command_corpus


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_root", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        help="Write the JSON report to this path (stdout when omitted).",
    )
    args = parser.parse_args()

    output_root = args.output_root.resolve()
    scenario_dirs = sorted(
        path for path in output_root.iterdir() if path.is_dir() and (path / "data").is_dir()
    )
    if not scenario_dirs:
        parser.error(f"no generated scenario data directories found under {output_root}")
    report = audit_generated_command_corpus(scenario_dirs)
    payload = json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n"
    if args.output is None:
        print(payload, end="")
    else:
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(output.suffix + ".tmp")
        temporary.write_text(payload, encoding="utf-8")
        temporary.replace(output)
        print(f"generated command quality report: {output}")
    print(
        "accepted="
        f"{str(report.accepted).lower()} "
        f"blocking={report.blocking_issue_count} "
        f"powershell={report.powershell_process_create_count} "
        f"unique_powershell={report.unique_powershell_command_count}"
    )
    return 0 if report.accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
