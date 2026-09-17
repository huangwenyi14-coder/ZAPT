#!/usr/bin/env python3
"""离线重评已生成报告数据集的来源链与物化完整性。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evidenceforge.report_ingest.quality import evaluate_published_output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="generate_from_report.py 生成的输出目录")
    parser.add_argument(
        "--json",
        action="store_true",
        help="向标准输出写入完整 JSON 结果，便于 Web 接入",
    )
    parser.add_argument(
        "--write",
        type=Path,
        default=None,
        help="可选：把重评 JSON 另存到指定文件",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    output = args.output.expanduser()
    if output.is_symlink() or not output.is_dir():
        print("错误：输出路径必须是非符号链接的已存在目录。", file=sys.stderr)
        return 1

    report = evaluate_published_output(output)
    payload = report.model_dump(mode="json")
    encoded = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if args.write is not None:
        target = args.write.expanduser()
        if target.is_symlink():
            print("错误：拒绝写入符号链接文件。", file=sys.stderr)
            return 1
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(encoded, encoding="utf-8")

    if args.json:
        print(encoded, end="")
    else:
        status = "通过" if report.passed else "未通过"
        print(f"来源贴合离线重评：{status}")
        print(f"综合分：{report.score:.2f}")
        for name, metric in report.metrics.items():
            print(f"- {name}: {metric.rate:.1%}")
        if report.hard_failures:
            print("硬门槛失败：")
            for failure in report.hard_failures:
                print(f"- {failure}")
    return 0 if report.passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
