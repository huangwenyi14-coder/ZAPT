#!/usr/bin/env python3
"""从 TXT 或具有可复制文字层的 PDF 生成完整 EvidenceForge 数据集。"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.report_ingest.compiler import ReportCompilerError
from evidenceforge.report_ingest.extractors import ReportInputError
from evidenceforge.report_ingest.minimax import (
    DEFAULT_MODEL,
    MiniMaxClient,
    MiniMaxError,
    load_minimax_credentials,
)
from evidenceforge.report_ingest.pipeline import (
    ReportModelOutputError,
    ReportPipeline,
    ReportPipelineError,
    ReportQualityError,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _validate_scenario(scenario_path: Path) -> None:
    """Run the existing deterministic scenario validator."""
    command = [sys.executable, "-m", "evidenceforge", "validate", str(scenario_path)]
    completed = subprocess.run(command, cwd=REPO_ROOT, check=False)
    if completed.returncode != 0:
        raise EvidenceForgeError(f"eforge validate 失败，退出码 {completed.returncode}")


def _generate_dataset(
    scenario_path: Path,
    output_dir: Path,
    force: bool,
    *,
    target: str,
) -> None:
    """Run the existing deterministic generator without shell interpolation."""
    command = [
        sys.executable,
        "-m",
        "evidenceforge",
        "generate",
        str(scenario_path),
        "--output",
        str(output_dir),
        "--target",
        target,
    ]
    if force:
        command.append("--force")
    completed = subprocess.run(command, cwd=REPO_ROOT, check=False)
    if completed.returncode != 0:
        raise EvidenceForgeError(f"eforge generate 失败，退出码 {completed.returncode}")


def build_parser() -> argparse.ArgumentParser:
    """Build the report-to-dataset command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="TXT 或带文本层 PDF 报告")
    parser.add_argument("--output", "-o", type=Path, required=True, help="最终输出目录")
    parser.add_argument("--api-key-file", type=Path, default=None, help="MiniMax 凭据文件")
    parser.add_argument("--base-url", default=None, help="MiniMax 官方 API 基地址")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"模型名称（默认 {DEFAULT_MODEL}）")
    parser.add_argument(
        "--target",
        choices=("default", "sof-elk", "splunk"),
        default="default",
        help="沿用 eforge generate 的输出目标",
    )
    parser.add_argument("--force", action="store_true", help="允许覆盖已有生成产物")
    return parser


def main() -> int:
    """Run the report-to-dataset pipeline and return a stable exit code."""
    args = build_parser().parse_args()
    try:
        credentials = load_minimax_credentials(
            api_key_file=args.api_key_file,
            base_url=args.base_url,
        )
        client = MiniMaxClient(credentials, model=args.model)

        def generator(scenario_path: Path, output_dir: Path, force: bool) -> None:
            _generate_dataset(
                scenario_path,
                output_dir,
                force,
                target=args.target,
            )

        pipeline = ReportPipeline(
            client,
            scenario_validator=_validate_scenario,
            dataset_generator=generator,
            workspace_root=REPO_ROOT,
            progress=print,
        )
        result = pipeline.run(args.input, args.output, force=args.force)
    except KeyboardInterrupt:
        print("\n已取消。", file=sys.stderr)
        return 130
    except ReportInputError as exc:
        print(f"输入错误：{exc}", file=sys.stderr)
        return 2
    except (MiniMaxError, ReportModelOutputError) as exc:
        print(f"模型错误：{exc}", file=sys.stderr)
        return 3
    except ReportCompilerError as exc:
        print(f"编译错误：{exc}", file=sys.stderr)
        return 4
    except ReportQualityError as exc:
        print(f"质量门失败：{exc}", file=sys.stderr)
        return 5
    except (ReportPipelineError, OSError) as exc:
        print(f"发布错误：{exc}", file=sys.stderr)
        return 6
    except (EvidenceForgeError, ValueError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1

    print("\n生成完成")
    print(f"输出目录：{result.output_dir}")
    print(f"场景文件：{result.scenario_path}")
    print(f"质量报告：{result.quality_report_path}")
    print(f"来源事实：{result.fact_count}")
    print(f"物化事件：{result.materialized_event_count}")
    print(f"可物化来源行为覆盖率：{result.materializable_coverage:.1%}")
    print(f"来源贴合评分：{result.quality_score:.2f}")
    print(f"模型调用：{result.model}，共 {result.model_calls} 次")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
