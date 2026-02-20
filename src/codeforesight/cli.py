from __future__ import annotations

import argparse
import json
from pathlib import Path

from codeforesight.config_env import load_dotenv
from codeforesight.pipeline import run_pipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CodeForesight CLI")
    parser.add_argument("--input", required=True, help="Path to source code file")
    parser.add_argument("--out", help="Optional path to write JSON output")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    parser.add_argument("--explain", action="store_true", help="Use LLM to explain findings")
    parser.add_argument("--max-explain", type=int, default=3, help="Max findings to explain")
    parser.add_argument("--llm-only", action="store_true", help="Use LLM-only analysis (skip rules/ML)")
    parser.add_argument("--stage1-only", action="store_true", help="Only return Stage 1 output")
    parser.add_argument("--stage2-only", action="store_true", help="Only return Stage 2 output")
    parser.add_argument("--stage3-only", action="store_true", help="Only return Stage 3 output")
    parser.add_argument("--stage1", action="store_true", help="Alias for --stage1-only")
    parser.add_argument("--stage2", action="store_true", help="Alias for --stage2-only")
    parser.add_argument("--stage3", action="store_true", help="Alias for --stage3-only")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    load_dotenv(Path(".env"))

    input_path = Path(args.input)
    if not input_path.exists():
        raise SystemExit(f"Input not found: {input_path}")

    stage1_only = args.stage1_only or args.stage1
    stage2_only = args.stage2_only or args.stage2
    stage3_only = args.stage3_only or args.stage3
    if sum(bool(x) for x in [stage1_only, stage2_only, stage3_only]) > 1:
        raise SystemExit("Use only one of --stage1/--stage2/--stage3 at a time.")

    report = run_pipeline(
        input_path,
        explain=args.explain,
        max_explain=args.max_explain,
        llm_only=args.llm_only,
        stage1_only=stage1_only,
        stage2_only=stage2_only,
        stage3_only=stage3_only,
    )
    indent = 2 if args.pretty else None
    output = json.dumps(report, indent=indent)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        print(output)


if __name__ == "__main__":
    main()
