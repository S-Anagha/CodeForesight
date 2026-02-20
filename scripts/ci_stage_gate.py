from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict


def _add_src_to_path() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    src_path = repo_root / "src"
    sys.path.insert(0, str(src_path))


def _write_report(report: Dict[str, Any], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def _fail(message: str, code: int) -> None:
    print(message)
    raise SystemExit(code)


def main() -> None:
    parser = argparse.ArgumentParser(description="CI gate for CodeForesight stages.")
    parser.add_argument("--input", required=True, help="Path to input source file.")
    parser.add_argument("--stage1", action="store_true", help="Run Stage 1 gate.")
    parser.add_argument("--stage2", action="store_true", help="Run Stage 2 gate.")
    parser.add_argument("--stage3", action="store_true", help="Run Stage 3 report.")
    parser.add_argument("--stage3-threshold", type=float, default=0.5, help="Fail Stage 3 if score >= threshold.")
    parser.add_argument("--explain", action="store_true", help="Enable LLM explanations.")
    parser.add_argument("--out", default="", help="Output report path.")
    args = parser.parse_args()

    stages = [args.stage1, args.stage2, args.stage3]
    if sum(bool(s) for s in stages) != 1:
        _fail("Select exactly one of --stage1/--stage2/--stage3.", 2)

    input_path = Path(args.input)
    if not input_path.exists():
        _fail(f"Input not found: {input_path}", 2)

    _add_src_to_path()
    from codeforesight.pipeline import run_pipeline  # noqa: E402

    stage1_only = bool(args.stage1)
    stage2_only = bool(args.stage2)
    stage3_only = bool(args.stage3)
    report = run_pipeline(
        input_path,
        explain=args.explain,
        stage1_only=stage1_only,
        stage2_only=stage2_only,
        stage3_only=stage3_only,
    )

    if args.out:
        out_path = Path(args.out)
    else:
        stage_name = "stage1" if stage1_only else "stage2" if stage2_only else "stage3"
        out_path = Path("ci_reports") / f"{stage_name}.json"
    _write_report(report, out_path)

    if stage1_only:
        findings = report.get("stage1_known", {}).get("findings", [])
        actionable = [f for f in findings if f.get("cwe_id") != "SAFE"]
        if actionable:
            _fail(f"Stage 1 gate failed: {len(actionable)} findings.", 1)
        print("Stage 1 gate passed.")
        return

    if stage2_only:
        stage2 = report.get("stage2_unknown", {})
        status = stage2.get("status", "error")
        if status != "ok":
            reason = stage2.get("reason", "Unknown error")
            _fail(f"Stage 2 gate failed: {reason}", 1)
        findings = stage2.get("findings", [])
        if findings:
            _fail(f"Stage 2 gate failed: {len(findings)} findings.", 1)
        print("Stage 2 gate passed.")
        return

    if stage3_only:
        stage3 = report.get("stage3_future", {})
        score = float(stage3.get("score", 0.0) or 0.0)
        if score >= args.stage3_threshold:
            _fail(f"Stage 3 gate failed: score {score:.2f} >= {args.stage3_threshold:.2f}.", 1)
        print("Stage 3 gate passed.")
        return


if __name__ == "__main__":
    main()
