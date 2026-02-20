from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict

from codeforesight.llm.groq_client import analyze_code as groq_analyze
from codeforesight.llm.groq_client import analyze_future_risk
from codeforesight.llm.groq_client import explain_findings as groq_explain
from codeforesight.stages.stage1_known import analyze_known
from codeforesight.stages.stage2_unknown import analyze_unknown
from codeforesight.stages.stage3_future import analyze_future


def run_pipeline(
    input_path: Path,
    explain: bool = False,
    max_explain: int = 3,
    llm_only: bool = False,
    stage1_only: bool = False,
    stage2_only: bool = False,
    stage3_only: bool = False,
) -> Dict[str, Any]:
    code = input_path.read_text(encoding="utf-8", errors="ignore")

    stage1_findings = []
    if not llm_only:
        stage1_findings = [asdict(f) for f in analyze_known(code, str(input_path))]
    cwe_counts: Dict[str, int] = {}
    for finding in stage1_findings:
        cwe = finding.get("cwe_id", "UNKNOWN")
        cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
    top_cwe = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:3]

    stage1_explanations = {
        "status": "skipped",
        "reason": "LLM explanations disabled",
        "explanations": [],
    }
    snippet = "\n".join(code.splitlines()[:120])
    if llm_only and explain:
        stage1_explanations = groq_analyze(code_snippet=snippet)
    elif explain and stage1_findings:
        stage1_explanations = groq_explain(
            stage1_findings,
            code_snippet=snippet,
            max_findings=max_explain,
        )

    stage2_result = analyze_unknown(code)
    stage2_clean = dict(stage2_result)
    stage2_clean.pop("model", None)
    stage3_result = analyze_future(code, stage1_findings, stage2_result.get("findings", []))
    stage3_explanation = {
        "status": "skipped",
        "reason": "LLM explanations disabled",
        "analysis": "",
    }
    if explain:
        stage3_explanation = analyze_future_risk("\n".join(code.splitlines()[:120]))
    stage1_explanations_list = stage1_explanations.get("explanations", []) or []
    stage3_explanations_list = []
    if stage3_explanation.get("analysis"):
        stage3_explanations_list = [stage3_explanation.get("analysis", "")]

    if stage1_only:
        return {
            "input": str(input_path),
            "stage1_known": {
                "findings": stage1_findings,
                "count": len(stage1_findings),
                "summary": {
                    "top_cwe": top_cwe,
                    "total_findings": len(stage1_findings),
                },
                "explanations": stage1_explanations_list,
            },
        }

    if stage2_only:
        return {
            "input": str(input_path),
            "stage2_unknown": stage2_clean,
        }

    if stage3_only:
        return {
            "input": str(input_path),
            "stage3_future": {
                **asdict(stage3_result),
                "explanations": stage3_explanations_list,
            },
        }

    return {
        "input": str(input_path),
        "stage1_known": {
            "findings": stage1_findings,
            "count": len(stage1_findings),
            "summary": {
                "top_cwe": top_cwe,
                "total_findings": len(stage1_findings),
            },
            "explanations": stage1_explanations_list,
        },
        "stage2_unknown": stage2_clean,
        "stage3_future": {
            **asdict(stage3_result),
            "explanations": stage3_explanations_list,
        },
    }
