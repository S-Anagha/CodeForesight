from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import List, Dict, Any

from codeforesight.config import CWE_CSV
from codeforesight.data.cwe_loader import load_cwe_catalog
from codeforesight.stages.stage3_temporal import predict_temporal_risk, summarize_recent_cwe_trends


@dataclass(frozen=True)
class FutureRisk:
    score: float
    timeline: str
    rationale: str
    factors: List[str]
    likely_vulnerabilities: List[Dict[str, Any]]
    temporal_model: Dict[str, Any]


def _extract_input_cwes(stage1_findings: List[dict]) -> List[str]:
    cwes: List[str] = []
    for finding in stage1_findings:
        cwe_id = finding.get("cwe_id", "")
        if cwe_id and cwe_id != "SAFE":
            cwes.append(cwe_id)
    return sorted(set(cwes))


def analyze_future(code: str, stage1_findings: List[dict], stage2_findings: List[dict] | None = None) -> FutureRisk:
    factors: List[str] = []
    _ = code
    _ = stage1_findings
    temporal = predict_temporal_risk()
    temporal_score = temporal.risk_score if temporal.status == "ok" else 0.0
    input_cwes = _extract_input_cwes(stage1_findings)
    likely_vulnerabilities = summarize_recent_cwe_trends(
        window_months=temporal.window_months or 0
    )
    catalog = {}
    if CWE_CSV.exists():
        catalog = load_cwe_catalog(CWE_CSV)
    enriched: List[Dict[str, Any]] = []
    for item in likely_vulnerabilities:
        cwe_id = item.get("cwe_id", "")
        record = catalog.get(cwe_id)
        observed = cwe_id in input_cwes
        relevance = int(item.get("count", 0)) * (2 if observed else 1)
        enriched.append(
            {
                "cwe_id": cwe_id,
                "name": record.name if record else "",
                "description": record.description if record else "",
                "count": item.get("count", 0),
                "observed_in_input": observed,
                "relevance_score": relevance,
                "reference": f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[-1]}.html"
                if cwe_id.startswith("CWE-")
                else "",
            }
        )
    enriched.sort(key=lambda x: (-x.get("relevance_score", 0), -x.get("count", 0)))
    likely_vulnerabilities = [item for item in enriched if not item.get("observed_in_input")]

    fusion_score = round(min(max(temporal_score, 0.0), 0.95), 2)

    rationale = (
        "Forecast uses NVD historical trends to estimate near-term vulnerability likelihood "
        "and highlight the most common CWE categories observed recently."
    )
    if temporal.status == "ok" and temporal.window_months:
        factors.append(f"NVD trend window: last {temporal.window_months} months")
    elif temporal.status != "ok":
        factors.append("Temporal model not trained")
    if likely_vulnerabilities:
        factors.append("Top CWE trends derived from recent NVD data")
    if input_cwes:
        factors.append("Excluded CWEs already detected in input")
    if stage2_findings:
        factors.append(f"Stage 2 logic findings: {len(stage2_findings)}")
    else:
        factors.append("No CWE trend data available")
    if temporal.timeline_bucket:
        timeline = temporal.timeline_bucket
    else:
        timeline = "unknown"
    temporal_dict = asdict(temporal)
    return FutureRisk(
        score=fusion_score,
        timeline=timeline,
        rationale=rationale,
        factors=factors,
        likely_vulnerabilities=likely_vulnerabilities,
        temporal_model=temporal_dict,
    )
