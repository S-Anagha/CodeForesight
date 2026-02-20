from __future__ import annotations

from datetime import datetime
import argparse
import os

import json
from pathlib import Path
from typing import Any, Dict, List


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _count_findings(stage1: Dict[str, Any], stage2: Dict[str, Any]) -> Dict[str, int]:
    s1 = stage1.get("stage1_known", {})
    s2 = stage2.get("stage2_unknown", {})
    return {
        "stage1": int(s1.get("count", 0)),
        "stage2": int(len(s2.get("findings", []) or [])),
    }


def _top_cwe(stage3: Dict[str, Any]) -> List[Dict[str, Any]]:
    s3 = stage3.get("stage3_future", {})
    return s3.get("likely_vulnerabilities", []) or []


def _stage3_summary(stage3: Dict[str, Any]) -> Dict[str, Any]:
    s3 = stage3.get("stage3_future", {})
    raw_factors = s3.get("factors", []) or []
    filtered_factors = [
        f
        for f in raw_factors
        if "Excluded CWEs already detected in input" not in f
        and "Stage 2 logic findings" not in f
    ]
    return {
        "score": s3.get("score", ""),
        "timeline": s3.get("timeline", ""),
        "factors": filtered_factors,
    }


def _svg_bar(
    labels: List[str],
    values: List[int],
    colors: List[str],
    width: int = 420,
    height: int = 180,
    value_labels: List[str] | None = None,
) -> str:
    if not values:
        return ""
    max_val = max(values) if max(values) > 0 else 1
    bar_height = 18
    gap = 10
    chart_height = (bar_height + gap) * len(values)
    top = max((height - chart_height) // 2, 10)
    left = 140
    right = 20
    chart_width = width - left - right
    bars = []
    for idx, (label, value, color) in enumerate(zip(labels, values, colors)):
        bar_len = int((value / max_val) * chart_width)
        y = top + idx * (bar_height + gap)
        value_text = value_labels[idx] if value_labels and idx < len(value_labels) else str(value)
        bars.append(
            f"<text x='{left - 10}' y='{y + 13}' text-anchor='end' font-size='12' fill='#444'>{label}</text>"
            f"<rect x='{left}' y='{y}' width='{bar_len}' height='{bar_height}' fill='{color}' rx='3'></rect>"
            f"<text x='{left + bar_len + 6}' y='{y + 13}' font-size='12' fill='#444'>{value_text}</text>"
        )
    return (
        f"<svg viewBox='0 0 {width} {height}' width='100%' height='100%'>"
        + "".join(bars)
        + "</svg>"
    )




def _stage1_findings(stage1: Dict[str, Any]) -> List[Dict[str, Any]]:
    s1 = stage1.get("stage1_known", {})
    findings = s1.get("findings", []) or []
    compact = []
    for f in findings:
        compact.append(
            {
                "cwe_id": f.get("cwe_id", ""),
                "name": f.get("name", ""),
                "severity": f.get("severity", ""),
                "line": f.get("line", ""),
                "snippet": f.get("snippet", ""),
                "fix": f.get("fix", ""),
            }
        )
    return compact


def _stage2_findings(stage2: Dict[str, Any]) -> List[Dict[str, Any]]:
    s2 = stage2.get("stage2_unknown", {})
    findings = s2.get("findings", []) or []
    compact = []
    for f in findings:
        compact.append(
            {
                "issue": f.get("issue", ""),
                "severity": f.get("severity", ""),
                "line": f.get("line", ""),
                "snippet": f.get("snippet", ""),
                "fix": f.get("fix", ""),
                "rationale": f.get("rationale", ""),
            }
        )
    return compact


def build_report(source_dir: Path, out_dir: Path) -> Path:
    stage1 = _load_json(source_dir / "stage1.json")
    stage2 = _load_json(source_dir / "stage2.json")
    stage3 = _load_json(source_dir / "stage3.json")

    counts = _count_findings(stage1, stage2)
    s3 = _stage3_summary(stage3)
    top_cwe = _top_cwe(stage3)[:5]
    stage1_items = _stage1_findings(stage1)
    stage2_items = _stage2_findings(stage2)

    stage_score_scaled = int(round((s3.get("score", 0) or 0) * 100))
    stage_labels = ["Stage 1", "Stage 2", "Stage 3"]
    stage_values = [counts["stage1"], counts["stage2"], stage_score_scaled]
    stage_colors = ["#114881", "#00a67c", "#f2a63b"]
    stage_value_labels = [str(counts["stage1"]), str(counts["stage2"]), f"{stage_score_scaled}%"]
    stage_bar_svg = _svg_bar(stage_labels, stage_values, stage_colors, value_labels=stage_value_labels)

    cwe_labels = [row.get("cwe_id", "") for row in top_cwe]
    cwe_counts = [int(row.get("count", 0)) for row in top_cwe]
    cwe_colors = ["#114881", "#00a67c", "#f2a63b", "#a53fa7", "#7aa6d9"]
    cwe_bar_svg = _svg_bar(cwe_labels, cwe_counts, cwe_colors)

    timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    build_no = os.getenv("BUILD_NUMBER", "")
    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>CodeForesight CI Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #222; }}
    h1 {{ color: #114881; }}
    .card {{ border: 1px solid #e0e0e0; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
    .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }}
    .metric {{ font-size: 28px; font-weight: bold; }}
    .label {{ color: #555; font-size: 14px; }}
    .muted {{ color: #666; font-size: 13px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
    th, td {{ border-bottom: 1px solid #eee; padding: 8px; text-align: left; }}
    .pill {{ display: inline-block; padding: 4px 8px; border-radius: 12px; background: #eef3f8; }}
    .chart-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; align-items: center; }}
    .chart-box {{ height: 180px; }}
    .chart-box.pie {{ height: 150px; }}
    .legend-list {{ list-style: none; padding: 0; margin: 0; font-size: 12px; color: #444; }}
    .legend-item {{ display: flex; align-items: center; margin: 6px 0; }}
    .legend-swatch {{ width: 10px; height: 10px; border-radius: 2px; margin-right: 8px; }}
  </style>
</head>
<body>
  <h1>CodeForesight CI Report</h1>
  <p class="label">Generated: {timestamp} {f"(Build {build_no})" if build_no else ""}</p>

  <div class="card grid">
    <div>
      <div class="metric">{counts['stage1']}</div>
      <div class="label">Stage 1 findings</div>
    </div>
    <div>
      <div class="metric">{counts['stage2']}</div>
      <div class="label">Stage 2 findings</div>
    </div>
    <div>
      <div class="metric">{s3.get('score', '')}</div>
      <div class="label">Stage 3 risk score</div>
    </div>
  </div>

  <div class="card">
    <h2>Stage 1 — Known Vulnerabilities</h2>
    <table>
      <thead>
        <tr><th>CWE</th><th>Name</th><th>Severity</th><th>Line</th><th>Snippet</th><th>Fix</th></tr>
      </thead>
      <tbody>
        {"".join(
            f"<tr><td>{row.get('cwe_id','')}</td>"
            f"<td>{row.get('name','')}</td>"
            f"<td>{row.get('severity','')}</td>"
            f"<td>{row.get('line','')}</td>"
            f"<td>{row.get('snippet','')}</td>"
            f"<td>{row.get('fix','')}</td></tr>"
            for row in stage1_items
        ) or "<tr><td colspan='6'>No Stage 1 findings.</td></tr>"}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Stage 2 — Unknown Vulnerabilities</h2>
    <table>
      <thead>
        <tr><th>Issue</th><th>Severity</th><th>Line</th><th>Snippet</th><th>Fix</th><th>Rationale</th></tr>
      </thead>
      <tbody>
        {"".join(
            f"<tr><td>{row.get('issue','')}</td>"
            f"<td>{row.get('severity','')}</td>"
            f"<td>{row.get('line','')}</td>"
            f"<td>{row.get('snippet','')}</td>"
            f"<td>{row.get('fix','')}</td>"
            f"<td>{row.get('rationale','')}</td></tr>"
            for row in stage2_items
        ) or "<tr><td colspan='6'>No Stage 2 findings.</td></tr>"}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Stage Summary (All Stages)</h2>
    <div class="muted">Distribution of findings plus Stage 3 risk score (scaled).</div>
    <div class="chart-grid">
      <div class="chart-box">{stage_bar_svg}</div>
      <div>
        <ul class="legend-list">
          <li class="legend-item"><span class="legend-swatch" style="background:#114881"></span>Stage 1 findings: {counts['stage1']}</li>
          <li class="legend-item"><span class="legend-swatch" style="background:#00a67c"></span>Stage 2 findings: {counts['stage2']}</li>
          <li class="legend-item"><span class="legend-swatch" style="background:#f2a63b"></span>Stage 3 score × 100: {stage_score_scaled}%</li>
        </ul>
        <div class="muted" style="margin-top:8px;">
          Stage 1 = known findings<br/>
          Stage 2 = unknown findings<br/>
          Stage 3 = risk score × 100 (%)
        </div>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>Stage 3 — Future Risk Forecast</h2>
    <p><span class="pill">Risk score</span> {s3.get('score', '')}</p>
    <p><span class="pill">Timeline</span> {s3.get('timeline', '')}</p>
    <p><span class="pill">Factors</span> {", ".join(s3.get('factors', []) or [])}</p>
    <div class="chart-grid">
      <div class="chart-box">{cwe_bar_svg}</div>
      <div class="chart-box"></div>
    </div>
    <table>
      <thead>
        <tr><th>CWE</th><th>Name</th><th>Count</th><th>Reference</th></tr>
      </thead>
      <tbody>
        {"".join(
            f"<tr><td>{row.get('cwe_id','')}</td>"
            f"<td>{row.get('name','')}</td>"
            f"<td>{row.get('count','')}</td>"
            f"<td><a href='{row.get('reference','')}'>{row.get('reference','')}</a></td></tr>"
            for row in top_cwe
        ) or "<tr><td colspan='4'>No Stage 3 trend data.</td></tr>"}
      </tbody>
    </table>
  </div>

</body>
</html>
"""

    out_path = out_dir / "report.html"
    out_path.write_text(html, encoding="utf-8")
    csv_path = out_dir / "metrics.csv"
    csv_path.write_text(
        "timestamp,stage1_findings,stage2_findings,stage3_score\n"
        f"{timestamp},{counts['stage1']},{counts['stage2']},{s3.get('score','')}\n",
        encoding="utf-8",
    )
    return out_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="", help="Output directory for ci_reports")
    parser.add_argument("--source", default="", help="Source directory containing stage JSON files")
    parser.add_argument("--mirror-local", action="store_true", help="Also write report to local project ci_reports")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[1]
    source_dir = Path(args.source) if args.source else (project_root / "ci_reports")
    out_dir = Path(args.out) if args.out else (project_root / "ci_reports")

    out_dir.mkdir(parents=True, exist_ok=True)
    output = build_report(source_dir, out_dir)
    print(f"Saved CI report to {output}")
    if args.mirror_local:
        local_dir = project_root / "ci_reports"
        local_dir.mkdir(parents=True, exist_ok=True)
        build_report(source_dir, local_dir)
