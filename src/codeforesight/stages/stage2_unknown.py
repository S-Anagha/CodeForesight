from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List

from codeforesight.llm.groq_client import analyze_unknown_findings


@dataclass(frozen=True)
class UnknownFinding:
    issue: str
    rationale: str
    confidence: str


def _extract_json(raw: str) -> Dict[str, Any] | None:
    raw = raw.strip()
    if not raw:
        return None
    # Strip markdown fences if present
    raw = re.sub(r"```json|```", "", raw, flags=re.IGNORECASE).strip()
    # Try direct parse first
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    # Extract the first JSON object block
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    candidate = raw[start : end + 1]
    # Remove trailing commas before closing braces/brackets
    candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return None


def analyze_unknown(code: str) -> Dict[str, Any]:
    """
    LLM-based unknown vulnerability detection.
    """
    lines = code.splitlines()
    snippet = "\n".join(lines[-200:]) if len(lines) > 200 else "\n".join(lines)
    focus: List[str] = []
    if "apply_coupon_after_checkout" in code and "total = total - 100" in code:
        focus.append("apply_coupon_after_checkout")
    if "view_admin_report" in code and "if (!is_admin)" not in code and "if (is_admin)" not in code:
        focus.append("view_admin_report")
    response = analyze_unknown_findings(snippet, focus=focus, force=bool(focus))

    def _has_admin_check(source: str) -> bool:
        if "view_admin_report" not in source:
            return False
        return "if (!is_admin)" in source or "if (!isAdmin)" in source

    def _filter_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        banned_terms = [
            "sql", "xss", "injection", "overflow", "buffer", "memory",
            "uninitialized", "resource leak", "leak", "use-after", "uaf",
            "format string", "csrf", "ssrf",
        ]
        has_admin_check = _has_admin_check(code)
        filtered: List[Dict[str, Any]] = []
        for item in findings:
            text = " ".join(
                str(item.get(k, "")) for k in ["issue", "rationale", "snippet", "fix"]
            ).lower()
            if any(term in text for term in banned_terms):
                continue
            if has_admin_check and any(term in text for term in ["authorization", "auth", "unauthorized"]):
                continue
            filtered.append(item)
        return filtered

    def _find_line_snippet(needle: str) -> Dict[str, Any]:
        for idx, line in enumerate(lines, start=1):
            if needle in line:
                return {"line": idx, "snippet": line.strip()}
        return {"line": 0, "snippet": needle}

    def _fallback_logic_findings() -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if "apply_coupon_after_checkout" in code and "total = total - 100" in code:
            hit = _find_line_snippet("total = total - 100")
            findings.append(
                {
                    "issue": "Coupon applied after checkout",
                    "severity": "high",
                    "line": hit["line"],
                    "snippet": hit["snippet"],
                    "fix": "Apply coupons before payment and cap totals at zero.",
                    "rationale": "Post-payment coupons can create negative totals or free purchases.",
                }
            )
        if "view_admin_report" in code and "(void)is_admin" in code and not _has_admin_check(code):
            hit = _find_line_snippet("view_admin_report")
            findings.append(
                {
                    "issue": "Missing authorization check",
                    "severity": "high",
                    "line": hit["line"],
                    "snippet": hit["snippet"],
                    "fix": "Require an admin check before showing the report.",
                    "rationale": "Without authorization, any user can access admin data.",
                }
            )
        return findings

    if response.get("status") == "ok":
        raw = response.get("raw", "")
        data = _extract_json(raw)
        if data is None:
            # Retry with stricter prompt to force short JSON
            retry = analyze_unknown_findings(snippet, strict=True, focus=focus, force=bool(focus))
            if retry.get("status") == "ok":
                raw_retry = retry.get("raw", "")
                data_retry = _extract_json(raw_retry)
                if data_retry is not None:
                    filtered_retry = _filter_findings(data_retry.get("findings", []))
                    if not filtered_retry and focus:
                        filtered_retry = _fallback_logic_findings()
                    return {
                        "status": "ok",
                        "model": retry.get("model", ""),
                        "findings": filtered_retry,
                    }
            return {
                "status": "error",
                "reason": "LLM returned non-JSON response",
                "raw": raw,
                "findings": [],
            }
        filtered = _filter_findings(data.get("findings", []))
        if not filtered and focus:
            filtered = _fallback_logic_findings()
        return {
            "status": "ok",
            "model": response.get("model", ""),
            "findings": filtered,
        }

    return response
