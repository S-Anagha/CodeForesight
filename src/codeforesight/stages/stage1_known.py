from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

from codeforesight.stages.language_utils import detect_language
from codeforesight.stages.stage1_model import predict_stage1


@dataclass(frozen=True)
class Finding:
    cwe_id: str
    name: str
    severity: str
    line: int
    snippet: str
    rule_id: str
    fix: str
    file: str


_RULES = [
    {
        "rule_id": "S1-EXEC-EVAL",
        "cwe_id": "CWE-95",
        "name": "Dynamic code execution",
        "severity": "high",
        "pattern": re.compile(r"\b(eval|exec)\s*\(", re.IGNORECASE),
        "fix": "Avoid eval/exec; use safe parsing or a restricted sandbox.",
    },
    {
        "rule_id": "S1-CMD-INJECT",
        "cwe_id": "CWE-78",
        "name": "OS command injection",
        "severity": "high",
        "pattern": re.compile(r"\b(os\.system|subprocess\.(popen|run|call))\s*\(", re.IGNORECASE),
        "fix": "Use parameterized APIs and validate/escape user input.",
    },
    {
        "rule_id": "S1-SHELL-TRUE",
        "cwe_id": "CWE-78",
        "name": "Subprocess shell usage",
        "severity": "medium",
        "pattern": re.compile(r"shell\s*=\s*True", re.IGNORECASE),
        "fix": "Avoid shell=True; pass args as a list and validate input.",
    },
    {
        "rule_id": "S1-SQL-CONCAT",
        "cwe_id": "CWE-89",
        "name": "Potential SQL injection",
        "severity": "high",
        "pattern": re.compile(
            r"(SELECT|INSERT|UPDATE|DELETE).*(\+|%s|format\(|f\")",
            re.IGNORECASE,
        ),
        "fix": "Use parameterized queries and input validation.",
    },
    {
        "rule_id": "S1-DESERIALIZE",
        "cwe_id": "CWE-502",
        "name": "Unsafe deserialization",
        "severity": "high",
        "pattern": re.compile(r"\b(pickle\.loads|yaml\.load)\s*\(", re.IGNORECASE),
        "fix": "Avoid deserializing untrusted data; use safe loaders.",
    },
    {
        "rule_id": "S1-XSS-HTML",
        "cwe_id": "CWE-79",
        "name": "Direct HTML injection",
        "severity": "medium",
        "pattern": re.compile(r"(innerHTML\s*=|dangerouslySetInnerHTML)", re.IGNORECASE),
        "fix": "Escape/encode output and avoid raw HTML injection.",
    },
    {
        "rule_id": "S1-PATH-TRAVERSAL",
        "cwe_id": "CWE-22",
        "name": "Path traversal pattern",
        "severity": "medium",
        "pattern": re.compile(r"\.\./", re.IGNORECASE),
        "fix": "Normalize paths and enforce allowlists.",
    },
    {
        "rule_id": "S1-HARDCODED-CREDS",
        "cwe_id": "CWE-798",
        "name": "Hardcoded credentials",
        "severity": "medium",
        "pattern": re.compile(r"(password|secret|api_key)\s*=\s*[\"'][^\"']+[\"']", re.IGNORECASE),
        "fix": "Move secrets to environment variables or a secrets manager.",
    },
    {
        "rule_id": "S1-UNSAFE-C-FN",
        "cwe_id": "CWE-120",
        "name": "Potential unsafe C memory operation",
        "severity": "high",
        "pattern": re.compile(r"\b(strcpy|strcat|sprintf|gets|memcpy)\s*\(", re.IGNORECASE),
        "fix": "Use bounded copies and validate buffer sizes.",
    },
]


def _line_from_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def analyze_known(code: str, input_path: str | None = None) -> List[Finding]:
    findings: List[Finding] = []

    language = "other"
    if input_path:
        language = detect_language(Path(input_path), code)
    file_path = input_path or ""

    for rule in _RULES:
        rule_hits = 0
        for match in rule["pattern"].finditer(code):
            line = _line_from_offset(code, match.start())
            snippet = code.splitlines()[line - 1].strip() if line - 1 < len(code.splitlines()) else ""
            findings.append(
                Finding(
                    cwe_id=rule["cwe_id"],
                    name=rule["name"],
                    severity=rule["severity"],
                    line=line,
                    snippet=snippet,
                    rule_id=rule["rule_id"],
                    fix=rule["fix"],
                    file=file_path,
                )
            )
            rule_hits += 1
            if rule_hits >= 3:
                break

    ml_prediction = predict_stage1(code, language)
    if ml_prediction:
        if ml_prediction.label != "SAFE" or not findings:
            findings.append(
                Finding(
                    cwe_id=ml_prediction.label,
                    name="ML-predicted vulnerability class",
                    severity="medium",
                    line=0,
                    snippet=f"confidence={ml_prediction.confidence:.2f}",
                    rule_id="S1-ML-MODEL",
                fix="Review the flagged area and apply secure coding practices.",
                file=file_path,
                )
            )
    return findings
