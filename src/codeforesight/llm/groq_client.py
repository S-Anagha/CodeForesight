from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List


GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"


def _post_json(url: str, payload: Dict[str, Any], api_key: str) -> Dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "CodeForesight/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        details = err.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"Groq API error {err.code}: {details}") from err


def explain_findings(
    findings: List[Dict[str, Any]],
    code_snippet: str,
    model: str = "openai/gpt-oss-120b",
    max_findings: int = 3,
) -> Dict[str, Any]:
    api_key = os.getenv("GROQ_API_KEY", "")
    if not api_key:
        return {
            "status": "skipped",
            "reason": "GROQ_API_KEY not set",
            "explanations": [],
        }

    trimmed_findings = findings[:max_findings]
    prompt = {
        "role": "user",
        "content": (
            "You are a security assistant. Explain each finding with:\n"
            "1) Why it is risky\n"
            "2) How to fix it\n"
            "Keep it short (2-3 sentences each).\n\n"
            f"Findings: {json.dumps(trimmed_findings)}\n\n"
            f"Code snippet:\n{code_snippet}\n"
        ),
    }

    payload = {
        "model": model,
        "messages": [prompt],
        "temperature": 0.2,
        "max_tokens": 400,
    }

    try:
        response = _post_json(GROQ_ENDPOINT, payload, api_key)
        content = response.get("choices", [{}])[0].get("message", {}).get("content", "")
        return {
            "status": "ok",
            "model": model,
            "explanations": [content.strip()] if content else [],
        }
    except RuntimeError:
        return {
            "status": "fallback",
            "reason": "Groq API unavailable; using template explanations",
            "explanations": _fallback_explanations(trimmed_findings),
        }


def analyze_code(
    code_snippet: str,
    model: str = "openai/gpt-oss-120b",
) -> Dict[str, Any]:
    api_key = os.getenv("GROQ_API_KEY", "")
    if not api_key:
        return {
            "status": "skipped",
            "reason": "GROQ_API_KEY not set",
            "analysis": "",
        }

    prompt = {
        "role": "user",
        "content": (
            "You are a security assistant. Analyze this code and list up to 3 "
            "potential vulnerabilities and brief fixes.\n\n"
            f"Code snippet:\n{code_snippet}\n"
        ),
    }

    payload = {
        "model": model,
        "messages": [prompt],
        "temperature": 0.2,
        "max_tokens": 300,
    }

    try:
        response = _post_json(GROQ_ENDPOINT, payload, api_key)
        content = response.get("choices", [{}])[0].get("message", {}).get("content", "")
        return {
            "status": "ok",
            "model": model,
            "analysis": content.strip(),
        }
    except RuntimeError:
        return {
            "status": "fallback",
            "reason": "Groq API unavailable; using template analysis",
            "analysis": "LLM analysis unavailable. Review code for unsafe input handling and memory operations.",
        }


def analyze_unknown_findings(
    code_snippet: str,
    model: str = "openai/gpt-oss-120b",
    strict: bool = False,
    focus: List[str] | None = None,
    force: bool = False,
) -> Dict[str, Any]:
    api_key = os.getenv("GROQ_API_KEY", "")
    if not api_key:
        return {
            "status": "skipped",
            "reason": "GROQ_API_KEY not set",
            "findings": [],
        }

    rules = (
        "Limit to at most 3 findings. Keep each field under 80 characters. "
        "Do not include markdown or code fences."
    ) if strict else "Return concise findings."

    focus_hint = ""
    if focus:
        focus_hint = (
            "Focus on these functions if present: "
            + ", ".join(sorted(set(focus)))
            + ". "
        )

    force_hint = ""
    if force:
        force_hint = (
            "If any focus function appears flawed, return at least 1 finding. "
            "Do not return an empty list unless you are confident there is no "
            "logic issue in the focus functions."
        )

    user_prompt = {
        "role": "user",
        "content": (
            "Find UNKNOWN or logic-based vulnerabilities (authorization, business logic, "
            "workflow bypass, missing checks). Do NOT report classic signature issues like "
            "SQLi/XSS/command injection/buffer overflow/memory leaks/uninitialized vars "
            "or integer overflow. Only report if you can point to a clear control-flow flaw "
            "or missing validation in the snippet. "
            f"{focus_hint}"
            f"{force_hint} "
            f"{rules} "
            "Return JSON only with this schema:\n"
            "{\n"
            "  \"findings\": [\n"
            "    {\n"
            "      \"issue\": \"short name\",\n"
            "      \"severity\": \"low|medium|high\",\n"
            "      \"line\": 0,\n"
            "      \"snippet\": \"code line\",\n"
            "      \"fix\": \"short fix\",\n"
            "      \"rationale\": \"why it is risky\"\n"
            "    }\n"
            "  ]\n"
            "}\n"
            "If no issues, return {\"findings\": []}.\n\n"
            f"Code snippet:\n{code_snippet}\n"
        ),
    }

    payload = {
        "model": model,
        "messages": [user_prompt],
        "temperature": 0.2,
        "max_tokens": 300 if strict else 500,
    }

    def _call(request_payload: Dict[str, Any]) -> str:
        response = _post_json(GROQ_ENDPOINT, request_payload, api_key)
        return response.get("choices", [{}])[0].get("message", {}).get("content", "").strip()

    def _try_with_payload(request_payload: Dict[str, Any]) -> str:
        content = _call(request_payload)
        if content:
            return content
        short_prompt = dict(user_prompt)
        short_prompt["content"] = short_prompt["content"].replace(code_snippet, code_snippet[:1000])
        retry_payload = dict(request_payload)
        retry_payload["messages"] = [short_prompt]
        return _call(retry_payload)

    try:
        content = _try_with_payload(payload)
        if not content:
            retry_payload = dict(payload)
            retry_payload["model"] = "llama-3.1-8b-instant"
            content = _try_with_payload(retry_payload)
        return {
            "status": "ok",
            "model": model,
            "raw": content,
        }
    except RuntimeError as exc:
        # Retry with smaller model on API error
        try:
            retry_payload = dict(payload)
            retry_payload["model"] = "llama-3.1-8b-instant"
            content = _try_with_payload(retry_payload)
            return {
                "status": "ok",
                "model": "llama-3.1-8b-instant",
                "raw": content,
            }
        except RuntimeError as exc_retry:
            return {
                "status": "error",
                "reason": f"Groq API unavailable: {exc_retry}",
                "findings": [],
            }


def analyze_future_risk(
    code_snippet: str,
    model: str = "openai/gpt-oss-120b",
) -> Dict[str, Any]:
    api_key = os.getenv("GROQ_API_KEY", "")
    if not api_key:
        return {
            "status": "skipped",
            "reason": "GROQ_API_KEY not set",
            "analysis": "",
        }

    prompt = {
        "role": "user",
        "content": (
            "You are a security analyst. Predict future vulnerability risk "
            "in this code (next 3-6 months). Provide:\n"
            "1) Risk level (low/medium/high)\n"
            "2) Short rationale\n"
            "3) One prevention recommendation\n\n"
            f"Code snippet:\n{code_snippet}\n"
        ),
    }

    payload = {
        "model": model,
        "messages": [prompt],
        "temperature": 0.2,
        "max_tokens": 250,
    }

    try:
        response = _post_json(GROQ_ENDPOINT, payload, api_key)
        content = response.get("choices", [{}])[0].get("message", {}).get("content", "")
        return {
            "status": "ok",
            "model": model,
            "analysis": content.strip(),
        }
    except RuntimeError as exc:
        return {
            "status": "error",
            "reason": f"Groq API unavailable: {exc}",
            "analysis": "",
        }


def _fallback_explanations(findings: List[Dict[str, Any]]) -> List[str]:
    templates = {
        "CWE-120": "Potential buffer overflow. Avoid unsafe functions and add bounds checks.",
        "CWE-78": "Command injection risk. Use safe APIs and validate inputs.",
        "CWE-89": "SQL injection risk. Use parameterized queries and input validation.",
        "CWE-79": "XSS risk. Encode output and avoid raw HTML injection.",
        "CWE-22": "Path traversal risk. Normalize paths and enforce allowlists.",
        "CWE-502": "Unsafe deserialization. Avoid deserializing untrusted data.",
    }
    explanations = []
    for finding in findings:
        cwe_id = finding.get("cwe_id", "")
        template = templates.get(cwe_id, "Potential security issue. Review and apply secure coding practices.")
        explanations.append(f"{cwe_id}: {template}")
    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for item in explanations:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped
