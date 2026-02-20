from __future__ import annotations


_CWE_GROUPS = {
    "XSS": {"CWE-79", "CWE-80", "CWE-83"},
    "INJECTION": {"CWE-89", "CWE-78", "CWE-77", "CWE-94", "CWE-95"},
    "PATH_TRAVERSAL": {"CWE-22", "CWE-23", "CWE-35"},
    "DESERIALIZATION": {"CWE-502"},
    "MEMORY_SAFETY": {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-787", "CWE-416"},
    "AUTHZ_AUTHN": {"CWE-287", "CWE-306", "CWE-862", "CWE-863"},
    "CRYPTO": {"CWE-319", "CWE-327", "CWE-326"},
    "INFO_DISCLOSURE": {"CWE-200", "CWE-201"},
    "DOS": {"CWE-400"},
    "INPUT_VALIDATION": {"CWE-20"},
}


def map_cwe_to_group(cwe_id: str) -> str:
    if not cwe_id:
        return "OTHER"
    for group, ids in _CWE_GROUPS.items():
        if cwe_id in ids:
            return group
    return "OTHER"
