from __future__ import annotations

from pathlib import Path


_C_EXTENSIONS = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"}


def detect_language(path: Path, code: str | None = None) -> str:
    if path.suffix.lower() in _C_EXTENSIONS:
        return "c"
    if code:
        if "#include" in code or "printf(" in code or "malloc(" in code:
            return "c"
    return "other"
