from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, List


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    published: str
    description: str
    cwe_ids: List[str]
    references: List[str]


def _extract_description(descriptions: list[dict]) -> str:
    for item in descriptions or []:
        if item.get("lang") == "en":
            return item.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _extract_cwe_ids(weaknesses: list[dict]) -> List[str]:
    cwe_ids: list[str] = []
    for weakness in weaknesses or []:
        for desc in weakness.get("description", []) or []:
            value = desc.get("value", "")
            if value.startswith("CWE-"):
                cwe_ids.append(value)
    return sorted(set(cwe_ids))


def iter_nvd_records(nvd_dir: Path) -> Iterator[CveRecord]:
    for path in sorted(nvd_dir.glob("*.json")):
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        for item in data.get("vulnerabilities", []) or []:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            record = CveRecord(
                cve_id=cve_id,
                published=cve.get("published", ""),
                description=_extract_description(cve.get("descriptions", [])),
                cwe_ids=_extract_cwe_ids(cve.get("weaknesses", [])),
                references=[ref.get("url", "") for ref in cve.get("references", []) or []],
            )
            yield record


def load_nvd_records(nvd_dir: Path) -> List[CveRecord]:
    return list(iter_nvd_records(nvd_dir))
