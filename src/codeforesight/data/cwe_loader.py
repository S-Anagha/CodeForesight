from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Dict


@dataclass(frozen=True)
class CweRecord:
    cwe_id: str
    name: str
    abstraction: str
    status: str
    description: str


def load_cwe_catalog(csv_path: Path) -> Dict[str, CweRecord]:
    catalog: Dict[str, CweRecord] = {}
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cwe_id = row.get("cwe_id", "")
            if not cwe_id:
                continue
            catalog[cwe_id] = CweRecord(
                cwe_id=cwe_id,
                name=row.get("name", ""),
                abstraction=row.get("abstraction", ""),
                status=row.get("status", ""),
                description=row.get("description", ""),
            )
    return catalog
