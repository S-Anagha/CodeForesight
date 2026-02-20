from __future__ import annotations

import json
from dataclasses import asdict

from codeforesight.config import NVD_DIR, PROCESSED_DIR
from codeforesight.data.nvd_loader import iter_nvd_records


def main() -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    out_path = PROCESSED_DIR / "cve_index.json"

    records = [asdict(r) for r in iter_nvd_records(NVD_DIR)]
    out_path.write_text(json.dumps(records), encoding="utf-8")
    print(f"Wrote {len(records)} CVE records to {out_path}")


if __name__ == "__main__":
    main()
