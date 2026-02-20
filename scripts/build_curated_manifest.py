from __future__ import annotations

import json
from dataclasses import asdict

from codeforesight.config import CURATED_PAIRS_DIR, PROCESSED_DIR
from codeforesight.data.curated_pairs import iter_curated_pairs


def main() -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    out_path = PROCESSED_DIR / "curated_manifest.json"

    records = [asdict(r) for r in iter_curated_pairs(CURATED_PAIRS_DIR)]
    out_path.write_text(json.dumps(records), encoding="utf-8")
    print(f"Wrote {len(records)} curated records to {out_path}")


if __name__ == "__main__":
    main()
