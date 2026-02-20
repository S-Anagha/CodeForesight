from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List


@dataclass(frozen=True)
class CuratedPair:
    cve_id: str
    repo_slug: str
    commit: str
    before_dir: Path
    after_dir: Path
    files: List[str]


def iter_curated_pairs(curated_dir: Path) -> Iterator[CuratedPair]:
    for cve_dir in sorted(curated_dir.glob("CVE-*")):
        for pair_dir in sorted(cve_dir.iterdir()):
            if not pair_dir.is_dir():
                continue
            before_dir = pair_dir / "before"
            after_dir = pair_dir / "after"
            meta_path = pair_dir / "metadata.txt"
            files: List[str] = []
            commit_url = ""
            if meta_path.exists():
                content = meta_path.read_text(encoding="utf-8").splitlines()
                for line in content:
                    if line.startswith("Commit: "):
                        commit_url = line.replace("Commit: ", "").strip()
                    if line and not line.startswith(("CVE:", "Commit:", "Repo:", "Files:")):
                        files.append(line.strip())
            yield CuratedPair(
                cve_id=cve_dir.name,
                repo_slug=pair_dir.name,
                commit=commit_url,
                before_dir=before_dir,
                after_dir=after_dir,
                files=files,
            )
