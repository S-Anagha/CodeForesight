from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

from codeforesight.config import CURATED_PAIRS_DIR, NVD_DIR


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Expand curated CVE commit pairs")
    parser.add_argument("--max", type=int, default=50, help="Target number of pairs")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    commit_re = re.compile(r"https://github\\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})")
    exclude_repos = {
        ("torvalds", "linux"),
        ("FFmpeg", "FFmpeg"),
        ("llvm", "llvm-project"),
        ("chromium", "chromium"),
        ("tensorflow", "tensorflow"),
        ("microsoft", "vscode"),
        ("openjdk", "jdk"),
        ("mozilla", "gecko-dev"),
        ("golang", "go"),
    }

    repos_dir = CURATED_PAIRS_DIR / "_repos"
    repos_dir.mkdir(parents=True, exist_ok=True)

    commit_entries = []
    for path in sorted(NVD_DIR.glob("*.json")):
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        for item in data.get("vulnerabilities", []) or []:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            for ref in cve.get("references", []) or []:
                url = ref.get("url", "")
                m = commit_re.match(url)
                if m:
                    owner, repo, sha = m.group(1), m.group(2), m.group(3)
                    if (owner, repo) in exclude_repos:
                        continue
                    commit_entries.append((cve_id, url, owner, repo, sha))

    seen = set()
    unique = []
    for entry in commit_entries:
        if entry[1] in seen:
            continue
        seen.add(entry[1])
        unique.append(entry)

    current_pairs = [p for p in CURATED_PAIRS_DIR.glob("CVE-*") if p.is_dir()]
    current_count = sum(1 for _ in CURATED_PAIRS_DIR.glob("CVE-*/**/metadata.txt"))
    target = max(args.max, current_count)

    collected = 0
    for cve_id, url, owner, repo, sha in unique:
        if current_count + collected >= target:
            break

        pair_dir = CURATED_PAIRS_DIR / cve_id / f"{owner}_{repo}_{sha[:7]}"
        if pair_dir.exists():
            continue

        repo_dir = repos_dir / f"{owner}_{repo}"
        if not repo_dir.exists():
            try:
                subprocess.run(
                    ["git", "clone", "--filter=blob:none", "--no-checkout", f"https://github.com/{owner}/{repo}.git", str(repo_dir)],
                    check=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError:
                continue

        try:
            subprocess.run(["git", "-C", str(repo_dir), "fetch", "--depth", "2", "origin", sha], check=True, capture_output=True)
            result = subprocess.run(
                ["git", "-C", str(repo_dir), "show", "--name-only", "--pretty=", sha],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError:
            continue

        files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if not files:
            continue

        before_dir = pair_dir / "before"
        after_dir = pair_dir / "after"
        before_dir.mkdir(parents=True, exist_ok=True)
        after_dir.mkdir(parents=True, exist_ok=True)

        kept_files = []
        for file_path in files[:10]:
            before = subprocess.run(["git", "-C", str(repo_dir), "show", f"{sha}^:{file_path}"], capture_output=True)
            after = subprocess.run(["git", "-C", str(repo_dir), "show", f"{sha}:{file_path}"], capture_output=True)
            if before.returncode != 0 or after.returncode != 0:
                continue
            if b"\x00" in before.stdout or b"\x00" in after.stdout:
                continue
            (before_dir / file_path).parent.mkdir(parents=True, exist_ok=True)
            (after_dir / file_path).parent.mkdir(parents=True, exist_ok=True)
            (before_dir / file_path).write_bytes(before.stdout)
            (after_dir / file_path).write_bytes(after.stdout)
            kept_files.append(file_path)

        if kept_files:
            meta = pair_dir / "metadata.txt"
            meta.write_text(
                "\n".join(
                    [
                        f"CVE: {cve_id}",
                        f"Commit: {url}",
                        f"Repo: https://github.com/{owner}/{repo}",
                        "Files:",
                        *kept_files,
                    ]
                ),
                encoding="utf-8",
            )
            collected += 1

    print(f"Added {collected} new pairs. Total now: {current_count + collected}")


if __name__ == "__main__":
    main()
