from __future__ import annotations

from pathlib import Path

from codeforesight.config import (
    CURATED_PAIRS_DIR,
    NVD_DIR,
    STAGE1_LABELS_C_PATH,
    STAGE1_LABELS_OTHER_PATH,
    STAGE1_MODEL_C_PATH,
    STAGE1_MODEL_OTHER_PATH,
)
from codeforesight.data.curated_pairs import iter_curated_pairs
from codeforesight.data.nvd_loader import iter_nvd_records
from codeforesight.stages.language_utils import detect_language
from codeforesight.stages.label_utils import map_cwe_to_group
from codeforesight.stages.stage1_model import train_stage1_model


def _build_cve_to_cwe(nvd_dir: Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for record in iter_nvd_records(nvd_dir):
        if not record.cve_id:
            continue
        if record.cwe_ids:
            mapping[record.cve_id] = record.cwe_ids[0]
    return mapping


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _chunk_text(text: str, lines_per_chunk: int = 40, stride: int = 20, max_chunks: int = 20) -> list[str]:
    lines = text.splitlines()
    if not lines:
        return []
    if len(lines) <= lines_per_chunk:
        return [text]
    chunks: list[str] = []
    for start in range(0, len(lines), stride):
        end = start + lines_per_chunk
        chunk = "\n".join(lines[start:end]).strip()
        if chunk:
            chunks.append(chunk)
        if len(chunks) >= max_chunks:
            break
    return chunks


def main() -> None:
    cve_to_cwe = _build_cve_to_cwe(NVD_DIR)

    texts_c: list[str] = []
    labels_c: list[str] = []
    texts_other: list[str] = []
    labels_other: list[str] = []

    for pair in iter_curated_pairs(CURATED_PAIRS_DIR):
        cwe = cve_to_cwe.get(pair.cve_id, "")
        label = map_cwe_to_group(cwe)
        for file_path in pair.before_dir.rglob("*"):
            if file_path.is_file():
                language = detect_language(file_path)
                for chunk in _chunk_text(_read_text(file_path)):
                    if language == "c":
                        texts_c.append(chunk)
                        labels_c.append(label)
                    else:
                        texts_other.append(chunk)
                        labels_other.append(label)
        for file_path in pair.after_dir.rglob("*"):
            if file_path.is_file():
                language = detect_language(file_path)
                for chunk in _chunk_text(_read_text(file_path)):
                    if language == "c":
                        texts_c.append(chunk)
                        labels_c.append("SAFE")
                    else:
                        texts_other.append(chunk)
                        labels_other.append("SAFE")

    if texts_c:
        train_stage1_model(texts_c, labels_c, STAGE1_MODEL_C_PATH, STAGE1_LABELS_C_PATH)
    if texts_other:
        train_stage1_model(texts_other, labels_other, STAGE1_MODEL_OTHER_PATH, STAGE1_LABELS_OTHER_PATH)

    def _print_dist(name: str, labels: list[str]) -> None:
        label_counts = {}
        for label in labels:
            label_counts[label] = label_counts.get(label, 0) + 1
        print(f"{name} samples: {len(labels)} across {len(set(labels))} labels.")
        print(f"{name} label distribution:")
        for label, count in sorted(label_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"- {label}: {count}")

    if labels_c:
        _print_dist("C/C++", labels_c)
    if labels_other:
        _print_dist("Other", labels_other)


if __name__ == "__main__":
    main()
