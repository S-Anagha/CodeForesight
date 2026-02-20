from __future__ import annotations

from collections import defaultdict
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
from codeforesight.stages.label_utils import map_cwe_to_group
from codeforesight.stages.language_utils import detect_language
from codeforesight.stages.stage1_model import load_stage1_model


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


def _predict_with_threshold(model, code: str, labels: list[str]) -> str:
    probs = model.predict_proba([code])[0]
    max_idx = int(probs.argmax())
    label = labels[max_idx]
    confidence = float(probs[max_idx])
    if label != "SAFE" and confidence < 0.6:
        return "SAFE"
    return label


def _load_models() -> dict[str, tuple]:
    models: dict[str, tuple] = {}
    if STAGE1_MODEL_C_PATH.exists() and STAGE1_LABELS_C_PATH.exists():
        models["c"] = load_stage1_model(STAGE1_MODEL_C_PATH, STAGE1_LABELS_C_PATH)
    if STAGE1_MODEL_OTHER_PATH.exists() and STAGE1_LABELS_OTHER_PATH.exists():
        models["other"] = load_stage1_model(STAGE1_MODEL_OTHER_PATH, STAGE1_LABELS_OTHER_PATH)
    return models


def main() -> None:
    models = _load_models()
    if not models:
        raise SystemExit("Stage 1 models not found. Run scripts/train_stage1_model.py first.")

    cve_to_cwe = _build_cve_to_cwe(NVD_DIR)
    per_lang = {"c": {"total": 0, "correct": 0}, "other": {"total": 0, "correct": 0}}

    y_true = []
    y_pred = []
    per_label = defaultdict(lambda: {"correct": 0, "total": 0})
    confusion = defaultdict(int)

    for pair in iter_curated_pairs(CURATED_PAIRS_DIR):
        cwe = cve_to_cwe.get(pair.cve_id, "")
        vuln_label = map_cwe_to_group(cwe)

        for file_path in pair.before_dir.rglob("*"):
            if not file_path.is_file():
                continue
            lang = detect_language(file_path)
            if lang not in models:
                continue
            model, labels = models[lang]
            for chunk in _chunk_text(_read_text(file_path)):
                pred = _predict_with_threshold(model, chunk, labels)
                y_true.append(vuln_label)
                y_pred.append(pred)
                per_label[vuln_label]["total"] += 1
                per_label[vuln_label]["correct"] += int(pred == vuln_label)
                confusion[(vuln_label, pred)] += 1
                per_lang[lang]["total"] += 1
                per_lang[lang]["correct"] += int(pred == vuln_label)

        for file_path in pair.after_dir.rglob("*"):
            if not file_path.is_file():
                continue
            lang = detect_language(file_path)
            if lang not in models:
                continue
            model, labels = models[lang]
            for chunk in _chunk_text(_read_text(file_path)):
                pred = _predict_with_threshold(model, chunk, labels)
                y_true.append("SAFE")
                y_pred.append(pred)
                per_label["SAFE"]["total"] += 1
                per_label["SAFE"]["correct"] += int(pred == "SAFE")
                confusion[("SAFE", pred)] += 1
                per_lang[lang]["total"] += 1
                per_lang[lang]["correct"] += int(pred == "SAFE")

    total = len(y_true)
    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    accuracy = (correct / total) if total else 0.0

    print("Stage 1 evaluation")
    print(f"Total samples: {total}")
    print(f"Accuracy: {accuracy:.2%}")
    print("")
    print("Per-label accuracy:")
    for label, stats in sorted(per_label.items()):
        if stats["total"] == 0:
            continue
        acc = stats["correct"] / stats["total"]
        print(f"- {label}: {acc:.2%} ({stats['correct']}/{stats['total']})")

    print("")
    safe_total = per_label["SAFE"]["total"]
    safe_correct = per_label["SAFE"]["correct"]
    vuln_total = total - safe_total
    vuln_correct = sum(
        stats["correct"] for label, stats in per_label.items() if label != "SAFE"
    )
    vuln_acc = (vuln_correct / vuln_total) if vuln_total else 0.0
    print(f"SAFE accuracy: {safe_correct}/{safe_total} = {safe_correct / safe_total:.2%}" if safe_total else "SAFE accuracy: n/a")
    print(f"VULN accuracy: {vuln_correct}/{vuln_total} = {vuln_acc:.2%}" if vuln_total else "VULN accuracy: n/a")

    print("")
    print("Top confusion pairs:")
    for (true_label, pred_label), count in sorted(confusion.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"- {true_label} -> {pred_label}: {count}")

    print("")
    print("Per-language accuracy:")
    for lang, stats in per_lang.items():
        if stats["total"] == 0:
            continue
        acc = stats["correct"] / stats["total"]
        print(f"- {lang}: {acc:.2%} ({stats['correct']}/{stats['total']})")


if __name__ == "__main__":
    main()
