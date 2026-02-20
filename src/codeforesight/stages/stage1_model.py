from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from codeforesight.config import (
    STAGE1_LABELS_C_PATH,
    STAGE1_LABELS_OTHER_PATH,
    STAGE1_MODEL_C_PATH,
    STAGE1_MODEL_OTHER_PATH,
)


@dataclass(frozen=True)
class Stage1Prediction:
    label: str
    confidence: float


def train_stage1_model(
    texts: List[str],
    labels: List[str],
    model_path: Path,
    labels_path: Path,
) -> None:
    if not texts:
        raise ValueError("No training texts provided.")
    if len(texts) != len(labels):
        raise ValueError("Texts and labels length mismatch.")

    pipeline: Pipeline = Pipeline(
        steps=[
            ("tfidf", TfidfVectorizer(max_features=20000, ngram_range=(1, 2))),
            ("clf", LogisticRegression(max_iter=300, n_jobs=1, class_weight="balanced")),
        ]
    )
    pipeline.fit(texts, labels)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_path)
    labels_path.write_text(json.dumps(sorted(set(labels))), encoding="utf-8")


def load_stage1_model(model_path: Path, labels_path: Path) -> Tuple[Pipeline, List[str]]:
    model = joblib.load(model_path)
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    return model, labels


def _predict_with_threshold(model: Pipeline, labels: List[str], code: str) -> Stage1Prediction:
    probs = model.predict_proba([code])[0]
    max_idx = int(probs.argmax())
    label = labels[max_idx]
    confidence = float(probs[max_idx])
    if label != "SAFE" and confidence < 0.6:
        return Stage1Prediction(label="SAFE", confidence=1.0 - confidence)
    return Stage1Prediction(label=label, confidence=confidence)


def predict_stage1(
    code: str,
    language: str,
) -> Stage1Prediction | None:
    if language == "c":
        model_path = STAGE1_MODEL_C_PATH
        labels_path = STAGE1_LABELS_C_PATH
    else:
        model_path = STAGE1_MODEL_OTHER_PATH
        labels_path = STAGE1_LABELS_OTHER_PATH

    if not model_path.exists() or not labels_path.exists():
        return None

    model, labels = load_stage1_model(model_path, labels_path)
    return _predict_with_threshold(model, labels, code)
