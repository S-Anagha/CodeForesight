from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
from sklearn.linear_model import LogisticRegression, Ridge

from codeforesight.config import (
    NVD_DIR,
    STAGE3_TEMPORAL_META_PATH,
    STAGE3_TEMPORAL_MODEL_PATH,
    STAGE3_TIMELINE_META_PATH,
    STAGE3_TIMELINE_MODEL_PATH,
)
from codeforesight.data.nvd_loader import iter_nvd_records


@dataclass(frozen=True)
class TemporalForecast:
    risk_score: float
    forecast_count: int
    window_months: int
    status: str
    reason: str
    timeline_bucket: str
    timeline_confidence: float


def _year_month(published: str) -> str | None:
    if not published or len(published) < 7:
        return None
    return published[:7]


def _month_range(start_ym: str, end_ym: str) -> List[str]:
    start_year, start_month = map(int, start_ym.split("-"))
    end_year, end_month = map(int, end_ym.split("-"))
    months: List[str] = []
    year, month = start_year, start_month
    while (year, month) <= (end_year, end_month):
        months.append(f"{year:04d}-{month:02d}")
        month += 1
        if month > 12:
            month = 1
            year += 1
    return months


def _load_monthly_counts(nvd_dir: Path) -> Tuple[List[str], List[int]]:
    counts: Dict[str, int] = {}
    for record in iter_nvd_records(nvd_dir):
        ym = _year_month(record.published)
        if not ym:
            continue
        counts[ym] = counts.get(ym, 0) + 1
    if not counts:
        return [], []

    months = _month_range(min(counts.keys()), max(counts.keys()))
    values = [counts.get(m, 0) for m in months]
    return months, values


def summarize_recent_cwe_trends(
    nvd_dir: Path = NVD_DIR,
    window_months: int = 6,
    top_k: int = 5,
) -> List[Dict[str, int]]:
    if window_months <= 0:
        return []

    months_seen: List[str] = []
    for record in iter_nvd_records(nvd_dir):
        ym = _year_month(record.published)
        if not ym:
            continue
        months_seen.append(ym)

    if not months_seen:
        return []

    max_month = max(months_seen)
    all_months = _month_range(min(months_seen), max_month)
    recent_months = set(all_months[-window_months:])

    filtered_counts: Dict[str, int] = {}
    for record in iter_nvd_records(nvd_dir):
        ym = _year_month(record.published)
        if not ym or ym not in recent_months:
            continue
        for cwe_id in record.cwe_ids or []:
            filtered_counts[cwe_id] = filtered_counts.get(cwe_id, 0) + 1

    if not filtered_counts:
        return []

    sorted_items = sorted(filtered_counts.items(), key=lambda x: x[1], reverse=True)[:top_k]
    return [{"cwe_id": cwe_id, "count": count} for cwe_id, count in sorted_items]


def _build_samples(values: List[int], window: int) -> Tuple[List[List[int]], List[int]]:
    x: List[List[int]] = []
    y: List[int] = []
    for idx in range(window, len(values)):
        x.append(values[idx - window : idx])
        y.append(values[idx])
    return x, y


def _build_timeline_samples(
    values: List[int],
    window: int,
    future_window: int,
) -> Tuple[List[List[int]], List[int], int]:
    x: List[List[int]] = []
    future_sums: List[int] = []
    for idx in range(window, len(values) - future_window + 1):
        x.append(values[idx - window : idx])
        future_sums.append(sum(values[idx : idx + future_window]))
    if not future_sums:
        return [], [], 0

    sorted_sums = sorted(future_sums)
    median_sum = sorted_sums[len(sorted_sums) // 2]
    labels = [1 if s >= median_sum else 0 for s in future_sums]
    return x, labels, int(median_sum)


def train_temporal_model(
    nvd_dir: Path = NVD_DIR,
    model_path: Path = STAGE3_TEMPORAL_MODEL_PATH,
    meta_path: Path = STAGE3_TEMPORAL_META_PATH,
    window: int = 6,
) -> Dict[str, int]:
    months, values = _load_monthly_counts(nvd_dir)
    if len(values) <= window:
        raise RuntimeError("Not enough NVD history to train temporal model.")

    x, y = _build_samples(values, window)
    model = Ridge(alpha=1.0)
    model.fit(x, y)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)

    future_window = 6
    x_timeline, y_timeline, median_sum = _build_timeline_samples(values, window, future_window)
    timeline_meta = {
        "window": window,
        "future_window": future_window,
        "median_future_sum": int(median_sum),
        "status": "skipped",
        "reason": "",
    }
    if x_timeline and len(set(y_timeline)) > 1:
        timeline_model = LogisticRegression(max_iter=300)
        timeline_model.fit(x_timeline, y_timeline)
        joblib.dump(timeline_model, STAGE3_TIMELINE_MODEL_PATH)
        timeline_meta["status"] = "ok"
    else:
        timeline_meta["status"] = "skipped"
        timeline_meta["reason"] = "Not enough variation to train timeline model"

    STAGE3_TIMELINE_META_PATH.write_text(json.dumps(timeline_meta, indent=2), encoding="utf-8")

    meta = {
        "window": window,
        "min_count": int(min(y)),
        "max_count": int(max(y)),
        "months": len(months),
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def predict_temporal_risk(
    nvd_dir: Path = NVD_DIR,
    model_path: Path = STAGE3_TEMPORAL_MODEL_PATH,
    meta_path: Path = STAGE3_TEMPORAL_META_PATH,
) -> TemporalForecast:
    if not model_path.exists() or not meta_path.exists():
        return TemporalForecast(
            risk_score=0.0,
            forecast_count=0,
            window_months=0,
            status="skipped",
            reason="Temporal model not trained",
            timeline_bucket="",
            timeline_confidence=0.0,
        )

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    window = int(meta.get("window", 6))
    min_count = int(meta.get("min_count", 0))
    max_count = int(meta.get("max_count", 1))
    _, values = _load_monthly_counts(nvd_dir)
    if len(values) <= window:
        return TemporalForecast(
            risk_score=0.0,
            forecast_count=0,
            window_months=window,
            status="error",
            reason="Not enough NVD history for prediction",
            timeline_bucket="",
            timeline_confidence=0.0,
        )

    model = joblib.load(model_path)
    recent_window = values[-window:]
    forecast = float(model.predict([recent_window])[0])
    forecast = max(forecast, 0.0)

    denom = max(max_count - min_count, 1)
    risk_score = (forecast - min_count) / denom
    risk_score = max(0.0, min(risk_score, 1.0))

    timeline_bucket = ""
    timeline_confidence = 0.0
    if STAGE3_TIMELINE_MODEL_PATH.exists() and STAGE3_TIMELINE_META_PATH.exists():
        timeline_meta = json.loads(STAGE3_TIMELINE_META_PATH.read_text(encoding="utf-8"))
        if timeline_meta.get("status") == "ok":
            timeline_model = joblib.load(STAGE3_TIMELINE_MODEL_PATH)
            proba = timeline_model.predict_proba([recent_window])[0]
            # index 1 = high (3-6 months), index 0 = low (6-12 months)
            timeline_bucket = "3-6 months" if proba[1] >= 0.5 else "6-12 months"
            timeline_confidence = round(float(max(proba)), 2)

    return TemporalForecast(
        risk_score=round(risk_score, 2),
        forecast_count=int(round(forecast)),
        window_months=window,
        status="ok",
        reason="",
        timeline_bucket=timeline_bucket,
        timeline_confidence=timeline_confidence,
    )
