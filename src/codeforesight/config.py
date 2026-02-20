from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = PROJECT_ROOT.parent

DATA_DIR = Path(os.getenv("CODEFORESIGHT_DATA_DIR", WORKSPACE_ROOT / "data"))
NVD_DIR = DATA_DIR / "nvd_api"
CWE_CSV = DATA_DIR / "cwe_catalog.csv"
CURATED_PAIRS_DIR = DATA_DIR / "curated_pairs"
PROCESSED_DIR = DATA_DIR / "processed"

STAGE1_MODEL_C_PATH = PROCESSED_DIR / "stage1_model_c.joblib"
STAGE1_LABELS_C_PATH = PROCESSED_DIR / "stage1_labels_c.json"
STAGE1_MODEL_OTHER_PATH = PROCESSED_DIR / "stage1_model_other.joblib"
STAGE1_LABELS_OTHER_PATH = PROCESSED_DIR / "stage1_labels_other.json"
STAGE3_TEMPORAL_MODEL_PATH = PROCESSED_DIR / "stage3_temporal_model.joblib"
STAGE3_TEMPORAL_META_PATH = PROCESSED_DIR / "stage3_temporal_meta.json"
STAGE3_TIMELINE_MODEL_PATH = PROCESSED_DIR / "stage3_timeline_model.joblib"
STAGE3_TIMELINE_META_PATH = PROCESSED_DIR / "stage3_timeline_meta.json"
