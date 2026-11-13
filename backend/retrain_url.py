"""Retrain Scam Shield URL classifier using scheme-invariant features,
out-of-fold host/path char n-grams, and calibrated HistGradientBoosting.

Usage (from ``backend/``):
    python3 retrain_url.py
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupKFold, GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from app.ml.url_features import URL_FEATURE_NAMES, parse_canonical_url

BACKEND_DIR = Path(__file__).resolve().parent
MODELS_DIR = BACKEND_DIR / "app" / "ml" / "saved_models"
URL_CSV = BACKEND_DIR / "malicious_urls.csv"
MODERN_SUPPLEMENT_CSV = BACKEND_DIR / "data" / "url_modern_supplement.csv"

# Rows >= 555186 in Kaggle malicious_urls.csv have swapped benign/phishing labels.
CLEAN_SLICE_END = 555186
MAX_URLS_PER_DOMAIN = 10
MODERN_SAMPLE_WEIGHT = 18.0
RANDOM_STATE = 42


def load_clean_url_dataset(csv_path: Path, supplement_path: Path | None = None) -> pd.DataFrame:
    """Load clean, deduplicated, domain-capped URL records without scheme leakage."""
    df = pd.read_csv(csv_path).dropna().reset_index(drop=True)
    df = df.iloc[:CLEAN_SLICE_END].copy()
    df = df[df["type"].isin(["benign", "phishing", "malware"])].copy()
    df["label"] = (df["type"] != "benign").astype(int)
    df["sample_weight"] = 1.0

    parsed_base = [parse_canonical_url(u) for u in df["url"]]
    df["canon_key"] = [f"{p.canonical_host_text}/{p.canonical_path_text}" for p in parsed_base]
    # Drop ambiguous conflicting labels inside raw Kaggle rows.
    label_nunique = df.groupby("canon_key")["label"].transform("nunique")
    df = df[label_nunique == 1].drop_duplicates(subset=["canon_key"]).copy()

    if supplement_path is not None and supplement_path.exists():
        supp = pd.read_csv(supplement_path).dropna().reset_index(drop=True)
        supp = supp[supp["type"].isin(["benign", "phishing", "malware"])].copy()
        supp["label"] = (supp["type"] != "benign").astype(int)
        supp["sample_weight"] = MODERN_SAMPLE_WEIGHT
        parsed_supp = [parse_canonical_url(u) for u in supp["url"]]
        supp["canon_key"] = [f"{p.canonical_host_text}/{p.canonical_path_text}" for p in parsed_supp]
        df = pd.concat([supp, df], ignore_index=True)
        df = df.drop_duplicates(subset=["canon_key"], keep="first").reset_index(drop=True)

    parsed = [parse_canonical_url(u) for u in df["url"]]
    df["host_text"] = [p.canonical_host_text for p in parsed]
    df["path_text"] = [p.canonical_path_text for p in parsed]
    df["domain_group"] = [p.registrable_domain for p in parsed]
    df["features"] = [p.features for p in parsed]

    # Cap URLs per (label, registrable_domain) so giant hubs cannot skew priors.
    df = df.sample(frac=1.0, random_state=RANDOM_STATE)
    df = df.groupby(["label", "domain_group"], sort=False).head(MAX_URLS_PER_DOMAIN).reset_index(drop=True)
    return df


def _oof_char_probs(
    texts: np.ndarray,
    y: np.ndarray,
    groups: np.ndarray,
    weights: np.ndarray,
    gkf: GroupKFold,
    *,
    max_features: int,
    min_df: int,
    c_val: float,
) -> tuple[np.ndarray, Pipeline]:
    """Compute leak-free GroupKFold OOF probabilities and fit final weighted pipeline."""
    oof = np.zeros(len(y), dtype=float)
    text_list = list(texts)
    for tr_idx, va_idx in gkf.split(text_list, y, groups):
        fold_pipe = _build_char_pipeline(max_features=max_features, min_df=min_df, c_val=c_val)
        fold_pipe.fit([text_list[i] for i in tr_idx], y[tr_idx], clf__sample_weight=weights[tr_idx])
        oof[va_idx] = fold_pipe.predict_proba([text_list[i] for i in va_idx])[:, 1]
    full_pipe = _build_char_pipeline(max_features=max_features, min_df=min_df, c_val=c_val)
    full_pipe.fit(text_list, y, clf__sample_weight=weights)
    return oof, full_pipe


def _build_char_pipeline(max_features: int, min_df: int, c_val: float) -> Pipeline:
    return Pipeline([
        (
            "vec",
            TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=(3, 5),
                min_df=min_df,
                max_features=max_features,
                sublinear_tf=True,
                dtype=np.float32,
            ),
        ),
        (
            "clf",
            LogisticRegression(
                C=c_val,
                max_iter=500,
                solver="lbfgs",
            ),
        ),
    ])


def _print_threshold_table(y_true: np.ndarray, y_prob: np.ndarray, prefix: str) -> None:
    roc = roc_auc_score(y_true, y_prob)
    pr = average_precision_score(y_true, y_prob)
    brier = brier_score_loss(y_true, y_prob)
    print(f"\n[{prefix}] n={len(y_true)} | ROC-AUC={roc:.4f} | PR-AUC={pr:.4f} | Brier={brier:.4f}")
    for thr in (0.40, 0.50, 0.65, 0.75, 0.85):
        pred = (y_prob >= thr).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        p = precision_score(y_true, pred, zero_division=0)
        r = recall_score(y_true, pred, zero_division=0)
        f1 = f1_score(y_true, pred, zero_division=0)
        print(f"  thr={thr:.2f} -> P={p:.4f} R={r:.4f} F1={f1:.4f} FPR={fpr*100:.2f}% (FP={fp}, FN={fn})")


def main() -> None:
    print("Loading & cleaning malicious_urls.csv (+ modern URL supplement)...")
    df = load_clean_url_dataset(URL_CSV, MODERN_SUPPLEMENT_CSV)
    print("Domain-capped counts:", df["type"].value_counts().to_dict())
    print("Binary counts:", df["label"].value_counts().to_dict())

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=RANDOM_STATE)
    train_idx, val_idx = next(splitter.split(df, df["label"], groups=df["domain_group"]))
    train_df = df.iloc[train_idx].reset_index(drop=True)
    val_df = df.iloc[val_idx].reset_index(drop=True)
    print(
        f"Domain-grouped split: train={len(train_df)} ({train_df['domain_group'].nunique()} domains), "
        f"val={len(val_df)} ({val_df['domain_group'].nunique()} domains)"
    )

    y_train = train_df["label"].values
    w_train = train_df["sample_weight"].values
    y_val = val_df["label"].values
    groups_train = train_df["domain_group"].values

    gkf = GroupKFold(n_splits=5)

    print("Computing out-of-fold host char n-gram risk scores (GroupKFold)...")
    p_host_oof, host_pipe = _oof_char_probs(
        train_df["host_text"].values,
        y_train,
        groups_train,
        w_train,
        gkf,
        max_features=18000,
        min_df=15,
        c_val=0.45,
    )

    print("Computing out-of-fold path char n-gram risk scores (GroupKFold)...")
    p_path_oof, path_pipe = _oof_char_probs(
        train_df["path_text"].values,
        y_train,
        groups_train,
        w_train,
        gkf,
        max_features=18000,
        min_df=25,
        c_val=0.25,
    )

    has_path_train = np.array([1.0 if pt else 0.0 for pt in train_df["path_text"]], dtype=float)
    p_path_oof_adj = np.where(has_path_train > 0.0, p_path_oof, 0.25)

    X_struct_train = np.array(train_df["features"].tolist(), dtype=float)
    X_meta_train = np.column_stack([X_struct_train, p_host_oof, p_path_oof_adj])

    print("Training calibrated HistGradientBoosting meta-classifier...")
    base_hgb = HistGradientBoostingClassifier(
        max_iter=250,
        max_depth=6,
        learning_rate=0.07,
        min_samples_leaf=40,
        l2_regularization=2.0,
        random_state=RANDOM_STATE,
    )
    cal_cv = list(GroupKFold(n_splits=3).split(X_meta_train, y_train, groups=groups_train))
    meta_clf = CalibratedClassifierCV(estimator=base_hgb, method="isotonic", cv=cal_cv)
    # Fit calibrated meta-classifier unweighted so structural feature calibration follows true priors.
    meta_clf.fit(X_meta_train, y_train)

    # Validation inference using trained host/path + calibrated meta classifier.
    p_host_val = host_pipe.predict_proba(val_df["host_text"].tolist())[:, 1]
    p_path_val = path_pipe.predict_proba(val_df["path_text"].tolist())[:, 1]
    has_path_val = np.array([1.0 if pt else 0.0 for pt in val_df["path_text"]], dtype=float)
    p_path_val_adj = np.where(has_path_val > 0.0, p_path_val, 0.25)

    X_struct_val = np.array(val_df["features"].tolist(), dtype=float)
    X_meta_val = np.column_stack([X_struct_val, p_host_val, p_path_val_adj])
    p_val = meta_clf.predict_proba(X_meta_val)[:, 1]

    _print_threshold_table(y_val, p_val, "Unseen-Domain CSV Validation")

    # Slice check on hard benign URLs inside val_df (auth/docs/blog/hyphenated paths).
    val_benign_mask = y_val == 0
    hard_mask = val_benign_mask & val_df["canon_key"].str.contains(
        r"(?:login|signin|account|password|support|docs\.|blog\.|\?)", regex=True
    ).values
    if hard_mask.any():
        hard_probs = p_val[hard_mask]
        print(
            f"\n[Val Benign Auth/Docs/Blog Slice] n={int(hard_mask.sum())} | "
            f"FPR@0.50={(hard_probs >= 0.50).mean()*100:.2f}% | "
            f"FPR@0.75={(hard_probs >= 0.75).mean()*100:.2f}%"
        )

    # Fit IsolationForest strictly on benign structural features for novelty flagging.
    print("\nTraining benign-only IsolationForest anomaly model...")
    X_benign_struct = X_struct_train[y_train == 0]
    anomaly_pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("iso", IsolationForest(n_estimators=100, max_samples=2048, contamination=0.03, random_state=RANDOM_STATE)),
    ])
    anomaly_pipe.fit(X_benign_struct)

    model_bundle: Dict[str, object] = {
        "version": 2,
        "host_vectorizer": host_pipe.named_steps["vec"],
        "host_clf": host_pipe.named_steps["clf"],
        "path_vectorizer": path_pipe.named_steps["vec"],
        "path_clf": path_pipe.named_steps["clf"],
        "meta_clf": meta_clf,
        "feature_names": URL_FEATURE_NAMES + ["p_host_char", "p_path_char"],
    }

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    url_out = MODELS_DIR / "url_model.pkl"
    ano_out = MODELS_DIR / "anomaly_model.pkl"
    joblib.dump(model_bundle, url_out, compress=3)
    joblib.dump(anomaly_pipe, ano_out, compress=3)

    print(f"\nSaved url_model.pkl ({url_out.stat().st_size / 1024:.1f} KB)")
    print(f"Saved anomaly_model.pkl ({ano_out.stat().st_size / 1024:.1f} KB)")


if __name__ == "__main__":
    main()
