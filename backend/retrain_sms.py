"""Retrain Scam Shield SMS text & hybrid fusion classifiers.

Combines deduplicated UCI SMS Spam Collection (``sms_spam.csv``) with
modern transactional ham & smishing messages (``data/sms_modern_supplement.csv``),
uses template-grouped cross-validation to prevent leakage, and calibrates
probabilities for low false-positive rates.

Usage (from ``backend/``):
    python3 retrain_sms.py
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
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
from sklearn.model_selection import GroupKFold, GroupShuffleSplit, cross_val_predict
from sklearn.pipeline import FeatureUnion, Pipeline

from app.ml import predictor
from app.ml.sms_features import SMS_META_FEATURE_NAMES, extract_sms_signals

BACKEND_DIR = Path(__file__).resolve().parent
MODELS_DIR = BACKEND_DIR / "app" / "ml" / "saved_models"
SMS_CSV = BACKEND_DIR / "sms_spam.csv"
SUPP_CSV = BACKEND_DIR / "data" / "sms_modern_supplement.csv"
RANDOM_STATE = 42


def _template_group_key(text: str) -> str:
    """Group messages differing only in numbers/IDs/URLs so splits cannot leak."""
    s = re.sub(r"https?://\S+", "__url__", str(text).lower().strip())
    s = re.sub(r"\d+", "#N", s)
    return re.sub(r"\s+", " ", s)


def load_sms_corpus() -> pd.DataFrame:
    """Load, merge, and deduplicate legacy UCI and modern SMS corpora."""
    uci = pd.read_csv(SMS_CSV, sep="\t", usecols=["v1", "v2"]).rename(
        columns={"v1": "label", "v2": "text"}
    ).dropna()
    uci = uci[uci["label"].isin(["ham", "spam"])].copy()
    uci["label"] = uci["label"].map({"ham": 0, "spam": 1}).astype(int)
    # Assign balanced synthetic sender categories to legacy UCI rows so
    # sender_is_alpha never leaks modern-vs-UCI dataset origin.
    rng = np.random.default_rng(RANDOM_STATE)
    uci["sender_id"] = [
        ("SMSALERT" if rng.random() < 0.5 else "03001234567")
        for _ in range(len(uci))
    ]
    uci["source"] = "uci"

    frames = [uci[["label", "sender_id", "text", "source"]]]
    if SUPP_CSV.exists():
        supp = pd.read_csv(SUPP_CSV).dropna(subset=["label", "text"]).copy()
        supp["label"] = supp["label"].astype(int)
        supp["sender_id"] = supp["sender_id"].fillna("").astype(str)
        supp["source"] = "modern"
        frames.append(supp[["label", "sender_id", "text", "source"]])

    df = pd.concat(frames, ignore_index=True)
    df["text"] = df["text"].astype(str).str.strip()
    df["dedup_key"] = df["text"].str.lower()
    df = df.drop_duplicates(subset=["dedup_key"]).reset_index(drop=True)
    df["group_key"] = [_template_group_key(t) for t in df["text"]]
    return df


def _build_text_pipeline() -> Pipeline:
    features = FeatureUnion([
        (
            "word",
            TfidfVectorizer(
                ngram_range=(1, 2),
                min_df=2,
                max_features=20000,
                sublinear_tf=True,
                dtype=np.float32,
            ),
        ),
        (
            "char",
            TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=(3, 5),
                min_df=3,
                max_features=25000,
                sublinear_tf=True,
                dtype=np.float32,
            ),
        ),
    ])
    base_lr = LogisticRegression(C=1.8, max_iter=1000, solver="lbfgs")
    cal_lr = CalibratedClassifierCV(estimator=base_lr, method="sigmoid", cv=5)
    return Pipeline([("features", features), ("clf", cal_lr)])


def _print_metrics(y_true: np.ndarray, y_prob: np.ndarray, label: str) -> None:
    roc = roc_auc_score(y_true, y_prob)
    pr = average_precision_score(y_true, y_prob)
    brier = brier_score_loss(y_true, y_prob)
    print(f"\n[{label}] n={len(y_true)} | ROC-AUC={roc:.4f} | PR-AUC={pr:.4f} | Brier={brier:.4f}")
    for thr in (0.40, 0.45, 0.50, 0.70, 0.75):
        pred = (y_prob >= thr).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        p = precision_score(y_true, pred, zero_division=0)
        r = recall_score(y_true, pred, zero_division=0)
        f1 = f1_score(y_true, pred, zero_division=0)
        print(f"  thr={thr:.2f} -> P={p:.4f} R={r:.4f} F1={f1:.4f} FPR={fpr*100:.2f}% (FP={fp}, FN={fn})")


def main() -> None:
    predictor.load_models()

    df = load_sms_corpus()
    print(f"Loaded {len(df)} deduplicated SMS rows: {df['label'].value_counts().to_dict()}")
    print("Source breakdown:", df.groupby(["source", "label"]).size().to_dict())

    signals = [
        extract_sms_signals(sndr, txt, url_risk_fn=predictor.detect_url)
        for sndr, txt in zip(df["sender_id"], df["text"])
    ]
    df["model_text"] = [s.model_input_text for s in signals]

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=RANDOM_STATE)
    train_idx, val_idx = next(splitter.split(df, df["label"], groups=df["group_key"]))
    train_df = df.iloc[train_idx].reset_index(drop=True)
    val_df = df.iloc[val_idx].reset_index(drop=True)
    train_signals = [signals[i] for i in train_idx]
    val_signals = [signals[i] for i in val_idx]

    y_train = train_df["label"].values
    y_val = val_df["label"].values
    groups_train = train_df["group_key"].values

    print(f"Template-grouped split: train={len(train_df)}, val={len(val_df)}")
    print("Computing out-of-fold calibrated text predictions (GroupKFold)...")
    text_pipe = _build_text_pipeline()
    gkf = GroupKFold(n_splits=5)
    p_text_oof = cross_val_predict(
        text_pipe,
        train_df["model_text"].tolist(),
        y_train,
        groups=groups_train,
        cv=gkf,
        method="predict_proba",
    )[:, 1]
    text_pipe.fit(train_df["model_text"].tolist(), y_train)

    X_meta_train = np.array(
        [sig.to_meta_vector(pt) for sig, pt in zip(train_signals, p_text_oof)],
        dtype=float,
    )

    p_text_val = text_pipe.predict_proba(val_df["model_text"].tolist())[:, 1]
    X_meta_val = np.array(
        [sig.to_meta_vector(pt) for sig, pt in zip(val_signals, p_text_val)],
        dtype=float,
    )

    print("Training calibrated SMS hybrid fusion model...")
    base_meta = HistGradientBoostingClassifier(
        max_iter=150,
        max_depth=4,
        learning_rate=0.06,
        min_samples_leaf=20,
        l2_regularization=2.0,
        random_state=RANDOM_STATE,
    )
    cal_cv = list(GroupKFold(n_splits=3).split(X_meta_train, y_train, groups=groups_train))
    meta_clf = CalibratedClassifierCV(estimator=base_meta, method="isotonic", cv=cal_cv)
    meta_clf.fit(X_meta_train, y_train)

    p_val_meta = meta_clf.predict_proba(X_meta_val)[:, 1]

    _print_metrics(y_val, p_text_val, "Val Text-Only (sms_model)")
    _print_metrics(y_val, p_val_meta, "Val Hybrid Fusion (sms_meta_model)")

    modern_mask = (val_df["source"] == "modern").values
    if modern_mask.any():
        _print_metrics(y_val[modern_mask], p_val_meta[modern_mask], "Val Modern Subset Only")

    meta_bundle: Dict[str, object] = {
        "version": 2,
        "meta_clf": meta_clf,
        "feature_names": SMS_META_FEATURE_NAMES,
    }

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    text_out = MODELS_DIR / "sms_model.pkl"
    meta_out = MODELS_DIR / "sms_meta_model.pkl"
    joblib.dump(text_pipe, text_out, compress=3)
    joblib.dump(meta_bundle, meta_out, compress=3)
    print(f"\nSaved sms_model.pkl ({text_out.stat().st_size / 1024:.1f} KB)")
    print(f"Saved sms_meta_model.pkl ({meta_out.stat().st_size / 1024:.1f} KB)")


if __name__ == "__main__":
    main()
