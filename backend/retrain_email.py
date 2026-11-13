"""Retrain Scam Shield Email text & hybrid context classifiers.

Debiases ``phishing_email.csv`` (removing Enron/mailing-list over-representation,
honeypot leaks, raw years, and punctuation-artifact skew) and combines it with
weighted modern SaaS/transactional/newsletter/phishing samples from
``data/email_modern_supplement.csv``.

Usage (from ``backend/``):
    python3 retrain_email.py
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
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
from sklearn.model_selection import GroupKFold, GroupShuffleSplit, train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

from app.ml import predictor
from app.ml.email_features import (
    EMAIL_META_FEATURE_NAMES,
    clean_email_text_for_model,
    extract_email_signals,
)

BACKEND_DIR = Path(__file__).resolve().parent
MODELS_DIR = BACKEND_DIR / "app" / "ml" / "saved_models"
EMAIL_CSV = BACKEND_DIR / "phishing_email.csv"
SUPP_CSV = BACKEND_DIR / "data" / "email_modern_supplement.csv"
RANDOM_STATE = 42


def load_debiased_email_corpus() -> pd.DataFrame:
    """Load deduplicated, Enron-debiased legacy emails + weighted modern supplement."""
    df = pd.read_csv(EMAIL_CSV).dropna()
    df.columns = ["text", "label"]
    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(int)

    # Identify 2000s corpus-specific artifacts that caused massive domain shift.
    is_honeypot = df["text"].str.contains(r"josemonkeyorg|monkeyorg", case=False, regex=True)
    df = df[~is_honeypot].reset_index(drop=True)
    txt_clean = df["text"]
    is_enron_c = txt_clean.str.contains(
        r"\b(?:enron|hpl nom|hou ect|vince|kaminski|louise kitchen|daren)\b",
        case=False,
        regex=True,
    )
    is_list_c = txt_clean.str.contains(
        r"\b(?:opensuse|mailing list|listinfo|perl6|fork|spamassassin)\b",
        case=False,
        regex=True,
    )
    general = df[~is_enron_c & ~is_list_c].copy()
    corpus_specific = df[is_enron_c | is_list_c].copy()

    # Keep only a small cap of Enron/mailing-list emails so they don't dominate baseline priors.
    corpus_cap_legit = corpus_specific[corpus_specific["label"] == 0].sample(
        n=min(1500, int((corpus_specific["label"] == 0).sum())), random_state=RANDOM_STATE
    )
    corpus_cap_scam = corpus_specific[corpus_specific["label"] == 1].sample(
        n=min(1000, int((corpus_specific["label"] == 1).sum())), random_state=RANDOM_STATE
    )

    gen_legit = general[general["label"] == 0]
    gen_scam = general[general["label"] == 1].sample(
        n=min(len(gen_legit) + 500, int((general["label"] == 1).sum())), random_state=RANDOM_STATE
    )

    legacy = pd.concat([gen_legit, gen_scam, corpus_cap_legit, corpus_cap_scam], ignore_index=True)
    legacy["cleaned_text"] = [clean_email_text_for_model("", t)[:5000] for t in legacy["text"]]
    legacy["sender"] = ""
    legacy["subject"] = ""
    legacy["body"] = legacy["text"]
    legacy["source"] = "legacy"
    legacy["weight"] = 1.0
    legacy = legacy[legacy["cleaned_text"].str.len() >= 15].drop_duplicates(subset=["cleaned_text"]).copy()

    frames = [legacy[["label", "sender", "subject", "body", "cleaned_text", "source", "weight"]]]

    if SUPP_CSV.exists():
        supp = pd.read_csv(SUPP_CSV).dropna(subset=["label", "body"]).copy()
        supp["label"] = supp["label"].astype(int)
        supp["sender"] = supp["sender"].fillna("").astype(str)
        supp["subject"] = supp["subject"].fillna("").astype(str)
        supp["body"] = supp["body"].fillna("").astype(str)
        supp["cleaned_text"] = [
            clean_email_text_for_model(s, b)[:5000] for s, b in zip(supp["subject"], supp["body"])
        ]
        supp["source"] = "modern"
        # Deduplicate while upweighting unique modern patterns so they aren't drowned out 100:1.
        supp = supp.drop_duplicates(subset=["sender", "cleaned_text"]).copy()
        supp["weight"] = 20.0
        frames.append(supp[["label", "sender", "subject", "body", "cleaned_text", "source", "weight"]])

    merged = pd.concat(frames, ignore_index=True)
    merged = merged.sample(frac=1.0, random_state=RANDOM_STATE).reset_index(drop=True)
    return merged


def _build_text_pipeline() -> Pipeline:
    features = FeatureUnion([
        (
            "word",
            TfidfVectorizer(
                ngram_range=(1, 2),
                min_df=3,
                max_df=0.95,
                max_features=30000,
                sublinear_tf=True,
                dtype=np.float32,
            ),
        ),
        (
            "char",
            TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=(3, 5),
                min_df=12,
                max_features=12000,
                sublinear_tf=True,
                dtype=np.float32,
            ),
        ),
    ])
    base_lr = LogisticRegression(C=1.5, max_iter=1000, solver="lbfgs")
    cal_lr = CalibratedClassifierCV(estimator=base_lr, method="sigmoid", cv=5)
    return Pipeline([("features", features), ("clf", cal_lr)])


def _print_metrics(y_true: np.ndarray, y_prob: np.ndarray, label: str) -> None:
    roc = roc_auc_score(y_true, y_prob)
    pr = average_precision_score(y_true, y_prob)
    brier = brier_score_loss(y_true, y_prob)
    print(f"\n[{label}] n={len(y_true)} | ROC-AUC={roc:.4f} | PR-AUC={pr:.4f} | Brier={brier:.4f}")
    for thr in (0.45, 0.50, 0.65, 0.72, 0.80):
        pred = (y_prob >= thr).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        p = precision_score(y_true, pred, zero_division=0)
        r = recall_score(y_true, pred, zero_division=0)
        f1 = f1_score(y_true, pred, zero_division=0)
        print(f"  thr={thr:.2f} -> P={p:.4f} R={r:.4f} F1={f1:.4f} FPR={fpr*100:.2f}% (FP={fp}, FN={fn})")


def main() -> None:
    predictor.load_models()

    df = load_debiased_email_corpus()
    print(f"Loaded {len(df)} deduplicated email rows: {df['label'].value_counts().to_dict()}")
    print("Source breakdown:", df.groupby(["source", "label"]).size().to_dict())

    legacy_df = df[df["source"] == "legacy"].reset_index(drop=True)
    modern_df = df[df["source"] == "modern"].reset_index(drop=True)

    leg_tr, leg_va = train_test_split(
        legacy_df, test_size=0.20, random_state=RANDOM_STATE, stratify=legacy_df["label"]
    )
    if len(modern_df):
        mod_groups = [
            re.sub(r"__num__|__year__|\d+", "#N", t) for t in modern_df["cleaned_text"]
        ]
        gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=RANDOM_STATE)
        m_tr_idx, m_va_idx = next(gss.split(modern_df, modern_df["label"], groups=mod_groups))
        mod_tr, mod_va = modern_df.iloc[m_tr_idx], modern_df.iloc[m_va_idx]
    else:
        mod_tr, mod_va = modern_df, modern_df

    train_df = pd.concat([leg_tr, mod_tr], ignore_index=True).sample(
        frac=1.0, random_state=RANDOM_STATE
    ).reset_index(drop=True)
    val_df = pd.concat([leg_va, mod_va], ignore_index=True).reset_index(drop=True)

    y_train = train_df["label"].values
    w_train = train_df["weight"].values
    y_val = val_df["label"].values

    print("Computing 5-fold template-grouped out-of-fold calibrated text scores...")
    text_pipe = _build_text_pipeline()
    # Keep identical modern templates in the same OOF fold so meta_clf trusts URL/sender cues.
    train_groups = [
        re.sub(r"__num__|__year__|\d+", "#N", t) if src == "modern" else f"leg_{idx}"
        for idx, (src, t) in enumerate(zip(train_df["source"], train_df["cleaned_text"]))
    ]
    gkf = GroupKFold(n_splits=5)
    p_text_oof = np.zeros(len(train_df), dtype=float)
    X_train_texts = train_df["cleaned_text"].tolist()

    for fold_tr, fold_va in gkf.split(X_train_texts, y_train, groups=train_groups):
        fold_pipe = _build_text_pipeline()
        fold_pipe.fit(
            [X_train_texts[i] for i in fold_tr],
            y_train[fold_tr],
            clf__sample_weight=w_train[fold_tr],
        )
        p_text_oof[fold_va] = fold_pipe.predict_proba([X_train_texts[i] for i in fold_va])[:, 1]

    print("Fitting final calibrated Email text pipeline...")
    text_pipe.fit(X_train_texts, y_train, clf__sample_weight=w_train)

    p_text_val = text_pipe.predict_proba(val_df["cleaned_text"].tolist())[:, 1]
    _print_metrics(y_val, p_text_val, "Val Text-Only (All)")

    modern_val_mask = (val_df["source"] == "modern").values
    if modern_val_mask.any():
        _print_metrics(y_val[modern_val_mask], p_text_val[modern_val_mask], "Val Text-Only (Modern Subset)")

    # Build meta-features on modern emails + a balanced legacy slice so meta-combiner sees rich sender/URL signals.
    print("\nExtracting structured sender + URL + intent signals for Email hybrid combiner...")
    legacy_meta_sample = train_df[train_df["source"] == "legacy"].sample(
        n=min(1200, int((train_df["source"] == "legacy").sum())), random_state=RANDOM_STATE
    )
    modern_train_df = train_df[train_df["source"] == "modern"]
    meta_subset = pd.concat([legacy_meta_sample, modern_train_df], ignore_index=False)
    meta_indices = meta_subset.index.to_numpy()

    X_meta_train = np.array(
        [
            extract_email_signals(
                row.subject, row.sender, row.body, url_risk_fn=predictor.detect_url
            ).to_meta_vector(p_text_oof[idx])
            for idx, row in meta_subset.iterrows()
        ],
        dtype=float,
    )
    y_meta_train = y_train[meta_indices]
    w_meta_train = w_train[meta_indices]

    meta_clf = LogisticRegression(C=1.5, max_iter=1000, solver="lbfgs")
    meta_clf.fit(X_meta_train, y_meta_train, sample_weight=w_meta_train)

    if modern_val_mask.any():
        modern_val_rows = val_df[modern_val_mask]
        X_meta_mod_val = np.array(
            [
                extract_email_signals(
                    row.subject, row.sender, row.body, url_risk_fn=predictor.detect_url
                ).to_meta_vector(p_text_val[idx])
                for idx, row in modern_val_rows.iterrows()
            ],
            dtype=float,
        )
        p_meta_mod_val = meta_clf.predict_proba(X_meta_mod_val)[:, 1]
        _print_metrics(y_val[modern_val_mask], p_meta_mod_val, "Val Hybrid Meta (Modern Subset)")

    # Inspect intercept and top tokens to verify Enron/honeypot artifacts are gone.
    cal_clfs = text_pipe.named_steps["clf"].calibrated_classifiers_
    mean_coef = sum(c.estimator.coef_[0] for c in cal_clfs) / len(cal_clfs)
    mean_intercept = float(sum(c.estimator.intercept_[0] for c in cal_clfs) / len(cal_clfs))
    feat_names = text_pipe.named_steps["features"].get_feature_names_out()
    top_scam = [(feat_names[i], round(float(mean_coef[i]), 2)) for i in np.argsort(mean_coef)[-12:][::-1]]
    top_legit = [(feat_names[i], round(float(mean_coef[i]), 2)) for i in np.argsort(mean_coef)[:12]]
    print(f"\nEmail base intercept: {mean_intercept:.3f}")
    print("Top scam tokens:", top_scam)
    print("Top legit tokens:", top_legit)

    meta_bundle: Dict[str, object] = {
        "version": 2,
        "meta_clf": meta_clf,
        "feature_names": EMAIL_META_FEATURE_NAMES,
    }

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    text_out = MODELS_DIR / "email_model.pkl"
    meta_out = MODELS_DIR / "email_meta_model.pkl"
    joblib.dump(text_pipe, text_out, compress=3)
    joblib.dump(meta_bundle, meta_out, compress=3)
    print(f"\nSaved email_model.pkl ({text_out.stat().st_size / 1024:.1f} KB)")
    print(f"Saved email_meta_model.pkl ({meta_out.stat().st_size / 1024:.1f} KB)")


if __name__ == "__main__":
    main()
