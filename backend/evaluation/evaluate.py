"""Unified evaluation harness for Scam Shield Email, SMS, and URL detectors.

Evaluates both:
  1. Suite A (CSV Anti-Leakage Audit): model footprints, duplicate/domain leakage,
     URL scheme-normalization shift, and deduplicated held-out metrics.
  2. Suite B (Hard-Benign & Threat Benchmark): full end-to-end pipeline evaluation
     of ``detect_email``, ``detect_sms``, and ``detect_url`` using API schemas.

Usage (from ``backend/``):
    python3 -m evaluation.evaluate --save evaluation/reports/baseline_report.json
    python3 -m evaluation.evaluate --compare evaluation/reports/baseline_report.json
    python3 -m evaluation.evaluate --skip-csv
"""

from __future__ import annotations

import argparse
import json
import math
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd
import tldextract
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    fbeta_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from app.ml import predictor
from app.ml.email_features import clean_email_text_for_model
from app.ml.url_features import predict_url_bundle
from app.schemas.detection import EmailDetectRequest, SMSDetectRequest, URLDetectRequest

BACKEND_DIR = Path(__file__).resolve().parents[1]
DEFAULT_SUITE_PATH = Path(__file__).resolve().parent / "benchmark_suite.json"
MODELS_DIR = BACKEND_DIR / "app" / "ml" / "saved_models"
OFFLINE_TLD = tldextract.TLDExtract(suffix_list_urls=())


def extract_registrable_domain(url: str) -> str:
    """Return lowercase eTLD+1 (or host fallback) without network calls."""
    cleaned = str(url).strip().lower()
    if not cleaned.startswith(("http://", "https://", "ftp://")):
        cleaned = f"http://{cleaned}"
    parsed = OFFLINE_TLD(cleaned)
    if parsed.domain and parsed.suffix:
        return f"{parsed.domain}.{parsed.suffix}"
    return parsed.domain or cleaned


def _safe_rate(numerator: int, denominator: int) -> float:
    return round(float(numerator / denominator), 4) if denominator else 0.0


def _binary_operating_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, Any]:
    """Compute confusion matrix and binary rates for a fixed decision array."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "fpr": _safe_rate(fp, fp + tn),
        "fnr": _safe_rate(fn, fn + tp),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "f0_5": round(float(fbeta_score(y_true, y_pred, beta=0.5, zero_division=0)), 4),
    }


def compute_classification_metrics(
    y_true: Iterable[int],
    y_prob: Iterable[float],
    y_pred_scam: Iterable[int],
    y_pred_alert: Iterable[int],
) -> Dict[str, Any]:
    """Compute strict-scam, any-alert, ranking, and calibration metrics."""
    yt = np.asarray(list(y_true), dtype=int)
    yp = np.clip(np.asarray(list(y_prob), dtype=float), 0.0, 1.0)
    pred_scam = np.asarray(list(y_pred_scam), dtype=int)
    pred_alert = np.asarray(list(y_pred_alert), dtype=int)

    has_both_classes = len(np.unique(yt)) == 2
    ranking = {
        "roc_auc": round(float(roc_auc_score(yt, yp)), 4) if has_both_classes else None,
        "pr_auc": round(float(average_precision_score(yt, yp)), 4) if has_both_classes else None,
        "brier_score": round(float(brier_score_loss(yt, yp)), 4),
    }
    return {
        "total": int(len(yt)),
        "positives": int((yt == 1).sum()),
        "negatives": int((yt == 0).sum()),
        "strict_scam": _binary_operating_metrics(yt, pred_scam),
        "any_alert": _binary_operating_metrics(yt, pred_alert),
        "ranking_and_calibration": ranking,
    }


def validate_and_normalize_case(modality: str, item: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a benchmark item against the live API Pydantic request schema."""
    if modality == "email":
        req = EmailDetectRequest(
            subject=item.get("subject", ""),
            sender=item.get("sender", ""),
            body=item.get("body", ""),
        )
        return {"subject": req.subject, "sender": req.sender, "body": req.body}
    if modality == "sms":
        req = SMSDetectRequest(
            sender_id=item["sender_id"],
            message=item["message"],
        )
        return {"sender_id": req.sender_id, "message": req.message}
    if modality == "url":
        req = URLDetectRequest(url=item["url"])
        return {"url": req.url}
    raise ValueError(f"Unsupported modality: {modality}")


def _evaluate_modality_suite(
    modality: str,
    cases: List[Dict[str, Any]],
    detector_fn: Callable[[Dict[str, Any]], Dict[str, Any]],
) -> Dict[str, Any]:
    """Run an end-to-end detector on all benchmark cases for one modality."""
    y_true: List[int] = []
    y_prob: List[float] = []
    y_pred_scam: List[int] = []
    y_pred_alert: List[int] = []
    latencies_ms: List[float] = []
    per_case: List[Dict[str, Any]] = []
    false_positives: List[Dict[str, Any]] = []
    false_negatives: List[Dict[str, Any]] = []
    category_buckets: Dict[str, List[Dict[str, Any]]] = {}

    for item in cases:
        payload = validate_and_normalize_case(modality, item)
        t0 = time.perf_counter()
        result = detector_fn(payload)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        latencies_ms.append(elapsed_ms)

        if "error" in result:
            raise RuntimeError(f"Detector error on {item['id']}: {result['error']}")

        label = int(item["label"])
        scam_level = str(result["scam_level"]).lower()
        confidence = float(result["confidence"])
        prob = max(0.0, min(1.0, confidence / 100.0))
        pred_scam = int(scam_level == "scam")
        pred_alert = int(scam_level in {"scam", "suspicious"})

        y_true.append(label)
        y_prob.append(prob)
        y_pred_scam.append(pred_scam)
        y_pred_alert.append(pred_alert)

        record = {
            "id": item["id"],
            "label": label,
            "category": item["category"],
            "difficulty": item["difficulty"],
            "scam_level": scam_level,
            "confidence": round(confidence, 2),
            "pred_scam": pred_scam,
            "pred_alert": pred_alert,
            "latency_ms": round(elapsed_ms, 2),
            "reasons": result.get("reasons", [])[:3],
        }
        per_case.append(record)
        category_buckets.setdefault(item["category"], []).append(record)

        if label == 0 and pred_alert == 1:
            false_positives.append(record)
        elif label == 1 and pred_alert == 0:
            false_negatives.append(record)

    overall = compute_classification_metrics(y_true, y_prob, y_pred_scam, y_pred_alert)

    hard_benign = [r for r in per_case if r["difficulty"] == "hard_benign"]
    hard_benign_summary = {
        "count": len(hard_benign),
        "flagged_scam": sum(r["pred_scam"] for r in hard_benign),
        "flagged_suspicious": sum(1 for r in hard_benign if r["scam_level"] == "suspicious"),
        "scam_fpr": _safe_rate(sum(r["pred_scam"] for r in hard_benign), len(hard_benign)),
        "any_alert_fpr": _safe_rate(sum(r["pred_alert"] for r in hard_benign), len(hard_benign)),
    }

    by_category: Dict[str, Any] = {}
    for category, rows in category_buckets.items():
        neg = [r for r in rows if r["label"] == 0]
        pos = [r for r in rows if r["label"] == 1]
        by_category[category] = {
            "count": len(rows),
            "scam_fpr": _safe_rate(sum(r["pred_scam"] for r in neg), len(neg)) if neg else None,
            "any_alert_fpr": _safe_rate(sum(r["pred_alert"] for r in neg), len(neg)) if neg else None,
            "scam_recall": _safe_rate(sum(r["pred_scam"] for r in pos), len(pos)) if pos else None,
            "any_alert_recall": _safe_rate(sum(r["pred_alert"] for r in pos), len(pos)) if pos else None,
        }

    false_positives.sort(key=lambda r: r["confidence"], reverse=True)
    false_negatives.sort(key=lambda r: r["confidence"])

    return {
        "overall": overall,
        "hard_benign": hard_benign_summary,
        "by_category": by_category,
        "latency_ms": {
            "mean": round(float(np.mean(latencies_ms)), 2),
            "p95": round(float(np.percentile(latencies_ms, 95)), 2),
        },
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "per_case": per_case,
    }


def evaluate_benchmark_suite(
    suite_path: Path = DEFAULT_SUITE_PATH,
    modalities: Tuple[str, ...] = ("email", "sms", "url"),
) -> Dict[str, Any]:
    """Evaluate selected pipelines on the Suite B benchmark file."""
    with suite_path.open("r", encoding="utf-8") as fh:
        suite = json.load(fh)

    dispatch: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
        "email": lambda p: predictor.detect_email(p["subject"], p["sender"], p["body"]),
        "sms": lambda p: predictor.detect_sms(p["sender_id"], p["message"]),
        "url": lambda p: predictor.detect_url(p["url"]),
    }

    return {
        modality: _evaluate_modality_suite(modality, suite[modality], dispatch[modality])
        for modality in modalities
    }


def _artifact_sizes_kb() -> Dict[str, float]:
    sizes: Dict[str, float] = {}
    for path in sorted(MODELS_DIR.glob("*.pkl")):
        sizes[path.name] = round(path.stat().st_size / 1024.0, 2)
    return sizes


def _audit_email_csv() -> Dict[str, Any]:
    csv_path = BACKEND_DIR / "phishing_email.csv"
    df = pd.read_csv(csv_path)
    df.columns = ["text", "label"]
    df = df.dropna()
    df["text"] = df["text"].astype(str)

    X_tr, X_te, y_tr, y_te = train_test_split(
        df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )
    train_unique = set(X_tr)
    is_unseen_in_train = ~X_te.isin(train_unique)
    X_te_dedup = X_te[is_unseen_in_train]
    y_te_dedup = y_te[is_unseen_in_train]

    # Drop duplicate test rows within test split as well.
    keep_mask = ~X_te_dedup.duplicated()
    X_te_clean = X_te_dedup[keep_mask]
    y_te_clean = y_te_dedup[keep_mask]

    if predictor.email_meta_model is not None:
        inputs = [clean_email_text_for_model("", t)[:5000] for t in X_te_clean]
        prob = predictor.email_model.predict_proba(inputs)[:, 1]
        metrics_07 = compute_classification_metrics(
            y_te_clean, prob, (prob >= 0.72).astype(int), (prob >= 0.45).astype(int)
        )
    else:
        prob = predictor.email_model.predict_proba(X_te_clean)[:, 1]
        metrics_07 = compute_classification_metrics(
            y_te_clean, prob, (prob >= 0.90).astype(int), (prob >= 0.70).astype(int)
        )
    return {
        "rows_total": int(len(df)),
        "exact_duplicate_rows": int(df["text"].duplicated().sum()),
        "train_test_exact_overlap": int(len(train_unique & set(X_te))),
        "dedup_test_rows": int(len(X_te_clean)),
        "punctuation_rate": round(float(df["text"].str.contains(r"[.,!?:;/]", regex=True).mean()), 4),
        "ml_threshold_07_09_metrics": metrics_07,
    }


def _audit_sms_csv() -> Dict[str, Any]:
    csv_path = BACKEND_DIR / "sms_spam.csv"
    df = pd.read_csv(csv_path, sep="\t", usecols=["v1", "v2"]).rename(columns={"v1": "label", "v2": "text"}).dropna()
    df = df[df["label"].isin(["ham", "spam"])].copy()
    df["label"] = df["label"].map({"ham": 0, "spam": 1})
    df["text"] = df["text"].astype(str)

    X_tr, X_te, y_tr, y_te = train_test_split(
        df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )
    train_unique = set(X_tr)
    mask = (~X_te.isin(train_unique)) & (~X_te.duplicated())
    X_te_clean = X_te[mask].tolist()
    y_te_clean = y_te[mask].tolist()

    y_prob: List[float] = []
    y_scam: List[int] = []
    y_alert: List[int] = []
    for text in X_te_clean:
        res = predictor.detect_sms("TESTSMS", text)
        y_prob.append(float(res["confidence"]) / 100.0)
        y_scam.append(int(res["scam_level"] == "scam"))
        y_alert.append(int(res["scam_level"] in {"scam", "suspicious"}))

    return {
        "rows_total": int(len(df)),
        "exact_duplicate_rows": int(df["text"].duplicated().sum()),
        "train_test_exact_overlap": int(len(train_unique & set(X_te))),
        "dedup_test_rows": int(len(X_te_clean)),
        "ham_rate": round(float((df["label"] == 0).mean()), 4),
        "end_to_end_dedup_metrics": compute_classification_metrics(y_te_clean, y_prob, y_scam, y_alert),
    }


def _audit_url_csv() -> Dict[str, Any]:
    csv_path = BACKEND_DIR / "malicious_urls.csv"
    df = pd.read_csv(csv_path).dropna()
    df["url"] = df["url"].astype(str)
    df["label"] = df["type"].map({"benign": 0, "defacement": 1, "phishing": 1, "malware": 1})
    df = df.dropna(subset=["label"]).copy()
    df["label"] = df["label"].astype(int)

    has_scheme_by_type = (
        df.assign(has_scheme=df["url"].str.lower().str.startswith(("http://", "https://", "ftp://")))
        .groupby("type")["has_scheme"]
        .mean()
        .round(4)
        .to_dict()
    )

    # Measure raw CSV split vs URLDetectRequest http:// normalization on the 100k sample.
    df_sample = df.sample(n=100000, random_state=42)
    _, X_te_raw, _, y_te_raw = train_test_split(
        df_sample["url"], df_sample["label"], test_size=0.2, random_state=42, stratify=df_sample["label"]
    )
    X_norm_urls = [
        u if u.lower().startswith(("http://", "https://", "ftp://")) else f"http://{u}"
        for u in X_te_raw
    ]
    p_raw = np.array([r["prob"] for r in predict_url_bundle(predictor.url_model, X_te_raw.tolist())])
    p_norm = np.array([r["prob"] for r in predict_url_bundle(predictor.url_model, X_norm_urls)])

    # End-to-end detect_url evaluation on a domain-grouped, deduplicated 400-URL clean subsample
    # (excluding defacement and the swapped-label Kaggle tail >= 555186).
    clean_df = df.iloc[:555186].copy()
    clean_df = clean_df[clean_df["type"].isin(["benign", "phishing", "malware"])].copy()
    clean_df = clean_df.drop_duplicates(subset=["url"]).copy()
    clean_df["domain_group"] = [extract_registrable_domain(u) for u in clean_df["url"]]
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    _, test_idx = next(splitter.split(clean_df, clean_df["label"], clean_df["domain_group"]))
    grouped_test = clean_df.iloc[test_idx].sample(n=400, random_state=42)

    y_e2e_true: List[int] = []
    y_e2e_prob: List[float] = []
    y_e2e_scam: List[int] = []
    y_e2e_alert: List[int] = []
    for u, lbl in zip(grouped_test["url"], grouped_test["label"]):
        norm_u = u if u.lower().startswith(("http://", "https://", "ftp://")) else f"http://{u}"
        res = predictor.detect_url(norm_u)
        y_e2e_true.append(int(lbl))
        y_e2e_prob.append(float(res["confidence"]) / 100.0)
        y_e2e_scam.append(int(res["scam_level"] == "scam"))
        y_e2e_alert.append(int(res["scam_level"] in {"scam", "suspicious"}))

    return {
        "rows_total": int(len(df)),
        "exact_duplicate_rows": int(df["url"].duplicated().sum()),
        "has_scheme_rate_by_type": has_scheme_by_type,
        "ml_raw_csv_20k": compute_classification_metrics(
            y_te_raw, p_raw, (p_raw >= 0.5).astype(int), (p_raw >= 0.5).astype(int)
        ),
        "ml_after_http_normalization_20k": compute_classification_metrics(
            y_te_raw, p_norm, (p_norm >= 0.5).astype(int), (p_norm >= 0.5).astype(int)
        ),
        "end_to_end_domain_grouped_400": compute_classification_metrics(
            y_e2e_true, y_e2e_prob, y_e2e_scam, y_e2e_alert
        ),
    }


def evaluate_csv_audit() -> Dict[str, Any]:
    """Run Suite A dataset leakage and held-out audits."""
    return {
        "model_sizes_kb": _artifact_sizes_kb(),
        "email": _audit_email_csv(),
        "sms": _audit_sms_csv(),
        "url": _audit_url_csv(),
    }


def mcnemar_exact_pvalue(b: int, c: int) -> float:
    """Two-sided exact binomial McNemar p-value for discordant pairs (b, c)."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) * (0.5 ** n)
    return round(min(1.0, 2.0 * tail), 6)


def compare_reports(baseline: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    """Compute paired metric deltas and exact McNemar test vs a saved baseline."""
    comparison: Dict[str, Any] = {}
    for modality in current["suite_b"]:
        if modality not in baseline.get("suite_b", {}):
            continue
        base_m = baseline["suite_b"][modality]
        curr_m = current["suite_b"][modality]
        base_cases = {c["id"]: c for c in base_m["per_case"]}
        curr_cases = {c["id"]: c for c in curr_m["per_case"]}
        shared_ids = sorted(set(base_cases) & set(curr_cases))

        b_discord = 0  # baseline correct, current wrong (any_alert)
        c_discord = 0  # baseline wrong, current correct (any_alert)
        for cid in shared_ids:
            bc = base_cases[cid]
            cc = curr_cases[cid]
            base_ok = bc["pred_alert"] == bc["label"]
            curr_ok = cc["pred_alert"] == cc["label"]
            if base_ok and not curr_ok:
                b_discord += 1
            elif not base_ok and curr_ok:
                c_discord += 1

        comparison[modality] = {
            "hard_benign_alert_fpr_delta": round(
                curr_m["hard_benign"]["any_alert_fpr"] - base_m["hard_benign"]["any_alert_fpr"], 4
            ),
            "hard_benign_scam_fpr_delta": round(
                curr_m["hard_benign"]["scam_fpr"] - base_m["hard_benign"]["scam_fpr"], 4
            ),
            "threat_alert_recall_delta": round(
                curr_m["overall"]["any_alert"]["recall"] - base_m["overall"]["any_alert"]["recall"], 4
            ),
            "f1_alert_delta": round(
                curr_m["overall"]["any_alert"]["f1"] - base_m["overall"]["any_alert"]["f1"], 4
            ),
            "roc_auc_delta": round(
                (curr_m["overall"]["ranking_and_calibration"]["roc_auc"] or 0.0)
                - (base_m["overall"]["ranking_and_calibration"]["roc_auc"] or 0.0),
                4,
            ),
            "brier_delta": round(
                curr_m["overall"]["ranking_and_calibration"]["brier_score"]
                - base_m["overall"]["ranking_and_calibration"]["brier_score"],
                4,
            ),
            "mcnemar_alert": {
                "baseline_only_correct": b_discord,
                "current_only_correct": c_discord,
                "exact_p_value": mcnemar_exact_pvalue(b_discord, c_discord),
            },
        }
    return comparison


def _print_summary(report: Dict[str, Any], comparison: Optional[Dict[str, Any]] = None) -> None:
    print("=" * 78)
    print("SCAM SHIELD — SUITE B BENCHMARK (END-TO-END HARD-BENIGN & THREAT AUDIT)")
    print("=" * 78)
    for modality in report["suite_b"]:
        m = report["suite_b"][modality]
        ov = m["overall"]
        hb = m["hard_benign"]
        scam = ov["strict_scam"]
        alert = ov["any_alert"]
        rk = ov["ranking_and_calibration"]
        print(
            f"\n[{modality.upper()}] cases={ov['total']} (benign={ov['negatives']}, threat={ov['positives']}) "
            f"| mean_latency={m['latency_ms']['mean']}ms (p95={m['latency_ms']['p95']}ms)"
        )
        print(
            f"  Hard-Benign ({hb['count']}): Scam FPR={hb['scam_fpr']*100:.1f}% ({hb['flagged_scam']}), "
            f"Alert(scam+susp) FPR={hb['any_alert_fpr']*100:.1f}% ({hb['flagged_scam']+hb['flagged_suspicious']})"
        )
        print(
            f"  Strict Scam : P={scam['precision']:.3f} R={scam['recall']:.3f} F1={scam['f1']:.3f} "
            f"FPR={scam['fpr']*100:.1f}% FNR={scam['fnr']*100:.1f}% (TN={scam['tn']} FP={scam['fp']} FN={scam['fn']} TP={scam['tp']})"
        )
        print(
            f"  Any Alert   : P={alert['precision']:.3f} R={alert['recall']:.3f} F1={alert['f1']:.3f} "
            f"FPR={alert['fpr']*100:.1f}% FNR={alert['fnr']*100:.1f}% (TN={alert['tn']} FP={alert['fp']} FN={alert['fn']} TP={alert['tp']})"
        )
        print(
            f"  Ranking/Cal : ROC-AUC={rk['roc_auc']} PR-AUC={rk['pr_auc']} Brier={rk['brier_score']}"
        )
        if m["false_positives"]:
            top_fp = ", ".join(f"{r['id']}({r['scam_level']}:{r['confidence']}%)" for r in m["false_positives"][:4])
            print(f"  Sample FPs  : {top_fp}")
        if m["false_negatives"]:
            top_fn = ", ".join(f"{r['id']}({r['scam_level']}:{r['confidence']}%)" for r in m["false_negatives"][:4])
            print(f"  Sample FNs  : {top_fn}")

    if "suite_a" in report:
        sa = report["suite_a"]
        print("\n" + "=" * 78)
        print("SUITE A — CSV ANTI-LEAKAGE & SHIFT AUDIT")
        print("=" * 78)
        print("  Saved model sizes (KB):", sa["model_sizes_kb"])
        e = sa["email"]
        em = e["ml_threshold_07_09_metrics"]["any_alert"]
        print(
            f"  Email CSV : {e['rows_total']} rows | dupes={e['exact_duplicate_rows']} "
            f"| train/test overlap={e['train_test_exact_overlap']} | punct_rate={e['punctuation_rate']} "
            f"| ML@0.7 FPR={em['fpr']*100:.2f}% R={em['recall']:.3f}"
        )
        s = sa["sms"]
        sm = s["end_to_end_dedup_metrics"]["any_alert"]
        print(
            f"  SMS CSV   : {s['rows_total']} rows | dupes={s['exact_duplicate_rows']} "
            f"| train/test overlap={s['train_test_exact_overlap']} | E2E dedup Alert FPR={sm['fpr']*100:.2f}% R={sm['recall']:.3f}"
        )
        u = sa["url"]
        raw_m = u["ml_raw_csv_20k"]["strict_scam"]
        norm_m = u["ml_after_http_normalization_20k"]["strict_scam"]
        e2e_u = u["end_to_end_domain_grouped_400"]["any_alert"]
        print(
            f"  URL CSV   : {u['rows_total']} rows | dupes={u['exact_duplicate_rows']} | scheme_rates={u['has_scheme_rate_by_type']}"
        )
        print(
            f"  URL Shift : raw 20k FPR={raw_m['fpr']*100:.2f}% (P={raw_m['precision']:.3f}) -> "
            f"after http:// norm FPR={norm_m['fpr']*100:.2f}% (P={norm_m['precision']:.3f})"
        )
        print(
            f"  URL E2E   : 400 domain-grouped Alert FPR={e2e_u['fpr']*100:.2f}% R={e2e_u['recall']:.3f} F1={e2e_u['f1']:.3f}"
        )

    if comparison:
        print("\n" + "=" * 78)
        print("PAIRED COMPARISON VS BASELINE")
        print("=" * 78)
        for modality, d in comparison.items():
            mc = d["mcnemar_alert"]
            print(
                f"  {modality.upper():5s}: hard_benign_alert_FPR {d['hard_benign_alert_fpr_delta']*100:+.1f}pp | "
                f"threat_recall {d['threat_alert_recall_delta']*100:+.1f}pp | "
                f"F1 {d['f1_alert_delta']:+.3f} | Brier {d['brier_delta']:+.4f} | "
                f"McNemar(+{mc['current_only_correct']}/-{mc['baseline_only_correct']}, p={mc['exact_p_value']})"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Scam Shield detection models.")
    parser.add_argument("--suite", type=Path, default=DEFAULT_SUITE_PATH, help="Path to benchmark JSON")
    parser.add_argument(
        "--modality",
        choices=("all", "email", "sms", "url"),
        default="all",
        help="Run Suite B for a single modality or all",
    )
    parser.add_argument("--skip-csv", action="store_true", help="Skip Suite A CSV audit")
    parser.add_argument("--save", type=Path, default=None, help="Save full JSON report to this path")
    parser.add_argument("--compare", type=Path, default=None, help="Compare against saved baseline JSON")
    args = parser.parse_args()

    modalities = ("email", "sms", "url") if args.modality == "all" else (args.modality,)
    predictor.load_models()
    report: Dict[str, Any] = {
        "suite_path": str(args.suite),
        "suite_b": evaluate_benchmark_suite(args.suite, modalities=modalities),
    }
    if not args.skip_csv:
        report["suite_a"] = evaluate_csv_audit()

    comparison: Optional[Dict[str, Any]] = None
    if args.compare:
        with args.compare.open("r", encoding="utf-8") as fh:
            baseline = json.load(fh)
        comparison = compare_reports(baseline, report)
        report["comparison_vs_baseline"] = comparison

    _print_summary(report, comparison)

    if args.save:
        args.save.parent.mkdir(parents=True, exist_ok=True)
        with args.save.open("w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\nSaved evaluation report to {args.save}")


if __name__ == "__main__":
    main()

