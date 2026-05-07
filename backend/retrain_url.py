from pathlib import Path

import pandas as pd
import numpy as np
import re
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Keep saved models anchored to the backend folder so training works from any cwd.
MODELS_DIR = Path(__file__).resolve().parent / "app" / "ml" / "saved_models"
URL_CSV = Path(__file__).resolve().parent / "malicious_urls.csv"

# ── Load your existing CSV dataset ────────────────────────
# Put your malicious_urls.csv in backend folder first!
df = pd.read_csv(URL_CSV)
df["label"] = df["type"].map({
    "benign": 0,
    "defacement": 1,
    "phishing": 1,
    "malware": 1
})
df = df.dropna()
df_sample = df.sample(n=100000, random_state=42)

print(f"✅ Loaded {len(df_sample)} samples")

# ── Feature Extractor ──────────────────────────────────────
def extract_url_features(url: str) -> list:
    url = str(url).lower().strip()
    try:
        domain = url.split("/")[2] if len(url.split("/")) > 2 else url
    except:
        domain = url
    return [
        len(url), len(domain),
        url.count("."), url.count("-"), url.count("/"),
        url.count("@"), url.count("?"), url.count("="),
        url.count("_"), url.count("%"), url.count("~"), url.count("#"),
        sum(c.isdigit() for c in url),
        sum(c.isupper() for c in url),
        sum(c.isalpha() for c in url),
        int("https" in url),
        int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))),
        int(any(t in domain for t in [".tk",".ml",".xyz",".win",".click",".gq",".cf",".ga"])),
        int("login" in url), int("verify" in url),
        int("secure" in url), int("account" in url),
        int("update" in url), int("free" in url),
        int("paypal" in url), int("bank" in url),
        int("signin" in url), int("confirm" in url),
        int("password" in url), int("admin" in url),
        len(domain.replace("www.", "")),
        domain.count("-"), domain.count("."),
    ]

print("⏳ Extracting features...")
X = np.array([extract_url_features(u) for u in df_sample["url"]])
y = df_sample["label"].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── Train Models ───────────────────────────────────────────
print("⏳ Training URL model...")
url_pipeline = Pipeline([
    ("scaler", StandardScaler()),
    ("clf", RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    ))
])
url_pipeline.fit(X_train, y_train)
y_pred = url_pipeline.predict(X_test)

print(f"\n✅ URL Model Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")
print(classification_report(y_test, y_pred, target_names=["Safe", "Malicious"]))

print("⏳ Training anomaly model...")
iso_forest = IsolationForest(contamination=0.3, n_estimators=100, random_state=42, n_jobs=-1)
iso_forest.fit(X_train)

# ── Save Models ────────────────────────────────────────────
MODELS_DIR.mkdir(parents=True, exist_ok=True)
joblib.dump(url_pipeline, MODELS_DIR / "url_model.pkl")
joblib.dump(iso_forest,   MODELS_DIR / "anomaly_model.pkl")

print("\n✅ Models saved to app/ml/saved_models/")
print("🔄 Restart uvicorn to load new models!")