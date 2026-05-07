"""
=============================================================
  SCAM SHIELD — ML Model Training
  Run this in Google Colab: https://colab.research.google.com
=============================================================

STEP 1: Upload this file to Colab OR copy-paste cell by cell.
STEP 2: Run all cells in order.
STEP 3: Download the saved .pkl model files.
STEP 4: Place them in backend/app/ml/saved_models/
"""

# ── CELL 1: Install dependencies ──────────────────────────
# !pip install scikit-learn pandas numpy lime joblib tldextract

# ── CELL 2: Imports ───────────────────────────────────────
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os

# ── CELL 3: Load Datasets ─────────────────────────────────
# Free datasets to download:
# Email: https://www.kaggle.com/datasets/uciml/sms-spam-collection-dataset
# URL:   https://www.kaggle.com/datasets/siddharthkumar25/malicious-and-benign-urls
# Phone: Use SMS Spam dataset filtered for phone patterns

# For demo — synthetic data (replace with real Kaggle data)
email_data = {
    "text": [
        "Congratulations! You won $1000. Click here to claim your prize now!",
        "URGENT: Your bank account has been suspended. Verify immediately.",
        "Hi, are you available for the team meeting tomorrow at 3pm?",
        "Your invoice #1234 is attached. Please review and confirm.",
        "FREE iPhone! You have been selected. Limited time offer. Act now!",
        "Please find the project report attached as discussed.",
        "Your OTP is 482910. Do not share this with anyone.",
        "Click here to get FREE Netflix for life! Limited offer ending soon!",
    ],
    "label": [1, 1, 0, 0, 1, 0, 0, 1]  # 1=scam, 0=legit
}

url_data = {
    "url": [
        "http://paypal-secure-login.xyz/verify",
        "http://192.168.1.1/admin/steal-data",
        "https://www.google.com",
        "https://github.com/user/repo",
        "http://free-iphone-win.tk/claim",
        "https://stackoverflow.com/questions/123",
        "http://amazon-prize.ml/winner",
        "https://docs.python.org/3/",
    ],
    "label": [1, 1, 0, 0, 1, 0, 1, 0]
}

df_email = pd.DataFrame(email_data)
df_url   = pd.DataFrame(url_data)

print("✅ Data loaded")
print(f"Email samples: {len(df_email)} | URL samples: {len(df_url)}")

# ── CELL 4: Train Email/Text Model ────────────────────────
X_email = df_email["text"]
y_email = df_email["label"]

email_pipeline = Pipeline([
    ("tfidf", TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=5000,
        stop_words="english"
    )),
    ("clf", LogisticRegression(max_iter=1000, C=1.0))
])

X_tr, X_te, y_tr, y_te = train_test_split(X_email, y_email, test_size=0.2, random_state=42)
email_pipeline.fit(X_tr, y_tr)
y_pred = email_pipeline.predict(X_te)

print("\n📧 EMAIL MODEL RESULTS:")
print(classification_report(y_te, y_pred, target_names=["Legit", "Scam"]))

# ── CELL 5: Train URL Model ────────────────────────────────
def extract_url_features(url: str) -> list:
    """Extract numerical features from URL"""
    import re
    features = [
        len(url),                                    # length
        url.count("."),                              # dot count
        url.count("-"),                              # hyphen count
        url.count("/"),                              # slash count
        url.count("@"),                              # @ symbol
        int("https" in url),                         # has https
        int(bool(re.search(r'\d{1,3}\.\d{1,3}', url))),  # has IP
        len(url.split("/")[2]) if len(url.split("/")) > 2 else 0,  # domain len
        int(any(tld in url for tld in [".tk", ".ml", ".xyz", ".win", ".click"])),  # suspicious TLD
        url.count("="),                              # query params
    ]
    return features

X_url = np.array([extract_url_features(u) for u in df_url["url"]])
y_url = df_url["label"].values

X_tr_u, X_te_u, y_tr_u, y_te_u = train_test_split(X_url, y_url, test_size=0.2, random_state=42)
url_model = LogisticRegression(max_iter=1000)
url_model.fit(X_tr_u, y_tr_u)

print("\n🔗 URL MODEL RESULTS:")
print(classification_report(y_te_u, url_model.predict(X_te_u), target_names=["Safe", "Malicious"]))

# ── CELL 6: Anomaly Detection (Isolation Forest) ──────────
iso_forest = IsolationForest(contamination=0.2, random_state=42)
iso_forest.fit(X_url)
print("\n🔍 Isolation Forest trained for anomaly detection")

# ── CELL 7: Save Models ────────────────────────────────────
os.makedirs("saved_models", exist_ok=True)

joblib.dump(email_pipeline,              "saved_models/email_model.pkl")
joblib.dump(url_model,                   "saved_models/url_model.pkl")
joblib.dump(iso_forest,                  "saved_models/anomaly_model.pkl")

# Save feature extractor as reference
with open("saved_models/url_feature_names.txt", "w") as f:
    f.write("length,dot_count,hyphen_count,slash_count,at_symbol,has_https,has_ip,domain_len,suspicious_tld,query_params")

print("\n✅ ALL MODELS SAVED:")
print("  → saved_models/email_model.pkl")
print("  → saved_models/url_model.pkl")
print("  → saved_models/anomaly_model.pkl")
print("\n📥 Download these files and place them in:")
print("   backend/app/ml/saved_models/")
