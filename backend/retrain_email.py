from pathlib import Path

import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

MODELS_DIR = Path(__file__).resolve().parent / "app" / "ml" / "saved_models"
EMAIL_CSV = Path(__file__).resolve().parent / "phishing_email.csv"

df = pd.read_csv(EMAIL_CSV)
df.columns = ["text", "label"]
df = df.dropna()

print(f"✅ Loaded {len(df)} samples")
print(df["label"].value_counts())

X = df["text"].astype(str)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

pipeline = Pipeline([
    ("tfidf", TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=15000,
        stop_words="english",
        sublinear_tf=True,
        min_df=2,
        max_df=0.95
    )),
    ("clf", LogisticRegression(
        max_iter=1000,
        C=5.0,
        class_weight="balanced",
        solver="lbfgs"
    ))
])

print("⏳ Training... (takes 1-2 mins)")
pipeline.fit(X_train, y_train)
y_pred = pipeline.predict(X_test)

print(f"\n✅ Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")
print(classification_report(y_test, y_pred, target_names=["Legit", "Phishing"]))

# Quick test
test_emails = [
    "Congratulations! You won $1000. Click here to claim your prize now!",
    "Hi, please review the attached project report for tomorrow meeting.",
    "URGENT: Your bank account suspended. Verify immediately!",
    "Team meeting rescheduled to 3pm. Please confirm attendance.",
]
print("\n🧪 Quick test:")
for e in test_emails:
    prob = pipeline.predict_proba([e])[0]
    label = "🚨 SCAM" if prob[1] > 0.5 else "✅ LEGIT"
    print(f"  {label} ({prob[1]*100:.1f}%) — {e[:55]}...")

MODELS_DIR.mkdir(parents=True, exist_ok=True)
joblib.dump(pipeline, MODELS_DIR / "email_model.pkl")
print("\n✅ Email model saved!")
print("🔄 Now restart uvicorn!")