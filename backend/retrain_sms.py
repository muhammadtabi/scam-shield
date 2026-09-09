from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

MODELS_DIR = Path(__file__).resolve().parent / "app" / "ml" / "saved_models"
SMS_CSV = Path(__file__).resolve().parent / "sms_spam.csv"


def main() -> None:
    df = pd.read_csv(SMS_CSV, sep="\t", usecols=["v1", "v2"])
    df = df.rename(columns={"v1": "label", "v2": "text"}).dropna()

    # Keep only the expected classes and map to binary.
    df = df[df["label"].isin(["ham", "spam"])].copy()
    df["label"] = df["label"].map({"ham": 0, "spam": 1})

    print(f"Loaded {len(df)} SMS samples")
    print(df["label"].value_counts())

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"].astype(str),
        df["label"],
        test_size=0.2,
        random_state=42,
        stratify=df["label"],
    )

    pipeline = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=20000,
                stop_words="english",
                sublinear_tf=True,
                min_df=2,
                max_df=0.98,
            ),
        ),
        (
            "clf",
            LogisticRegression(
                max_iter=1000,
                C=4.0,
                class_weight="balanced",
                solver="lbfgs",
            ),
        ),
    ])

    print("Training SMS model...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    print(f"SMS accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=["Ham", "Spam"]))

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = MODELS_DIR / "sms_model.pkl"
    joblib.dump(pipeline, out_path)
    print(f"Saved SMS model to {out_path}")


if __name__ == "__main__":
    main()
