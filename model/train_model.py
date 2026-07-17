"""
Train the phishing URL classifier.

Dataset: labeled URLs (good/bad) -> we relabel bad=phishing(1), good=legit(0).
Model: RandomForestClassifier over lexical/structural URL features.

Run:
    python model/train_model.py
"""

import os
import sys
import json
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from features import extract_features, FEATURE_NAMES  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "raw_data.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model", "phishing_model.pkl")
METRICS_PATH = os.path.join(BASE_DIR, "model", "metrics.json")

DATASET_URL = (
    "https://raw.githubusercontent.com/faizann24/"
    "Using-machine-learning-to-detect-malicious-URLs/master/data/data.csv"
)

RANDOM_STATE = 42
SAMPLE_PER_CLASS = 40000  # balanced subsample for a fast, non-overfit model


def ensure_dataset():
    if os.path.exists(DATA_PATH):
        return
    print(f"Dataset not found locally, downloading from:\n  {DATASET_URL}")
    import urllib.request
    urllib.request.urlretrieve(DATASET_URL, DATA_PATH)
    print(f"Saved dataset to {DATA_PATH}")


def load_data():
    ensure_dataset()
    df = pd.read_csv(DATA_PATH)
    df = df.dropna(subset=["url", "label"])
    df["label"] = df["label"].map({"bad": 1, "good": 0})
    df = df.dropna(subset=["label"])

    bad = df[df.label == 1]
    good = df[df.label == 0]
    n = min(SAMPLE_PER_CLASS, len(bad), len(good))
    bad = bad.sample(n=n, random_state=RANDOM_STATE)
    good = good.sample(n=n, random_state=RANDOM_STATE)

    balanced = pd.concat([bad, good]).sample(frac=1, random_state=RANDOM_STATE)
    return balanced.reset_index(drop=True)


def build_feature_matrix(urls):
    rows = [extract_features(u) for u in urls]
    return pd.DataFrame(rows, columns=FEATURE_NAMES)


def main():
    print("Loading dataset...")
    df = load_data()
    print(f"Using {len(df)} balanced rows (phishing={sum(df.label==1)}, legit={sum(df.label==0)})")

    print("Extracting features...")
    X = build_feature_matrix(df["url"])
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )

    print("Training RandomForestClassifier...")
    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=14,
        min_samples_leaf=5,
        class_weight="balanced",
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1_score": f1_score(y_test, y_pred),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "n_train": len(X_train),
        "n_test": len(X_test),
        "feature_importances": dict(
            sorted(
                zip(FEATURE_NAMES, clf.feature_importances_.tolist()),
                key=lambda kv: kv[1],
                reverse=True,
            )
        ),
    }

    print("\n=== Evaluation ===")
    print(classification_report(y_test, y_pred, target_names=["legit", "phishing"]))
    print("Confusion matrix:\n", metrics["confusion_matrix"])

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump({"model": clf, "feature_names": FEATURE_NAMES}, MODEL_PATH, compress=3)
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nSaved model to {MODEL_PATH}")
    print(f"Saved metrics to {METRICS_PATH}")


if __name__ == "__main__":
    main()
