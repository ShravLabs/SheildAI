"""
ShieldAI - Threat Classifier Training
Random Forest + SHAP explainability | Saves model to ml/model/
"""

import os
import json
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# ── Load dataset ──────────────────────────────────────────────
df = pd.read_csv("data/traffic_dataset.csv")

FEATURES = [
    "request_rate", "payload_size", "unique_endpoints",
    "error_rate", "has_sql_keywords", "header_anomaly",
    "geo_risk_score", "repeated_ip"
]

X = df[FEATURES]
y = df["label"]

le = LabelEncoder()
y_enc = le.fit_transform(y)

X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
)

# ── Train ─────────────────────────────────────────────────────
print("Training Random Forest classifier...")
clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    min_samples_split=5,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)
clf.fit(X_train, y_train)

# ── Evaluate ──────────────────────────────────────────────────
y_pred = clf.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"\nAccuracy: {acc:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=le.classes_))

# ── Feature importance ────────────────────────────────────────
importances = dict(zip(FEATURES, clf.feature_importances_.tolist()))
print("\nFeature Importances:")
for k, v in sorted(importances.items(), key=lambda x: -x[1]):
    print(f"  {k:25s} {v:.4f}")

# ── Save artifacts ────────────────────────────────────────────
os.makedirs("ml/model", exist_ok=True)

with open("ml/model/classifier.pkl", "wb") as f:
    pickle.dump(clf, f)

with open("ml/model/label_encoder.pkl", "wb") as f:
    pickle.dump(le, f)

metadata = {
    "accuracy": round(acc, 4),
    "features": FEATURES,
    "classes": le.classes_.tolist(),
    "feature_importances": importances,
    "n_estimators": 200,
    "model_type": "RandomForestClassifier"
}
with open("ml/model/metadata.json", "w") as f:
    json.dump(metadata, f, indent=2)

print("\nModel artifacts saved to ml/model/")
print("  classifier.pkl")
print("  label_encoder.pkl")
print("  metadata.json")
