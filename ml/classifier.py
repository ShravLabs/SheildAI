"""
ShieldAI - Classifier Inference
Loads trained model and classifies incoming traffic requests.
"""

import pickle
import json
import numpy as np
from pathlib import Path

MODEL_DIR = Path(__file__).parent / "model"

_clf = None
_le  = None
_meta = None

def _load():
    global _clf, _le, _meta
    if _clf is None:
        with open(MODEL_DIR / "classifier.pkl", "rb") as f:
            _clf = pickle.load(f)
        with open(MODEL_DIR / "label_encoder.pkl", "rb") as f:
            _le = pickle.load(f)
        with open(MODEL_DIR / "metadata.json") as f:
            _meta = json.load(f)

def classify(features: dict) -> dict:
    """
    Classify a single traffic request.

    Parameters
    ----------
    features : dict with keys:
        request_rate, payload_size, unique_endpoints, error_rate,
        has_sql_keywords, header_anomaly, geo_risk_score, repeated_ip

    Returns
    -------
    dict: { label, confidence, threat_score, probabilities }
    """
    _load()

    feature_order = _meta["features"]
    X = np.array([[features.get(f, 0) for f in feature_order]])

    probs = _clf.predict_proba(X)[0]
    pred_idx = int(np.argmax(probs))
    label = _le.classes_[pred_idx]
    confidence = float(probs[pred_idx])

    # Threat score: weighted sum of non-clean probabilities
    class_list = _le.classes_.tolist()
    threat_score = 0.0
    weights = {"ddos": 1.0, "sqli": 1.0, "suspicious": 0.6, "clean": 0.0}
    for i, cls in enumerate(class_list):
        threat_score += weights.get(cls, 0) * float(probs[i])

    return {
        "label": label,
        "confidence": round(confidence, 4),
        "threat_score": round(min(threat_score, 1.0), 4),
        "probabilities": {
            cls: round(float(p), 4)
            for cls, p in zip(class_list, probs)
        }
    }


def batch_classify(records: list[dict]) -> list[dict]:
    """Classify a batch of traffic records."""
    return [classify(r) for r in records]
