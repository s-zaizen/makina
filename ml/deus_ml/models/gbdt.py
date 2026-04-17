"""
Stage 1 GBDT model (~200-2000 labels).
Invoked via: python -m deus_ml.models.gbdt train <feedback.db> <output_model.json>
                                                  predict <model.json> <features.json>
"""

import json
import sys
import sqlite3
from pathlib import Path
import numpy as np

try:
    import xgboost as xgb
except ImportError:
    print("xgboost not installed. Run: pip install xgboost", file=sys.stderr)
    sys.exit(1)

from deus_ml.features import extract_ast_features


REPLAY_RATIO = 0.30  # 30% reservoir sample from original training data


def load_labeled_findings(db_path: str) -> tuple[np.ndarray, np.ndarray]:
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT feature_vector, label FROM findings WHERE label IS NOT NULL AND feature_vector IS NOT NULL"
    ).fetchall()
    conn.close()

    if not rows:
        raise ValueError("No labeled findings with feature vectors found.")

    X, y = [], []
    for fv_bytes, label in rows:
        fv = np.frombuffer(fv_bytes, dtype=np.float32)
        if len(fv) == 50:
            X.append(fv)
            y.append(1 if label == "tp" else 0)

    return np.array(X), np.array(y)


def train(db_path: str, output_path: str) -> None:
    X, y = load_labeled_findings(db_path)
    print(f"Training GBDT on {len(X)} samples ({y.sum()} TP, {len(y)-y.sum()} FP)", file=sys.stderr)

    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
    )
    model.fit(X, y)
    model.save_model(output_path)
    print(f"Model saved to {output_path}", file=sys.stderr)


def predict(model_path: str, features_json: str) -> None:
    model = xgb.XGBClassifier()
    model.load_model(model_path)

    with open(features_json) as f:
        data = json.load(f)

    X = np.array(data["features"], dtype=np.float32).reshape(1, -1)
    prob = model.predict_proba(X)[0][1]
    print(json.dumps({"confidence": float(prob), "label": "tp" if prob >= 0.5 else "fp"}))


def main():
    if len(sys.argv) < 4:
        print("Usage: python -m deus_ml.models.gbdt train <db> <output>", file=sys.stderr)
        print("       python -m deus_ml.models.gbdt predict <model> <features.json>", file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "train":
        train(sys.argv[2], sys.argv[3])
    elif cmd == "predict":
        predict(sys.argv[2], sys.argv[3])
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
