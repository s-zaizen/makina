"""GBDT training service.

Pulled out of `server.py` so the FastAPI route stays thin (parse →
delegate → return) and the actual training pipeline (read labels →
group-aware split → fit → eval → persist → reset analyzer cache) has
one home that's easy to test and reason about.

The pipeline preserves bit-for-bit behaviour:
  * group_key column is read NULL-tolerantly (older DBs lack it)
  * `GroupShuffleSplit` is used when ≥ 2 distinct CVE groups are
    present; otherwise a stratified 80/20 split is used; otherwise
    the full dataset is used (no held-out validation)
  * after eval the model is refit on the *full* dataset so the
    production artifact uses every label
  * metrics are persisted to `MAKINA_METRICS` (default
    `/root/.makina/metrics.json`)
  * the analyzer's in-memory caches are invalidated on success
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

logger = logging.getLogger("makina_ml")


def model_stage(total: int) -> str:
    """Maturity indicator — not a capability gate.
    The model trains and predicts from the first label onward."""
    if total == 0:
        return "bootstrapping"
    if total < 50:
        return "learning"
    if total < 500:
        return "refining"
    return "mature"


def _has_group_column(conn: sqlite3.Connection) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM pragma_table_info('findings') WHERE name='group_key'"
        ).fetchone()
        is not None
    )


def _load_dataset(db_path: Path) -> list[tuple[bytes, str, str | None]]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        if _has_group_column(conn):
            rows = conn.execute(
                "SELECT feature_vector, label, group_key FROM findings "
                "WHERE label IS NOT NULL AND feature_vector IS NOT NULL"
            ).fetchall()
            return [(r[0], r[1], r[2]) for r in rows]
        rows = conn.execute(
            "SELECT feature_vector, label FROM findings "
            "WHERE label IS NOT NULL AND feature_vector IS NOT NULL"
        ).fetchall()
        return [(r[0], r[1], None) for r in rows]
    finally:
        conn.close()


def _new_classifier():
    import xgboost as xgb

    return xgb.XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        random_state=42,
    )


def _eval_metrics(model, x_val, y_val) -> dict:
    val_pred = model.predict(x_val)
    val_prob = model.predict_proba(x_val)[:, 1]
    val_acc = float((val_pred == y_val).mean())
    tp_pred = int(((val_pred == 1) & (y_val == 1)).sum())
    fp_pred = int(((val_pred == 1) & (y_val == 0)).sum())
    fn_pred = int(((val_pred == 0) & (y_val == 1)).sum())
    precision = float(tp_pred / (tp_pred + fp_pred)) if (tp_pred + fp_pred) else 0.0
    recall = float(tp_pred / (tp_pred + fn_pred)) if (tp_pred + fn_pred) else 0.0
    return {
        "val_samples": int(len(y_val)),
        "val_accuracy": round(val_acc, 4),
        "val_precision": round(precision, 4),
        "val_recall": round(recall, 4),
        "val_prob_mean_tp": round(float(val_prob[y_val == 1].mean()), 4)
        if (y_val == 1).any()
        else None,
        "val_prob_mean_fp": round(float(val_prob[y_val == 0].mean()), 4)
        if (y_val == 0).any()
        else None,
    }


def train_from_arrays(
    embeddings: np.ndarray,
    labels: list[str],
    groups: list[str | None],
    model_path: Path,
    metrics_path: Path,
) -> dict:
    """Train the GBDT directly from in-memory arrays.

    `embeddings` is an N×768 float32 matrix, `labels[i]` is `"tp"`/`"fp"`,
    `groups[i]` is the CVE id (or None). Used by both the SQLite-backed
    `train()` route and by the offline trainer that bypasses the API.
    Caller is responsible for ensuring xgboost / sklearn are importable.
    """
    import xgboost as xgb  # noqa: F401  — verify import early

    if embeddings.shape[0] == 0:
        return {"ok": False, "reason": "no samples", "samples": 0}

    y_list = [1 if lbl == "tp" else 0 for lbl in labels]

    if len(set(y_list)) < 2:
        logger.info(
            "train skipped: single-class",
            extra={
                "samples": len(y_list),
                "stage": model_stage(len(y_list)),
            },
        )
        return {
            "ok": False,
            "reason": "need both TP and FP labels",
            "samples": len(y_list),
        }

    x_arr = embeddings.astype(np.float32)
    y_arr = np.array(y_list)
    tp_count = int(y_arr.sum())
    fp_count = int(len(y_arr) - tp_count)

    # CVE-aware grouping: every sample produced by bulk_import carries its
    # CVE id as group_key so a paired TP/FP twin never straddles the
    # train/val split. Live-scan rows have group_key=NULL — we fill those
    # with unique synthetic ids so they each form a singleton group and
    # behave the same as random samples.
    use_group_split = (
        any(g is not None for g in groups) and len({g for g in groups if g}) >= 2
    )
    groups_arr = (
        np.array([g if g is not None else f"_solo_{i}" for i, g in enumerate(groups)])
        if use_group_split
        else None
    )

    can_split = min(tp_count, fp_count) >= 5
    val_metrics: dict | None = None
    t0 = time.perf_counter()

    if can_split and use_group_split:
        from sklearn.model_selection import GroupShuffleSplit

        gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
        train_idx, val_idx = next(gss.split(x_arr, y_arr, groups=groups_arr))
        x_train, x_val = x_arr[train_idx], x_arr[val_idx]
        y_train, y_val = y_arr[train_idx], y_arr[val_idx]
    elif can_split:
        from sklearn.model_selection import train_test_split

        x_train, x_val, y_train, y_val = train_test_split(
            x_arr, y_arr, test_size=0.2, random_state=42, stratify=y_arr
        )

    model = _new_classifier()
    if can_split:
        model.fit(x_train, y_train)
        val_metrics = _eval_metrics(model, x_val, y_val)
        # After reporting, retrain on the full dataset so the production
        # model uses every label available.
        model.fit(x_arr, y_arr)
    else:
        model.fit(x_arr, y_arr)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    model.save_model(str(model_path))
    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    metrics = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "samples": len(y_list),
        "tp": tp_count,
        "fp": fp_count,
        "stage": model_stage(len(y_list)),
        "elapsed_ms": elapsed_ms,
        "split": (
            "80/20 group (CVE-aware)"
            if (can_split and use_group_split)
            else "80/20 stratified"
            if can_split
            else "no split (insufficient per-class samples)"
        ),
        **(val_metrics or {}),
    }
    try:
        metrics_path.parent.mkdir(parents=True, exist_ok=True)
        metrics_path.write_text(json.dumps(metrics, indent=2))
    except Exception as e:
        logger.warning("failed to persist metrics: %s", e)

    logger.info("gbdt retrained", extra=metrics)

    return {
        "ok": True,
        "samples": len(y_list),
        "model_path": str(model_path),
        **(val_metrics or {}),
    }


def train(db_path: Path, model_path: Path, metrics_path: Path) -> dict:
    """Retrain the GBDT from scratch on every label currently in
    `db_path`. Returns the JSON body the route should serialise back
    to the caller. Raises only on missing xgboost (the route layer
    surfaces that as an HTTP 500)."""
    import xgboost as xgb  # noqa: F401  — verify import early

    if not db_path.exists():
        logger.info("train skipped: no database yet")
        return {"ok": False, "reason": "no database yet", "samples": 0}

    rows = _load_dataset(db_path)

    x_list: list[np.ndarray] = []
    labels: list[str] = []
    groups: list[str | None] = []
    for fv_bytes, label, group_key in rows:
        fv = np.frombuffer(fv_bytes, dtype="<f4")
        if len(fv) == 768:
            x_list.append(fv)
            labels.append(label)
            groups.append(group_key)

    if not x_list:
        return {"ok": False, "reason": "no samples", "samples": 0}

    return train_from_arrays(np.array(x_list), labels, groups, model_path, metrics_path)


def read_metrics(metrics_path: Path) -> dict | None:
    """Return the latest metrics dict written by `train`, or None if the
    file is absent / unreadable."""
    if not metrics_path.exists():
        return None
    try:
        return json.loads(metrics_path.read_text())
    except Exception as e:
        logger.warning("failed to read metrics: %s", e)
        return None


def label_counts(db_path: Path) -> dict:
    if not db_path.exists():
        return {"total": 0, "tp": 0, "fp": 0}
    conn = sqlite3.connect(str(db_path))
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE label IS NOT NULL"
        ).fetchone()[0]
        tp = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE label = 'tp'"
        ).fetchone()[0]
        fp = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE label = 'fp'"
        ).fetchone()[0]
    finally:
        conn.close()
    return {"total": total, "tp": tp, "fp": fp}


def load_model(model_path: Path):
    """Load XGBoost model if available, else return None."""
    if not model_path.exists():
        return None
    try:
        import xgboost as xgb

        m = xgb.XGBClassifier()
        m.load_model(str(model_path))
        return m
    except Exception:
        return None
