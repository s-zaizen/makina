"""
makina ML service — HTTP API called by the Rust core.

Endpoints:
  GET  /health           liveness probe
  GET  /status           current model stage + label count + embedding model status
  POST /train            trigger retraining from feedback.db
  POST /predict          return confidence score for a feature vector
  POST /analyze          semantic analysis via CodeBERT (all languages)
  POST /semgrep          rule-based scan via semgrep community rules
"""

import json
import logging
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Optional

import numpy as np
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import uvicorn

from . import embedder, analyzer, semgrep_scanner
from .logging_config import reset_request_id, set_request_id, setup_logging

setup_logging()
logger = logging.getLogger("makina_ml")

DB_PATH = Path(os.environ.get("MAKINA_DB", "/root/.makina/feedback.db"))
MODEL_PATH = Path(os.environ.get("MAKINA_MODEL", "/root/.makina/model.json"))
METRICS_PATH = Path(os.environ.get("MAKINA_METRICS", "/root/.makina/metrics.json"))

app = FastAPI(title="makina-ml", version="0.1.0")


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    req_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    token = set_request_id(req_id)
    start = time.perf_counter()
    status = 500
    try:
        resp = await call_next(request)
        status = resp.status_code
        resp.headers["x-request-id"] = req_id
        return resp
    except Exception:
        logger.exception(
            "request failed",
            extra={"method": request.method, "path": request.url.path},
        )
        raise
    finally:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        # Don't log health check noise
        if request.url.path != "/health":
            logger.info(
                "request",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status": status,
                    "elapsed_ms": elapsed_ms,
                },
            )
        reset_request_id(token)


# Start loading CodeBERT in the background immediately
embedder.ensure_loaded()

# ---------- helpers ----------------------------------------------------------


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _label_count() -> dict:
    if not DB_PATH.exists():
        return {"total": 0, "tp": 0, "fp": 0}
    conn = _db()
    total = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE label IS NOT NULL"
    ).fetchone()[0]
    tp = conn.execute("SELECT COUNT(*) FROM findings WHERE label = 'tp'").fetchone()[0]
    fp = conn.execute("SELECT COUNT(*) FROM findings WHERE label = 'fp'").fetchone()[0]
    conn.close()
    return {"total": total, "tp": tp, "fp": fp}


def _model_stage(total: int) -> str:
    """Maturity indicator — not a capability gate.
    The model trains and predicts from the first label onward."""
    if total == 0:
        return "bootstrapping"
    if total < 50:
        return "learning"
    if total < 500:
        return "refining"
    return "mature"


def _load_model():
    """Load XGBoost model if available, else return None."""
    if not MODEL_PATH.exists():
        return None
    try:
        import xgboost as xgb

        m = xgb.XGBClassifier()
        m.load_model(str(MODEL_PATH))
        return m
    except Exception:
        return None


# ---------- endpoints --------------------------------------------------------


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/status")
def status():
    counts = _label_count()
    return {
        "total_labels": counts["total"],
        "tp_count": counts["tp"],
        "fp_count": counts["fp"],
        "model_stage": _model_stage(counts["total"]),
        "model_ready": MODEL_PATH.exists(),
        "labels_until_next_stage": 0,
        "embedding_model_status": embedder.status(),
        "embedding_model_ready": embedder.is_ready(),
    }


class TrainRequest(BaseModel):
    pass  # no minimum — train whenever both classes are present


@app.post("/train")
def train(req: TrainRequest):
    """Retrain GBDT on all accumulated labels. Called after every Verify Submit."""
    try:
        import xgboost as xgb
    except ImportError:
        raise HTTPException(status_code=500, detail="xgboost not installed.")

    if not DB_PATH.exists():
        logger.info("train skipped: no database yet")
        return {"ok": False, "reason": "no database yet", "samples": 0}

    conn = _db()
    # `group_key` was added in a later schema; older DBs may lack the column
    # so we read it via a NULL-tolerant subquery and fall back gracefully.
    has_group_col = (
        conn.execute(
            "SELECT 1 FROM pragma_table_info('findings') WHERE name='group_key'"
        ).fetchone()
        is not None
    )
    if has_group_col:
        rows = conn.execute(
            "SELECT feature_vector, label, group_key FROM findings "
            "WHERE label IS NOT NULL AND feature_vector IS NOT NULL"
        ).fetchall()
    else:
        rows = [
            (fv, lbl, None)
            for fv, lbl in conn.execute(
                "SELECT feature_vector, label FROM findings "
                "WHERE label IS NOT NULL AND feature_vector IS NOT NULL"
            ).fetchall()
        ]
    conn.close()

    X, y, groups = [], [], []
    for fv_bytes, label, group_key in rows:
        fv = np.frombuffer(fv_bytes, dtype="<f4")
        if len(fv) == 768:
            X.append(fv)
            y.append(1 if label == "tp" else 0)
            groups.append(group_key)

    if len(set(y)) < 2:
        logger.info(
            "train skipped: single-class",
            extra={"samples": len(X), "stage": _model_stage(len(X))},
        )
        return {"ok": False, "reason": "need both TP and FP labels", "samples": len(X)}

    X_arr, y_arr = np.array(X), np.array(y)
    tp_count = int(y_arr.sum())
    fp_count = int(len(y_arr) - tp_count)

    # CVE-aware grouping: every sample produced by bulk_import carries its
    # CVE id as group_key, so a paired TP/FP twin never straddles the
    # train/val split. Live-scan rows have group_key=NULL — we fill those
    # with unique synthetic ids so they each form a singleton group and
    # behave the same as random samples.
    use_group_split = (
        any(g is not None for g in groups) and len({g for g in groups if g}) >= 2
    )
    if use_group_split:
        groups_arr = np.array(
            [g if g is not None else f"_solo_{i}" for i, g in enumerate(groups)]
        )

    # Train/val split — group-aware when we have CVE keys, stratified 80/20
    # otherwise. Either way needs ≥ 5 of each class to be meaningful.
    val_metrics: dict | None = None
    can_split = min(tp_count, fp_count) >= 5
    t0 = time.perf_counter()
    if can_split and use_group_split:
        from sklearn.model_selection import GroupShuffleSplit

        gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
        train_idx, val_idx = next(gss.split(X_arr, y_arr, groups=groups_arr))
        X_train, X_val = X_arr[train_idx], X_arr[val_idx]
        y_train, y_val = y_arr[train_idx], y_arr[val_idx]
    elif can_split:
        from sklearn.model_selection import train_test_split

        X_train, X_val, y_train, y_val = train_test_split(
            X_arr, y_arr, test_size=0.2, random_state=42, stratify=y_arr
        )
    if can_split:
        model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=4,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="logloss",
            random_state=42,
        )
        model.fit(X_train, y_train)
        # Eval on the held-out split
        val_pred = model.predict(X_val)
        val_prob = model.predict_proba(X_val)[:, 1]
        val_acc = float((val_pred == y_val).mean())
        # TP/FP precision/recall at 0.5 cutoff
        tp_mask = (val_pred == 1) & (y_val == 1)
        fp_mask = (val_pred == 1) & (y_val == 0)
        fn_mask = (val_pred == 0) & (y_val == 1)
        tp_pred = int(tp_mask.sum())
        fp_pred = int(fp_mask.sum())
        fn_pred = int(fn_mask.sum())
        precision = float(tp_pred / (tp_pred + fp_pred)) if (tp_pred + fp_pred) else 0.0
        recall = float(tp_pred / (tp_pred + fn_pred)) if (tp_pred + fn_pred) else 0.0
        val_metrics = {
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
        # After reporting, retrain on the full dataset so the production model
        # uses every label available.
        model.fit(X_arr, y_arr)
    else:
        model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=4,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="logloss",
            random_state=42,
        )
        model.fit(X_arr, y_arr)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    model.save_model(str(MODEL_PATH))
    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    from datetime import datetime, timezone

    metrics = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "samples": len(X),
        "tp": tp_count,
        "fp": fp_count,
        "stage": _model_stage(len(X)),
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
        METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
        METRICS_PATH.write_text(json.dumps(metrics, indent=2))
    except Exception as e:
        logger.warning("failed to persist metrics: %s", e)

    logger.info("gbdt retrained", extra=metrics)

    # Fresh labels just landed — invalidate analyzer's kNN + GBDT caches so
    # the next /analyze call picks up the retrained artifacts.
    analyzer.reset_index()

    return {
        "ok": True,
        "samples": len(X),
        "model_path": str(MODEL_PATH),
        **(val_metrics or {}),
    }


@app.get("/metrics")
def get_metrics():
    """Return the latest training metrics written by /train, or `None` if
    the model has not been trained yet."""
    if not METRICS_PATH.exists():
        return {"metrics": None}
    try:
        return {"metrics": json.loads(METRICS_PATH.read_text())}
    except Exception as e:
        logger.warning("failed to read metrics: %s", e)
        return {"metrics": None}


EMBEDDING_DIM = 768


class PredictRequest(BaseModel):
    feature_vector: list[float]  # 768-dim CodeBERT embedding


@app.post("/predict")
def predict(req: PredictRequest):
    model = _load_model()
    if model is None:
        return {"confidence": None, "stage": "rules-only"}

    fv = np.array(req.feature_vector, dtype=np.float32).reshape(1, -1)
    if fv.shape[1] != EMBEDDING_DIM:
        raise HTTPException(
            status_code=422,
            detail=f"feature_vector must have {EMBEDDING_DIM} elements (got {fv.shape[1]}).",
        )

    prob = float(model.predict_proba(fv)[0][1])
    return {"confidence": prob, "label": "tp" if prob >= 0.5 else "fp"}


class PredictBatchRequest(BaseModel):
    feature_vectors: list[list[float]]  # N × 768


@app.post("/predict_batch")
def predict_batch(req: PredictBatchRequest):
    """Score N embeddings at once. Returns `confidences: [...]` in request
    order, or `confidences: null` if the model is not trained yet."""
    if not req.feature_vectors:
        return {"confidences": [], "model_ready": False}

    model = _load_model()
    if model is None:
        return {"confidences": None, "model_ready": False}

    arr = np.array(req.feature_vectors, dtype=np.float32)
    if arr.ndim != 2 or arr.shape[1] != EMBEDDING_DIM:
        raise HTTPException(
            status_code=422,
            detail=f"feature_vectors must be N×{EMBEDDING_DIM} (got shape {list(arr.shape)}).",
        )

    probs = model.predict_proba(arr)[:, 1]
    return {
        "confidences": [float(p) for p in probs],
        "model_ready": True,
    }


class AnalyzeRequest(BaseModel):
    code: str
    language: Optional[str] = None


@app.post("/analyze")
def analyze_code(req: AnalyzeRequest):
    return analyzer.analyze(req.code, req.language)


class SemgrepRequest(BaseModel):
    code: str
    language: Optional[str] = None


@app.post("/semgrep")
def semgrep_scan(req: SemgrepRequest):
    return semgrep_scanner.scan(req.code, req.language or "auto")


class EmbedBatchRequest(BaseModel):
    snippets: list[str]


@app.post("/embed_batch")
def embed_batch(req: EmbedBatchRequest):
    if not req.snippets or not embedder.is_ready():
        return {"embeddings": []}
    embs = embedder.embed_batch(req.snippets)
    if embs is None:
        return {"embeddings": []}
    return {"embeddings": embs.tolist()}


class TaintRequest(BaseModel):
    code: str
    language: Optional[str] = None


@app.post("/taint")
def taint_scan(req: TaintRequest):
    from . import taint_engine
    from .semgrep_scanner import _detect_language

    language = req.language or "auto"
    if language in ("auto", "unknown", "", None):
        language = _detect_language(req.code)
    return taint_engine.analyze(req.code, language)


class EmbedWithGraphRequest(BaseModel):
    code: str
    language: str
    line_starts: list[int]


@app.post("/embed_with_graph")
def embed_with_graph(req: EmbedWithGraphRequest):
    """
    Embed code regions with call-graph-augmented context.
    For each line in line_starts, finds the enclosing function and
    expands context to include called functions (1 hop).
    This gives CodeBERT cross-function awareness for better learning.
    """
    if not req.line_starts or not embedder.is_ready():
        return {"embeddings": []}

    from .call_graph import extract_functions, build_augmented_context

    functions = extract_functions(req.code, req.language)
    lines = req.code.splitlines()

    snippets = []
    for line in req.line_starts:
        if functions:
            context = build_augmented_context(
                functions, req.code, line, line, max_depth=1
            )
        else:
            ctx_s = max(0, line - 4)
            ctx_e = min(len(lines), line + 3)
            context = "\n".join(lines[ctx_s:ctx_e])
        snippets.append(context)

    embs = embedder.embed_batch(snippets)
    if embs is None:
        return {"embeddings": []}
    return {"embeddings": embs.tolist()}


# ---------- entry point -------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("ML_PORT", 8080))
    uvicorn.run("makina_ml.server:app", host="0.0.0.0", port=port, reload=False)
