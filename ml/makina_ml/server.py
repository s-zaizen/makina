"""
makina ML service — HTTP API called by the Rust core.

Endpoints:
  GET  /health           liveness probe
  GET  /status           current model stage + label count + embedding model status
  POST /train            trigger retraining from feedback.db
  POST /predict          return confidence score for a feature vector
  POST /analyze          semantic analysis via CodeBERT (all languages)
  POST /semgrep          rule-based scan via semgrep community rules

Route handlers stay thin — heavy lifting lives in `services/`.
"""

import logging
import os
import time
import uuid
from pathlib import Path
from typing import Optional

import numpy as np
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import uvicorn

from . import embedder, analyzer, semgrep_scanner
from .flags import is_public_mode, setup_flags
from .logging_config import reset_request_id, set_request_id, setup_logging
from .services import training

setup_logging()
setup_flags()
logger = logging.getLogger("makina_ml")
if is_public_mode():
    logger.info("public mode: /train is disabled")

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


# ---------- endpoints --------------------------------------------------------


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/status")
def status():
    counts = training.label_counts(DB_PATH)
    return {
        "total_labels": counts["total"],
        "tp_count": counts["tp"],
        "fp_count": counts["fp"],
        "model_stage": training.model_stage(counts["total"]),
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
    if is_public_mode():
        raise HTTPException(
            status_code=405,
            detail="training disabled in public mode (frozen model)",
        )
    try:
        import xgboost  # noqa: F401  — pre-flight; service raises if missing
    except ImportError:
        raise HTTPException(status_code=500, detail="xgboost not installed.")

    result = training.train(DB_PATH, MODEL_PATH, METRICS_PATH)
    # Fresh labels just landed — invalidate analyzer's kNN + GBDT caches so
    # the next /analyze call picks up the retrained artifacts.
    if result.get("ok"):
        analyzer.reset_index()
    return result


@app.get("/metrics")
def get_metrics():
    """Return the latest training metrics written by /train, or `None` if
    the model has not been trained yet."""
    return {"metrics": training.read_metrics(METRICS_PATH)}


EMBEDDING_DIM = 768


class PredictRequest(BaseModel):
    feature_vector: list[float]  # 768-dim CodeBERT embedding


@app.post("/predict")
def predict(req: PredictRequest):
    model = training.load_model(MODEL_PATH)
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

    model = training.load_model(MODEL_PATH)
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
