"""Lazy-loading CodeBERT embedder with background initialization."""
import threading
import os
from pathlib import Path
import numpy as np

MODEL_ID = "microsoft/codebert-base"
MODEL_CACHE = Path(os.environ.get("MAKINA_MODELS", "/root/.makina/models"))

_lock = threading.Lock()
_tokenizer = None
_model = None
_status = "not_loaded"  # not_loaded | loading | ready | error:<msg>


def _do_load():
    global _tokenizer, _model, _status
    try:
        from transformers import AutoTokenizer, AutoModel
        MODEL_CACHE.mkdir(parents=True, exist_ok=True)
        _tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, cache_dir=str(MODEL_CACHE))
        _model = AutoModel.from_pretrained(MODEL_ID, cache_dir=str(MODEL_CACHE))
        _model.eval()
        with _lock:
            _status = "ready"
    except Exception as e:
        with _lock:
            _status = f"error: {e}"


def ensure_loaded():
    """Kick off background load; safe to call multiple times."""
    global _status
    with _lock:
        if _status != "not_loaded":
            return
        _status = "loading"
    threading.Thread(target=_do_load, daemon=True).start()


def is_ready() -> bool:
    return _status == "ready"


def status() -> str:
    return _status


def embed(code: str) -> "np.ndarray | None":
    if _status != "ready":
        return None
    import torch
    inputs = _tokenizer(
        code, return_tensors="pt", truncation=True, max_length=512, padding=True
    )
    with torch.no_grad():
        out = _model(**inputs)
    return out.last_hidden_state[:, 0, :].squeeze().numpy()


def embed_batch(codes: list) -> "np.ndarray | None":
    if _status != "ready":
        return None
    import torch
    inputs = _tokenizer(
        codes, return_tensors="pt", truncation=True, max_length=512, padding=True
    )
    with torch.no_grad():
        out = _model(**inputs)
    return out.last_hidden_state[:, 0, :].numpy()
