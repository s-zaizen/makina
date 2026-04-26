"""Integration test for the GBDT training pipeline.

Skipped when xgboost / sklearn aren't importable so the pure-Python
test set can still run on a thin host. Inside the `ml` container both
deps are available.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import numpy as np
import pytest

xgboost = pytest.importorskip("xgboost")
pytest.importorskip("sklearn")

from makina_ml.services import training  # noqa: E402  — after importorskip


def _populate(db: Path, n_per_class: int, with_groups: bool):
    """Insert `n_per_class` TP and `n_per_class` FP rows. If `with_groups`
    is set, twins share a group_key so GroupShuffleSplit fires."""
    rng = np.random.default_rng(0)
    conn = sqlite3.connect(str(db))
    rows = []
    for i in range(n_per_class):
        # TP cluster centred at +1, FP cluster at -1 — trivially separable
        fv_tp = (rng.standard_normal(768).astype("<f4") + 1.0).tobytes()
        fv_fp = (rng.standard_normal(768).astype("<f4") - 1.0).tobytes()
        gkey = f"CVE-{i:04d}" if with_groups else None
        rows.append((f"tp-{i}", "tp", fv_tp, gkey))
        rows.append((f"fp-{i}", "fp", fv_fp, gkey))
    conn.executemany(
        "INSERT INTO findings (id, label, feature_vector, group_key) VALUES (?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    conn.close()


def test_train_no_db_returns_skip(tmp_path: Path):
    db = tmp_path / "absent.db"
    out = training.train(db, tmp_path / "model.json", tmp_path / "metrics.json")
    assert out == {"ok": False, "reason": "no database yet", "samples": 0}


def test_train_single_class_returns_skip(feedback_db: Path, tmp_path: Path):
    fv = np.full(768, 0.5, dtype="<f4").tobytes()
    conn = sqlite3.connect(str(feedback_db))
    conn.executemany(
        "INSERT INTO findings (id, label, feature_vector) VALUES (?, ?, ?)",
        [(f"row-{i}", "tp", fv) for i in range(5)],
    )
    conn.commit()
    conn.close()

    out = training.train(feedback_db, tmp_path / "model.json", tmp_path / "metrics.json")
    assert out["ok"] is False
    assert "both TP and FP" in out["reason"]


def test_train_full_pipeline_with_group_split(feedback_db: Path, tmp_path: Path):
    _populate(feedback_db, n_per_class=20, with_groups=True)

    model_path = tmp_path / "model.json"
    metrics_path = tmp_path / "metrics.json"
    out = training.train(feedback_db, model_path, metrics_path)

    assert out["ok"] is True
    assert out["samples"] == 40
    assert out["model_path"] == str(model_path)
    assert model_path.exists(), "saved xgboost model must persist"

    # CVE group-aware split must be reflected in metrics.
    persisted = training.read_metrics(metrics_path)
    assert persisted is not None
    assert persisted["split"] == "80/20 group (CVE-aware)"
    assert persisted["tp"] == 20
    assert persisted["fp"] == 20
    assert 0.0 <= persisted["val_accuracy"] <= 1.0


def test_train_falls_back_to_stratified_split_without_groups(feedback_db: Path, tmp_path: Path):
    _populate(feedback_db, n_per_class=20, with_groups=False)

    out = training.train(
        feedback_db, tmp_path / "model.json", tmp_path / "metrics.json"
    )
    assert out["ok"] is True

    persisted = training.read_metrics(tmp_path / "metrics.json")
    assert persisted is not None
    assert persisted["split"] == "80/20 stratified"


def test_train_skips_validation_when_per_class_too_small(feedback_db: Path, tmp_path: Path):
    # 4 of each class — below the 5-of-each cutoff for held-out eval.
    _populate(feedback_db, n_per_class=4, with_groups=False)

    out = training.train(
        feedback_db, tmp_path / "model.json", tmp_path / "metrics.json"
    )
    assert out["ok"] is True
    persisted = training.read_metrics(tmp_path / "metrics.json")
    assert persisted is not None
    assert persisted["split"].startswith("no split")
    # No val_accuracy when no held-out set was carved.
    assert "val_accuracy" not in persisted


def test_load_model_round_trip(feedback_db: Path, tmp_path: Path):
    _populate(feedback_db, n_per_class=20, with_groups=True)
    model_path = tmp_path / "model.json"
    training.train(feedback_db, model_path, tmp_path / "metrics.json")

    model = training.load_model(model_path)
    assert model is not None

    # 768-dim vector centred at +1 should score TP (≥ 0.5) given the
    # training data structure above.
    rng = np.random.default_rng(1)
    fv = (rng.standard_normal(768).astype(np.float32) + 1.0).reshape(1, -1)
    prob_tp = float(model.predict_proba(fv)[0][1])
    assert prob_tp > 0.5
