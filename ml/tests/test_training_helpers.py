"""Tests for `services.training` — the GBDT pipeline helpers.

The full `train()` integration test sits under `test_training_pipeline.py`
to keep this file's runtime fast (these tests don't load xgboost).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import numpy as np
import pytest

from makina_ml.services import training


# ── model_stage — pure boundary logic ────────────────────────────────────────


@pytest.mark.parametrize(
    "total,expected",
    [
        (0, "bootstrapping"),
        (1, "learning"),
        (49, "learning"),
        (50, "refining"),
        (499, "refining"),
        (500, "mature"),
        (10_000, "mature"),
    ],
)
def test_model_stage_boundaries(total: int, expected: str):
    assert training.model_stage(total) == expected


# ── label_counts — DB shape contract ─────────────────────────────────────────


def test_label_counts_missing_db_returns_zeros(tmp_path: Path):
    out = training.label_counts(tmp_path / "absent.db")
    assert out == {"total": 0, "tp": 0, "fp": 0}


def test_label_counts_skips_unlabeled_rows(feedback_db: Path):
    conn = sqlite3.connect(str(feedback_db))
    conn.executemany(
        "INSERT INTO findings (id, label) VALUES (?, ?)",
        [
            ("a", "tp"),
            ("b", "tp"),
            ("c", "fp"),
            ("d", None),  # unlabeled — must be excluded from `total`
        ],
    )
    conn.commit()
    conn.close()

    out = training.label_counts(feedback_db)
    assert out == {"total": 3, "tp": 2, "fp": 1}


# ── _has_group_column — schema migration tolerance ───────────────────────────


def test_has_group_column_present(feedback_db: Path):
    conn = sqlite3.connect(str(feedback_db))
    try:
        assert training._has_group_column(conn) is True
    finally:
        conn.close()


def test_has_group_column_absent(feedback_db_no_group: Path):
    conn = sqlite3.connect(str(feedback_db_no_group))
    try:
        assert training._has_group_column(conn) is False
    finally:
        conn.close()


# ── _load_dataset — round-trips bytes / labels / group_key ───────────────────


def _row(label: str, group_key: str | None, vec_seed: int) -> tuple[bytes, str, str | None]:
    fv = np.full(768, vec_seed, dtype="<f4").tobytes()
    return fv, label, group_key


def test_load_dataset_returns_labels_groups(feedback_db: Path):
    fv1 = np.full(768, 0.1, dtype="<f4").tobytes()
    fv2 = np.full(768, 0.2, dtype="<f4").tobytes()
    conn = sqlite3.connect(str(feedback_db))
    conn.executemany(
        "INSERT INTO findings (id, label, feature_vector, group_key) VALUES (?, ?, ?, ?)",
        [
            ("a", "tp", fv1, "CVE-2024-1"),
            ("b", "fp", fv2, "CVE-2024-1"),
            ("c", None, fv1, "CVE-2024-2"),  # excluded — no label
            ("d", "tp", None, "CVE-2024-2"),  # excluded — no feature_vector
        ],
    )
    conn.commit()
    conn.close()

    rows = training._load_dataset(feedback_db)
    labels = sorted([r[1] for r in rows])
    groups = sorted([r[2] for r in rows])
    assert labels == ["fp", "tp"]
    assert groups == ["CVE-2024-1", "CVE-2024-1"]
    # Bytes survive round trip
    fvs = sorted(np.frombuffer(r[0], dtype="<f4")[0] for r in rows)
    assert fvs == pytest.approx([0.1, 0.2])


def test_load_dataset_falls_back_when_group_column_missing(feedback_db_no_group: Path):
    fv = np.full(768, 0.5, dtype="<f4").tobytes()
    conn = sqlite3.connect(str(feedback_db_no_group))
    conn.executemany(
        "INSERT INTO findings (id, label, feature_vector) VALUES (?, ?, ?)",
        [
            ("a", "tp", fv),
            ("b", "fp", fv),
        ],
    )
    conn.commit()
    conn.close()

    rows = training._load_dataset(feedback_db_no_group)
    assert {r[1] for r in rows} == {"tp", "fp"}
    assert all(r[2] is None for r in rows), "missing column → all groups must be None"


# ── read_metrics — JSON round trip and missing-file path ─────────────────────


def test_read_metrics_missing_file(tmp_path: Path):
    assert training.read_metrics(tmp_path / "metrics.json") is None


def test_read_metrics_round_trip(tmp_path: Path):
    p = tmp_path / "metrics.json"
    p.write_text('{"trained_at":"2026-04-26","samples":42}')
    out = training.read_metrics(p)
    assert out == {"trained_at": "2026-04-26", "samples": 42}


def test_read_metrics_invalid_json(tmp_path: Path):
    p = tmp_path / "metrics.json"
    p.write_text("not json")
    # Must not raise — service returns None and logs a warning.
    assert training.read_metrics(p) is None


# ── load_model — absent path ─────────────────────────────────────────────────


def test_load_model_absent(tmp_path: Path):
    assert training.load_model(tmp_path / "model.json") is None
