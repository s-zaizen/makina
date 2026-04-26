"""Test setup — make `makina_ml` importable when pytest is run from
the `ml/` directory and provide shared fixtures."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

# Ensure `import makina_ml.*` works when running from `ml/` even without
# editable install (handy for in-container `python -m pytest`).
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def feedback_db(tmp_path: Path) -> Path:
    """Return a path to a fresh `feedback.db` schema-compatible with the
    columns `services.training` reads (`feature_vector`, `label`,
    `group_key`, `code_hash`)."""
    db_path = tmp_path / "feedback.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        CREATE TABLE findings (
            id            TEXT PRIMARY KEY,
            code_hash     TEXT,
            feature_vector BLOB,
            rule_id       TEXT,
            language      TEXT,
            line_number   INTEGER,
            confidence    REAL,
            label         TEXT,
            labeled_at    TEXT,
            created_at    TEXT,
            group_key     TEXT
        )
        """
    )
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def feedback_db_no_group(tmp_path: Path) -> Path:
    """Older schema without the `group_key` column — `_load_dataset`
    must fall back gracefully here."""
    db_path = tmp_path / "feedback.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        CREATE TABLE findings (
            id            TEXT PRIMARY KEY,
            code_hash     TEXT,
            feature_vector BLOB,
            rule_id       TEXT,
            language      TEXT,
            line_number   INTEGER,
            confidence    REAL,
            label         TEXT,
            labeled_at    TEXT,
            created_at    TEXT
        )
        """
    )
    conn.commit()
    conn.close()
    return db_path
