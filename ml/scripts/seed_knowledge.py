#!/usr/bin/env python3
"""Build a knowledge.db showcase from samples.jsonl.

The public Cloud Run deployment runs in `MAKINA_PUBLIC_MODE=true`,
which strips every learning-loop write route — so the runtime
`knowledge.db` would otherwise stay empty and the Knowledge tab on
makina.sh would be a sad blank page.

This script materialises one knowledge case per sample (TP-side or
FP-side method, same shape `bulk_import.py` would produce minus the
embeddings stored in `feedback.db`). It runs at Docker image build
time so the resulting `knowledge.db` ships baked into the container.

Schema must match `crates/makina/src/store/mod.rs::init_db`:

    CREATE TABLE knowledge (
        case_no       INTEGER PRIMARY KEY,
        cve_id        TEXT,
        code          TEXT    NOT NULL,
        language      TEXT    NOT NULL,
        findings_json TEXT    NOT NULL DEFAULT '[]',
        labels_json   TEXT    NOT NULL DEFAULT '{}',
        submitted_at  TEXT    NOT NULL,
        verified_at   TEXT    NOT NULL
    );

Usage
-----
    python ml/scripts/seed_knowledge.py \\
        --jsonl third_party/datasets/cvefixes/samples.jsonl \\
        --out   models/v1.0.8/knowledge.db
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# The schema is duplicated from crates/makina/src/store/mod.rs so the
# build doesn't depend on the running Rust core. Keep both in sync.
SCHEMA = """
CREATE TABLE IF NOT EXISTS knowledge (
    case_no       INTEGER PRIMARY KEY,
    cve_id        TEXT,
    code          TEXT    NOT NULL,
    language      TEXT    NOT NULL,
    findings_json TEXT    NOT NULL DEFAULT '[]',
    labels_json   TEXT    NOT NULL DEFAULT '{}',
    submitted_at  TEXT    NOT NULL,
    verified_at   TEXT    NOT NULL
);
"""


def _severity_for(cwe: str | None) -> str:
    """Mirror bulk_import.py::_cwe_to_severity for showcase display."""
    if not cwe:
        return "medium"
    high = {
        "CWE-78", "CWE-77", "CWE-89", "CWE-94", "CWE-502",
        "CWE-120", "CWE-787", "CWE-416",
    }
    mid = {"CWE-22", "CWE-79", "CWE-352", "CWE-918", "CWE-400", "CWE-611"}
    if cwe in high:
        return "high"
    if cwe in mid:
        return "medium"
    return "low"


def _build_finding(sample: dict, rng: dict) -> tuple[dict, str]:
    """Translate one (sample, range) into a Finding object that matches
    the JSON shape the frontend expects. Returns `(finding_dict,
    label_str)` so the caller can build the labels map."""
    finding_id = str(uuid.uuid4())
    cwe = sample.get("cwe")
    label = sample.get("label", "tp")
    if label == "tp":
        message = cwe or "vulnerable region (CVEfixes)"
    else:
        message = (
            f"patched region for {cwe} (CVEfixes)"
            if cwe
            else "patched region (CVEfixes)"
        )

    code_lines = sample["code"].splitlines()
    ls = max(0, int(rng["line_start"]) - 1)
    le = min(len(code_lines), int(rng["line_end"]))
    snippet = "\n".join(code_lines[ls:le])

    finding = {
        "id": finding_id,
        "rule_id": cwe or "manual",
        "message": message,
        "severity": _severity_for(cwe),
        "line_start": int(rng["line_start"]),
        "line_end": int(rng["line_end"]),
        "code_snippet": snippet,
        "confidence": 1.0,
        "is_uncertain": False,
        "cwe": cwe,
        "source": "manual",
    }
    return finding, label


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--jsonl", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument(
        "--limit",
        type=int,
        default=0,
        help="cap on the number of cases (0 = all). Useful for thinning the showcase.",
    )
    args = ap.parse_args()

    if not args.jsonl.exists():
        print(f"jsonl not found: {args.jsonl}", file=sys.stderr)
        return 2

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.unlink(missing_ok=True)

    conn = sqlite3.connect(str(args.out))
    conn.executescript(SCHEMA)

    now_iso = datetime.now(timezone.utc).isoformat()
    case_no = 0
    written = 0
    with args.jsonl.open(encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            ranges = obj.get("ranges") or []
            if not ranges or not obj.get("code"):
                continue

            findings: list[dict] = []
            labels: dict[str, str] = {}
            for rng in ranges:
                try:
                    f, lbl = _build_finding(obj, rng)
                except (TypeError, KeyError, ValueError):
                    continue
                findings.append(f)
                labels[f["id"]] = lbl
            if not findings:
                continue

            case_no += 1
            conn.execute(
                "INSERT INTO knowledge "
                "(case_no, cve_id, code, language, findings_json, labels_json, "
                "submitted_at, verified_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    case_no,
                    obj.get("cve_id"),
                    obj["code"],
                    obj.get("language") or "auto",
                    json.dumps(findings, ensure_ascii=False),
                    json.dumps(labels, ensure_ascii=False),
                    now_iso,
                    now_iso,
                ),
            )
            written += 1
            if args.limit and written >= args.limit:
                break

    conn.commit()
    conn.close()
    print(f"wrote {written} knowledge cases → {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
