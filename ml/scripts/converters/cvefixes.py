#!/usr/bin/env python3
"""Convert CVEfixes.db → samples.jsonl in deus's corpus format.

Streams (vulnerable_method, patched_method) pairs from a CVEfixes SQLite
dump and writes one JSON object per line. The resulting JSONL can be
fed into bulk_import.py (future) or inspected directly without
re-parsing the full ~1 GB CVEfixes.db each time.

Output schema (per line):
    {"code": str, "language": str, "vulnerable": bool,
     "cve_id": str|None, "cwe": str|None,
     "severity": "critical"|"high"|"medium"|"low",
     "message": str}

Defaults assume deus's repo layout:
    --db   third_party/datasets/cvefixes/CVEfixes.db
    --out  third_party/datasets/cvefixes/samples.jsonl

Usage
-----
    python ml/scripts/converters/cvefixes.py
    python ml/scripts/converters/cvefixes.py --langs Python Java
    python ml/scripts/converters/cvefixes.py --limit 5000

License: CVEfixes itself is CC BY 4.0 (Bhandari, Naseer, Moonen, 2021);
see third_party/datasets/cvefixes/README.md for attribution details.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from dataclasses import asdict
from pathlib import Path

# Reuse Sample + language helpers from the sibling bulk_import script.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))
from bulk_import import SUPPORTED_LANGS, Sample, _LANG_MAP, _cwe_to_severity  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DB = REPO_ROOT / "third_party/datasets/cvefixes/CVEfixes.db"
DEFAULT_OUT = REPO_ROOT / "third_party/datasets/cvefixes/samples.jsonl"


def _query_for_schema(conn: sqlite3.Connection) -> str:
    """Return a SQL template (with {langs} placeholder) for this dump's schema."""
    mc_cols = {row[1] for row in conn.execute("PRAGMA table_info(method_change)")}
    # v1.0.7 / v1.0.8: one row per version with mc.code + mc.before_change ('True'/'False').
    if "code" in mc_cols and "before_change" in mc_cols:
        return """
            SELECT vuln.code               AS code_before,
                   patched.code            AS code_after,
                   fc.programming_language AS lang,
                   cwec.cwe_id             AS cwe,
                   fx.cve_id               AS cve
            FROM method_change vuln
            JOIN method_change patched
                 ON patched.name = vuln.name
                AND patched.signature = vuln.signature
                AND patched.file_change_id = vuln.file_change_id
                AND patched.before_change = 'False'
            JOIN file_change fc ON vuln.file_change_id = fc.file_change_id
            JOIN fixes fx       ON fc.hash = fx.hash
            LEFT JOIN cwe_classification cwec ON fx.cve_id = cwec.cve_id
            WHERE vuln.before_change = 'True'
              AND vuln.code    IS NOT NULL
              AND patched.code IS NOT NULL
              AND LENGTH(vuln.code) BETWEEN ? AND ?
              AND fc.programming_language IN ({langs})
            GROUP BY vuln.method_change_id
        """
    # Older schema: both versions on the same row.
    return """
        SELECT mc.code_before, mc.code_after, fc.programming_language, cwec.cwe_id, fx.cve_id
        FROM method_change mc
        JOIN file_change fc ON mc.file_change_id = fc.file_change_id
        JOIN fixes fx       ON fc.hash = fx.hash
        LEFT JOIN cwe_classification cwec ON fx.cve_id = cwec.cve_id
        WHERE mc.code_before IS NOT NULL AND mc.code_after IS NOT NULL
          AND LENGTH(mc.code_before) BETWEEN ? AND ?
          AND fc.programming_language IN ({langs})
    """


def _sample_dict(
    code: str, lang_tag: str, vulnerable: bool, cwe: str | None, cve: str | None
) -> dict:
    s = Sample(
        code=code,
        language=lang_tag,
        vulnerable=vulnerable,
        cve_id=cve,
        cwe=cwe if vulnerable else None,
        severity=(
            _cwe_to_severity(cwe) if vulnerable and cwe
            else ("medium" if vulnerable else "low")
        ),
        message=(
            (cwe or "vulnerable method (CVEfixes)") if vulnerable
            else "patched version (CVEfixes)"
        ),
    )
    return asdict(s)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--db", type=Path, default=DEFAULT_DB, help="path to CVEfixes.db")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output JSONL path")
    ap.add_argument(
        "--langs",
        nargs="+",
        default=sorted(SUPPORTED_LANGS),
        help=f"CVEfixes language labels to include (default: {sorted(SUPPORTED_LANGS)})",
    )
    ap.add_argument("--min-len", type=int, default=100, help="min code length in chars")
    ap.add_argument("--max-len", type=int, default=8000, help="max code length in chars")
    ap.add_argument("--limit", type=int, default=0, help="stop after N samples (0 = all)")
    args = ap.parse_args()

    if not args.db.exists():
        print(f"CVEfixes DB not found: {args.db}", file=sys.stderr)
        print("Run ./third_party/datasets/cvefixes/fetch.sh first.", file=sys.stderr)
        return 2

    invalid = [lang for lang in args.langs if lang not in SUPPORTED_LANGS]
    if invalid:
        print(
            f"Unsupported languages: {invalid}. Choose from {sorted(SUPPORTED_LANGS)}.",
            file=sys.stderr,
        )
        return 2

    args.out.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    lang_sql = ",".join(f"'{lang}'" for lang in args.langs)
    sql = _query_for_schema(conn).format(langs=lang_sql)

    written = 0
    seen: set[str] = set()
    with args.out.open("w", encoding="utf-8") as fh:
        cur = conn.execute(sql, (args.min_len, args.max_len))
        for code_before, code_after, lang, cwe, cve in cur:
            lang_tag = _LANG_MAP.get(lang)
            if not lang_tag:
                continue
            for code, vulnerable in ((code_before, True), (code_after, False)):
                if not code or not code.strip() or code in seen:
                    continue
                seen.add(code)
                rec = _sample_dict(code, lang_tag, vulnerable, cwe, cve)
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                written += 1
                if args.limit and written >= args.limit:
                    break
            if args.limit and written >= args.limit:
                break

    conn.close()
    print(f"wrote {written} samples → {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
