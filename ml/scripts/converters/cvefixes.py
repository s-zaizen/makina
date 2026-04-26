#!/usr/bin/env python3
"""Convert CVEfixes.db → samples.jsonl with full-method code + vulnerable
line ranges.

For each `method_change` row on the pre-patch side (`before_change='True'`)
we keep the entire method body and project the diff's deleted-line set
onto method-relative coordinates. Consecutive deleted lines are clustered
into ranges; each range becomes one TP finding when imported. Methods
whose diff produces no in-range deletions are skipped.

This is the new corpus format that bulk_import.py expects: it lets the
GBDT learn from per-finding embeddings (full code as context, narrow
line range as the focus) instead of training on whole-method labels —
the latter drifted from the per-finding distribution the model sees at
inference time.

Output schema (per line):
    {"code": str,                 # full method body (vulnerable side)
     "language": str,
     "cve_id": str|None,
     "cwe": str|None,
     "severity": str,             # critical|high|medium|low
     "filename": str|None,
     "ranges": [
        {"line_start": int, "line_end": int}, ...   # method-relative, 1-indexed
     ]}

Defaults assume makina's repo layout:
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
import ast
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))
from bulk_import import SUPPORTED_LANGS, _LANG_MAP, _cwe_to_severity  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DB = REPO_ROOT / "third_party/datasets/cvefixes/CVEfixes.db"
DEFAULT_OUT = REPO_ROOT / "third_party/datasets/cvefixes/samples.jsonl"


SQL = """
    SELECT mc.code,
           mc.start_line,
           mc.end_line,
           fc.diff_parsed,
           fc.programming_language,
           fc.filename,
           cwec.cwe_id,
           fx.cve_id
    FROM method_change mc
    JOIN file_change fc ON mc.file_change_id = fc.file_change_id
    JOIN fixes fx       ON fc.hash = fx.hash
    LEFT JOIN cwe_classification cwec ON fx.cve_id = cwec.cve_id
    WHERE mc.before_change = 'True'
      AND mc.code IS NOT NULL
      AND mc.start_line IS NOT NULL
      AND mc.end_line IS NOT NULL
      AND fc.diff_parsed IS NOT NULL
      AND fc.programming_language IN ({langs})
      AND LENGTH(mc.code) BETWEEN ? AND ?
"""


def _parse_diff(raw: str) -> dict | None:
    try:
        v = ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        return None
    return v if isinstance(v, dict) else None


def _cluster(nums: list[int], gap: int) -> list[tuple[int, int]]:
    """Cluster sorted ints into [start, end] spans where consecutive
    members are at most `gap` apart."""
    if not nums:
        return []
    s = sorted(set(nums))
    out: list[tuple[int, int]] = []
    start = prev = s[0]
    for n in s[1:]:
        if n - prev > gap:
            out.append((start, prev))
            start = n
        prev = n
    out.append((start, prev))
    return out


def _to_method_ranges(
    deleted: list, method_start: int, method_end: int, gap: int
) -> list[tuple[int, int]]:
    """Project file-relative deleted line numbers onto method-relative
    coordinates, then cluster into ranges. Lines outside the method are
    dropped."""
    nums: list[int] = []
    for entry in deleted:
        if not isinstance(entry, (list, tuple)) or not entry:
            continue
        try:
            ln = int(entry[0])
        except (TypeError, ValueError):
            continue
        if method_start <= ln <= method_end:
            nums.append(ln - method_start + 1)
    return _cluster(nums, gap=gap)


def _expand_range(
    rng: tuple[int, int], total_lines: int, padding: int
) -> tuple[int, int]:
    """Add `padding` lines of context above and below, clamped to method bounds."""
    lo, hi = rng
    return max(1, lo - padding), min(total_lines, hi + padding)


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
    ap.add_argument(
        "--max-len", type=int, default=8000, help="max code length in chars"
    )
    ap.add_argument(
        "--gap",
        type=int,
        default=2,
        help="merge deleted-line spans at most N lines apart",
    )
    ap.add_argument(
        "--padding",
        type=int,
        default=0,
        help="extra lines of context above/below each range (clamped to method)",
    )
    ap.add_argument(
        "--limit", type=int, default=0, help="stop after N samples (0 = all)"
    )
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
    sql = SQL.format(langs=lang_sql)

    written = 0
    seen: set[str] = set()
    skipped_no_range = 0
    skipped_dup = 0
    skipped_lang = 0
    skipped_parse = 0

    with args.out.open("w", encoding="utf-8") as fh:
        cur = conn.execute(sql, (args.min_len, args.max_len))
        for code, start_line, end_line, diff_parsed, lang, filename, cwe, cve in cur:
            lang_tag = _LANG_MAP.get(lang)
            if not lang_tag:
                skipped_lang += 1
                continue

            try:
                method_start = int(start_line)
                method_end = int(end_line)
            except (TypeError, ValueError):
                skipped_parse += 1
                continue

            parsed = _parse_diff(diff_parsed)
            if not parsed:
                skipped_parse += 1
                continue

            ranges = _to_method_ranges(
                parsed.get("deleted") or [], method_start, method_end, args.gap
            )
            if not ranges:
                skipped_no_range += 1
                continue

            total_lines = code.count("\n") + 1
            ranges = [_expand_range(r, total_lines, args.padding) for r in ranges]

            key = hashlib.sha1(code.encode("utf-8")).hexdigest()
            if key in seen:
                skipped_dup += 1
                continue
            seen.add(key)

            rec = {
                "code": code,
                "language": lang_tag,
                "cve_id": cve,
                "cwe": cwe,
                "severity": _cwe_to_severity(cwe) if cwe else "medium",
                "filename": filename,
                "ranges": [{"line_start": lo, "line_end": hi} for lo, hi in ranges],
            }
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            written += 1

            if args.limit and written >= args.limit:
                break

    conn.close()
    print(
        f"wrote {written} samples → {args.out}\n"
        f"  skipped: {skipped_no_range} (no in-range deletions), "
        f"{skipped_dup} (dup code), {skipped_lang} (lang), "
        f"{skipped_parse} (diff parse)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
