#!/usr/bin/env python3
"""Convert CVEfixes.db diffs → samples_pairs.jsonl (paired before/after hunks).

Each output line is one CVE-fix hunk PAIR, keeping the vulnerable and
patched versions of the same code region together. This is the input
format for the experimental pair-feature training pipeline
(`train_pairs_experimental.py`): concatenating `emb_before`,
`emb_after`, and their delta exposes the patch signal that frozen-encoder
single-hunk supervision cannot separate.

Pairing heuristic: within each `file_change`, cluster deleted-line and
added-line spans independently (gap ≤ N merges adjacent lines), sort
both lists by start line, then zip them index-wise (``min(len_del,
len_add)`` pairs per file). This matches most CVE patches which add and
remove code in the same local region; it loses correctness when fixes
are purely additive or purely removing on one side, which we filter out.

Output schema (per line):
    {"before_code": str, "after_code": str, "language": str,
     "cve_id": str|None, "cwe": str|None,
     "filename": str|None}

Defaults:
    --db   third_party/datasets/cvefixes/CVEfixes.db
    --out  third_party/datasets/cvefixes/samples_pairs.jsonl
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
from bulk_import import SUPPORTED_LANGS, _LANG_MAP  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DB = REPO_ROOT / "third_party/datasets/cvefixes/CVEfixes.db"
DEFAULT_OUT = REPO_ROOT / "third_party/datasets/cvefixes/samples_pairs.jsonl"

SKIP_FILENAME_SUBSTR = (
    "CHANGELOG", "README", "LICENSE", "NEWS", "AUTHORS",
    "/test/", "/tests/", "_test.", "test_",
    ".md", ".rst", ".txt", ".json", ".yaml", ".yml",
    ".xml", ".html", ".svg", "/doc/", "/docs/",
)


def _should_skip_file(filename: str | None) -> bool:
    if not filename:
        return False
    low = filename.lower()
    return any(s.lower() in low for s in SKIP_FILENAME_SUBSTR)


def _cluster_lines(entries: list, gap: int = 3) -> list[tuple[int, int]]:
    if not entries:
        return []
    nums = sorted({int(e[0]) for e in entries if isinstance(e, (list, tuple)) and e})
    spans: list[tuple[int, int]] = []
    if not nums:
        return spans
    start = prev = nums[0]
    for n in nums[1:]:
        if n - prev > gap:
            spans.append((start, prev))
            start = n
        prev = n
    spans.append((start, prev))
    return spans


def _slice_context(code: str, start: int, end: int, radius: int) -> str:
    if not code:
        return ""
    lines = code.splitlines()
    lo = max(0, start - 1 - radius)
    hi = min(len(lines), end + radius)
    return "\n".join(lines[lo:hi])


def _query() -> str:
    return """
        SELECT fc.diff_parsed,
               fc.code_before,
               fc.code_after,
               fc.programming_language,
               fc.filename,
               fx.cve_id,
               cwec.cwe_id
        FROM file_change fc
        JOIN fixes fx      ON fc.hash = fx.hash
        LEFT JOIN cwe_classification cwec ON fx.cve_id = cwec.cve_id
        WHERE fc.diff_parsed IS NOT NULL
          AND fc.programming_language IN ({langs})
    """


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--langs", nargs="+", default=sorted(SUPPORTED_LANGS))
    ap.add_argument("--radius", type=int, default=5)
    ap.add_argument("--gap", type=int, default=3)
    ap.add_argument("--min-lines", type=int, default=3)
    ap.add_argument("--max-lines", type=int, default=60)
    ap.add_argument("--min-chars", type=int, default=40)
    ap.add_argument("--max-chars", type=int, default=4000)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    if not args.db.exists():
        print(f"CVEfixes DB not found: {args.db}", file=sys.stderr)
        return 2

    invalid = [lang for lang in args.langs if lang not in SUPPORTED_LANGS]
    if invalid:
        print(f"Unsupported languages: {invalid}", file=sys.stderr)
        return 2

    args.out.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    lang_sql = ",".join(f"'{lang}'" for lang in args.langs)
    sql = _query().format(langs=lang_sql)

    seen_pairs: set[str] = set()
    stats = {
        "rows": 0,
        "skipped_file": 0,
        "skipped_parse": 0,
        "skipped_lang": 0,
        "emitted_pairs": 0,
        "dedup_skips": 0,
        "length_skips": 0,
        "unpaired": 0,  # files with only added or only deleted hunks
    }

    with args.out.open("w", encoding="utf-8") as fh:
        for (diff_parsed, code_before, code_after, lang, filename, cve, cwe) in conn.execute(sql):
            stats["rows"] += 1

            if _should_skip_file(filename):
                stats["skipped_file"] += 1
                continue

            lang_tag = _LANG_MAP.get(lang)
            if not lang_tag:
                stats["skipped_lang"] += 1
                continue

            try:
                parsed = ast.literal_eval(diff_parsed) if diff_parsed else None
            except (ValueError, SyntaxError):
                stats["skipped_parse"] += 1
                continue
            if not isinstance(parsed, dict):
                stats["skipped_parse"] += 1
                continue

            deleted_spans = sorted(_cluster_lines(parsed.get("deleted") or [], gap=args.gap))
            added_spans = sorted(_cluster_lines(parsed.get("added") or [], gap=args.gap))

            n = min(len(deleted_spans), len(added_spans))
            if n == 0:
                stats["unpaired"] += 1
                continue

            for i in range(n):
                del_start, del_end = deleted_spans[i]
                add_start, add_end = added_spans[i]

                before_hunk = _slice_context(code_before, del_start, del_end, args.radius)
                after_hunk = _slice_context(code_after, add_start, add_end, args.radius)

                def _bad(h: str) -> bool:
                    if not h:
                        return True
                    lines = h.count("\n") + 1
                    return (
                        lines < args.min_lines
                        or lines > args.max_lines
                        or len(h) < args.min_chars
                        or len(h) > args.max_chars
                    )

                if _bad(before_hunk) or _bad(after_hunk):
                    stats["length_skips"] += 1
                    continue

                key = hashlib.sha1((before_hunk + "\x00" + after_hunk).encode("utf-8")).hexdigest()
                if key in seen_pairs:
                    stats["dedup_skips"] += 1
                    continue
                seen_pairs.add(key)

                rec = {
                    "before_code": before_hunk,
                    "after_code": after_hunk,
                    "language": lang_tag,
                    "cve_id": cve,
                    "cwe": cwe,
                    "filename": filename,
                }
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                stats["emitted_pairs"] += 1

                if args.limit and stats["emitted_pairs"] >= args.limit:
                    break

            if args.limit and stats["emitted_pairs"] >= args.limit:
                break

    conn.close()
    print(f"wrote {stats['emitted_pairs']} pairs → {args.out}")
    print(f"stats: {stats}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
