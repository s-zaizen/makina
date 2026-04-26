#!/usr/bin/env python3
"""Convert CVEfixes.db → samples.jsonl with paired TP/FP cases.

For every method whose patch is recorded in CVEfixes we emit TWO cases
keyed by the same CVE:

    TP — the vulnerable side (`before_change='True'`).
         `code` is the full method body, `ranges` are the diff's
         deleted-line spans projected onto method-relative coordinates.

    FP — the patched side  (`before_change='False'`).
         `code` is the full patched method, `ranges` are the diff's
         added-line spans on its method-relative coordinates.

Why FP samples come from `code_after` and not from random clean code:

The GBDT must learn what *fixes* look like, not just what vulnerable
code looks like. Pairing the vulnerable method with its actual patched
counterpart gives the model a hard counterexample for every CVE — same
function name, same call-graph context, but the dangerous lines have
been replaced. Random clean code would teach a much weaker boundary
and produce a brittle classifier.

We do *not* re-use `code_before` as an FP source because labelling the
same code both ways collapses the supervision signal and overfits the
model to the residual context lines.

Output schema (per line):
    {"code":     str,                 # full method body (TP or FP side)
     "language": str,
     "label":    "tp" | "fp",
     "ranges": [
        {"line_start": int, "line_end": int}, ...   # method-relative
     ],
     "cve_id":   str|None,
     "cwe":      str|None,            # only set on TP rows
     "severity": str,                 # critical|high|medium|low
     "filename": str|None}

Defaults assume makina's repo layout:
    --db   third_party/datasets/cvefixes/CVEfixes.db
    --out  third_party/datasets/cvefixes/samples.jsonl

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
    SELECT vuln.code               AS vuln_code,
           vuln.start_line          AS vuln_start,
           vuln.end_line            AS vuln_end,
           patched.code             AS patched_code,
           patched.start_line       AS patched_start,
           patched.end_line         AS patched_end,
           fc.diff_parsed,
           fc.programming_language  AS lang,
           fc.filename,
           cwec.cwe_id              AS cwe,
           fx.cve_id                AS cve
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
      AND vuln.start_line IS NOT NULL
      AND patched.start_line IS NOT NULL
      AND fc.diff_parsed IS NOT NULL
      AND fc.programming_language IN ({langs})
      AND LENGTH(vuln.code)    BETWEEN ? AND ?
      AND LENGTH(patched.code) BETWEEN ? AND ?
    GROUP BY vuln.method_change_id
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
    diff_lines: list, method_start: int, method_end: int, gap: int
) -> list[tuple[int, int]]:
    """Project file-relative diff line numbers onto method-relative
    coordinates and cluster into ranges. Lines outside the method are
    dropped."""
    nums: list[int] = []
    for entry in diff_lines:
        if not isinstance(entry, (list, tuple)) or not entry:
            continue
        try:
            ln = int(entry[0])
        except (TypeError, ValueError):
            continue
        if method_start <= ln <= method_end:
            nums.append(ln - method_start + 1)
    return _cluster(nums, gap=gap)


def _expand(rng: tuple[int, int], total_lines: int, padding: int) -> tuple[int, int]:
    lo, hi = rng
    return max(1, lo - padding), min(total_lines, hi + padding)


def _emit(
    fh,
    code: str,
    label: str,
    ranges: list[tuple[int, int]],
    lang: str,
    cve: str | None,
    cwe: str | None,
    filename: str | None,
    seen: set[str],
    counters: dict,
    padding: int,
) -> bool:
    """Emit one JSONL record. Returns True if written, False if deduped."""
    key = hashlib.sha1((label + "\x00" + code).encode("utf-8")).hexdigest()
    if key in seen:
        counters["dedup"] += 1
        return False
    seen.add(key)

    total_lines = code.count("\n") + 1
    expanded = [_expand(r, total_lines, padding) for r in ranges]

    rec = {
        "code": code,
        "language": lang,
        "label": label,
        "ranges": [{"line_start": lo, "line_end": hi} for lo, hi in expanded],
        "cve_id": cve,
        "cwe": cwe if label == "tp" else None,
        "severity": _cwe_to_severity(cwe) if (label == "tp" and cwe) else "low",
        "filename": filename,
    }
    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    counters[label] += 1
    return True


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
        help="merge diff line spans at most N lines apart",
    )
    ap.add_argument(
        "--padding",
        type=int,
        default=0,
        help="extra lines of context above/below each range (clamped to method)",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=0,
        help="stop after N pairs (each pair emits up to 2 records); 0 = all",
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

    seen: set[str] = set()
    counters = {"tp": 0, "fp": 0, "dedup": 0, "no_range": 0, "lang": 0, "parse": 0}
    pairs_seen = 0

    with args.out.open("w", encoding="utf-8") as fh:
        cur = conn.execute(
            sql, (args.min_len, args.max_len, args.min_len, args.max_len)
        )
        for (
            vuln_code,
            vuln_start,
            vuln_end,
            patched_code,
            patched_start,
            patched_end,
            diff_parsed,
            lang,
            filename,
            cwe,
            cve,
        ) in cur:
            lang_tag = _LANG_MAP.get(lang)
            if not lang_tag:
                counters["lang"] += 1
                continue

            try:
                vs, ve = int(vuln_start), int(vuln_end)
                ps, pe = int(patched_start), int(patched_end)
            except (TypeError, ValueError):
                counters["parse"] += 1
                continue

            parsed = _parse_diff(diff_parsed)
            if not parsed:
                counters["parse"] += 1
                continue

            tp_ranges = _to_method_ranges(parsed.get("deleted") or [], vs, ve, args.gap)
            fp_ranges = _to_method_ranges(parsed.get("added") or [], ps, pe, args.gap)

            if not tp_ranges and not fp_ranges:
                counters["no_range"] += 1
                continue

            wrote_any = False
            if tp_ranges:
                wrote_any |= _emit(
                    fh,
                    vuln_code,
                    "tp",
                    tp_ranges,
                    lang_tag,
                    cve,
                    cwe,
                    filename,
                    seen,
                    counters,
                    args.padding,
                )
            if fp_ranges:
                wrote_any |= _emit(
                    fh,
                    patched_code,
                    "fp",
                    fp_ranges,
                    lang_tag,
                    cve,
                    cwe,
                    filename,
                    seen,
                    counters,
                    args.padding,
                )

            if wrote_any:
                pairs_seen += 1

            if args.limit and pairs_seen >= args.limit:
                break

    conn.close()
    total = counters["tp"] + counters["fp"]
    print(
        f"wrote {total} samples ({counters['tp']} TP + {counters['fp']} FP) "
        f"from {pairs_seen} pairs → {args.out}\n"
        f"  skipped: {counters['no_range']} (no in-range edits), "
        f"{counters['dedup']} (dup), {counters['lang']} (lang), "
        f"{counters['parse']} (parse)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
