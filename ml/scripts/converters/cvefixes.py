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


# ── Per-CVE batched query design ────────────────────────────────────────────
#
# An earlier version of this converter ran a single mega-query joining
# method_change × method_change × file_change × fixes × commits ×
# cwe_classification with a trailing GROUP BY method_change_id, then
# streamed rows back via a sqlite cursor. That works on the v1.0.7
# dump (~7k commits) but on v1.0.8 (12k commits / 278k method_change
# rows / 48 GB DB) sqlite has to materialise the entire grouped result
# set in RAM before yielding the first row, which OOMs the host.
#
# We split the work in two:
#
#   1. CVE_LIST_SQL: cheap outer scan that just enumerates the CVE ids
#      worth processing (one row per CVE, ~12k rows total). Includes
#      the commit message so the Python-side keyword filter can drop
#      pure refactors before any expensive fetch happens.
#
#   2. CVE_BATCH_SQL: scoped inner query bound to a single CVE id at
#      a time. The result set is ≤ a handful of method_change rows,
#      so the GROUP BY runs on tiny inputs and memory stays bounded.
#
# Net effect: peak memory is O(rows-per-CVE) ≈ a few KB instead of
# O(all rows) ≈ tens of GB.

CVE_LIST_SQL = """
    SELECT DISTINCT fx.cve_id, c.msg
    FROM fixes fx
    JOIN file_change fc ON fc.hash = fx.hash
    LEFT JOIN commits c ON c.hash  = fc.hash
    WHERE fc.programming_language IN ({langs})
      AND fc.diff_parsed IS NOT NULL
"""

CVE_BATCH_SQL = """
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
           fx.cve_id                AS cve,
           c.msg                    AS commit_msg
    FROM method_change vuln
    JOIN method_change patched
         ON patched.name = vuln.name
        AND patched.signature = vuln.signature
        AND patched.file_change_id = vuln.file_change_id
        AND patched.before_change = 'False'
    JOIN file_change fc ON vuln.file_change_id = fc.file_change_id
    JOIN fixes fx       ON fc.hash = fx.hash
    LEFT JOIN commits c ON fc.hash = c.hash
    LEFT JOIN cwe_classification cwec ON fx.cve_id = cwec.cve_id
    WHERE fx.cve_id = ?
      AND vuln.before_change = 'True'
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


# Skip non-code or test-only files — CVEfixes flags every method touched
# in the security commit, but test cases and docs around the fix carry no
# vulnerability signal and pollute the labelled set with structural false
# positives.
_SKIP_FILENAME_SUBSTR = (
    "/test/",
    "/tests/",
    "/spec/",
    "/specs/",
    "/__tests__/",
    "_test.",
    ".test.",
    "test_",
    "_spec.",
    "spec_",
    ".spec.",
    "/fixtures/",
    "/testdata/",
    "/example",
    "/examples/",
    "/doc/",
    "/docs/",
    "CHANGELOG",
    "README",
    "LICENSE",
    "NEWS",
    "AUTHORS",
    ".md",
    ".rst",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".html",
    ".svg",
)


def _should_skip_file(filename: str | None) -> bool:
    if not filename:
        return False
    low = filename.lower()
    return any(s.lower() in low for s in _SKIP_FILENAME_SUBSTR)


# Commit-message filter. Many CVEfixes commits sweep up incidental cleanup
# (rename/refactor/style) alongside the actual security fix; without
# something to gate them, the diff hunks from those commits become
# structural noise in the labelled set. We require at least one security
# keyword to appear and reject commits whose message is dominated by pure
# refactor/cleanup language.
_COMMIT_INCLUDE = (
    "secur",
    "vuln",
    "cve-",
    "cve ",
    "exploit",
    "overflow",
    "underflow",
    "inject",
    "xss",
    "csrf",
    "rce",
    "ssrf",
    "traversal",
    "deserial",
    "escape",
    "bypass",
    "auth",
    "crash",
    "leak",
    "uaf",
    "use-after-free",
    "double free",
    "double-free",
    "race",
    "tocttou",
    "oob",
    "out-of-bounds",
    "out of bounds",
    "memory corrupt",
    "null deref",
    "null pointer",
    "buffer ",
    "format string",
    "denial of service",
    "dos",
    "sanitiz",
    "validate",
    "validation",
    "fix",
)

_COMMIT_EXCLUDE = (
    "refactor",
    "rename",
    "cleanup",
    "clean up",
    "lint",
    "format",
    "formatting",
    "typo",
    "whitespace",
    "comment",
    "docs only",
    "doc only",
    "doc:",
    "docs:",
    "test only",
    "tests only",
    "wip",
    "merge branch",
    "merge pull",
    "version bump",
    "bump version",
    "release ",
)


def _should_skip_commit(msg: str | None) -> bool:
    """Drop pairs whose commit message looks like cleanup, not a fix.

    Returns True if the message lacks any security-ish keyword OR is
    dominated by refactor/cleanup language. A None/empty message is kept
    (we have no signal to reject on)."""
    if not msg:
        return False
    low = msg.lower()
    if any(kw in low for kw in _COMMIT_EXCLUDE):
        return True
    return not any(kw in low for kw in _COMMIT_INCLUDE)


_NOISE_RE = (
    # whitespace-only / blank lines
    "^\\s*$",
    # one-line block & line comments — covers C/C++/Java/JS/TS/Go/Rust/Ruby
    "^\\s*//",
    "^\\s*/\\*",
    "^\\s*\\*",
    "^\\s*#",
    "^\\s*--",
)


_TRIVIAL_INIT_RE = (
    # `<lhs> = 0/0L/0u/0.0/'\0'/NULL/nullptr/None/nil/null/true/false;`
    # — covers C/C++/Java/JS/TS/Go/Rust/Python/Ruby. Constant scalar
    # initialisations carry no security signal but get pulled into diff
    # hunks (e.g. a counter reset alongside the actual fix).
    r"^\s*[\w\.\[\]\->]+\s*=\s*"
    r"(?:0[uUlL]*|0\.0[fFdD]?|0x0+|'\\0'|NULL|nullptr|None|nil|null|true|false)\s*;?\s*$",
    # `<type> <name> = 0/NULL/...;` — declaration with constant init.
    r"^\s*(?:unsigned|signed|static|const|extern|register|auto|volatile|mut|let|var|val)?\s*"
    r"(?:int|char|long|short|float|double|bool|size_t|ssize_t|u?int\d*_t|byte|word|"
    r"void\s*\*|[A-Z]\w*\s*\*?)\s+[\w\[\]]+\s*=\s*"
    r"(?:0[uUlL]*|0\.0[fFdD]?|0x0+|'\\0'|NULL|nullptr|None|nil|null|true|false)\s*;?\s*$",
)


# Pure jumps and constant-only returns. These appear in diff hunks all the
# time (re-ordered error paths, renamed variables, status-flag plumbing)
# but the security signal lives in the call/assignment that produces the
# value, not in the jump statement itself. Returns that *contain* a
# function call (parentheses) or operator/string literal are kept — those
# may be the sink site itself (e.g. `return execute(req)`).
_TRIVIAL_FLOW_RE = (
    # bare jumps — C/C++/Java/JS/TS/Go/Rust (`break;`, `continue;`)
    r"^\s*(?:break|continue|pass)\s*;?\s*$",
    # labelled jumps — `goto out;` / `goto err_unlock;` (C/C++)
    r"^\s*goto\s+\w+\s*;?\s*$",
    # bare return — `return;` / `return` (Python/Ruby/Rust)
    r"^\s*return\s*;?\s*$",
    # return with simple identifier(s) / dotted or arrow access / index
    # — no call (no parens), no operator beyond `->` / `.`, no string.
    # Covers `return x;`, `return self.err`, `return ptr->next;`,
    # `return res, nil` (Go multi-return), `return -1;`.
    r"^\s*return\s+-?[\w\.\[\]>\-]+(?:\s*,\s*-?[\w\.\[\]>\-]+)*\s*;?\s*$",
)


def _is_noise(line_text: str) -> bool:
    """True for diff lines that almost certainly carry no security signal:
    blank lines, comment-only lines, brace-only lines, trivial constant
    initialisations (`x = 0;`, `unsigned int n = 0;`), and pure control
    flow (`break;`, `goto out;`, `return res;`)."""
    import re as _re

    text = line_text or ""
    if any(_re.match(p, text) for p in _NOISE_RE):
        return True
    stripped = text.strip()
    if stripped in {"", "{", "}", "};", "});", "})", "(", ")", "[]", "[", "]"}:
        return True
    if any(_re.match(p, text) for p in _TRIVIAL_INIT_RE):
        return True
    return any(_re.match(p, text) for p in _TRIVIAL_FLOW_RE)


def _to_method_ranges(
    diff_lines: list,
    method_start: int,
    method_end: int,
    gap: int,
    drop_noise: bool,
) -> list[tuple[int, int]]:
    """Project file-relative diff line numbers onto method-relative
    coordinates and cluster into ranges. Lines outside the method are
    dropped. When `drop_noise` is set, blank/comment/brace-only lines are
    skipped before clustering so trivial whitespace patches don't generate
    findings."""
    nums: list[int] = []
    for entry in diff_lines:
        if not isinstance(entry, (list, tuple)) or not entry:
            continue
        try:
            ln = int(entry[0])
        except (TypeError, ValueError):
            continue
        if not (method_start <= ln <= method_end):
            continue
        if drop_noise and len(entry) > 1 and _is_noise(str(entry[1])):
            continue
        nums.append(ln - method_start + 1)
    return _cluster(nums, gap=gap)


def _expand(rng: tuple[int, int], total_lines: int, padding: int) -> tuple[int, int]:
    lo, hi = rng
    return max(1, lo - padding), min(total_lines, hi + padding)


def _window_extract(
    code: str, ranges: list[tuple[int, int]], window: int
) -> tuple[str, list[tuple[int, int]]]:
    """Slice `code` down to the union of (range ± window) and return the
    sliced text plus ranges remapped onto its 1-indexed line numbers.
    Adjacent or overlapping windows are merged."""
    if not ranges or window <= 0:
        return code, ranges
    lines = code.splitlines()
    total = len(lines)
    # Build merged windows on the original coords.
    raw = sorted((max(1, lo - window), min(total, hi + window)) for lo, hi in ranges)
    merged: list[tuple[int, int]] = []
    for lo, hi in raw:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))

    # Concatenate the windowed slices, joined by a 2-line gutter so the
    # encoder sees that they're separate regions. Track new line offsets.
    out_lines: list[str] = []
    remap: list[tuple[int, int, int]] = []  # (orig_lo, orig_hi, new_offset)
    for lo, hi in merged:
        if out_lines:
            out_lines.append("")
            out_lines.append("// ────────────")
        new_offset = len(out_lines) + 1  # 1-indexed line number for `lo`
        remap.append((lo, hi, new_offset - lo))
        out_lines.extend(lines[lo - 1 : hi])

    new_ranges: list[tuple[int, int]] = []
    for orig_lo, orig_hi in ranges:
        # Find which merged window contains this range, apply its shift.
        for win_lo, win_hi, shift in remap:
            if orig_lo >= win_lo and orig_hi <= win_hi:
                new_ranges.append((orig_lo + shift, orig_hi + shift))
                break
    return "\n".join(out_lines), new_ranges


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
    ap.add_argument(
        "--window",
        type=int,
        default=0,
        help="when > 0, replace `code` with just (changed-lines ± window). "
        "Tightens the focus of the embedding so it isn't dominated by "
        "shared context lines that don't differ between TP and FP.",
    )
    ap.add_argument(
        "--drop-noise",
        action="store_true",
        help="skip diff lines that are blank, comment-only, or pure brace "
        "tokens — they carry no security signal and pollute the dataset.",
    )
    ap.add_argument(
        "--max-ranges",
        type=int,
        default=3,
        help="drop the entire pair if either side has more than N ranges. "
        "Large per-side range counts almost always indicate a sweeping "
        "refactor/cleanup commit rather than a focused security fix and "
        "produce noisy labels.",
    )
    ap.add_argument(
        "--cross-cve-fp-ratio",
        type=float,
        default=0.0,
        help="emit additional FP samples by pairing each TP with a random "
        "patched method from a *different* CVE. Helps the model avoid "
        "overfitting to within-pair fix patterns. 0.0 disables, 1.0 "
        "doubles the FP volume.",
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
    # Larger page cache + memory-resident temp tables make the per-CVE
    # GROUP BY land entirely in RAM on the v1.0.8 (48 GB) dump. Default
    # cache is 2 MB, which thrashes badly here.
    conn.execute("PRAGMA cache_size = -524288")  # 512 MiB
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA mmap_size  = 1073741824")  # 1 GiB
    lang_sql = ",".join(f"'{lang}'" for lang in args.langs)
    cve_list_sql = CVE_LIST_SQL.format(langs=lang_sql)
    cve_batch_sql = CVE_BATCH_SQL.format(langs=lang_sql)

    seen: set[str] = set()
    counters = {
        "tp": 0,
        "fp": 0,
        "dedup": 0,
        "no_range": 0,
        "lang": 0,
        "parse": 0,
        "filename": 0,
        "commit_msg": 0,
        "max_ranges": 0,
    }
    pairs_seen = 0
    # Cross-CVE FP pool — every patched method we've seen, keyed by CVE so
    # we can sample one whose CVE differs from the current TP.
    import random as _random

    rng_pool = _random.Random(20260426)
    cross_pool: list[tuple[str, str, str, list[tuple[int, int]]]] = []
    # tuples: (cve, lang_tag, patched_code, fp_ranges_method_relative)

    with args.out.open("w", encoding="utf-8") as fh:
        # Outer scan — enumerate every (cve_id, commit_msg) tuple. This is
        # cheap (one row per CVE, ~12k in v1.0.8) and lets us reject
        # refactor-only CVEs before the heavier inner JOIN runs.
        cve_rows = conn.execute(cve_list_sql).fetchall()
        print(
            f"Found {len(cve_rows)} CVEs with at least one in-language fix.",
            file=sys.stderr,
            flush=True,
        )
        rows_iter: list[tuple] = []

        def _yield_rows():
            for cve_id, commit_msg in cve_rows:
                if cve_id is None:
                    continue
                if _should_skip_commit(commit_msg):
                    counters["commit_msg"] += 1
                    continue
                # Per-CVE inner query — bounded result set.
                cur = conn.execute(
                    cve_batch_sql,
                    (cve_id, args.min_len, args.max_len, args.min_len, args.max_len),
                )
                for row in cur:
                    yield row

        rows_iter = _yield_rows()  # type: ignore[assignment]

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
            commit_msg,
        ) in rows_iter:
            lang_tag = _LANG_MAP.get(lang)
            if not lang_tag:
                counters["lang"] += 1
                continue

            if _should_skip_file(filename):
                counters["filename"] += 1
                continue

            # commit-msg filter already ran in the outer CVE scan;
            # commit_msg is kept in the row tuple only for parity with
            # earlier signatures. No re-check needed here.
            del commit_msg

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

            tp_ranges = _to_method_ranges(
                parsed.get("deleted") or [], vs, ve, args.gap, args.drop_noise
            )
            fp_ranges = _to_method_ranges(
                parsed.get("added") or [], ps, pe, args.gap, args.drop_noise
            )

            if not tp_ranges and not fp_ranges:
                counters["no_range"] += 1
                continue

            # Sweeping commits with many disjoint hunks per side rarely
            # represent a single focused vulnerability — drop the whole
            # pair so we don't pollute the labelled set with structural
            # noise from refactors.
            if args.max_ranges > 0 and (
                len(tp_ranges) > args.max_ranges or len(fp_ranges) > args.max_ranges
            ):
                counters["max_ranges"] += 1
                continue

            # Apply window extraction independently per side.
            tp_code_out, tp_ranges_out = _window_extract(
                vuln_code, tp_ranges, args.window
            )
            fp_code_out, fp_ranges_out = _window_extract(
                patched_code, fp_ranges, args.window
            )

            if fp_ranges:
                cross_pool.append((cve or "", lang_tag, fp_code_out, fp_ranges_out))

            wrote_any = False
            if tp_ranges:
                wrote_any |= _emit(
                    fh,
                    tp_code_out,
                    "tp",
                    tp_ranges_out,
                    lang_tag,
                    cve,
                    cwe,
                    filename,
                    seen,
                    counters,
                    args.padding,
                )

                # Cross-CVE FP: pair this TP with a random patched method
                # from a different CVE so the model also learns "looks
                # like a fix from anywhere = not vulnerable", not just
                # "looks like the paired fix".
                if args.cross_cve_fp_ratio > 0 and cross_pool:
                    if rng_pool.random() < args.cross_cve_fp_ratio:
                        attempts = 0
                        while attempts < 5:
                            cand = rng_pool.choice(cross_pool)
                            if cand[0] != (cve or "") and cand[1] == lang_tag:
                                _emit(
                                    fh,
                                    cand[2],
                                    "fp",
                                    cand[3],
                                    lang_tag,
                                    f"{cve}::cross::{cand[0]}",
                                    None,
                                    filename,
                                    seen,
                                    counters,
                                    args.padding,
                                )
                                break
                            attempts += 1

            if fp_ranges:
                wrote_any |= _emit(
                    fh,
                    fp_code_out,
                    "fp",
                    fp_ranges_out,
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
        f"  skipped: {counters['filename']} (test/doc filename), "
        f"{counters['commit_msg']} (commit msg), "
        f"{counters['max_ranges']} (>max-ranges), "
        f"{counters['no_range']} (no in-range edits), "
        f"{counters['dedup']} (dup), {counters['lang']} (lang), "
        f"{counters['parse']} (parse)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
