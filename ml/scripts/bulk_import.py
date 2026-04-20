#!/usr/bin/env python3
"""Bulk-import vulnerability samples into deus.

Picks N vulnerable + M non-vulnerable samples from a dataset and injects
them directly as ground-truth labels via the deus API — bypassing the
scanner.

Every /api/knowledge POST uses `?skip_train=true`, and a single
`POST /api/retrain` is fired at the end to avoid N× retraining.

Supported sources (pick one with --source):

  cvefixes   Official CVEfixes SQLite dump (multi-language, CVE+commit
             provenance). Download from Zenodo:
               v1.0.7 https://zenodo.org/records/7029359   (~3.9 GB zip)
               v1.0.8 https://zenodo.org/records/13118970  (~12 GB zip)
             Unzip to get `CVEfixes.db`, then pass --cvefixes-db PATH.
  hf         Hugging Face dataset via `datasets.load_dataset`.
             Use --hf-dataset <id> --hf-adapter <bigvul|devign>.

Usage
-----
1. Start deus (backend + ml):
     docker compose up -d

2. Install script deps (in a local venv, NOT the ml container):
     pip install -r ml/scripts/requirements.txt

3. Run:
     python ml/scripts/bulk_import.py \\
       --source cvefixes --cvefixes-db ~/data/CVEfixes.db \\
       --count 1000 --ratio 0.5
"""

from __future__ import annotations

import argparse
import os
import random
import sqlite3
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Iterable

import httpx

API = os.environ.get("DEUS_API", "http://localhost:7373")


@dataclass
class Sample:
    code: str
    language: str
    vulnerable: bool
    cve_id: str | None
    cwe: str | None
    severity: str  # 'critical' | 'high' | 'medium' | 'low'
    message: str


def _cwe_to_severity(cwe: str | None) -> str:
    if not cwe:
        return "medium"
    high = {"CWE-78", "CWE-77", "CWE-89", "CWE-94", "CWE-502", "CWE-120", "CWE-787", "CWE-416"}
    mid = {"CWE-22", "CWE-79", "CWE-352", "CWE-918", "CWE-400", "CWE-611"}
    if cwe in high:
        return "high"
    if cwe in mid:
        return "medium"
    return "low"


_LANG_MAP = {
    "Python": "python",
    "JavaScript": "javascript",
    "TypeScript": "typescript",
    "Java": "java",
    "Go": "go",
    "Ruby": "ruby",
    "C": "c",
    "C++": "cpp",
    "Rust": "rust",
}
SUPPORTED_LANGS = set(_LANG_MAP)


# ── Hugging Face adapters ───────────────────────────────────────────────────

def adapt_bigvul(rows: Iterable[dict]) -> Iterable[Sample]:
    for row in rows:
        vul = int(row.get("vul") or row.get("target") or 0)
        if vul == 1:
            code = row.get("func_before") or row.get("func") or ""
        else:
            code = row.get("func_after") or row.get("func") or row.get("func_before") or ""
        if not code or not code.strip():
            continue
        cwe = row.get("cwe_id") or row.get("cwe") or None
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None
        cve = row.get("cve_id") or row.get("cve") or None
        if isinstance(cve, list):
            cve = cve[0] if cve else None
        yield Sample(
            code=code,
            language="c",
            vulnerable=(vul == 1),
            cve_id=cve,
            cwe=cwe,
            severity=_cwe_to_severity(cwe) if vul == 1 else "low",
            message=(cwe or "vulnerable function") if vul == 1 else "non-vulnerable baseline",
        )


def adapt_devign(rows: Iterable[dict]) -> Iterable[Sample]:
    for row in rows:
        code = row.get("func") or ""
        target = int(row.get("target") or 0)
        if not code.strip():
            continue
        yield Sample(
            code=code,
            language="c",
            vulnerable=(target == 1),
            cve_id=None,
            cwe=None,
            severity="medium" if target == 1 else "low",
            message="vulnerable function (devign)" if target == 1 else "non-vulnerable baseline",
        )


HF_ADAPTERS: dict[str, Callable[[Iterable[dict]], Iterable[Sample]]] = {
    "bigvul": adapt_bigvul,
    "devign": adapt_devign,
}


# ── CVEfixes SQLite loader ──────────────────────────────────────────────────

def _cvefixes_query(conn: sqlite3.Connection) -> str:
    """Return a query that works for the columns present in this DB."""
    mc_cols = {row[1] for row in conn.execute("PRAGMA table_info(method_change)")}
    # v1.0.7 / v1.0.8: mc.code + mc.before_change ('True'/'False'), one row per version.
    if "code" in mc_cols and "before_change" in mc_cols:
        return """
            SELECT vuln.code                        AS code_before,
                   patched.code                     AS code_after,
                   fc.programming_language          AS lang,
                   cwec.cwe_id                      AS cwe,
                   fx.cve_id                        AS cve
            FROM method_change vuln
            JOIN method_change patched
                 ON patched.name = vuln.name
                AND patched.signature = vuln.signature
                AND patched.file_change_id = vuln.file_change_id
                AND patched.before_change = 'False'
            JOIN file_change fc ON vuln.file_change_id = fc.file_change_id
            JOIN fixes fx      ON fc.hash = fx.hash
            LEFT JOIN cwe_classification cwec ON fx.cve_id = cwec.cve_id
            WHERE vuln.before_change = 'True'
              AND vuln.code    IS NOT NULL
              AND patched.code IS NOT NULL
              AND LENGTH(vuln.code) BETWEEN 100 AND 8000
              AND fc.programming_language IN ({langs})
            GROUP BY vuln.method_change_id
            ORDER BY RANDOM()
            LIMIT ?
        """
    # Older dumps with paired columns on the same row.
    return """
        SELECT mc.code_before, mc.code_after, fc.programming_language, cwec.cwe_id, fx.cve_id
        FROM method_change mc
        JOIN file_change fc ON mc.file_change_id = fc.file_change_id
        JOIN fixes fx       ON fc.hash = fx.hash
        LEFT JOIN cwe_classification cwec ON fx.cve_id = cwec.cve_id
        WHERE mc.code_before IS NOT NULL AND mc.code_after IS NOT NULL
          AND LENGTH(mc.code_before) BETWEEN 100 AND 8000
          AND fc.programming_language IN ({langs})
        ORDER BY RANDOM()
        LIMIT ?
    """


def load_cvefixes(
    db_path: str, tp_target: int, fp_target: int, langs: list[str]
) -> tuple[list[Sample], list[Sample]]:
    conn = sqlite3.connect(db_path)
    lang_sql = ",".join(f"'{lang}'" for lang in langs)
    sql = _cvefixes_query(conn).format(langs=lang_sql)

    fetch_limit = max(tp_target, fp_target) * 3
    rows = conn.execute(sql, (fetch_limit,)).fetchall()
    conn.close()

    seen: set[str] = set()
    tps: list[Sample] = []
    fps: list[Sample] = []
    for code_before, code_after, lang, cwe, cve in rows:
        if len(tps) >= tp_target and len(fps) >= fp_target:
            break
        lang_tag = _LANG_MAP.get(lang)
        if not lang_tag:
            continue
        if len(tps) < tp_target and code_before and code_before.strip() and code_before not in seen:
            seen.add(code_before)
            tps.append(Sample(
                code=code_before,
                language=lang_tag,
                vulnerable=True,
                cve_id=cve,
                cwe=cwe,
                severity=_cwe_to_severity(cwe) if cwe else "medium",
                message=cwe or "vulnerable method (CVEfixes)",
            ))
        if len(fps) < fp_target and code_after and code_after.strip() and code_after not in seen:
            seen.add(code_after)
            fps.append(Sample(
                code=code_after,
                language=lang_tag,
                vulnerable=False,
                cve_id=cve,
                cwe=None,
                severity="low",
                message="patched version (CVEfixes)",
            ))
    return tps, fps


# ── API client ──────────────────────────────────────────────────────────────

def post_manual_finding(client: httpx.Client, s: Sample, req_id: str) -> dict:
    line_count = max(1, s.code.count("\n") + 1)
    r = client.post(
        f"{API}/api/findings/manual",
        headers={"x-request-id": req_id},
        json={
            "code": s.code,
            "language": s.language,
            "line_start": 1,
            "line_end": line_count,
            "severity": s.severity,
            "cwe": s.cwe,
            "message": s.message,
        },
        timeout=120.0,
    )
    r.raise_for_status()
    return r.json()


def post_queue(client: httpx.Client, s: Sample, finding: dict, req_id: str) -> int:
    r = client.post(
        f"{API}/api/verify/queue",
        headers={"x-request-id": req_id},
        json={
            "cve_id": s.cve_id,
            "code": s.code,
            "language": s.language,
            "findings": [finding],
        },
        timeout=30.0,
    )
    r.raise_for_status()
    return r.json()["case_no"]


def post_knowledge(client: httpx.Client, case_no: int, finding_id: str, label: str, req_id: str):
    r = client.post(
        f"{API}/api/knowledge?skip_train=true",
        headers={"x-request-id": req_id},
        json={"case_no": case_no, "labels": {finding_id: label}},
        timeout=30.0,
    )
    r.raise_for_status()


def post_retrain(client: httpx.Client, req_id: str) -> dict:
    r = client.post(
        f"{API}/api/retrain",
        headers={"x-request-id": req_id},
        json={},
        timeout=600.0,
    )
    r.raise_for_status()
    return r.json()


# ── Hugging Face sampling ───────────────────────────────────────────────────

def pick_samples_hf(
    ds, adapter: Callable, tp_target: int, fp_target: int, max_lines: int, seed: int
) -> tuple[list[Sample], list[Sample]]:
    rng = random.Random(seed)
    tps: list[Sample] = []
    fps: list[Sample] = []
    indices = list(range(len(ds)))
    rng.shuffle(indices)

    for idx in indices:
        if len(tps) >= tp_target and len(fps) >= fp_target:
            break
        try:
            row = ds[idx]
        except Exception:
            continue
        for s in adapter([row]):
            lines = s.code.count("\n") + 1
            if lines > max_lines or lines < 5:
                continue
            if s.vulnerable and len(tps) < tp_target:
                tps.append(s)
            elif not s.vulnerable and len(fps) < fp_target:
                fps.append(s)
    return tps, fps


# ── Main ────────────────────────────────────────────────────────────────────

def main() -> int:
    global API  # noqa: PLW0603

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", choices=["cvefixes", "hf"], required=True, help="data source")
    ap.add_argument("--count", type=int, default=1000)
    ap.add_argument("--ratio", type=float, default=0.5, help="fraction of TP samples (0..1)")
    ap.add_argument("--api", default=API)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--dry-run", action="store_true", help="pick samples but don't POST")

    ap.add_argument("--cvefixes-db", help="path to CVEfixes.db (for --source cvefixes)")
    ap.add_argument("--langs", default=",".join(sorted(SUPPORTED_LANGS)),
                    help="comma-separated programming_language values to include")

    ap.add_argument("--hf-dataset", help="HF dataset id, e.g. bstee615/bigvul")
    ap.add_argument("--hf-split", default="train")
    ap.add_argument("--hf-adapter", choices=list(HF_ADAPTERS), default="bigvul")
    ap.add_argument("--max-lines", type=int, default=200, help="HF only — skip functions longer than this")

    args = ap.parse_args()
    API = args.api

    tp_target = int(round(args.count * args.ratio))
    fp_target = args.count - tp_target
    print(f"Target: {tp_target} TP + {fp_target} FP = {args.count}")

    if args.source == "cvefixes":
        if not args.cvefixes_db or not os.path.exists(args.cvefixes_db):
            print("--cvefixes-db must point to an existing CVEfixes.db", file=sys.stderr)
            return 2
        langs = [lang for lang in args.langs.split(",") if lang]
        print(f"Loading CVEfixes from {args.cvefixes_db} (langs={langs})…")
        tps, fps = load_cvefixes(args.cvefixes_db, tp_target, fp_target, langs)
    else:
        if not args.hf_dataset:
            print("--hf-dataset required with --source hf", file=sys.stderr)
            return 2
        try:
            from datasets import load_dataset
        except ImportError:
            print("Missing dep: pip install datasets", file=sys.stderr)
            return 2
        print(f"Loading {args.hf_dataset}…")
        ds = load_dataset(args.hf_dataset, split=args.hf_split)
        adapter = HF_ADAPTERS[args.hf_adapter]
        tps, fps = pick_samples_hf(ds, adapter, tp_target, fp_target, args.max_lines, args.seed)

    print(f"Selected: {len(tps)} TP + {len(fps)} FP")

    lang_counts: dict[str, int] = {}
    for s in tps + fps:
        lang_counts[s.language] = lang_counts.get(s.language, 0) + 1
    if lang_counts:
        print("Language mix: " + ", ".join(f"{k}={v}" for k, v in sorted(lang_counts.items())))

    if args.dry_run:
        print("Dry run — not posting.")
        return 0

    with httpx.Client() as client:
        try:
            client.get(f"{API}/api/stats", timeout=5.0).raise_for_status()
        except Exception as e:
            print(f"Backend not reachable at {API}: {e}", file=sys.stderr)
            return 2

    try:
        from tqdm import tqdm
    except ImportError:
        def tqdm(x, **kw):
            return x

    batch_id = uuid.uuid4().hex[:8]
    print(f"Batch id: {batch_id}")

    ok_tp = ok_fp = 0
    fail = 0
    t0 = time.perf_counter()

    with httpx.Client() as client:
        items = [(s, "tp") for s in tps] + [(s, "fp") for s in fps]
        for i, (sample, label) in enumerate(tqdm(items, desc="Importing", unit="sample")):
            req_id = f"bulk-{batch_id}-{i:05d}"
            try:
                finding = post_manual_finding(client, sample, req_id)
                case_no = post_queue(client, sample, finding, req_id)
                post_knowledge(client, case_no, finding["id"], label, req_id)
                if label == "tp":
                    ok_tp += 1
                else:
                    ok_fp += 1
            except Exception as e:
                fail += 1
                print(f"  ! sample {i} ({label}) failed: {e}", file=sys.stderr)

    elapsed = time.perf_counter() - t0
    print(f"\nImported: {ok_tp} TP + {ok_fp} FP ({fail} failed) in {elapsed:.1f}s")

    print("Triggering retrain…")
    try:
        with httpx.Client() as client:
            result = post_retrain(client, f"bulk-{batch_id}-retrain")
            print(f"Retrain result: {result}")
    except Exception as e:
        print(f"Retrain failed: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
