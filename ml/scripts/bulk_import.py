#!/usr/bin/env python3
"""Bulk-import vulnerability samples into deus.

Loads a Hugging Face dataset, picks N vulnerable + M non-vulnerable
samples, and injects them directly as ground-truth labels via the
deus API — bypassing the scanner.

Every /api/knowledge POST uses `?skip_train=true`, and a single
`POST /api/retrain` is fired at the end to avoid 1000× retraining.

Usage
-----
1. Start deus (backend + ml) — the script talks to backend :7373
   docker compose up -d

2. Install script deps (in a local venv, NOT the ml container):
   pip install -r ml/scripts/requirements.txt

3. Run:
   python ml/scripts/bulk_import.py --count 1000 --ratio 0.5

Adapters
--------
Different datasets use different field names. Pass --adapter to pick one;
add a new adapter below when extending to other datasets.
"""

from __future__ import annotations

import argparse
import os
import random
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


# ── Dataset adapters ─────────────────────────────────────────────────────────
# Each adapter yields `Sample` objects from a loaded HF dataset split.
# When adding a new dataset, register a new adapter function and add it to
# ADAPTERS below.

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


def adapt_bigvul(rows: Iterable[dict]) -> Iterable[Sample]:
    """BigVul-style schemas. Expected fields:
      func_before: str | None   (vulnerable version, present when vul==1)
      func_after:  str | None   (patched version, present when vul==1)
      func:        str | None   (fallback — some mirrors use this name)
      vul:         int (0/1) | bool
      cwe_id:      str | None   (e.g. 'CWE-89' or list)
      cve_id:      str | None
    """
    for row in rows:
        vul = int(row.get("vul") or row.get("target") or 0)
        if vul == 1:
            code = row.get("func_before") or row.get("func") or ""
        else:
            # Non-vulnerable: use the patched version when available, else func
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
            language="c",  # BigVul is C/C++
            vulnerable=(vul == 1),
            cve_id=cve,
            cwe=cwe,
            severity=_cwe_to_severity(cwe) if vul == 1 else "low",
            message=(cwe or "vulnerable function") if vul == 1 else "non-vulnerable baseline",
        )


def adapt_devign(rows: Iterable[dict]) -> Iterable[Sample]:
    """Devign (CodeXGLUE Defect detection). Fields: func, target (0/1), project."""
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


ADAPTERS: dict[str, Callable[[Iterable[dict]], Iterable[Sample]]] = {
    "bigvul": adapt_bigvul,
    "devign": adapt_devign,
}


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
        timeout=60.0,
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


# ── Main ────────────────────────────────────────────────────────────────────

def pick_samples(
    ds, adapter: Callable, tp_target: int, fp_target: int, max_lines: int, seed: int
) -> tuple[list[Sample], list[Sample]]:
    """Stream through the dataset once, collecting TP and FP samples."""
    rng = random.Random(seed)
    tps: list[Sample] = []
    fps: list[Sample] = []
    # Shuffle indices for pseudo-random sampling without loading everything
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--count", type=int, default=1000)
    ap.add_argument("--ratio", type=float, default=0.5, help="fraction of TP samples (0..1)")
    ap.add_argument("--dataset", default="bstee615/bigvul",
                    help="HF dataset id (e.g. bstee615/bigvul, google/code_x_glue_cc_defect_detection)")
    ap.add_argument("--split", default="train")
    ap.add_argument("--adapter", choices=list(ADAPTERS), default="bigvul")
    ap.add_argument("--api", default=API)
    ap.add_argument("--max-lines", type=int, default=200, help="skip functions longer than this")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--dry-run", action="store_true", help="pick samples but don't POST")
    args = ap.parse_args()

    global API
    API = args.api

    tp_target = int(round(args.count * args.ratio))
    fp_target = args.count - tp_target
    print(f"Target: {tp_target} TP + {fp_target} FP = {args.count}")
    print(f"Dataset: {args.dataset} (split={args.split}, adapter={args.adapter})")

    try:
        from datasets import load_dataset
    except ImportError:
        print("Missing dependency: pip install datasets httpx tqdm", file=sys.stderr)
        return 2

    print(f"Loading {args.dataset}…")
    try:
        ds = load_dataset(args.dataset, split=args.split)
    except Exception as e:
        print(f"Failed to load dataset: {e}", file=sys.stderr)
        print("Tip: --dataset google/code_x_glue_cc_defect_detection --adapter devign "
              "is a widely-mirrored alternative.", file=sys.stderr)
        return 2

    adapter = ADAPTERS[args.adapter]
    print(f"Dataset loaded: {len(ds)} rows. Sampling…")
    tps, fps = pick_samples(ds, adapter, tp_target, fp_target, args.max_lines, args.seed)
    print(f"Selected: {len(tps)} TP + {len(fps)} FP")

    if args.dry_run:
        print("Dry run — not posting.")
        return 0

    # Health check
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
        for i, (sample, label) in enumerate(
            tqdm([(s, "tp") for s in tps] + [(s, "fp") for s in fps],
                 desc="Importing", unit="sample")
        ):
            req_id = f"bulk-{batch_id}-{i:04d}"
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
