#!/usr/bin/env python3
"""Bulk-import CVEfixes-style training cases into makina.

Each input record is one method (vulnerable side OR patched side) with
method-relative ranges and a TP/FP label. We turn each range into a
manual finding pinned to that range, queue all findings under one
verify case, and submit them with the per-record label — matching
exactly what a real Verify Submit looks like, including per-finding
embeddings.

Why ranges and not the whole method:

The earlier "label the whole code TP/FP" shortcut trained the GBDT on
whole-method embeddings, which drifted from the per-finding
distribution the model sees at inference time. Pinning each finding to
the actual edited lines (with the full method as context) closes that
gap while staying offline — we don't depend on the live scanner
producing the right hits, which is the point of bulk seeding.

Why FP samples come from `code_after`:

Re-using `code_before` as both TP and FP would collapse the
supervision signal and overfit the model to incidental context lines
that didn't change. Using the patched method instead gives a hard,
semantically-meaningful counterexample for every CVE — the function
identity and surrounding code stay similar, but the dangerous region
has been rewritten.

Input schema (JSONL, one object per line):

    {"code":     str,                 # full method body
     "language": str,                 # python|c|cpp|...
     "label":    "tp" | "fp",
     "cve_id":   str|None,
     "cwe":      str|None,
     "severity": "critical"|"high"|"medium"|"low",
     "filename": str|None,
     "ranges": [
        {"line_start": int, "line_end": int},   # method-relative, 1-indexed
        ...
     ]}

Produced by `ml/scripts/converters/cvefixes.py`.

Every /api/knowledge POST uses `?skip_train=true`, and a single
`POST /api/retrain` is fired at the end to avoid N× retraining.

Usage
-----
1. Start makina (backend + ml):
     docker compose up -d

2. Install script deps (in a local venv, NOT the ml container):
     pip install -r ml/scripts/requirements.txt

3. Convert CVEfixes once:
     python ml/scripts/converters/cvefixes.py

4. Import:
     python ml/scripts/bulk_import.py \\
       --jsonl third_party/datasets/cvefixes/samples.jsonl \\
       --count 100
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Iterable

import httpx

API = os.environ.get("MAKINA_API", "http://localhost:7373")


# ── Severity helpers (re-exported for the converter) ────────────────────────


def _cwe_to_severity(cwe: str | None) -> str:
    if not cwe:
        return "medium"
    high = {
        "CWE-78",
        "CWE-77",
        "CWE-89",
        "CWE-94",
        "CWE-502",
        "CWE-120",
        "CWE-787",
        "CWE-416",
    }
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


# ── Sample dataclass ────────────────────────────────────────────────────────


@dataclass
class CaseSample:
    code: str
    language: str
    label: str  # "tp" | "fp" — applied to every finding in this case
    ranges: list[dict]  # [{"line_start": int, "line_end": int}, ...]
    cve_id: str | None
    cwe: str | None
    severity: str
    filename: str | None = None


def load_jsonl(path: str, count: int) -> list[CaseSample]:
    """Read up to `count` samples (0 = all). Skips records with no ranges
    or with an unrecognised label."""
    out: list[CaseSample] = []
    with open(path, encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"  ! line {line_no}: bad json ({e})", file=sys.stderr)
                continue
            ranges = obj.get("ranges") or []
            if not ranges:
                continue
            label = (obj.get("label") or "tp").lower()
            if label not in ("tp", "fp"):
                print(
                    f"  ! line {line_no}: unknown label {obj.get('label')!r}, skipped",
                    file=sys.stderr,
                )
                continue
            out.append(
                CaseSample(
                    code=obj["code"],
                    language=obj["language"],
                    label=label,
                    ranges=ranges,
                    cve_id=obj.get("cve_id"),
                    cwe=obj.get("cwe"),
                    severity=obj.get("severity") or _cwe_to_severity(obj.get("cwe")),
                    filename=obj.get("filename"),
                )
            )
            if count and len(out) >= count:
                break
    return out


# ── API client ──────────────────────────────────────────────────────────────


def post_manual_finding(
    client: httpx.Client, sample: CaseSample, rng: dict, req_id: str
) -> dict:
    if sample.label == "tp":
        message = sample.cwe or "vulnerable region (CVEfixes)"
    else:
        message = (
            f"patched region for {sample.cwe} (CVEfixes)"
            if sample.cwe
            else "patched region (CVEfixes)"
        )
    r = client.post(
        f"{API}/api/findings/manual",
        headers={"x-request-id": req_id},
        json={
            "code": sample.code,
            "language": sample.language,
            "line_start": int(rng["line_start"]),
            "line_end": int(rng["line_end"]),
            "severity": sample.severity,
            "cwe": sample.cwe,
            "message": message,
        },
        timeout=120.0,
    )
    r.raise_for_status()
    return r.json()


def post_queue(
    client: httpx.Client, sample: CaseSample, findings: list[dict], req_id: str
) -> int:
    r = client.post(
        f"{API}/api/verify/queue",
        headers={"x-request-id": req_id},
        json={
            "cve_id": sample.cve_id,
            "code": sample.code,
            "language": sample.language,
            "findings": findings,
        },
        timeout=60.0,
    )
    r.raise_for_status()
    return r.json()["case_no"]


def post_knowledge(
    client: httpx.Client, case_no: int, labels: dict[str, str], req_id: str
) -> None:
    r = client.post(
        f"{API}/api/knowledge?skip_train=true",
        headers={"x-request-id": req_id},
        json={"case_no": case_no, "labels": labels},
        timeout=60.0,
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


def import_case(
    client: httpx.Client, sample: CaseSample, batch_id: str, idx: int
) -> int:
    """Returns the number of findings imported (0 on hard failure)."""
    findings: list[dict] = []
    for j, rng in enumerate(sample.ranges):
        req_id = f"bulk-{batch_id}-{idx:05d}-r{j}"
        findings.append(post_manual_finding(client, sample, rng, req_id))

    case_req_id = f"bulk-{batch_id}-{idx:05d}-case"
    case_no = post_queue(client, sample, findings, case_req_id)
    post_knowledge(
        client,
        case_no,
        {f["id"]: sample.label for f in findings},
        case_req_id,
    )
    return len(findings)


# ── Main ────────────────────────────────────────────────────────────────────


def main() -> int:
    global API  # noqa: PLW0603

    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--jsonl",
        required=True,
        help="path to samples.jsonl (produced by converters/cvefixes.py)",
    )
    ap.add_argument(
        "--count",
        type=int,
        default=0,
        help="number of cases to import (0 = all available)",
    )
    ap.add_argument("--api", default=API)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument(
        "--dry-run", action="store_true", help="load samples but don't POST"
    )
    args = ap.parse_args()
    API = args.api

    if not os.path.exists(args.jsonl):
        print(f"--jsonl not found: {args.jsonl}", file=sys.stderr)
        return 2

    print(f"Loading samples from {args.jsonl}…")
    samples = load_jsonl(args.jsonl, args.count)
    print(f"Loaded {len(samples)} cases")

    lang_counts: dict[str, int] = {}
    label_counts: dict[str, int] = {"tp": 0, "fp": 0}
    range_counts = 0
    for s in samples:
        lang_counts[s.language] = lang_counts.get(s.language, 0) + 1
        label_counts[s.label] = label_counts.get(s.label, 0) + 1
        range_counts += len(s.ranges)
    if lang_counts:
        print(
            "Language mix: "
            + ", ".join(f"{k}={v}" for k, v in sorted(lang_counts.items()))
        )
    print(f"Label mix: {label_counts['tp']} TP / {label_counts['fp']} FP")
    if samples:
        print(
            f"Total findings to import: {range_counts} "
            f"(avg {range_counts / len(samples):.1f} per case)"
        )

    if args.dry_run:
        print("Dry run — not posting.")
        return 0

    if not samples:
        print("Nothing to import.", file=sys.stderr)
        return 1

    with httpx.Client() as client:
        try:
            client.get(f"{API}/api/stats", timeout=5.0).raise_for_status()
        except Exception as e:
            print(f"Backend not reachable at {API}: {e}", file=sys.stderr)
            return 2

    try:
        from tqdm import tqdm
    except ImportError:

        def tqdm(it: Iterable, **_kw):
            return it

    # Shuffle so partial completion stays representative under interrupt.
    random.Random(args.seed).shuffle(samples)

    batch_id = uuid.uuid4().hex[:8]
    print(f"Batch id: {batch_id}")

    ok_cases = 0
    tp_findings = 0
    fp_findings = 0
    failed = 0
    t0 = time.perf_counter()

    with httpx.Client() as client:
        for i, sample in enumerate(tqdm(samples, desc="Importing", unit="case")):
            try:
                n = import_case(client, sample, batch_id, i)
                ok_cases += 1
                if sample.label == "tp":
                    tp_findings += n
                else:
                    fp_findings += n
            except Exception as e:
                failed += 1
                print(f"  ! case {i} failed: {e}", file=sys.stderr)

    elapsed = time.perf_counter() - t0
    print(
        f"\nImported: {ok_cases} cases "
        f"({tp_findings} TP + {fp_findings} FP findings, "
        f"{failed} failed) in {elapsed:.1f}s"
    )

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
