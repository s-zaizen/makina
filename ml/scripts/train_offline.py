#!/usr/bin/env python3
"""Offline GBDT trainer — bypass the HTTP API entirely.

`bulk_import.py` is the canonical seeding path because it exercises the
exact same Verify-Submit codepath as a human reviewer. That makes it
correct for development but **slow** for prod model bake: each finding
hits `/embed_with_graph` over loopback HTTP, then SQLite writes, then
finally `POST /api/retrain` runs the GBDT. On the v1.0.8 corpus
(~14 k samples) the round-trip overhead alone dominates and the whole
loop takes 5–15 hours on CPU.

This script does the same job in-process:

    samples.jsonl
        ↓ expand each range to one (code, line_start) tuple
        ↓ build call-graph augmented context (1-hop callees)
        ↓ embedder.embed_batch(snippets, batch_size=BATCH)
        ↓ in-memory (X, y, groups) arrays
        ↓ services.training.train_from_arrays(...)
    model.json + metrics.json

Skipping HTTP and SQLite drops per-finding overhead from ~25 ms to
near zero. Batched CodeBERT inference cuts forward-pass cost by ~10×
on CPU, ~100× on GPU. End-to-end: 5–15 h → 20–45 min on CPU,
5–10 min on GPU (T4/L4).

Usage
-----
    python -m makina_ml.scripts.train_offline \\
        --jsonl third_party/datasets/cvefixes/samples.jsonl \\
        --model-path /tmp/model.json \\
        --metrics-path /tmp/metrics.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import numpy as np

# Allow running from a clone without `pip install -e ml`.
_REPO_ML = Path(__file__).resolve().parents[1]
if str(_REPO_ML) not in sys.path:
    sys.path.insert(0, str(_REPO_ML))

from makina_ml import embedder  # noqa: E402
from makina_ml.services import training  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("train_offline")


# ── Snippet construction (mirror /embed_with_graph) ─────────────────────────


# Hard ceiling on the snippet we hand to the tokenizer. CodeBERT
# truncates to 512 tokens (~ 2-4 KB of source) anyway, so 8 KB is
# plenty of slack and protects us from the occasional CVEfixes method
# with many large 1-hop callees that would otherwise blow the
# tokenizer's working buffers (we hit OOM on a Docker host at
# ~12.8 k findings without this cap).
_MAX_SNIPPET_CHARS = 8000


def _build_context_snippet(code: str, language: str, line_start: int) -> str:
    """Produce the same call-graph-augmented snippet that
    `/embed_with_graph` builds at runtime — keeps the offline-trained
    model's embedding distribution aligned with the live scanner's."""
    try:
        from makina_ml.call_graph import build_augmented_context, extract_functions
    except Exception:
        # tree-sitter unavailable — fall back to ±4 lines around the
        # focus line so the offline trainer still runs in thin envs.
        lines = code.splitlines()
        ctx_s = max(0, line_start - 4)
        ctx_e = min(len(lines), line_start + 3)
        snippet = "\n".join(lines[ctx_s:ctx_e])
        return snippet[:_MAX_SNIPPET_CHARS]

    functions = extract_functions(code, language)
    if functions:
        snippet = build_augmented_context(
            functions, code, line_start, line_start, max_depth=1
        )
    else:
        lines = code.splitlines()
        ctx_s = max(0, line_start - 4)
        ctx_e = min(len(lines), line_start + 3)
        snippet = "\n".join(lines[ctx_s:ctx_e])
    return snippet[:_MAX_SNIPPET_CHARS]


# ── Sample expansion ────────────────────────────────────────────────────────


def _flatten_samples(jsonl_path: Path):
    """Yield `(code, language, line_start, label, cve_id)` per range —
    one tuple per finding the live scanner would have produced."""
    with jsonl_path.open(encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                logger.warning("line %d: bad json (%s)", line_no, e)
                continue
            ranges = obj.get("ranges") or []
            label = (obj.get("label") or "tp").lower()
            if label not in ("tp", "fp"):
                continue
            code = obj.get("code")
            language = obj.get("language")
            cve_id = obj.get("cve_id")
            if not code or not language:
                continue
            for rng in ranges:
                try:
                    line_start = int(rng["line_start"])
                except (TypeError, KeyError, ValueError):
                    continue
                yield code, language, line_start, label, cve_id


# ── Main ────────────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--jsonl",
        type=Path,
        required=True,
        help="path to samples.jsonl produced by converters/cvefixes.py",
    )
    ap.add_argument(
        "--model-path",
        type=Path,
        default=Path("model.json"),
        help="output path for the trained xgboost model (default: ./model.json)",
    )
    ap.add_argument(
        "--metrics-path",
        type=Path,
        default=Path("metrics.json"),
        help="output path for the metrics JSON (default: ./metrics.json)",
    )
    ap.add_argument(
        "--batch-size",
        type=int,
        default=32,
        help="CodeBERT inference batch size (default: 32). Larger = faster "
        "throughput, higher peak memory.",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=0,
        help="cap on the number of findings to embed (0 = all). Useful for smoke runs.",
    )
    args = ap.parse_args()

    if not args.jsonl.exists():
        print(f"--jsonl not found: {args.jsonl}", file=sys.stderr)
        return 2

    # ── 1. Flatten samples → list of findings ───────────────────────────
    findings = list(_flatten_samples(args.jsonl))
    if args.limit and len(findings) > args.limit:
        findings = findings[: args.limit]
    if not findings:
        print("no usable findings in jsonl", file=sys.stderr)
        return 1
    logger.info("flattened %d findings from %s", len(findings), args.jsonl)

    # ── 2. Build call-graph snippets ────────────────────────────────────
    t0 = time.perf_counter()
    snippets: list[str] = []
    labels: list[str] = []
    groups: list[str | None] = []
    for code, language, line_start, label, cve_id in findings:
        snippets.append(_build_context_snippet(code, language, line_start))
        labels.append(label)
        groups.append(cve_id)
    logger.info(
        "built %d snippets in %.1fs",
        len(snippets),
        time.perf_counter() - t0,
    )

    # ── 3. Batch-embed via local CodeBERT ───────────────────────────────
    embedder.ensure_loaded()
    if not embedder.is_ready():
        # ensure_loaded() may run async — block until ready.
        for _ in range(120):
            if embedder.is_ready():
                break
            time.sleep(1)
        else:
            print("CodeBERT failed to load within 120 s", file=sys.stderr)
            return 3

    t0 = time.perf_counter()
    batch = args.batch_size
    chunks: list[np.ndarray] = []
    keep_indices: list[int] = []
    for i in range(0, len(snippets), batch):
        sub = snippets[i : i + batch]
        try:
            embs = embedder.embed_batch(sub)
        except Exception as e:
            # Single bad batch shouldn't kill the whole run — log and
            # skip the offending slice. Most often this is a memory
            # spike on a pathological tokeniser input.
            logger.warning(
                "batch %d-%d failed (%s) — skipping",
                i,
                i + batch,
                e,
            )
            continue
        if embs is None:
            logger.warning("embed_batch returned None at index %d — skipping", i)
            continue
        chunks.append(np.asarray(embs, dtype=np.float32))
        keep_indices.extend(range(i, i + len(embs)))
        if (i // batch) % 50 == 0:
            done = min(i + batch, len(snippets))
            elapsed = time.perf_counter() - t0
            rate = done / elapsed if elapsed > 0 else 0
            remaining = (len(snippets) - done) / rate if rate else 0
            logger.info(
                "embedded %d / %d (%.1f /s, ~%.1f min remaining)",
                done,
                len(snippets),
                rate,
                remaining / 60,
            )
    if not chunks:
        print("no batches succeeded", file=sys.stderr)
        return 4
    embeddings = np.vstack(chunks)
    # Align labels / groups with the rows that actually made it through.
    kept_labels = [labels[k] for k in keep_indices]
    kept_groups = [groups[k] for k in keep_indices]
    skipped = len(snippets) - len(keep_indices)
    logger.info(
        "embedded %d snippets in %.1fs (%.1f /s, %d skipped)",
        len(keep_indices),
        time.perf_counter() - t0,
        len(keep_indices) / max(1e-3, time.perf_counter() - t0),
        skipped,
    )

    # ── 4. Train + persist ──────────────────────────────────────────────
    result = training.train_from_arrays(
        embeddings, kept_labels, kept_groups, args.model_path, args.metrics_path
    )
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
