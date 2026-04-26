#!/usr/bin/env python3
"""Run a battery of pair-feature ablations in one process.

Embeds every hunk once (the expensive step), then trains an XGBoost
classifier under several feature subsets to measure which blocks
actually carry signal. Reports a summary table.

Configurations evaluated:
  full          - all blocks (own_emb + delta + abs_delta + stats + cwe + lang)
  no-cwe        - drop CWE one-hot (test for CWE shortcut)
  no-lang       - drop language one-hot
  no-stats      - drop length/diff stats
  no-own-emb    - drop own_emb (only delta + meta)
  no-delta      - drop delta + abs_delta (only own_emb + meta)
  delta-only    - keep only delta + abs_delta
  own-emb-only  - keep only own_emb (matches single-hunk baseline)
  meta-only     - drop both emb blocks (test for trivial leakage via stats/cwe/lang)

Usage (inside the makina-ml container):
    docker compose exec -T ml python3 /ml/scripts/run_ablations.py \\
        --pairs /tmp/samples_pairs.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np

EMBED_DIM = 768
BATCH = 64


def _one_hot(idx_map: dict, key, dim: int) -> np.ndarray:
    v = np.zeros(dim, dtype=np.float32)
    if key is None:
        return v
    idx = idx_map.get(key)
    if idx is not None:
        v[idx] = 1.0
    return v


def _load_embedder():
    if "/ml" not in sys.path:
        sys.path.insert(0, "/ml")
    from makina_ml import embedder  # noqa: E402
    embedder.ensure_loaded()
    while not embedder.is_ready():
        print("waiting for embedder…", flush=True)
        time.sleep(2)
    return embedder


def _embed_all(embedder, codes: list[str], batch: int = BATCH) -> np.ndarray:
    out = np.zeros((len(codes), EMBED_DIM), dtype=np.float32)
    for i in range(0, len(codes), batch):
        chunk = codes[i : i + batch]
        vecs = embedder.embed_batch(chunk)
        if vecs is None:
            continue
        out[i : i + len(chunk)] = np.asarray(vecs, dtype=np.float32)
        if (i // batch) % 50 == 0:
            print(f"  embedded {i + len(chunk)}/{len(codes)}", flush=True)
    return out


CONFIGS = [
    # name, flags  — toggle off blocks to disable them
    ("full",            dict()),
    ("no-cwe",          dict(no_cwe=True)),
    ("no-lang",         dict(no_lang=True)),
    ("no-stats",        dict(no_stats=True)),
    ("no-own-emb",      dict(no_own_emb=True)),
    ("no-delta",        dict(no_delta=True)),
    ("delta-only",      dict(no_own_emb=True, no_stats=True, no_cwe=True, no_lang=True)),
    ("own-emb-only",    dict(no_delta=True, no_stats=True, no_cwe=True, no_lang=True)),
    ("meta-only",       dict(no_own_emb=True, no_delta=True)),
    # "Best of effective" combos derived from the first ablation pass:
    # delta carries ~14pt, stats ~11pt, cwe ~1pt; own_emb and lang are ~0.
    ("delta+stats",     dict(no_own_emb=True, no_cwe=True, no_lang=True)),
    ("delta+stats+cwe", dict(no_own_emb=True, no_lang=True)),
    ("delta+cwe",       dict(no_own_emb=True, no_stats=True, no_lang=True)),
    ("stats+cwe",       dict(no_own_emb=True, no_delta=True, no_lang=True)),
    ("no-lang-no-own",  dict(no_own_emb=True, no_lang=True)),  # alias of delta+stats+cwe; sanity
]


def _build_feat(emb_self, emb_other, stats_pair, cwe_oh, lang_oh, flags):
    parts = []
    if not flags.get("no_own_emb"):
        parts.append(emb_self)
    if not flags.get("no_delta"):
        d = emb_self - emb_other
        parts.append(d)
        parts.append(np.abs(d))
    if not flags.get("no_stats"):
        parts.append(stats_pair)
    if not flags.get("no_cwe"):
        parts.append(cwe_oh)
    if not flags.get("no_lang"):
        parts.append(lang_oh)
    if not parts:
        return np.zeros(1, dtype=np.float32)
    return np.concatenate(parts).astype(np.float32)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pairs", type=Path, default=Path("/tmp/samples_pairs.jsonl"))
    ap.add_argument("--metrics-out", type=Path, default=Path("/root/.makina/ablations.json"))
    ap.add_argument("--cwe-topk", type=int, default=20)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument(
        "--emb-cache",
        type=Path,
        default=Path("/root/.makina/pair_embs.npy"),
        help="path to cache embeddings; loads if present, else computes and saves",
    )
    args = ap.parse_args()

    if not args.pairs.exists():
        print(f"pairs file not found: {args.pairs}", file=sys.stderr)
        return 2

    # ── Load pairs ──────────────────────────────────────────────────────────
    pairs = []
    with args.pairs.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                pairs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if args.limit and len(pairs) >= args.limit:
                break
    print(f"loaded {len(pairs)} pairs", flush=True)

    cwe_counts = Counter(p.get("cwe") for p in pairs if p.get("cwe"))
    cwe_vocab = [c for c, _ in cwe_counts.most_common(args.cwe_topk)]
    cwe_idx = {c: i for i, c in enumerate(cwe_vocab)}
    lang_vocab = sorted({p.get("language") for p in pairs if p.get("language")})
    lang_idx = {lang: i for i, lang in enumerate(lang_vocab)}

    # ── Embed all hunks once (cached on disk for repeat ablations) ──────────
    expected_n = len(pairs) * 2
    if args.emb_cache.exists():
        cached = np.load(args.emb_cache)
        if cached.shape == (expected_n, EMBED_DIM):
            print(f"loaded cached embeddings from {args.emb_cache} (shape {cached.shape})", flush=True)
            all_embs = cached
        else:
            print(
                f"cache shape {cached.shape} != expected {(expected_n, EMBED_DIM)}; re-computing",
                flush=True,
            )
            all_embs = None
    else:
        all_embs = None

    if all_embs is None:
        embedder = _load_embedder()
        print("embedder ready, embedding all hunks…", flush=True)
        t0 = time.perf_counter()
        all_codes: list[str] = []
        for p in pairs:
            all_codes.append(p["before_code"])
            all_codes.append(p["after_code"])
        all_embs = _embed_all(embedder, all_codes)
        print(f"embedding done in {time.perf_counter() - t0:.1f}s", flush=True)
        args.emb_cache.parent.mkdir(parents=True, exist_ok=True)
        np.save(args.emb_cache, all_embs)
        print(f"cached embeddings → {args.emb_cache}", flush=True)

    # ── Pre-compute side metadata once ──────────────────────────────────────
    n = len(pairs)
    stats_arr = np.zeros((n, 5), dtype=np.float32)
    cwe_arr = np.zeros((n, len(cwe_vocab)), dtype=np.float32)
    lang_arr = np.zeros((n, len(lang_vocab)), dtype=np.float32)
    groups_per_pair = np.empty(n, dtype=object)
    for i, p in enumerate(pairs):
        bl = p["before_code"].count("\n") + 1
        al = p["after_code"].count("\n") + 1
        stats_arr[i] = [bl, al, len(p["before_code"]), len(p["after_code"]), al - bl]
        cwe_arr[i] = _one_hot(cwe_idx, p.get("cwe"), len(cwe_vocab))
        lang_arr[i] = _one_hot(lang_idx, p.get("language"), len(lang_vocab))
        groups_per_pair[i] = p.get("cve_id") or f"unknown-{i}"

    # Same group split for every config so they're directly comparable.
    from sklearn.model_selection import GroupShuffleSplit
    pair_idx = np.arange(n)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_pairs_idx, val_pairs_idx = next(gss.split(pair_idx, groups=groups_per_pair))

    import xgboost as xgb

    summary = []
    for name, flags in CONFIGS:
        # Build feature matrix for this config
        def _row(i: int, side: str):
            eb = all_embs[2 * i]
            ea = all_embs[2 * i + 1]
            if side == "before":
                return _build_feat(eb, ea, stats_arr[i], cwe_arr[i], lang_arr[i], flags)
            return _build_feat(ea, eb, stats_arr[i], cwe_arr[i], lang_arr[i], flags)

        # Probe dimensionality
        probe = _row(0, "before")
        feat_dim = probe.shape[0]

        X = np.zeros((n * 2, feat_dim), dtype=np.float32)
        y = np.zeros(n * 2, dtype=np.int32)
        for i in range(n):
            X[2 * i] = _row(i, "before")
            y[2 * i] = 1
            X[2 * i + 1] = _row(i, "after")
            y[2 * i + 1] = 0

        # Map pair-level split to sample-level
        train_mask = np.zeros(n * 2, dtype=bool)
        train_mask[2 * train_pairs_idx] = True
        train_mask[2 * train_pairs_idx + 1] = True
        val_mask = ~train_mask

        t1 = time.perf_counter()
        model = xgb.XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1,
            subsample=0.8, colsample_bytree=0.8,
            eval_metric="logloss", random_state=42, n_jobs=-1,
        )
        model.fit(X[train_mask], y[train_mask])
        train_t = time.perf_counter() - t1

        val_pred = model.predict(X[val_mask])
        val_prob = model.predict_proba(X[val_mask])[:, 1]
        y_val = y[val_mask]
        acc = float((val_pred == y_val).mean())
        tp = int(((val_pred == 1) & (y_val == 1)).sum())
        fp_p = int(((val_pred == 1) & (y_val == 0)).sum())
        fn_p = int(((val_pred == 0) & (y_val == 1)).sum())
        prec = float(tp / (tp + fp_p)) if (tp + fp_p) else 0.0
        rec = float(tp / (tp + fn_p)) if (tp + fn_p) else 0.0
        p_tp = float(val_prob[y_val == 1].mean()) if (y_val == 1).any() else 0.0
        p_fp = float(val_prob[y_val == 0].mean()) if (y_val == 0).any() else 0.0
        delta = p_tp - p_fp

        row = {
            "config": name,
            "feat_dim": feat_dim,
            "train_time_s": round(train_t, 2),
            "val_accuracy": round(acc, 4),
            "val_precision": round(prec, 4),
            "val_recall": round(rec, 4),
            "val_prob_mean_tp": round(p_tp, 4),
            "val_prob_mean_fp": round(p_fp, 4),
            "val_delta": round(delta, 4),
        }
        summary.append(row)
        print(f"  {name:14s}  dim={feat_dim:5d}  acc={acc:.4f}  Δ={delta:+.4f}  ({train_t:.1f}s)", flush=True)

    args.metrics_out.parent.mkdir(parents=True, exist_ok=True)
    args.metrics_out.write_text(json.dumps({"summary": summary}, indent=2, ensure_ascii=False))
    print(f"\nsaved → {args.metrics_out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
