# deus — Architecture

## Design Philosophy

deus is a security scanner that continuously self-learns from human verification.
The model updates on **every Verify Submit** — not at fixed thresholds.
Label count is a maturity indicator, not a capability gate.

## System Components

```
┌─────────────────────────────────────────────────────┐
│  Browser (SvelteKit)                                │
│  Scan tab → Verify tab → Knowledge tab              │
└────────────────────┬────────────────────────────────┘
                     │ HTTP
┌────────────────────▼────────────────────────────────┐
│  Rust core  (axum)            :7373                 │
│  - /api/scan                                        │
│  - /api/feedback                                    │
│  - /api/verify/queue  (GET / POST / DELETE)         │
│  - /api/knowledge     (GET / POST[?skip_train])     │
│  - /api/retrain       (POST — proxy to ML /train)   │
│  - /api/stats                                       │
│  SQLite  ~/.deus/feedback.db  (ML training data)    │
│  SQLite  ~/.deus/verify.db    (pending queue)       │
│  SQLite  ~/.deus/knowledge.db (verified cases)      │
└──────────┬──────────────────────────────────────────┘
           │ HTTP (internal)
┌──────────▼──────────────────────────────────────────┐
│  Python ML service            :8080                 │
│  - /semgrep   rule-based scan (semgrep + taint)     │
│  - /analyze   CodeBERT semantic similarity          │
│  - /taint     interprocedural taint flow            │
│  - /embed_with_graph  call-graph-augmented embeds   │
│  - /train         GBDT retrain on all labels        │
│  - /predict       GBDT confidence (768-dim embed)   │
│  - /predict_batch GBDT confidence, N embeddings     │
└─────────────────────────────────────────────────────┘
```

## Scan Pipeline

For each scan request, three detectors run in parallel and are merged:

1. **semgrep** — community rules + custom taint rules (YAML)
2. **CodeBERT semantic** — see *"ML analysis gate"* below
3. **taint engine** — tree-sitter BFS from sources to sinks, cross-function

After merge, each finding is embedded with call-graph-augmented context
(enclosing function + 1-hop callees) and stored in SQLite. The Rust core
then calls `POST /predict_batch` with every finding's embedding to get a
GBDT probability, and blends:

```
finding.confidence = 0.5 × heuristic_score + 0.5 × gbdt_probability
```

If the GBDT model isn't trained yet (`model.json` absent), the heuristic
score is kept unchanged. This is how the accumulated labels actually
influence scan output.

### ML analysis gate (hybrid, GBDT-first)

`/analyze` uses a hybrid gate so CodeBERT's noisy similarity alone cannot
flood a scan with false positives. For each sliding window:

1. **Sink regex (primary)** — the window is emitted immediately if any
   per-CWE sink regex (`eval`, `system`, `pickle.loads`,
   `r_core_call_str_at`, `Runtime.getRuntime().exec`, …) matches inside
   it. Sinks are ground truth for this detector; the GBDT is *not*
   consulted.
2. **Similarity + GBDT (secondary)** — otherwise the window must satisfy
   BOTH of:
   - CWE prototype cosine similarity ≥ `CWE_CLASSIFY_THRESHOLD` (0.95)
   - GBDT probability ≥ `GBDT_GATE_THRESHOLD` (0.70)
3. **GBDT absent** — when `model.json` does not exist yet, the analyzer
   falls back to pure similarity with the old 0.80 threshold.

Empirically this cut gson's false-positive count from ~600 to ~7 while
keeping recall on the radare2 `r_core_call_str_at` case-study. The
`gate`, `refined_by`, and `mode` fields on each finding record which
path was taken.

### Refining the `ML` source to exact lines

The CodeBERT analyzer uses a 20-line sliding window for detection, then
narrows each window match to a tight range via (in order of preference):

1. **Sink regex** — per-CWE regex of known dangerous calls (`eval`,
   `system`, `pickle.loads`, `r_core_call_str_at`, …). If a sink matches
   inside the window, the finding is pinned to that line ± 2.
2. **Embedding peak** — otherwise, re-score each line within the window
   against the matched CWE patterns and center the range on the highest-
   similarity line.
3. **Window fallback** — used only when neither signal is available.

The `refined_by` field on each finding records which path was taken.

## Learning Loop

```
Scan → findings stored with CodeBERT embedding vectors
  ↓
Human reviews in Verify tab (TP / FP labels)
  ↓
Verify Submit → POST /api/knowledge {case_no, labels}
  ↓
Rust core: saves labels to feedback.db, moves case to knowledge.db
  ↓
Rust core calls POST /train (fire-and-forget)
  ↓
ML service retrains GBDT on ALL accumulated (embedding, label) pairs
  ↓
New model.json written to ~/.deus/model.json
  ↓
Next scan uses updated GBDT confidence scores
```

The GBDT is retrained from scratch on the full dataset after every Submit.
This is intentional: with small datasets full retraining is cheap (<1s)
and avoids incremental drift. After each retrain the analyzer's in-memory
pattern index is invalidated (`analyzer.reset_index()`) so the next scan
picks up any newly added CWE categories.

### Why the labeled index is not the primary matcher

`analyzer.py` also knows how to build a kNN index of TP embeddings grouped
by CWE from `feedback.db` (`_build_labeled_index`). It is intentionally
**not** used as the primary pattern matcher today, because CVEfixes stores
*whole-method* embeddings — any C function ends up sim≈0.99 against every
other C function, collapsing CWE discrimination. The labeled corpus earns
its keep through the GBDT (method-level TP/FP decision), not through
max-similarity matching. Line-level labeled embeddings would make the
kNN path viable; that is a future direction.

### Bulk import path

`ml/scripts/bulk_import.py` seeds the model from curated datasets
(CVEfixes SQLite dump, or Hugging Face datasets like BigVul). Datasets are
**not vendored** — each lives under `third_party/datasets/<name>/` with a
`fetch.sh` that pulls from the authoritative source (Zenodo for CVEfixes,
Hugging Face for BigVul), a `README.md` with license + citation, and a
`.gitignore` that excludes the downloaded artefacts. CVEfixes is CC BY 4.0
(Bhandari, Naseer, Moonen, 2021); see `third_party/datasets/README.md` for
attribution policy. Each row becomes a `POST /api/findings/manual` (which
embeds the snippet) → a one-finding verify queue case → a
`POST /api/knowledge?skip_train=true` that labels and archives the case
without triggering the per-submit retrain. After the batch completes, the
script fires a single `POST /api/retrain` to bring the GBDT up to date.
This avoids a retrain stampede when importing hundreds of samples.

A secondary retrain fires every 10 individual feedback labels as a
supplementary signal path.

## Logging

Both services emit **structured JSON to stdout** (picked up by `docker compose logs`).

- **Rust** — `tracing` + `tracing-subscriber` (JSON). A middleware reads or
  generates `x-request-id` per request, attaches it to a span, echoes it
  back in the response header, and logs method / path / status / elapsed_ms.
- **Python ML** — stdlib `logging` + `python-json-logger`. A FastAPI
  middleware binds `x-request-id` to a `contextvars` context; a filter
  injects it into every log record.
- **Propagation** — every Rust → ML HTTP call forwards `x-request-id`, so
  logs across the two services can be joined on `request_id`.

Log level is controlled by `RUST_LOG` (Rust) and `DEUS_LOG_LEVEL` (Python),
both defaulting to `info`.

## Model Maturity Stages

Stages are **descriptive** — the model is always active and learning.

| Stage         | Labels | Description                                    |
|---------------|--------|------------------------------------------------|
| bootstrapping | 0      | Rules + CodeBERT only; no GBDT yet             |
| learning      | 1–49   | GBDT training begins; limited signal           |
| refining      | 50–499 | GBDT improving; confidence scores meaningful   |
| mature        | 500+   | Well-trained; high-confidence predictions      |

## Data Model

Three SQLite databases under `~/.deus/`:

```sql
-- feedback.db: ML training data (read by Python ML service)
-- findings: one row per detected finding
id TEXT PRIMARY KEY        -- UUID
code_hash TEXT             -- SHA-256 of scanned code
feature_vector BLOB        -- CodeBERT embedding (768 × float32, 3072 bytes)
rule_id TEXT               -- semgrep rule or CWE identifier
language TEXT
line_number INTEGER
confidence REAL
label TEXT                 -- 'tp' | 'fp' (NULL until verified)
labeled_at TEXT            -- ISO-8601
created_at TEXT

-- verify.db: pending human review queue
-- verify_queue: cases awaiting labeling
case_no INTEGER PRIMARY KEY AUTOINCREMENT
cve_id TEXT                -- optional CVE identifier
code TEXT
language TEXT
findings_json TEXT         -- JSON array of Finding objects
submitted_at TEXT

-- knowledge.db: verified cases with labels
-- knowledge: cases that have been labeled and submitted
case_no INTEGER PRIMARY KEY
cve_id TEXT
code TEXT
language TEXT
findings_json TEXT         -- JSON array of Finding objects
labels_json TEXT           -- JSON map of {finding_id: "tp"|"fp"}
submitted_at TEXT
verified_at TEXT
```

## Directory Layout

```
deus/
├── crates/deus/           Rust core (axum API, SQLite, scan orchestration)
│   └── src/
│       ├── api/           handlers.rs, models.rs, mod.rs
│       ├── feedback/      store.rs (SQLite), mod.rs
│       └── logging.rs     tracing JSON init + request_id middleware
├── ml/                    Python ML service (FastAPI)
│   ├── scripts/           bulk_import.py (dataset → knowledge, no scan)
│   │   └── converters/    cvefixes.py (CVEfixes.db → samples.jsonl)
│   └── deus_ml/
│       ├── server.py      API endpoints + GBDT train/predict
│       ├── analyzer.py    CodeBERT semantic analysis
│       ├── embedder.py    CodeBERT embedding (lazy-loaded)
│       ├── taint_engine.py interprocedural taint via tree-sitter
│       ├── call_graph.py  call graph extraction (AST + regex fallback)
│       ├── features.py    50-element hand-crafted feature vector
│       ├── logging_config.py  JSON logging + request_id contextvar
│       └── semgrep_scanner.py  semgrep wrapper + language detection
├── frontend/              SvelteKit UI (Svelte 5 Runes, adapter-node)
│   └── src/
│       ├── routes/        +page.svelte (main layout + state), +layout.ts
│       └── lib/
│           ├── components/ CodeEditor, FileTree, FindingCard, VerifyTab, KnowledgeTab …
│           ├── highlighter.ts  shiki singleton (vitesse-dark theme)
│           ├── api.ts     fetch wrappers (PUBLIC_API_URL)
│           ├── types.ts   shared TypeScript types
│           └── folder.ts  folder drag-and-drop utilities
├── third_party/           External assets (not vendored)
│   └── datasets/          Training datasets (fetched via per-dir fetch.sh)
│       └── cvefixes/      CVEfixes — CC BY 4.0, see README.md
├── .claude/               Claude Code configuration
│   ├── commands/          vuln-add, vuln-verify, vuln-add-verify-with-claude
│   ├── hooks/typecheck.sh   PostToolUse: lint after Write/Edit
│   ├── hooks/pre-push       git pre-push hook: clippy + test + ruff + npm check
│   ├── hooks/prepush-gate.sh PreToolUse (Bash): intercepts git push for Claude
│   ├── rules/               Path-scoped rules (backend.md, ml.md, frontend.md)
│   └── settings.json        Hook bindings (PreToolUse + PostToolUse)
├── CLAUDE.md              AI assistant instructions for this repo
├── CONTRIBUTING.md        Commit conventions, dev setup, code style
└── docs/ARCHITECTURE.md   this file
```
