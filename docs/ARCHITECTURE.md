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
│  - /api/knowledge     (GET / POST — verified cases) │
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
│  - /train     GBDT retrain on all accumulated labels│
│  - /predict   GBDT confidence score                 │
└─────────────────────────────────────────────────────┘
```

## Scan Pipeline

For each scan request, three detectors run in parallel and are merged:

1. **semgrep** — community rules + custom taint rules (YAML)
2. **CodeBERT semantic** — cosine similarity against 11 CWE embeddings
3. **taint engine** — tree-sitter BFS from sources to sinks, cross-function

All three sources are merged and each finding is embedded with
call-graph-augmented context (enclosing function + 1-hop callees) and
stored in SQLite with the embedding vector.

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
and avoids incremental drift.

A secondary retrain fires every 10 individual feedback labels as a
supplementary signal path.

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
│       └── feedback/      store.rs (SQLite), mod.rs
├── ml/                    Python ML service (FastAPI)
│   └── deus_ml/
│       ├── server.py      API endpoints + GBDT train/predict
│       ├── analyzer.py    CodeBERT semantic analysis
│       ├── embedder.py    CodeBERT embedding (lazy-loaded)
│       ├── taint_engine.py interprocedural taint via tree-sitter
│       ├── call_graph.py  call graph extraction (AST + regex fallback)
│       ├── features.py    50-element hand-crafted feature vector
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
