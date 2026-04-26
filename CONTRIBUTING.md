# Contributing to makina

## Development Setup

**Prerequisites:** Rust (stable), Python 3.11+, Node.js 20+, Docker

```bash
# Activate git hooks (one-time per clone)
git config core.hooksPath .claude/hooks

# Start all services
docker compose up -d

# Watch logs
docker compose logs -f

# Rebuild a single service after code changes
docker compose up -d --build backend   # Rust API
docker compose up -d --build ml        # Python ML
docker compose up -d --build frontend  # SvelteKit UI
```

## CVEfixes Import & Training

Reproducible commands for the bulk-import and ML-training workflow.
Conversion runs on the host (only needs Python + sqlite); training runs
inside the `ml` container so it shares the cached CodeBERT weights.

```bash
# 0. Fetch CVEfixes (one-time, ~3.9 GB)
./third_party/datasets/cvefixes/fetch.sh

# 1. Convert CVEfixes → paired TP/FP samples for bulk_import.
#    For each CVE pair we emit two records: a TP from the vulnerable
#    method (deleted-line ranges) and an FP from the patched method
#    (added-line ranges). Each range becomes one finding at import
#    time so the GBDT trains on per-finding embeddings — full method
#    as context, narrow line range as the focus, with hard
#    counterexamples coming from the actual fix.
#
#    Recommended flags:
#      --window 6              tighten code to (changed lines ± 6) so the
#                              embedding focuses on the diff hunk
#      --drop-noise            skip diff lines that are blank, comment-only,
#                              brace-only, trivial constant inits (`x = 0;`),
#                              or pure control flow (`return x;`, `goto out;`)
#      --max-ranges 3          drop the entire CVE pair if either side has
#                              more than 3 disjoint hunks — sweeping commits
#                              are almost never focused security fixes
#      --cross-cve-fp-ratio 0.5 also pair each TP with a random patched
#                              method from a *different* CVE (helps the
#                              model not overfit to within-pair fix patterns)
#
#    The converter also enforces two pair-level filters with no flag:
#      * commit-message filter — requires a security keyword (vuln/cve/
#        overflow/inject/escape/bypass/…) in the commit subject and
#        rejects pure refactor/rename/cleanup/typo/merge/version-bump
#        commits, since CVEfixes labels every method touched in the
#        security commit regardless of intent
#      * filename filter — drops paths under /test/, /docs/, fixtures,
#        CHANGELOG, *.md, etc.
python ml/scripts/converters/cvefixes.py \
  --window 6 --drop-noise --max-ranges 3 --cross-cve-fp-ratio 0.5

# 2. Convert CVEfixes → diff-aware hunk pairs (for pair-feature experiments)
python ml/scripts/converters/cvefixes_pairs.py

# 3. Reset makina DBs (keeps CodeBERT cache and other volumes intact)
docker compose exec ml rm -f \
  /root/.makina/feedback.db /root/.makina/knowledge.db /root/.makina/verify.db \
  /root/.makina/model.json /root/.makina/metrics.json
docker compose restart backend ml

# 4. Bulk-import. Each case becomes a verify-queue entry with the full
#    method as `code` and one manual finding per range; findings carry
#    the per-record TP/FP label and the case's CVE id is sent as
#    `group_key` so the GBDT trainer's GroupShuffleSplit keeps every
#    paired TP/FP twin on the same side of the train/val split.
#    --count 0 ingests every record.
python ml/scripts/bulk_import.py \
  --jsonl third_party/datasets/cvefixes/samples.jsonl \
  --count 0

# 5. Pair-feature ablation suite (research, runs inside the ml container)
docker cp third_party/datasets/cvefixes/samples_pairs.jsonl makina-ml-1:/tmp/
docker cp ml/scripts/run_ablations.py makina-ml-1:/ml/scripts/
docker compose exec -T ml python3 /ml/scripts/run_ablations.py \
  --pairs /tmp/samples_pairs.jsonl
```

## Project Layout

```
crates/makina/src/   Rust core — hexagonal + vertical-slice
  api/               router composition + shared API DTOs
  features/          one module per feature (scan, labels, findings,
                     verify, knowledge, model)
  infra/ml.rs        outbound adapter for the Python ML service
  store/             SQLite data layer
  logging.rs         tracing + request_id middleware
ml/makina_ml/        Python ML service (FastAPI)
  server.py          thin route handlers
  services/          use cases (training.py = GBDT pipeline)
  analyzer.py / embedder.py / taint_engine.py / call_graph.py …
                     domain modules (CodeBERT, taint, call graph, features)
frontend/src/        SvelteKit UI (Svelte 5 Runes)
  routes/            +page.svelte (state + layout coordinator)
  lib/components/    Scan / Verify / Knowledge / Model tab components
  lib/api.ts         fetch wrappers (PUBLIC_API_URL)
  lib/placeholders.ts  per-language sample snippets for the Scan tab
docs/                Architecture and design documentation
.claude/             Claude Code configuration
  commands/          Slash commands — vuln-add, vuln-verify, vuln-add-verify-with-claude
  hooks/             typecheck.sh (PostToolUse), pre-push (git), prepush-gate.sh (PreToolUse)
  rules/             Path-scoped lint/style rules (backend, ml, frontend)
  settings.json      Hook configuration
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for a full system overview.

## Commit Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>
```

**Commit messages must be a single line.** No multi-line subject, no body unless the tradeoff is genuinely non-obvious to a future reader.

**Types:**

| Type       | When to use                                         |
|------------|-----------------------------------------------------|
| `feat`     | New feature visible to users or callers             |
| `fix`      | Bug fix                                             |
| `perf`     | Performance improvement                             |
| `refactor` | Code change that is neither a feature nor a fix     |
| `test`     | Adding or updating tests                            |
| `chore`    | Tooling, dependencies, CI, build scripts            |
| `docs`     | Documentation only                                  |

**Scopes** (optional but encouraged):

| Scope        | Area                       |
|--------------|----------------------------|
| `backend`    | Rust crate                 |
| `ml`         | Python ML service          |
| `frontend`   | SvelteKit app              |
| `.claude`    | Claude Code slash commands |
| `api`        | HTTP API contract changes  |
| `verify`     | Verify queue / labeling    |
| `scan`       | Scan pipeline              |
| `learning`   | ML training / GBDT         |

**Examples:**

```
feat(verify): add persistent queue with SQLite backend
fix(ml): handle single-class training gracefully
perf(scan): run semgrep, CodeBERT, and taint in parallel
chore: add Dockerfile multi-stage build
docs: document continuous learning architecture
```

## Keeping Docs Current

`docs/ARCHITECTURE.md` and `CONTRIBUTING.md` must stay in sync with the code.
When a commit changes something they describe — API routes, directory layout, toolchain, scopes, workflows — update those files **in the same commit**.
Standalone docs-only commits exist only for documentation that is truly independent of any code change.

## Pull Request Guidelines

- One logical change per PR
- Title follows the same `type(scope): summary` convention
- Link to relevant issue if one exists
- All services should still build: `docker compose up -d` must succeed

## Testing

**Current coverage**: there are no unit tests yet — `cargo test` runs
zero tests, the Python service has no `test_*.py`, and the frontend
has no test runner configured. New code should land with tests where
practical (`refactor:` and `fix:` commits especially), but the bar is
"don't make it worse" until a baseline test setup exists.

End-to-end: `docker compose up -d`, then use `/vuln-add` in Claude Code
to queue a case. For ad-hoc smoke testing, the routes most worth
hitting are `/api/scan`, `/api/stats`, and `/api/knowledge`.

Automatic checks run at two points:

- **Edit/Write** — `.claude/hooks/typecheck.sh` (PostToolUse): `cargo clippy`, `ruff check`, `npm run check`
- **Push** — `.claude/hooks/pre-push` (git hook + PreToolUse gate): clippy + `cargo test` + ruff + npm check

Language-specific style rules are in `.claude/rules/`.
