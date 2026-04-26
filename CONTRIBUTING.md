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
python ml/scripts/converters/cvefixes.py

# 2. Convert CVEfixes → diff-aware hunk pairs (for pair-feature experiments)
python ml/scripts/converters/cvefixes_pairs.py

# 3. Reset makina DBs (keeps CodeBERT cache and other volumes intact)
docker compose exec ml rm -f \
  /root/.makina/feedback.db /root/.makina/knowledge.db /root/.makina/verify.db \
  /root/.makina/model.json /root/.makina/metrics.json
docker compose restart backend ml

# 4. Bulk-import. Each case becomes a verify-queue entry with the full
#    method as `code` and one manual finding per range; all findings
#    are submitted as TRUE POSITIVE. --count 0 ingests every record.
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
crates/makina/   Rust core — axum API, SQLite, scan orchestration
ml/            Python ML service — CodeBERT, GBDT, semgrep, taint
frontend/      SvelteKit UI — Scan / Verify / Knowledge tabs
docs/          Architecture and design documentation
.claude/       Claude Code configuration
  commands/    Slash commands — vuln-add, vuln-verify, vuln-add-verify-with-claude
  hooks/       typecheck.sh (PostToolUse), pre-push (git hook), prepush-gate.sh (PreToolUse)
  rules/       Path-scoped lint/style rules (backend, ml, frontend)
  settings.json  Hook configuration
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

End-to-end: `docker compose up -d`, then use `/vuln-add` in Claude Code to queue a case.

Automatic checks run at two points:

- **Edit/Write** — `.claude/hooks/typecheck.sh` (PostToolUse): `cargo clippy`, `ruff check`, `npm run check`
- **Push** — `.claude/hooks/pre-push` (git hook + PreToolUse gate): clippy + `cargo test` + ruff + npm check

Language-specific style rules are in `.claude/rules/`.
