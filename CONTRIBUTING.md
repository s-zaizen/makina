# Contributing to deus

## Development Setup

**Prerequisites:** Rust (stable), Python 3.11+, Node.js 20+, Docker

```bash
# Start all services
docker compose up -d

# Watch logs
docker compose logs -f

# Rebuild a single service after code changes
docker compose up -d --build backend   # Rust API
docker compose up -d --build ml        # Python ML
docker compose up -d --build frontend  # Next.js UI
```

## Project Layout

```
crates/deus/   Rust core — axum API, SQLite, scan orchestration
ml/            Python ML service — CodeBERT, GBDT, semgrep, taint
frontend/      Next.js UI — Scan / Verify / Knowledge tabs
docs/          Architecture and design documentation
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
| `frontend`   | Next.js app                |
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

## Code Style

- **Rust:** `cargo fmt` + `cargo clippy` (no warnings)
- **Python:** `ruff format` + `ruff check`
- **TypeScript:** `tsc --noEmit` must pass; follow existing code style

## Testing

```bash
# Rust unit tests
cargo test

# End-to-end: start stack, then run the CVE import
docker compose up -d
python3 import_cves.py
```

There are no mandatory automated tests yet.
New features should include at minimum a manual test note in the PR description.
