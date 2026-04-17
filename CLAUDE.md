# CLAUDE.md

Instructions for AI assistants working in this repository.

## Project in One Sentence

**deus** is a security scanner (Rust API + Python ML + Next.js UI) that continuously self-learns from human TP/FP labels submitted via the Verify tab. The GBDT model retrains on every Verify Submit.

## Key Invariants

- **Continuous learning** — the model trains from the first label onward; there are no threshold gates. `model_stage` is a maturity label, not a capability switch.
- **Retrain trigger** — `DELETE /api/verify/queue/:case_no` (Verify Submit) always calls `POST /train` on the ML service. Do not remove or gate this call.
- **Scan pipeline** — semgrep, CodeBERT semantic analysis, and taint engine run in parallel; results are merged and deduplicated by CWE.
- **Rust = orchestration, Python = ML** — scanner logic lives in `ml/`; the Rust crate calls it over HTTP. Do not move ML logic into Rust.

## Running Locally

```bash
docker compose up -d
docker compose up -d --build frontend
docker compose up -d --build backend
docker compose up -d --build ml
docker compose logs -f
```

Services: frontend `:3000`, backend `:7373`, ML `:8080`.

## Commit Rules

Follow Conventional Commits — **one-line message, no body**:

```
feat(backend): ...
fix(ml): ...
chore: ...
docs: ...
```

**`docs/ARCHITECTURE.md` and `CONTRIBUTING.md` must be updated in the same commit** when a change affects what they describe (API routes, directory layout, toolchain, scopes, workflows). Do not create a separate docs commit for something that accompanied a code change.

@CONTRIBUTING.md
@docs/ARCHITECTURE.md
