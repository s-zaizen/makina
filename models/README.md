# Trained GBDT models

Each subdirectory is a single, **immutable** model release. The
container loads exactly one — selected at build time by
`MAKINA_MODEL_VERSION` (Dockerfile arg). Versions are named after the
CVEfixes dataset they were derived from; trailing `.N` segments
distinguish re-trainings of the same dataset (e.g. with different
hyper-parameters).

| Version | Source dataset       | Stage | val_acc | val_recall | Notes |
|---------|----------------------|-------|---------|------------|-------|
| v1.0.8  | CVEfixes v1.0.8      | mature | 0.51 | 0.34 | first prod bake — 19,209 findings |

Each version directory contains:

* `model.json` — XGBoost model dump (~200 KB), loaded by `services.training.load_model`
* `metrics.json` — held-out evaluation produced by `train_offline.py`

## Adding a new version

```bash
# 1. Re-train (see CONTRIBUTING.md → "Shipping a Frozen Model to Production")
docker compose exec ml python3 /ml/scripts/train_offline.py \
  --jsonl /tmp/samples.jsonl --model-path /tmp/model.json --metrics-path /tmp/metrics.json

# 2. Copy artefacts into a fresh version directory
mkdir -p models/v1.0.9
docker cp makina-ml-1:/tmp/model.json models/v1.0.9/model.json
docker cp makina-ml-1:/tmp/metrics.json models/v1.0.9/metrics.json

# 3. Bump the Dockerfile's `MAKINA_MODEL_VERSION` arg, commit, push.
#    CI builds an image baked with the new model and rolls a Cloud Run revision.
```
