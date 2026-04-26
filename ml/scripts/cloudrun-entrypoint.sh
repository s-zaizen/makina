#!/bin/sh
# Boot both halves of makina inside one Cloud Run container.
#
#   - Python ML on 127.0.0.1:$ML_PORT  (loopback only)
#   - Rust API  on 0.0.0.0:$PORT       (Cloud Run-injected, public)
#
# Cloud Run watches PID 1, so the Rust API runs in the foreground via
# `exec`. Python ML runs as a child; if it dies we exit the whole
# container so Cloud Run restarts the instance — half-live containers
# silently broken are worse than a fast crash + reschedule.

set -eu

ML_PORT="${ML_PORT:-8081}"
PORT="${PORT:-8080}"
export ML_PORT
export PORT
export MAKINA_ML_URL="http://127.0.0.1:${ML_PORT}"

# Pull the frozen GBDT model from Cloud Storage so /api/scan can blend
# its confidence into the heuristic score. The file is small (~100 KB)
# so the extra cold-start tax is negligible. We use Application Default
# Credentials — Cloud Run's compute SA already has objectViewer on the
# bucket. Failure here is non-fatal: the API still serves heuristic-
# only findings if the model is missing.
MAKINA_MODEL_BUCKET="${MAKINA_MODEL_BUCKET:-makina-prod-models}"
MAKINA_MODEL_OBJECT="${MAKINA_MODEL_OBJECT:-model.json}"
MODEL_DEST="${MAKINA_MODEL:-/root/.makina/model.json}"

if [ -n "${MAKINA_MODEL_BUCKET}" ] && [ -n "${MAKINA_MODEL_OBJECT}" ]; then
    echo "[entrypoint] fetching gs://${MAKINA_MODEL_BUCKET}/${MAKINA_MODEL_OBJECT} → ${MODEL_DEST}" >&2
    mkdir -p "$(dirname "${MODEL_DEST}")"
    if python3 -c "
import sys
from google.cloud import storage
try:
    storage.Client().bucket('${MAKINA_MODEL_BUCKET}').blob('${MAKINA_MODEL_OBJECT}').download_to_filename('${MODEL_DEST}')
except Exception as e:
    print(f'[entrypoint] model download failed: {e}', file=sys.stderr)
    sys.exit(1)
" 2>&2; then
        echo "[entrypoint] model loaded ($(wc -c < "${MODEL_DEST}") bytes)" >&2
    else
        echo "[entrypoint] continuing without model (heuristic-only confidence)" >&2
    fi
fi

echo "[entrypoint] starting Python ML on 127.0.0.1:${ML_PORT}" >&2
python -m makina_ml.server &
ML_PID=$!

# Bail the container if ML crashes mid-run — `wait -n` returns the
# exit status of whichever child finishes first.
on_exit() {
    kill "${ML_PID}" 2>/dev/null || true
    wait "${ML_PID}" 2>/dev/null || true
}
trap on_exit EXIT INT TERM

# Wait until ML answers /health before fronting the API. CodeBERT lazy-
# loads in the background, but binding the port comes first; once the
# socket is up the Rust core's request-flow degrades gracefully.
echo "[entrypoint] waiting for ML to bind…" >&2
ATTEMPTS=0
until curl -fsS "http://127.0.0.1:${ML_PORT}/health" >/dev/null 2>&1; do
    ATTEMPTS=$((ATTEMPTS + 1))
    if [ "${ATTEMPTS}" -ge 60 ]; then
        echo "[entrypoint] ML did not become ready in 30s, aborting" >&2
        exit 1
    fi
    sleep 0.5
done
echo "[entrypoint] ML ready, starting Rust API on 0.0.0.0:${PORT}" >&2

exec /usr/local/bin/makina serve --host 0.0.0.0 --port "${PORT}"
