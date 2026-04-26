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
