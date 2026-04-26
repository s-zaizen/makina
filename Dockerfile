# ════════════════════════════════════════════════════════════════════════════
# backend
# ════════════════════════════════════════════════════════════════════════════

FROM rust:1.86-bookworm AS backend-builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates/makina/Cargo.toml crates/makina/Cargo.toml

RUN mkdir -p crates/makina/src \
    && echo 'fn main() {}' > crates/makina/src/main.rs \
    && cargo build --release \
    && rm -rf crates/makina/src

COPY crates/ crates/
RUN touch crates/makina/src/main.rs && cargo build --release

FROM debian:bookworm-slim AS backend

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=backend-builder /build/target/release/makina /usr/local/bin/makina

VOLUME ["/root/.makina"]
EXPOSE 7373

ENTRYPOINT ["makina"]
CMD ["serve", "--host", "0.0.0.0", "--port", "7373"]

# ════════════════════════════════════════════════════════════════════════════
# frontend
# ════════════════════════════════════════════════════════════════════════════

FROM node:20-slim AS frontend-deps

WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

FROM node:20-slim AS frontend-builder

WORKDIR /app
COPY --from=frontend-deps /app/node_modules ./node_modules
COPY frontend/ ./

ARG PUBLIC_API_URL=http://localhost:7373
ENV PUBLIC_API_URL=$PUBLIC_API_URL

RUN npm run build

FROM node:20-slim AS frontend

WORKDIR /app
ENV NODE_ENV=production

COPY --from=frontend-builder /app/build ./build
COPY --from=frontend-builder /app/node_modules ./node_modules
COPY --from=frontend-builder /app/package.json ./

EXPOSE 3000
CMD ["node", "build"]

# ════════════════════════════════════════════════════════════════════════════
# ml
# ════════════════════════════════════════════════════════════════════════════

FROM python:3.11-slim AS ml

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc curl git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /ml

COPY ml/pyproject.toml ./
COPY ml/makina_ml/ ./makina_ml/
COPY ml/scripts/ ./scripts/
COPY ml/tests/ ./tests/
COPY ml/semgrep-custom/ /opt/semgrep-custom/

RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

RUN pip install --no-cache-dir \
    "fastapi>=0.110.0" \
    "uvicorn[standard]>=0.27.0" \
    "xgboost>=2.0.0" \
    "numpy>=1.26.0" \
    "scikit-learn>=1.4.0" \
    "pydantic>=2.6.0" \
    "transformers>=4.38.0" \
    "tokenizers>=0.15.0" \
    "semgrep>=1.70.0" \
    "tree-sitter==0.21.3" \
    "tree-sitter-languages==1.10.2" \
    "python-json-logger>=2.0.7" \
    "openfeature-sdk>=0.7.0" \
    "pytest>=8.0.0" \
    "google-cloud-storage>=2.14.0"

RUN git clone --depth 1 --filter=blob:none --sparse \
        https://github.com/semgrep/semgrep-rules.git /opt/semgrep-rules \
    && cd /opt/semgrep-rules \
    && git sparse-checkout set \
        python/lang/security \
        javascript/lang/security \
        typescript/lang/security \
        go/lang/security \
        java/lang/security \
        ruby/lang/security \
        c/lang/security \
        rust/lang/security \
    && rm -rf /opt/semgrep-rules/.git

# Pre-download CodeBERT into the image so Cloud Run cold-starts hit a
# warm local cache instead of pulling ~500 MB from the HuggingFace hub
# on every revision boot. The cache lives outside `/root/.makina` so
# the runtime VOLUME directive on that path doesn't shadow it.
ENV MAKINA_MODELS=/opt/codebert-cache
RUN python -c "from transformers import AutoTokenizer, AutoModel; \
    AutoTokenizer.from_pretrained('microsoft/codebert-base', cache_dir='/opt/codebert-cache'); \
    AutoModel.from_pretrained('microsoft/codebert-base', cache_dir='/opt/codebert-cache')"

# Pre-warm semgrep — first call parses the entire rule corpus and takes
# 60+ seconds on a fresh container, which used to trip the API gateway
# timeout. Running it once at build time materialises the parsed-rule
# cache and the bytecode under ~/.cache so the runtime first call is
# closer to a few hundred ms.
RUN echo 'pass' > /tmp/warm.py \
    && semgrep --config=/opt/semgrep-rules/python/lang/security \
               --quiet --no-git-ignore --metrics=off /tmp/warm.py \
       > /dev/null 2>&1 || true \
    && rm -f /tmp/warm.py

VOLUME ["/root/.makina"]
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

CMD ["python", "-m", "makina_ml.server"]

# ════════════════════════════════════════════════════════════════════════════
# cloudrun — single image hosting both Rust API and Python ML for Cloud Run.
# Cold-starts once, communicates over loopback, exposes only the Rust port.
# Build with: docker build --target cloudrun -t makina-cloudrun .
# ════════════════════════════════════════════════════════════════════════════

FROM ml AS cloudrun

# Bring the Rust binary into the Python ML image — same /usr/local layout
# as the standalone backend stage so logs/paths stay identical.
COPY --from=backend-builder /build/target/release/makina /usr/local/bin/makina

# Loopback wiring — the Rust core talks to the Python ML over 127.0.0.1
# so nothing ML-internal is exposed to the public internet.
ENV ML_PORT=8081 \
    MAKINA_ML_URL=http://127.0.0.1:8081 \
    MAKINA_PUBLIC_MODE=true \
    RUST_LOG=info \
    MAKINA_LOG_LEVEL=info

COPY ml/scripts/cloudrun-entrypoint.sh /usr/local/bin/cloudrun-entrypoint.sh
RUN chmod +x /usr/local/bin/cloudrun-entrypoint.sh

# Cloud Run injects $PORT — the entrypoint binds the Rust API to it.
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/cloudrun-entrypoint.sh"]
