# ════════════════════════════════════════════════════════════════════════════
# backend
# ════════════════════════════════════════════════════════════════════════════

FROM rust:1.86-bookworm AS backend-builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates/deus/Cargo.toml crates/deus/Cargo.toml

RUN mkdir -p crates/deus/src \
    && echo 'fn main() {}' > crates/deus/src/main.rs \
    && cargo build --release \
    && rm -rf crates/deus/src

COPY crates/ crates/
RUN touch crates/deus/src/main.rs && cargo build --release

FROM debian:bookworm-slim AS backend

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=backend-builder /build/target/release/deus /usr/local/bin/deus

VOLUME ["/root/.deus"]
EXPOSE 7373

ENTRYPOINT ["deus"]
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
COPY ml/deus_ml/ ./deus_ml/
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
    "python-json-logger>=2.0.7"

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

VOLUME ["/root/.deus"]
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

CMD ["python", "-m", "deus_ml.server"]
