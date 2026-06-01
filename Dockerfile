# ---- build ----
FROM rust:1-slim-trixie AS builder

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY cli/ cli/
COPY app/ app/

# Build the webhook server and the CLI (runner calls `primer scan` as a subprocess).
RUN cargo build --release -p primer -p primer-app

# ---- runtime ----
FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false primer

COPY --from=builder /build/target/release/primer     /usr/local/bin/primer
COPY --from=builder /build/target/release/primer-app /usr/local/bin/primer-app
COPY docs/ /app/docs/

USER primer

# Cloud Run injects PORT; LISTEN_ADDR is the fallback for local runs.
ENV LISTEN_ADDR=0.0.0.0:8080
ENV DOCS_DIR=/app/docs
EXPOSE 8080

CMD ["primer-app"]
