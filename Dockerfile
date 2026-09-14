# syntax=docker/dockerfile:1

# Builder: compile the release binary.
FROM rust:1-bookworm AS builder
WORKDIR /app

# Copy manifests first for better layer caching, then source + migrations.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations

# Cargo.lock is committed, pinning the full dependency tree; --locked fails
# the build rather than silently resolving different versions.
RUN cargo build --release --locked

# Runtime: minimal Debian. The binary uses rustls (see sqlx
# runtime-tokio-rustls), so no OpenSSL/libssl install is needed here.
FROM debian:bookworm-slim

RUN useradd --uid 10000 -m appuser \
    && mkdir -p /data && chown appuser:appuser /data

COPY --from=builder /app/target/release/python-package-server /usr/local/bin/python-package-server

USER 10000
EXPOSE 8000
ENV STORAGE_DIR=/data

CMD ["/usr/local/bin/python-package-server"]
