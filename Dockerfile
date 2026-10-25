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
# BuildKit cache mounts keep the registry/git checkouts and incremental
# target dir warm across builds. The target dir is a cache mount, so its
# contents are NOT in the final builder layer: copy the binary out to a
# non-mounted path in the same RUN.
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=cargo-target,target=/app/target \
    cargo build --release --locked && \
    cp /app/target/release/python-package-server /app/python-package-server

# Runtime: minimal Debian. The binary uses rustls (see sqlx
# runtime-tokio-rustls), so no OpenSSL/libssl install is needed here.
FROM debian:bookworm-slim

RUN useradd --uid 10000 -m appuser \
    && mkdir -p /data && chown appuser:appuser /data

COPY --from=builder /app/python-package-server /usr/local/bin/python-package-server

USER 10000
EXPOSE 8000
ENV STORAGE_DIR=/data

CMD ["/usr/local/bin/python-package-server"]
