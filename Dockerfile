# syntax=docker/dockerfile:1

# Chef base: official rust toolchain + pinned cargo-chef. Every Rust stage
# below inherits from here so the toolchain and chef versions stay in sync.
# (Chose `cargo install` over the lukemathwalker/cargo-chef image to keep
# the exact same rust:1-bookworm base and pin chef by version; tradeoff is
# one ~1-2 min chef compile on cold builds, cached as a layer afterwards.)
FROM rust:1-bookworm AS chef
WORKDIR /app
# Pinned for reproducibility (--locked uses cargo-chef's own lockfile).
RUN cargo install cargo-chef --version 0.1.78 --locked

# Planner: compute the dependency recipe from the manifests. This step
# re-runs on any file change but takes seconds; downstream stages only
# rebuild when recipe.json itself changes (manifest edits).
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Builder: cook all third-party dependencies, then compile only the
# workspace crates. Warm CI builds restore the cook layer from the
# registry cache (see .github/workflows/ci.yml), skipping the dependency
# compile entirely.
#
# Cook and build live in one stage on purpose: the cooked target/ and
# the cargo registry stay in this stage's own layer chain. Splitting
# them into a sibling "cacher" stage forced COPY --from layers of the
# whole target dir and cargo home into the builder, so every warm build
# downloaded and extracted the same artifacts several times over, and
# mode=max exported each duplicate to the cache.
#
# NOTE: no BuildKit cache mounts here on purpose. Cooked deps live in
# layers (restored via the registry cache), and a target-dir mount would
# shadow the cooked artifacts while adding export/import overhead — the
# mounts were the old bottleneck, layers replace them.
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Cargo.lock pins the exact tree chef cooks, and a lockfile-only change
# (e.g. `cargo update`) still invalidates this layer, so the cooked deps
# always match the final `cargo build --locked` resolution.
COPY Cargo.lock ./
RUN cargo chef cook --release --locked --recipe-path recipe.json
# Needs the real source AND ./migrations at compile time
# (sqlx::migrate! embeds them).
COPY . .
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
