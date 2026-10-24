# python-package-server

A private Python package server (PEP 503/691 simple index + twine uploads) written in Rust, with Postgres metadata and pluggable file storage.

## Features

- PEP 503 HTML simple index (`/simple/`, `/simple/{project}/`) and PEP 691 JSON
  (same URLs with `Accept: application/vnd.pypi.simple.v1+json`)
- Authenticated file downloads (`/files/{project}/{filename}`)
- Twine-compatible uploads via `POST /legacy/` (multipart `file_upload`)
- Token auth (`user:token` file) on all package routes; open `/health` and `/metrics`
- Postgres-backed project/file index; file bytes on disk or in S3-compatible storage
- Embedded SQLx migrations run automatically at startup
- Prometheus metrics at `/metrics`, structured logging via `RUST_LOG`

## Architecture

Request flow:

```text
pip / uv / twine
      │  (Bearer/basic token on package routes)
      ▼
  axum server ──► Postgres (project + file index)
      │
      └──► disk (STORAGE_DIR: file bytes)
```

Storage split:

```text
+------------------+        +-------------------+
|  Postgres        |        |  Disk (STORAGE_DIR)|
|  project/file    |        |  wheel/sdist bytes |
|  index + hashes  |        |  served as         |
|  (source of      |        |  application/octet-|
|   truth for the  |        |  stream            |
|   index)         |        |                    |
+------------------+        +-------------------+
         ▲                           ▲
         └────── server ──────────────┘
```

## Quickstart (docker compose)

Prerequisites: Docker with the compose plugin.

```sh
# Start Postgres + the server (builds the image on first run).
docker compose up --build

# In another terminal: health check (open endpoint, no auth needed).
curl -s http://localhost:8000/health
# {"status":"ok",...}

# Service info.
curl -s http://localhost:8000/
```

Build a package, then upload with twine (dev credentials: user `dev`,
token from [dev.tokens](./dev.tokens)):

```sh
python -m build
python -m twine upload \
  --repository-url http://localhost:8000/legacy/ \
  -u dev -p dev-local-token-change-me \
  dist/*
```

Install from the private index with pip:

```sh
pip install \
  --index-url http://dev:dev-local-token-change-me@localhost:8000/simple/ \
  --trusted-host localhost \
  mypackage
```

Or with uv:

```sh
export UV_INDEX_URL="http://dev:dev-local-token-change-me@localhost:8000/simple/"
uv pip install --trusted-host localhost mypackage
```

Notes:

- `--trusted-host localhost` is needed only because local dev is plain HTTP;
  put TLS (ingress / reverse proxy) in front for anything shared.
- `docker compose up` mounts `./data` (file bytes) and `./dev.tokens`
  (read-only auth tokens) into the app container.

## Configuration

All configuration is via environment variables:

| Variable          | Required | Default        | Description                                              |
| ----------------- | -------- | -------------- | -------------------------------------------------------- |
| `BIND_ADDR`       | No       | `0.0.0.0:8000` | Socket address to listen on.                             |
| `DATABASE_URL`    | Yes      | —              | Postgres URL, e.g. `postgres://user:pass@db:5432/packages`. |
| `STORAGE_BACKEND` | No       | `filesystem`   | `filesystem` or `s3`.                                    |
| `STORAGE_DIR`     | No       | `/data`        | Filesystem root; for `s3`, the local upload staging dir. |
| `S3_BUCKET`       | S3 only  | —              | Bucket holding file bytes under `{project}/{filename}` keys. |
| `S3_REGION`       | No       | SDK chain      | Region override; unset uses `AWS_REGION`/profile/IMDS.   |
| `S3_ENDPOINT_URL` | No       | AWS S3         | S3-compatible endpoint, e.g. `http://minio:9000`.        |
| `AUTH_TOKEN_FILE` | Yes      | —              | Path to the token file (see Auth).                       |
| `MAX_UPLOAD_BYTES`| No       | `1073741824`   | Max upload body in bytes (default 1 GiB).                |
| `RUST_LOG`        | No       | `info`         | Log filter, e.g. `info`, `debug`, `warn`.                |

DB migrations are embedded in the binary and run automatically at startup.

With `STORAGE_BACKEND=s3`, credentials come from the standard AWS SDK
chain (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, shared config, IMDS).
The bucket must already exist: startup verifies it with `HeadBucket` and
exits on failure, so bad credentials, endpoints, or bucket names fail
fast instead of erroring per request. Uploads still stage on local disk
(`STORAGE_DIR`, 1 GiB default cap) and stream to the bucket. For local
MinIO, `docker compose --profile s3 up minio minio-init` creates a
`packages` bucket (see [docker-compose.yml](./docker-compose.yml)).

## Auth

Package routes (`/simple/*`, `/files/*`, `/legacy/`) require a token;
`GET /`, `GET /health`, and `GET /metrics` are open.

`/metrics` exposes request counts, latencies, and upload/download counters
labelled by route template. Keep it reachable only from trusted networks
or your Prometheus scraper (firewall/ingress rules); do not publish it on
a shared or public ingress.

Token file format (path given by `AUTH_TOKEN_FILE`):

```text
# lines starting with `#` are comments; blank lines are ignored
alice:8348f3c2-9d1a-4b7e-a5c2-9f6a1e7d0b42
ci:7c9e6679-7425-40de-944b-e07fc1f90ae7
```

Rotation: edit the file (or replace the mounted secret) — new tokens take
effect on the next request; no restart needed. Revoking a token is the same:
remove its line.

Project ownership: the first user to upload a project owns it, and only
that user may publish further files to it (`403` for everyone else).
Downloads and index reads stay open to every authenticated user. Projects
created before ownership was introduced are claimed by their next uploader
(or by the first user to administer them via the endpoints below).
Transfer ownership with `POST /admin/projects/{project}/transfer`
(`{"new_owner": "<user>"}`; the target must be a known user). The owner can
also yank or unyank a file (PEP 592; yanked files stay downloadable by
direct URL but installers skip them unless pinned) and permanently delete
it. See the API summary below.

## API summary

| Method | Path                        | Auth | Description                                              |
| ------ | --------------------------- | ---- | -------------------------------------------------------- |
| GET    | `/`                         | Open | Service info JSON.                                       |
| GET    | `/health`                   | Open | Readiness: `200 {"status":"ok",...}` or `503` degraded when a dependency is down. |
| GET    | `/live`                     | Open | Liveness: always `200` while the process serves HTTP; no dependency checks. |
| GET    | `/metrics`                  | Open | Prometheus text exposition (trusted networks only; see Auth). |
| GET    | `/simple/`                  | Yes  | Project list (PEP 503 HTML; PEP 691 JSON with matching `Accept`). |
| GET    | `/simple/{project}/`        | Yes  | Project file list (PEP 503 HTML / PEP 691 JSON).         |
| GET    | `/files/{project}/{filename}` | Yes | Download bytes; single `Range`, `If-None-Match`, and `If-Range` supported. |
| POST   | `/legacy/`                  | Yes  | Twine multipart `file_upload`; HTTP 200 JSON on success. |
| POST   | `/admin/projects/{project}/files/{filename}/yank` | Owner | Yank a file (PEP 592); optional JSON `{"reason": "..."}`. |
| POST   | `/admin/projects/{project}/files/{filename}/unyank` | Owner | Clear a file's yank. |
| DELETE | `/admin/projects/{project}/files/{filename}` | Owner | Permanently delete a file (row + bytes). |
| POST   | `/admin/projects/{project}/transfer` | Owner | Transfer ownership; JSON `{"new_owner": "<user>"}`. |

## Local development

Prerequisites: Rust stable toolchain (rustup) with clippy + rustfmt.

```sh
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Most tests use an in-memory store, so no live Postgres is needed for
`cargo test`. Postgres-backed tests in `tests/postgres.rs` run only when
`TEST_DATABASE_URL` is set (CI sets it against a Postgres service); they
skip otherwise.

Run the server locally (needs Postgres + a token file):

```sh
export DATABASE_URL=postgres://packages:packages@localhost:5432/packages
export AUTH_TOKEN_FILE=$PWD/dev.tokens
export STORAGE_DIR=$PWD/data
mkdir -p "$STORAGE_DIR"
cargo run
```

## Kubernetes

Manifests live in [k8s/](./k8s/) (Kustomize). The image defaults to
`ghcr.io/REPLACE-ME/python-package-server:0.1.0` — replace with your registry.

1. Create the real secret out-of-band (see
   [k8s/secret.example.yaml](./k8s/secret.example.yaml); never commit it):

   ```sh
   kubectl -n packages create secret generic package-server-secrets \
     --from-literal=DATABASE_URL='postgres://packages:PASSWORD@postgres:5432/packages' \
     --from-file=tokens=/path/to/tokens
   ```

   The secret key MUST be named `tokens`: the deployment projects it as the
   file `/secrets/auth/tokens`, which the server reads as `AUTH_TOKEN_FILE`.

2. Deploy:

   ```sh
   kustomize build k8s | kubectl apply -f -
   ```

3. Test via port-forward:

   ```sh
   kubectl -n packages port-forward svc/package-server 8000:8000
   curl -s http://localhost:8000/health
   ```

Notes:

- Single replica with the default filesystem backend: the data volume is
  a `ReadWriteOnce` PVC, so only one pod can mount it. The PVC uses the
  cluster default StorageClass and requests 10 Gi.
- For S3-backed storage, build `k8s/overlays/s3` instead: 2 replicas, no
  PVC (staging is per-pod `emptyDir`), `STORAGE_BACKEND=s3`. Set the real
  bucket name in the overlay first (see its comments).
- Probes: startup/readiness use deep `GET /health`; liveness uses shallow
  `GET /live` so a database outage marks the pod unready without restarting it.

## Project layout

```text
.
├── src/
│   ├── main.rs        # binary entrypoint (bind, migrate, serve)
│   ├── config.rs      # env-based Settings
│   ├── auth.rs        # token-file auth
│   ├── db.rs          # Postgres project/file index
│   ├── storage.rs     # file-byte storage dispatch + filesystem backend
│   ├── s3.rs          # S3-compatible storage backend
│   ├── simple.rs      # PEP 503/691 index handlers
│   ├── files.rs       # download handler
│   ├── upload.rs      # twine legacy upload handler
│   ├── admin.rs       # owner-only yank/delete/transfer handlers
│   ├── packaging.rs   # filename/metadata parsing helpers
│   └── error.rs       # error types
├── migrations/        # embedded SQLx migrations (run at startup)
├── k8s/               # Kustomize manifests + secret example
├── Dockerfile         # multi-stage build (rust builder, slim runtime)
├── docker-compose.yml # local Postgres + app
├── dev.tokens         # DEV-ONLY local auth tokens
└── .github/workflows/ci.yml
```

## Roadmap

- Virtual/merged repos (upstream proxying)
- OIDC SSO alongside token auth
- nginx read-through cache in front of `/files`

## License

Licensed under either MIT or Apache-2.0 at your option (`MIT OR Apache-2.0`,
matching `Cargo.toml`).
