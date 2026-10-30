# python-package-server

A private Python package server (PEP 503/691 simple index + twine uploads) written in Rust, with Postgres metadata and pluggable file storage.

## Features

- PEP 503 HTML simple index (`/simple/`, `/simple/{project}/`) and PEP 691 JSON
  (same URLs with `Accept: application/vnd.pypi.simple.v1+json`)
- Authenticated file downloads (`/files/{project}/{filename}`)
- Twine-compatible uploads via `POST /legacy/` (multipart `file_upload`)
- Token auth (`user:token` file) on all package routes; open `/health` and `/metrics`
- Optional OIDC Bearer JWT auth alongside tokens (any RS/ES OIDC issuer, discovery+JWKS)
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
| `OIDC_ISSUER_URL` | No       | —              | OIDC issuer base (http(s) URL with a host), e.g. `https://accounts.example.com`; unset or blank disables OIDC. |
| `OIDC_AUDIENCE`   | OIDC only | —             | Expected JWT audience; required when `OIDC_ISSUER_URL` is set, and setting it alone is an error. |
| `MAX_UPLOAD_BYTES`| No       | `1073741824`   | Max upload body in bytes (default 1 GiB).                |
| `RUST_LOG`        | No       | `info`         | Log filter, e.g. `info`, `debug`, `warn`.                |
| `UPSTREAM_URL`    | No       | —              | Upstream simple index base, e.g. `https://pypi.org/simple/`; unset disables pull-through. |
| `UPSTREAM_INDEX_TTL_SECS` | No | `300`         | TTL for cached upstream project index responses.         |
| `UPSTREAM_CACHE_MAX_AGE_DAYS` | No | `30`   | Max age in days for cached upstream file bytes; `0` never expires. |
| `UPSTREAM_PRIVATE_ONLY_PROJECTS` | No | —       | Comma-separated denylist of projects that never fetch upstream. |
| `POLICY_FILE`   | No       | —              | Path to the JSON quarantine policy file; unset disables quarantine. |

DB migrations are embedded in the binary and run automatically at startup.

With `STORAGE_BACKEND=s3`, credentials come from the standard AWS SDK
chain (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, shared config, IMDS).
The bucket must already exist: startup verifies it with `HeadBucket` and
exits on failure, so bad credentials, endpoints, or bucket names fail
fast instead of erroring per request. Uploads still stage on local disk
(`STORAGE_DIR`, 1 GiB default cap) and stream to the bucket. For a local
S3-compatible endpoint, `docker compose --profile s3 up s3mock` provides
an in-memory one with a pre-created `packages` bucket (development only;
see [docker-compose.yml](./docker-compose.yml)).

### Upstream pull-through (virtual repo)

Set `UPSTREAM_URL` (e.g. `https://pypi.org/simple/`) to merge a hosted
index with upstream GAR-style: `/simple/{project}/` returns hosted files
plus upstream files, with hosted winning on exact filename. Projects
listed in `UPSTREAM_PRIVATE_ONLY_PROJECTS` (comma-separated, normalized
like `Demo_Pkg` → `demo-pkg`) never fetch upstream. Upstream downloads
are sha256-verified against the index hash before caching, and cached
bytes keep serving while upstream is down (the merged index itself
returns `502` once its short cache expires). Index fetches time out
after 10s; file downloads after 600s. File URLs from the upstream index
are fetched server-side, so `UPSTREAM_URL` must be trusted.

Cached file bytes expire by age (`UPSTREAM_CACHE_MAX_AGE_DAYS`, default
30 days; `0` disables expiry), superseding the old v1 "no eviction"
behavior for age expiry (there is still no API to clear the cache).
Each cached entry records its fetch time in its `.upstream-cache`
sidecar. Expiry works two ways: lazily, a download whose entry is older
than the TTL re-fetches, re-verifies, and re-caches with a fresh stamp
(unexpired warm hits still serve with zero upstream I/O); and by sweep,
which deletes expired bytes + sidecars to reclaim disk — once at startup
and then every 6 hours in the background. Hosted files (anything with a
database row) are never evicted, even if a stale sidecar exists for the
same key. Sidecars written before timestamps existed carry no fetch time
and count as expired while a TTL applies, so they refresh once and gain
a stamp. Every eviction counts the `upstream_cache_evictions_total`
counter, labelled `source="lazy"` or `source="sweep"`.

### Upstream quarantine

Set `POLICY_FILE` to a JSON policy file to hold new upstream releases
for a soak period before they become visible or downloadable:

```json
{
  "default": { "upstream_quarantine_days": 3 },
  "packages": {
    "requests": { "upstream_quarantine_days": 10 },
    "torch": { "upstream_quarantine_days": 0 }
  }
}
```

An upstream file is hidden from `/simple/{project}/` and blocked on
`/files/...` until `upload-time + quarantine_days`, where the days come
from the per-package override or the global `default` (unlisted projects
use the default; `0` disables quarantine for that scope). Package names
normalize like everywhere else (`Requests` → `requests`). Quarantined
files 404 as if missing: an index with no hosted files and only
quarantined upstream files returns `404`, and downloads 404 even when
the bytes sit warm in the cache. Hosted files are never quarantined.

Fail-closed rules: an upstream file with unknown age (missing or
unparseable `upload-time`, or the HTML index fallback, which carries no
timestamps) is treated as quarantined whenever days apply. Likewise, if
the upstream index cannot be reached, quarantined-project downloads 404
— even with warm bytes cached — while `0`-day projects keep serving
warm bytes (outage tradeoff: quarantine needs fresh age metadata).

The file is read once at startup: a missing, unreadable, or malformed
file (unknown keys, negative/non-integer days, invalid project names)
fails startup, and policy changes need a restart to take effect. In
Kubernetes, edit `k8s/base/policy.json` and re-apply: the generated
ConfigMap name carries a content hash, so the Deployment rolls
automatically — no manual `rollout restart` needed. Filtered
files count in the `upstream_quarantine_filtered_total` counter, labelled
by `stage` (`index` or `download`).

## Auth

Package routes (`/simple/*`, `/files/*`, `/legacy/`) require auth (token or OIDC JWT);
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
(`{"new_owner": "<user>"}`; the target must be a known user unless OIDC is on — see OIDC below). The owner can
also yank or unyank a file (PEP 592; yanked files stay downloadable by
direct URL but installers skip them unless pinned) and permanently delete
it. See the API summary below.

### OIDC

Package routes also accept OIDC Bearer JWTs alongside tokens. Enable by
setting both `OIDC_ISSUER_URL` (the issuer base, e.g.
`https://accounts.example.com`) and `OIDC_AUDIENCE` (the expected JWT
audience). At startup the server fetches the issuer's discovery document
and JWKS, and fails startup if they are unreachable or mismatched (for
example a discovery `issuer` that does not match the configured URL).

Clients send the JWT as `Authorization: Bearer <JWT>`. Tokens must be
signed with RS256/384/512 or ES256/384; `iss`, `aud`, and `exp` are
always checked (`nbf` when present), with 60 seconds of clock-skew
leeway on `exp`/`nbf`. The authenticated principal is
`preferred_username` when present, else `email`, else the `sub` claim
(first non-blank wins; principals over 256 chars or with control
characters are rejected with 401). OIDC users have full parity with token users: index reads,
downloads, uploads (including claiming ownership of new or unclaimed
projects), and owner admin (yank/unyank/delete/transfer) all work the
same way.

pip sends Basic auth, not Bearer, so pass the JWT as the password with
the principal as the user (it must match the JWT principal exactly, or
the request is 401; if the principal is an email, percent-encode the
user, `@` → `%40`):

```sh
pip install \
  --index-url https://alice:<jwt>@packages.example.com/simple/ \
  mypackage
```

Tools that support Bearer headers can send `Authorization: Bearer <JWT>`
instead.

Notes and warnings:

- When OIDC is on, a JWT-shaped Bearer credential (three non-empty dot-separated
  parts) is always treated as a JWT. JWT-shaped opaque tokens in the
  token file are therefore rejected as Bearer credentials — though they
  still work via Basic auth — so don't use dotted opaque tokens.
- Enabling OIDC trusts the IdP for the whole username namespace,
  including names that also exist in the token file.
- Transfer accepts any non-empty trimmed new-owner name without
  control characters (except the current owner) when OIDC is on: the
  IdP is the directory, so spelling the name correctly is the
  operator's responsibility. With OIDC off, transfers still require the
  target to be a known token-file user.
- `AUTH_TOKEN_FILE` is still required: tokens remain a parallel auth
  path alongside OIDC.
- This version validates Bearer JWTs only; there is no browser
  login/session flow (no SSO redirect).

## API summary

| Method | Path                        | Auth | Description                                              |
| ------ | --------------------------- | ---- | -------------------------------------------------------- |
| GET    | `/`                         | Open | Service info JSON.                                       |
| GET    | `/health`                   | Open | Readiness: `200 {"status":"ok",...}` or `503` degraded when a dependency is down. |
| GET    | `/live`                     | Open | Liveness: always `200` while the process serves HTTP; no dependency checks. |
| GET    | `/metrics`                  | Open | Prometheus text exposition (trusted networks only; see Auth). |
| GET    | `/simple/`                  | Token or OIDC JWT | Project list (PEP 503 HTML; PEP 691 JSON with matching `Accept`). |
| GET    | `/simple/{project}/`        | Token or OIDC JWT | Project file list (PEP 503 HTML / PEP 691 JSON).         |
| GET    | `/files/{project}/{filename}` | Token or OIDC JWT | Download bytes; single `Range`, `If-None-Match`, and `If-Range` supported. |
| POST   | `/legacy/`                  | Token or OIDC JWT | Twine multipart `file_upload`; HTTP 200 JSON on success. |
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
`ghcr.io/seemethere/python-package-server:latest`, published by CI —
see [docs/image-publishing.md](./docs/image-publishing.md).

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
│   ├── oidc.rs        # OIDC JWT validation (discovery/JWKS)
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

- [x] Virtual/merged repos (upstream proxying)
- [x] OIDC Bearer JWT alongside token auth (browser SSO is not included)
- nginx read-through cache in front of `/files`

## License

Licensed under either MIT or Apache-2.0 at your option (`MIT OR Apache-2.0`,
matching `Cargo.toml`).
