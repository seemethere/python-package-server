# Image publishing

The production container image is built and pushed to GHCR by CI —
no manual `docker push` needed.

## Flow

- The `publish` job in [.github/workflows/ci.yml](../.github/workflows/ci.yml)
  runs on pushes to `main` and on version tags (`v*`), after the `test`
  job passes. PRs (and other branches) run the `docker` job, which
  builds the same Dockerfile **without pushing**.
- Auth is the built-in `GITHUB_TOKEN` with `packages: write`; no stored
  credentials. The image is `ghcr.io/seemethere/python-package-server`
  (spelled `ghcr.io/${{ github.repository }}` in the workflow so forks
  and renames keep working).
- Builds reuse the shared `:buildcache` registry cache, so publishes
  only compile what changed.

## Tags

Produced by `docker/metadata-action` per push:

| Push to       | Tags pushed                                             |
| ------------- | ------------------------------------------------------- |
| `main`        | `latest`, `main`, `sha-<short-sha>`                     |
| `v1.2.3` tag  | `v1.2.3`, `1.2.3`, `1.2`, `1`, `sha-<short-sha>`        |

(`latest` comes from the action's default `latest=auto` flavor: it is
only attached on default-branch pushes, never on tags.)

## Releasing

```sh
git tag v1.2.3
git push origin v1.2.3
```

CI publishes the semver tags above. Then point the deployment at the
release — either edit `k8s/base/deployment.yaml`, or pin the exact
digest for a reproducible deploy:

```sh
DIGEST=$(docker buildx imagetools inspect \
  ghcr.io/seemethere/python-package-server:1.2.3 \
  --format '{{json .Manifest.digest}}' | tr -d '"')
kubectl -n packages set image deployment/package-server \
  "package-server=ghcr.io/seemethere/python-package-server@${DIGEST}"
```

## First-publish note

The `python-package-server` package is created on the first successful
`publish` run. New GHCR packages owned by a personal account start
private; if deploys from other clusters or users need to pull it, flip
the package visibility to public (package page → Settings → Change
visibility) or create a pull secret with a `read:packages`-scoped
token.
