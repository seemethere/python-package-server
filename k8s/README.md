# Kubernetes manifests (Kustomize)

## ⛔ Production Secret: create out-of-band, never commit

The Deployment needs a Secret named `package-server-secrets` with two keys:

| Key          | Content                                              |
| ------------ | ---------------------------------------------------- |
| `tokens`     | Token file bytes: one `user:token` line per user    |
| `DATABASE_URL` | Real Postgres URL (password is a real secret)      |

**The real Secret lives only in the cluster.** It is not in this directory
on purpose: `kustomization.yaml` does not reference
[`secret.example.yaml`](./secret.example.yaml), and nothing here will ever
generate it. Create it once per cluster, before the first deploy:

```sh
# 1. Generate tokens OUTSIDE the repo (stdout only; never commit the file).
scripts/generate-tokens.sh alice ci > /tmp/prod.tokens
chmod 600 /tmp/prod.tokens

# 2. Create the Secret out-of-band. The key MUST be named `tokens`: the
#    Deployment projects it as /secrets/auth/tokens (AUTH_TOKEN_FILE).
kubectl -n packages create secret generic package-server-secrets \
  --from-literal=DATABASE_URL='postgres://packages:REPLACE-ME-PASSWORD@postgres:5432/packages' \
  --from-file=tokens=/tmp/prod.tokens

# 3. Destroy the temp file.
shred -u /tmp/prod.tokens   # macOS: rm -P /tmp/prod.tokens
```

Full rotation steps, fail-closed behavior, and leak response:
[docs/prod-secrets.md](../docs/prod-secrets.md).

### REPLACE-ME rejection checklist (run before going live)

`secret.example.yaml` and the Deployment ship with `REPLACE-ME`
placeholders. The server does not special-case them, so grep them out of
your live configuration:

```sh
# 1. No placeholder tokens in the live Secret.
kubectl -n packages get secret package-server-secrets \
  -o jsonpath='{.data.tokens}' | base64 -d | grep -E 'REPLACE-ME|change-me' \
  && echo 'PLACEHOLDER SECRET IN PROD — fix before going live'

# 2. Real image (the base Deployment defaults to ghcr.io/REPLACE-ME/...).
kustomize build k8s | grep -E 'REPLACE-ME|change-me' \
  && echo 'PLACEHOLDER STILL IN MANIFESTS — fix before applying'

# 3. Real database host (example value is non-routable on purpose).
kubectl -n packages get secret package-server-secrets \
  -o jsonpath='{.data.DATABASE_URL}' | base64 -d; echo
```

### What failure looks like (all fail closed)

- **Secret missing:** pod cannot start (unmountable `secrets` volume).
- **`tokens` key empty / comment-only:** server exits(1)
  (`no users found; refusing to start with zero credentials`) and the pod
  CrashLoops — fix the Secret, do not work around it.
- **Malformed replacement during rotation:** server keeps the old
  credentials and logs `auth token reload failed`; fix the file and
  re-apply the Secret.

## Deploy

```sh
kustomize build k8s | kubectl apply -f -
kubectl -n packages port-forward svc/package-server 8000:8000
curl -s http://localhost:8000/health
```

Notes:

- Single replica with the default filesystem backend (`ReadWriteOnce`
  PVC, 10 Gi, cluster default StorageClass).
- For S3-backed storage, build `k8s/overlays/s3` instead: 2 replicas, no
  PVC (per-pod `emptyDir` staging), `STORAGE_BACKEND=s3`. Set the real
  bucket name in the overlay first.
- Probes: startup/readiness use deep `GET /health`; liveness uses shallow
  `GET /live` so a database outage marks the pod unready without
  restarting it.
