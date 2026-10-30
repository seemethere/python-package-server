# Production secrets

How to create, rotate, and never leak the production auth tokens and
database credentials for python-package-server.

## Ground rules

- The real Secret (`package-server-secrets`) is created **out-of-band**
  with `kubectl` (see [k8s/README.md](../k8s/README.md)). It is **never**
  committed to git — not as YAML, not as env files, not in docs.
- `dev.tokens` at the repo root is **dev-only**: a documented placeholder
  (`dev-local-token-change-me`) for `docker compose` and local runs. Never
  point production `AUTH_TOKEN_FILE` at it, and never copy a real token
  into it.
- CI runs gitleaks on every push/PR and **fails on committed secrets**
  (see [`.gitleaks.toml`](../.gitleaks.toml)). Only the documented dev-only
  placeholder is allowlisted.
- Example values in docs and manifests use `REPLACE-ME` placeholders. The
  server does not special-case them — treat any `REPLACE-ME` (or
  `dev-local-token-change-me`) value in production as a misconfiguration to
  fix before going live. Suggested pre-deploy check:

  ```sh
  kubectl -n packages get secret package-server-secrets \
    -o jsonpath='{.data.tokens}' | base64 -d | grep -E 'REPLACE-ME|change-me' \
    && echo 'PLACEHOLDER SECRET IN PROD — fix before going live'
  ```

## Fail-closed behavior (know what to expect)

- **Empty token file at startup:** the server exits(1) with
  `no users found; refusing to start with zero credentials`. An empty or
  comment-only `tokens` key therefore CrashLoops the pod instead of serving
  traffic unauthenticated — that is the intended signal that the Secret is
  missing or malformed.
- **Bad rotation:** if the mounted token file is replaced with malformed or
  empty contents, the server keeps the previously loaded credentials and
  logs a warning; it retries once the file changes again. Rotation is
  atomic-safe: a file briefly missing mid-replace does not log anyone out.
- **Missing Secret:** without `package-server-secrets` the pod cannot start
  (unmountable `secrets` volume), so there is no window serving without auth.

## Generating production tokens

Use the repo script (writes to stdout only — redirect outside the repo):

```sh
scripts/generate-tokens.sh alice ci > /tmp/prod.tokens
chmod 600 /tmp/prod.tokens
cat /tmp/prod.tokens   # verify: one `user:64-hex-chars` line per user
```

Tokens are 32 random bytes (256-bit), hex-encoded. The generator prefers
`openssl rand` and falls back to `/dev/urandom`. Never commit the output:
`.gitignore` excludes `prod.tokens`, `tokens`, and `*.tokens.generated`.

## Creating the production Secret

```sh
kubectl -n packages create secret generic package-server-secrets \
  --from-literal=DATABASE_URL='postgres://packages:REPLACE-ME-PASSWORD@postgres:5432/packages' \
  --from-file=tokens=/tmp/prod.tokens
shred -u /tmp/prod.tokens   # or: rm -P /tmp/prod.tokens (macOS)
```

The secret key **must** be named `tokens`: the Deployment projects it as
`/secrets/auth/tokens`, which the server reads via `AUTH_TOKEN_FILE`.
`DATABASE_URL` must be the real production URL — the
`k8s/secret.example.yaml` value is a non-routable placeholder.

Verify:

```sh
kubectl -n packages get secret package-server-secrets -o jsonpath='{.data}' \
  | python3 -c 'import json,sys; print(sorted(json.load(sys.stdin)))'
# expect: ['DATABASE_URL', 'tokens']
```

## Rotating tokens (no restart needed)

The server watches the token file's mtime and reloads on the next request.
Rotation is: generate → update Secret → confirm → retire old tokens.

```sh
# 1. Generate the new token file (keep old lines until cutover is confirmed).
scripts/generate-tokens.sh alice > /tmp/prod.tokens.new
cat /tmp/prod.tokens.new >> /tmp/prod.tokens   # dup users: last line wins

# 2. Push it into the Secret (kubelet re-projects the file within ~1 min).
kubectl -n packages create secret generic package-server-secrets \
  --from-literal=DATABASE_URL="$(kubectl -n packages get secret package-server-secrets \
    -o jsonpath='{.data.DATABASE_URL}' | base64 -d)" \
  --from-file=tokens=/tmp/prod.tokens \
  --dry-run=client -o yaml | kubectl -n packages apply -f -

# 3. Confirm the new token works (then distribute it to the user out-of-band).
NEW_TOKEN='<paste the new token here>'
curl -s -o /dev/null -w '%{http_code}\n' -u "alice:$NEW_TOKEN" \
  http://localhost:8000/simple/
unset NEW_TOKEN

# 4. Retire the old line from /tmp/prod.tokens, re-apply as in step 2,
#    and securely delete the temp files.
```

Notes:

- Duplicate usernames: the **last** line wins, and the old token stops
  working on reload. Keep the overlap window short.
- Revoking a user/token is the same flow: remove their line and re-apply.
- Never rotate **down to zero** users: an empty replacement is ignored
  (old credentials kept), and a fresh pod with an empty file refuses to
  start.
- If the new file is malformed, the server logs
  `auth token reload failed ... keeping current credentials` and keeps
  serving with the old ones — fix the file and re-apply.

## If a secret leaks

1. Rotate immediately (above) — assume the leaked credential is compromised.
2. Purge it from git history if committed (`git filter-repo`, then
   force-push and rotate again if the old value was ever in the repo).
3. Check gitleaks did not get weaker: `.gitleaks.toml` must only allowlist
   the documented non-secrets (dev-only placeholder + the one test-only
   fixture key), never real-looking values.
