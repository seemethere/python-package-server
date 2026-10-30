# Prod overlay

Production wiring on top of [../../base](../..): in-cluster Postgres
(`StatefulSet` + headless `Service` + persistent storage) and a TLS
`Ingress` for the app. The base `Deployment` is used unpatched, so probe
behaviour is unchanged: startup/readiness on deep `GET /health`, liveness
on shallow `GET /live` (a Postgres outage marks the app unready without
restart-looping it).

## Deploy

1. Pick your public hostname and TLS issuer, and edit
   [ingress.yaml](./ingress.yaml): replace `packages.example.com` and
   `REPLACE-ME-CLUSTER-ISSUER` (your cert-manager `ClusterIssuer`, e.g.
   `letsencrypt-prod`).

2. Create the real secret out-of-band (see
   [secret.example.yaml](./secret.example.yaml); never commit it).
   Generate a strong password — there is no default:

   ```sh
   PW=$(openssl rand -base64 32)
   kubectl -n packages create secret generic package-server-secrets \
     --from-literal=POSTGRES_PASSWORD="$PW" \
     --from-literal=DATABASE_URL="postgres://packages:${PW}@postgres:5432/packages" \
     --from-file=tokens=/path/to/tokens
   ```

3. Apply:

   ```sh
   kustomize build k8s/overlays/prod | kubectl apply -f -
   ```

4. Verify:

   ```sh
   kubectl -n packages rollout status statefulset/postgres
   kubectl -n packages rollout status deployment/package-server
   curl -s https://packages.example.com/health
   ```

## Notes

- Single-replica Postgres with a 10 Gi PVC on the cluster default
  `StorageClass`; no replication or failover. Back up with `pg_dump` on a
  schedule that fits your recovery objective.
- If you prefer managed Postgres, ignore this overlay: use the base
  kustomization and set `DATABASE_URL` to your managed instance (the
  `POSTGRES_PASSWORD` key is then unused and the StatefulSet never runs).
- `/metrics` is served through the same ingress rule as everything else.
  Keep it reachable only from trusted networks or your Prometheus scraper
  (firewall/ingress rules); do not publish it on a shared or public
  ingress.
