# Storage backends: production default is S3

File bytes live either on a filesystem volume or in an S3-compatible
bucket, selected by `STORAGE_BACKEND` (`filesystem` or `s3`).
Postgres always holds the project/file index either way.

## Production: `k8s/overlays/s3`

Build this overlay for any real deployment:

```sh
kustomize build k8s/overlays/s3 | kubectl apply -f -
```

It sets `STORAGE_BACKEND=s3` with 2 replicas, per-pod `emptyDir`
upload staging (capped at 2 GiB), preferred pod anti-affinity plus
zone topology spread, and a PodDisruptionBudget (`minAvailable: 1`)
so node drains never take the API offline. Before applying, replace
the `REPLACE-ME-BUCKET` / `REPLACE-ME-REGION` placeholders and
provide credentials (env entries or your platform's IAM role); see
the comments in
[`k8s/overlays/s3/kustomization.yaml`](./overlays/s3/kustomization.yaml).
No application code change is needed to switch backends — the server
reads the same env contract in both modes.

## Single-node / dev only: base filesystem

The base deployment (`kustomize build k8s`) uses the `filesystem`
backend on a single `ReadWriteOnce` PVC, so exactly one pod can mount
the data volume. It runs `replicas: 1` and **must not be scaled**:
raising the replica count leaves the extra pods stuck in
`ContainerCreating` (volume already mounted elsewhere) while the
running pod keeps serving. Use it for local/dev clusters only; scale
out via the S3 overlay instead.
