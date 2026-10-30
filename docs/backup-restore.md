# Backup and restore

Prod path is S3-first: Postgres holds metadata, the bucket holds file
bytes, and nightly `pg_dump` snapshots go to S3 via the
`package-server-postgres-backup` CronJob
([manifest](../k8s/base/postgres-backup-cronjob.yaml)). No real bucket or
credentials are committed — every value below marked `REPLACE-ME` is set
by the operator.

## Backup schedule

| What | How | Schedule |
|---|---|---|
| Postgres | CronJob: `pg_dump` (plain SQL, gzipped) to `s3://<backup-bucket>/postgres/pgdump-<UTC-timestamp>.sql.gz` | Daily `0 3 * * *` (UTC), `concurrencyPolicy: Forbid` |
| Package file bytes (S3 mode) | S3 versioning on the package bucket (every overwrite is recoverable) | Continuous |
| Package file bytes (filesystem mode) | No in-cluster backup; see "Filesystem mode" below | Manual |

The CronJob ships `suspend: true` so a default install never schedules
runs against the placeholder bucket. After setup (bucket, lifecycle
rules, credentials — see the manifest header), unsuspend it:

```sh
kubectl -n packages patch cronjob package-server-postgres-backup \
  -p '{"spec":{"suspend":false}}'
```

Trigger one run immediately to prove the path works, then watch it:

```sh
kubectl -n packages create job --from=cronjob/package-server-postgres-backup \
  backup-smoke-1
kubectl -n packages wait --for=condition=complete job/backup-smoke-1 \
  --timeout=600s
kubectl -n packages logs job/backup-smoke-1 -c s3-upload
```

## Retention

Retention is enforced server-side by S3 lifecycle rules, not by
in-job pruning (one mechanism, no failure noise from the backup job
itself). Review and apply the example (strip the `_comment` key —
S3 rejects unknown fields):

```sh
aws s3api put-bucket-lifecycle-configuration \
  --bucket REPLACE-ME-BACKUP-BUCKET \
  --lifecycle-configuration file://k8s/overlays/s3/bucket-lifecycle.example.json
```

Defaults in
[k8s/overlays/s3/bucket-lifecycle.example.json](../k8s/overlays/s3/bucket-lifecycle.example.json):

- `postgres/` dumps expire after 30 days; incomplete multipart uploads
  abort after 7 days.
- Old versions under `packages/` expire 90 days after being superseded
  (requires versioning, below); adjust the prefix to the real layout.

Enable versioning on the package bucket so overwrites/deletes stay
recoverable, and confirm it:

```sh
aws s3api put-bucket-versioning --bucket REPLACE-ME-BUCKET \
  --versioning-configuration Status=Enabled
aws s3api get-bucket-versioning --bucket REPLACE-ME-BUCKET
```

For S3-compatible endpoints (MinIO), add `--endpoint-url` to each
command, matching the CronJob's `S3_ENDPOINT_URL`.

## Failure visibility

- `failedJobsHistoryLimit: 5` keeps recent failures inspectable;
  `backoffLimit: 3` retries transient errors; `activeDeadlineSeconds:
  3600` bounds a stuck run.
- Check status:

  ```sh
  kubectl -n packages get cronjob package-server-postgres-backup
  kubectl -n packages get jobs -l app=package-server
  kubectl -n packages logs job/<failed-job> -c pg-dump
  kubectl -n packages logs job/<failed-job> -c s3-upload
  ```

- Alert on missed/failed runs (example for kube-state-metrics +
  Prometheus):

  ```yaml
  - alert: PostgresBackupFailing
    expr: |
      increase(kube_job_failed{job_name=~"package-server-postgres-backup-.*"}[25h]) > 0
      or
      (time() - kube_cronjob_status_last_successful_time{cronjob="package-server-postgres-backup"} > 26 * 3600)
    for: 15m
    labels: { severity: page }
  ```

## Restore runbook

Do a trial restore on a non-prod database first. Pick the dump to
restore (newest shown here):

```sh
aws s3 ls s3://REPLACE-ME-BACKUP-BUCKET/postgres/ | tail -5
aws s3 cp s3://REPLACE-ME-BACKUP-BUCKET/postgres/pgdump-REPLACE-ME-TIMESTAMP.sql.gz \
  /tmp/restore.sql.gz
gunzip -c /tmp/restore.sql.gz | head -c 300  # sanity: plain SQL, not empty
```

### 1. Restore Postgres

The dump is plain SQL with `--no-owner --no-privileges`, so it replays
with `psql` against a fresh database. Scale the server to zero first so
nothing writes mid-restore:

```sh
kubectl -n packages scale deploy/package-server --replicas=0

# Recreate a clean database (adjust host/user to your Postgres).
psql "$ADMIN_DATABASE_URL" \
  -c "DROP DATABASE IF EXISTS packages;" \
  -c "CREATE DATABASE packages OWNER packages;"
gunzip -c /tmp/restore.sql.gz | psql "$DATABASE_URL"

# Verify: migrations table and a row count look sane.
psql "$DATABASE_URL" -c "SELECT version FROM _sqlx_migrations ORDER BY version DESC LIMIT 3;"
psql "$DATABASE_URL" -c "SELECT count(*) FROM projects;" -c "SELECT count(*) FROM files;"
```

`$DATABASE_URL` is the app's connection string (same value as the
`DATABASE_URL` key in `package-server-secrets`); `$ADMIN_DATABASE_URL`
is a superuser connection to the same cluster.

### 2. Restore / verify file bytes (S3 mode)

File bytes normally need no restore — versioning keeps every object.
After a bad overwrite/delete, recover the previous version:

```sh
# List versions of one object, then fetch the last-good VersionId.
aws s3api list-object-versions --bucket REPLACE-ME-BUCKET \
  --prefix packages/REPLACE-ME-PROJECT/REPLACE-ME-FILE
aws s3api get-object --bucket REPLACE-ME-BUCKET \
  --key packages/REPLACE-ME-PROJECT/REPLACE-ME-FILE \
  --version-id REPLACE-ME-VERSION-ID /tmp/recovered-file
# Re-upload it as current (or copy the version onto itself).
aws s3 cp /tmp/recovered-file \
  s3://REPLACE-ME-BUCKET/packages/REPLACE-ME-PROJECT/REPLACE-ME-FILE
```

Verify the bucket the server points at still lists expected content:

```sh
aws s3 ls s3://REPLACE-ME-BUCKET/packages/ | head
```

### 3. Smoke-check

Scale the server back up and prove it serves from the restored state:

```sh
kubectl -n packages scale deploy/package-server --replicas=2  # 1 for filesystem mode
kubectl -n packages rollout status deploy/package-server
kubectl -n packages port-forward svc/package-server 8000:8000 &
curl -fsS http://localhost:8000/health
curl -fsS http://localhost:8000/simple/ | head -c 300
pip install --index-url http://localhost:8000/simple/ --no-deps REPLACE-ME-PROJECT==REPLACE-ME-VERSION
```

The runbook is green when `/health` returns ok, the index lists the
restored project, and `pip install` of a pinned version succeeds.

## Filesystem mode

The default base deployment stores file bytes on the `ReadWriteOnce`
PVC, which the CronJob does not back up. Options, in order of
preference:

1. Move prod to the S3 overlay (`k8s/overlays/s3`), where this runbook
   applies as written.
2. Snapshot the PVC with your storage provider / Velero on the same
   nightly schedule as the Postgres dump.
3. As a stopgap, sync the volume to S3 from a throwaway pod that mounts
   the same PVC (scale the server to 0 first — the PVC is RWO):

   ```sh
   kubectl -n packages run files-sync --rm -i --image=amazon/aws-cli:2.17.35 \
     --overrides='{"spec":{"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"package-server-data"}}],"containers":[{"name":"files-sync","image":"amazon/aws-cli:2.17.35","command":["sh","-c","aws s3 sync /data s3://REPLACE-ME-BACKUP-BUCKET/files-$(date -u +%Y%m%dT%H%M%SZ)/"],"volumeMounts":[{"name":"data","mountPath":"/data"}]}]}}'
   ```
