//! Startup orphan reconciliation between metadata rows and stored bytes.
//!
//! NOTE (wiring agent): call [`reconcile`] once at startup, after the database
//! pool and storage directories are ready and before serving traffic.

use http_body_util::BodyExt;

use crate::{
    db::{MetadataBackend, MetadataStore},
    files::{cache_entry_expired, parse_sidecar, SIDECAR_PROJECT, SIDECAR_SUFFIX},
    storage::{bad_segment, Storage},
};

/// File rows older than this whose bytes are missing from storage are deleted.
const ORPHAN_ROW_AGE_SECS: i64 = 900;

/// Staging files older than this are swept as abandoned uploads.
const STAGING_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(3600);

/// Delete stale file rows whose objects never landed, then sweep old staging files.
///
/// Best-effort and infallible by design: every failure is logged and reconciliation
/// never fails startup. The DB unique constraint remains the sole duplicate arbiter;
/// this function only removes rows whose bytes are provably absent.
pub async fn reconcile(db: &MetadataBackend, storage: &Storage) {
    match db.list_orphan_candidates(ORPHAN_ROW_AGE_SECS).await {
        Ok(candidates) => {
            for (project, filename) in candidates {
                match storage.stat(&project, &filename).await {
                    Ok(None) => {
                        tracing::warn!(
                            project = project.as_str(),
                            filename = filename.as_str(),
                            "removing orphan file row (object missing from storage)"
                        );
                        if let Err(err) = db.delete_file(&project, &filename).await {
                            tracing::warn!(
                                project = project.as_str(),
                                filename = filename.as_str(),
                                error = %err,
                                "failed to delete orphan file row"
                            );
                        }
                    }
                    Ok(Some(_)) => {}
                    Err(err) => {
                        tracing::warn!(
                            project = project.as_str(),
                            filename = filename.as_str(),
                            error = %err,
                            "orphan check skipped: storage stat failed"
                        );
                    }
                }
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, "orphan reconciliation skipped: candidate listing failed");
        }
    }

    match storage.sweep_staging_older_than(STAGING_MAX_AGE) {
        Ok(removed) => {
            tracing::info!(removed, "staging sweep complete");
        }
        Err(err) => {
            tracing::warn!(error = %err, "staging sweep failed");
        }
    }
}

/// Evict expired pull-through cache entries, returning the evicted count.
///
/// Best-effort and infallible by design: every failure is logged and the
/// sweep never fails startup or the background loop. Each `*.sha256` sidecar
/// under `.upstream-cache` is read for its fetch stamp; entries past
/// `max_age_days` — including legacy unstamped sidecars, whose age is
/// unknown — are deleted (bytes + sidecar), but only after `db.get_file`
/// proves no hosted row shadows that key, re-checked immediately before
/// the bytes delete so a concurrent upload is never evicted. Hosted files
/// are never evicted.
/// `0` days disables the sweep entirely (returns 0 without listing).
/// Each eviction counts `upstream_cache_evictions_total{source="sweep"}`.
pub async fn sweep_upstream_cache(
    db: &MetadataBackend,
    storage: &Storage,
    max_age_days: u32,
) -> usize {
    if max_age_days == 0 {
        return 0;
    }
    let sidecars = match storage.list(SIDECAR_PROJECT).await {
        Ok(names) => names,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "upstream cache sweep skipped: sidecar listing failed"
            );
            return 0;
        }
    };
    let now = crate::upstream::now_unix_secs();
    let mut evicted = 0usize;
    for sidecar in &sidecars {
        let Some(stem) = sidecar.strip_suffix(SIDECAR_SUFFIX) else {
            continue;
        };
        // Normalized projects never contain `--` (separator runs collapse
        // to one dash), so the first separator marks the project/file
        // boundary even when the filename itself holds `--`.
        let Some((project, filename)) = stem.split_once("--") else {
            continue;
        };
        if bad_segment(project) || bad_segment(filename) {
            continue;
        }
        let cached_at = match read_sidecar_stamp(storage, sidecar).await {
            Some(stamp) => stamp,
            None => continue,
        };
        if !cache_entry_expired(max_age_days, cached_at, now) {
            continue;
        }
        // Hosted exemption first: a DB row shadows the cache, so a hosted
        // key is never evicted even with a stale sidecar beside it. A
        // failed lookup also skips: unverified keys are never deleted.
        if hosted_or_unverified(db, project, filename).await {
            continue;
        }
        // Re-check immediately before the bytes delete: an upload that
        // published between the first check and this delete must not lose
        // its bytes. This narrows the TOCTOU window to a single await
        // boundary; the upload-side sidecar cleanup removes the steady
        // state that makes the race reachable at all.
        if hosted_or_unverified(db, project, filename).await {
            continue;
        }
        // Bytes first: a crash between the deletes leaves a tiny orphan
        // sidecar the next sweep collects, never orphan bytes it can't see.
        if let Err(err) = storage.delete(project, filename).await {
            tracing::warn!(
                project,
                filename,
                error = %err,
                "upstream cache eviction failed: could not delete cached bytes"
            );
            continue;
        }
        if let Err(err) = storage.delete(SIDECAR_PROJECT, sidecar).await {
            tracing::warn!(
                project,
                filename,
                error = %err,
                "upstream cache eviction failed: could not delete sidecar"
            );
            continue;
        }
        tracing::info!(
            project,
            filename,
            "evicted expired upstream cache entry (sweep)"
        );
        metrics::counter!("upstream_cache_evictions_total", "source" => "sweep").increment(1);
        evicted += 1;
    }
    tracing::info!(evicted, "upstream cache sweep complete");
    evicted
}

/// Whether `(project, filename)` is hosted right now — or unverifiable.
///
/// Returns true (skip eviction) when a DB row shadows the key or when the
/// lookup itself failed: unverified keys are never deleted.
async fn hosted_or_unverified(db: &MetadataBackend, project: &str, filename: &str) -> bool {
    match db.get_file(project, filename).await {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(err) => {
            tracing::warn!(
                project,
                filename,
                error = %err,
                "upstream cache eviction skipped: hosted check failed"
            );
            true
        }
    }
}

/// Read one sidecar's fetch stamp (`None` stamp = legacy unknown age).
///
/// Returns `None` (skip this entry) when the sidecar vanished mid-sweep,
/// cannot be read, or holds no valid hash — garbage is not an entry.
async fn read_sidecar_stamp(storage: &Storage, sidecar: &str) -> Option<Option<u64>> {
    let found = match storage.get(SIDECAR_PROJECT, sidecar).await {
        Ok(found) => found,
        Err(err) => {
            tracing::warn!(
                sidecar,
                error = %err,
                "upstream cache sweep skipped entry: sidecar read failed"
            );
            return None;
        }
    };
    let (_, body) = found?;
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            tracing::warn!(
                sidecar,
                error = %err,
                "upstream cache sweep skipped entry: sidecar read failed"
            );
            return None;
        }
    };
    let text = std::str::from_utf8(&bytes).ok()?;
    parse_sidecar(text).map(|(_, cached_at)| cached_at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::{MemoryStore, NewFile},
        files::{format_sidecar, sidecar_filename},
    };

    async fn seed_entry(
        storage: &Storage,
        project: &str,
        filename: &str,
        bytes: &[u8],
        sidecar_body: &str,
    ) {
        let staged = storage.stage_path().unwrap();
        tokio::fs::write(&staged, bytes).await.unwrap();
        storage.put_file(project, filename, &staged).await.unwrap();
        let staged = storage.stage_path().unwrap();
        tokio::fs::write(&staged, sidecar_body.as_bytes())
            .await
            .unwrap();
        storage
            .put_file(
                SIDECAR_PROJECT,
                &sidecar_filename(project, filename),
                &staged,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sweep_evicts_only_expired_unhosted_entries() {
        const DAY: u64 = 86_400;
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::filesystem(dir.path().to_path_buf());
        storage.ensure_dirs().await.unwrap();
        let db = MetadataBackend::Memory(MemoryStore::new());
        let now = crate::upstream::now_unix_secs();
        let hash = "ab".repeat(32);

        // Expired entry: evicted (bytes + sidecar).
        seed_entry(
            &storage,
            "oldpkg",
            "oldpkg-1.0.tar.gz",
            b"old",
            &format_sidecar(&hash, now - 31 * DAY),
        )
        .await;
        // Fresh entry: kept.
        seed_entry(
            &storage,
            "newpkg",
            "newpkg-1.0.tar.gz",
            b"new",
            &format_sidecar(&hash, now),
        )
        .await;
        // Legacy unstamped sidecar: unknown age counts as expired.
        seed_entry(
            &storage,
            "legacypkg",
            "legacypkg-1.0.tar.gz",
            b"legacy",
            &hash,
        )
        .await;
        // Hosted key with an ancient sidecar: never evicted.
        seed_entry(
            &storage,
            "hostedpkg",
            "hostedpkg-1.0.tar.gz",
            b"hosted",
            &format_sidecar(&hash, 0),
        )
        .await;
        db.insert_file(&NewFile {
            project_normalized: "hostedpkg".to_string(),
            project_display: "HostedPkg".to_string(),
            filename: "hostedpkg-1.0.tar.gz".to_string(),
            version: "1.0".to_string(),
            sha256: hash.clone(),
            size_bytes: 6,
            requires_python: None,
            uploaded_by: "ci".to_string(),
        })
        .await
        .unwrap();
        // Garbage sidecar and stray key: not entries, left alone.
        seed_entry(
            &storage,
            "junkpkg",
            "junk-1.0.tar.gz",
            b"junk",
            "not-a-sidecar",
        )
        .await;
        let staged = storage.stage_path().unwrap();
        tokio::fs::write(&staged, b"note").await.unwrap();
        storage
            .put_file(SIDECAR_PROJECT, "note.txt", &staged)
            .await
            .unwrap();

        assert_eq!(sweep_upstream_cache(&db, &storage, 30).await, 2);

        for (project, filename) in [
            ("oldpkg", "oldpkg-1.0.tar.gz"),
            ("legacypkg", "legacypkg-1.0.tar.gz"),
        ] {
            assert!(
                storage.stat(project, filename).await.unwrap().is_none(),
                "{project}/{filename} bytes must be evicted"
            );
            assert!(
                storage
                    .stat(SIDECAR_PROJECT, &sidecar_filename(project, filename))
                    .await
                    .unwrap()
                    .is_none(),
                "{project}/{filename} sidecar must be evicted"
            );
        }
        for (project, filename) in [
            ("newpkg", "newpkg-1.0.tar.gz"),
            ("hostedpkg", "hostedpkg-1.0.tar.gz"),
            ("junkpkg", "junk-1.0.tar.gz"),
        ] {
            assert!(
                storage.stat(project, filename).await.unwrap().is_some(),
                "{project}/{filename} bytes must survive"
            );
            assert!(
                storage
                    .stat(SIDECAR_PROJECT, &sidecar_filename(project, filename))
                    .await
                    .unwrap()
                    .is_some(),
                "{project}/{filename} sidecar must survive"
            );
        }
        assert!(
            storage
                .stat(SIDECAR_PROJECT, "note.txt")
                .await
                .unwrap()
                .is_some(),
            "stray sidecar-dir key must survive"
        );
        // Hosted bytes are byte-identical, not merely present.
        let (_, body) = storage
            .get("hostedpkg", "hostedpkg-1.0.tar.gz")
            .await
            .unwrap()
            .expect("hosted bytes must survive");
        assert_eq!(
            body.collect().await.unwrap().to_bytes().as_ref(),
            &b"hosted"[..]
        );
    }

    #[tokio::test]
    async fn sweep_disabled_with_zero_ttl() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::filesystem(dir.path().to_path_buf());
        storage.ensure_dirs().await.unwrap();
        let db = MetadataBackend::Memory(MemoryStore::new());
        let hash = "ab".repeat(32);
        // Ancient stamp that a live TTL would evict.
        seed_entry(
            &storage,
            "oldpkg",
            "oldpkg-1.0.tar.gz",
            b"old",
            &format_sidecar(&hash, 0),
        )
        .await;

        assert_eq!(sweep_upstream_cache(&db, &storage, 0).await, 0);
        assert!(storage
            .stat("oldpkg", "oldpkg-1.0.tar.gz")
            .await
            .unwrap()
            .is_some());
        assert!(storage
            .stat(
                SIDECAR_PROJECT,
                &sidecar_filename("oldpkg", "oldpkg-1.0.tar.gz")
            )
            .await
            .unwrap()
            .is_some());
    }
}
