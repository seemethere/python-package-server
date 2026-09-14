//! Startup orphan reconciliation between metadata rows and stored bytes.
//!
//! NOTE (wiring agent): call [`reconcile`] once at startup, after the database
//! pool and storage directories are ready and before serving traffic.

use crate::{
    db::{MetadataBackend, MetadataStore},
    storage::Storage,
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
