//! S3-compatible artifact storage (AWS S3 and S3-compatible endpoints
//! such as MinIO).
//!
//! Objects live under `{project}/{filename}` keys in one bucket. Uploads
//! still stage on local disk first (see [`FsBackend`]); this backend only
//! serves stored objects. Credentials and region resolution follow AWS
//! SDK conventions (environment, shared config, IMDS), with an optional
//! custom endpoint for S3-compatible services.

use std::path::Path;

use aws_sdk_s3::Client;
use axum::body::Body;

use crate::{
    config::Settings,
    storage::{bad_segment, FsBackend, StorageBackend, StorageError},
};

/// S3-backed storage. The local [`FsBackend`] is kept for upload staging.
#[derive(Clone)]
pub struct S3Backend {
    client: Client,
    bucket: String,
    staging: FsBackend,
}

impl std::fmt::Debug for S3Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Backend")
            .field("bucket", &self.bucket)
            .field("staging", &self.staging)
            .finish_non_exhaustive()
    }
}

impl S3Backend {
    /// Build a client from settings. No network I/O happens here beyond
    /// SDK credential/region resolution; the bucket is first touched by
    /// `health_check`.
    pub async fn from_settings(settings: &Settings) -> Result<Self, StorageError> {
        let bucket = settings
            .s3_bucket
            .clone()
            .ok_or_else(|| StorageError::Io("s3 backend requires S3_BUCKET".to_string()))?;
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        let mut builder = aws_sdk_s3::config::Builder::from(&sdk_config)
            .region(aws_sdk_s3::config::Region::new(settings.s3_region.clone()));
        if let Some(endpoint) = &settings.s3_endpoint_url {
            // Path-style addressing keeps bucket names out of DNS, which
            // S3-compatible endpoints on bare hosts/IPs require.
            builder = builder.endpoint_url(endpoint).force_path_style(true);
        }
        Ok(Self {
            client: Client::from_conf(builder.build()),
            bucket,
            staging: FsBackend::new(settings.storage_dir.clone()),
        })
    }

    /// Local staging backend (uploads buffer here before transfer).
    pub(crate) fn staging(&self) -> &FsBackend {
        &self.staging
    }

    fn key(project: &str, filename: &str) -> Result<String, StorageError> {
        if bad_segment(project) || bad_segment(filename) {
            return Err(StorageError::NotFound(format!("{project}/{filename}")));
        }
        Ok(format!("{project}/{filename}"))
    }
}

/// Format a single-range `Range` header value; `len` must be at least 1.
fn range_header(start: u64, len: u64) -> String {
    let end = start.saturating_add(len).saturating_sub(1);
    format!("bytes={start}-{end}")
}

/// Extract the total size from a `Content-Range` value (`bytes 0-3/42`).
fn total_from_content_range(value: Option<&str>) -> Option<u64> {
    value?.rsplit('/').next()?.parse::<u64>().ok()
}

#[allow(async_fn_in_trait)]
impl StorageBackend for S3Backend {
    async fn put_file(
        &self,
        _project: &str,
        _filename: &str,
        _src: &Path,
    ) -> Result<u64, StorageError> {
        // Landed with the write-path change; reads work without it.
        Err(StorageError::Io(
            "s3 put_file is not implemented yet".to_string(),
        ))
    }

    async fn get(
        &self,
        project: &str,
        filename: &str,
    ) -> Result<Option<(u64, Body)>, StorageError> {
        let key = Self::key(project, filename)?;
        let output = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(output) => output,
            Err(err) => {
                if err
                    .as_service_error()
                    .is_some_and(|svc| svc.is_no_such_key())
                {
                    return Ok(None);
                }
                return Err(StorageError::io("get object", err));
            }
        };
        let total = u64::try_from(output.content_length().unwrap_or(0)).unwrap_or(0);
        Ok(Some((total, Body::new(output.body.into_inner()))))
    }

    async fn get_range(
        &self,
        project: &str,
        filename: &str,
        start: u64,
        len: u64,
    ) -> Result<Option<(u64, u64, Body)>, StorageError> {
        let key = Self::key(project, filename)?;
        let output = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .range(range_header(start, len))
            .send()
            .await
        {
            Ok(output) => output,
            Err(err) => {
                if err
                    .as_service_error()
                    .is_some_and(|svc| svc.is_no_such_key())
                {
                    return Ok(None);
                }
                if err
                    .as_service_error()
                    .is_some_and(|svc| svc.meta().code() == Some("InvalidRange"))
                {
                    // The object shrank below `start` after the caller
                    // statted it; report its current size with no bytes.
                    let total = self.stat(project, filename).await?.unwrap_or(0);
                    return Ok(Some((total, 0, Body::empty())));
                }
                return Err(StorageError::io("get ranged object", err));
            }
        };
        let served = u64::try_from(output.content_length().unwrap_or(0)).unwrap_or(0);
        let total = total_from_content_range(output.content_range())
            .unwrap_or_else(|| start.saturating_add(served));
        Ok(Some((total, served, Body::new(output.body.into_inner()))))
    }

    async fn stat(&self, project: &str, filename: &str) -> Result<Option<u64>, StorageError> {
        let key = Self::key(project, filename)?;
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(output) => Ok(Some(
                u64::try_from(output.content_length().unwrap_or(0)).unwrap_or(0),
            )),
            Err(err) => {
                if err.as_service_error().is_some_and(|svc| svc.is_not_found()) {
                    return Ok(None);
                }
                Err(StorageError::io("stat object", err))
            }
        }
    }

    async fn delete(&self, project: &str, filename: &str) -> Result<(), StorageError> {
        let key = Self::key(project, filename)?;
        // S3 deletes are idempotent: a missing key is not an error.
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|err| StorageError::io("delete object", err))?;
        Ok(())
    }

    async fn health_check(&self) -> Result<(), StorageError> {
        self.client
            .head_bucket()
            .bucket(&self.bucket)
            .send()
            .await
            .map_err(|err| StorageError::io("bucket unreachable", err))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_object_keys_and_rejects_traversal() {
        assert_eq!(
            S3Backend::key("demo-pkg", "demo_pkg-1.0-py3-none-any.whl").unwrap(),
            "demo-pkg/demo_pkg-1.0-py3-none-any.whl"
        );
        for (project, filename) in [("..", "x.whl"), ("pkg", "../x.whl"), ("pkg", "a/b.whl")] {
            assert!(matches!(
                S3Backend::key(project, filename),
                Err(StorageError::NotFound(_))
            ));
        }
    }

    #[test]
    fn formats_range_headers() {
        assert_eq!(range_header(0, 5), "bytes=0-4");
        assert_eq!(range_header(10, 1), "bytes=10-10");
        assert_eq!(
            range_header(u64::MAX - 1, 5),
            "bytes=18446744073709551614-18446744073709551614"
        );
    }

    #[test]
    fn parses_content_range_totals() {
        assert_eq!(total_from_content_range(Some("bytes 0-4/42")), Some(42));
        assert_eq!(total_from_content_range(Some("bytes */42")), Some(42));
        assert_eq!(total_from_content_range(Some("bytes 0-4/*")), None);
        assert_eq!(total_from_content_range(None), None);
        assert_eq!(total_from_content_range(Some("garbage")), None);
    }
}
