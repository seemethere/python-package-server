//! S3 storage integration tests against an S3-compatible endpoint.
//!
//! Skipped unless `TEST_S3_ENDPOINT` is set (CI provides MinIO). Test
//! credentials default to MinIO's `minioadmin`/`minioadmin`; override
//! with `TEST_S3_ACCESS_KEY_ID` / `TEST_S3_SECRET_ACCESS_KEY`. The test
//! bucket (`TEST_S3_BUCKET`, default `pps-test`) is created if needed.

use http_body_util::BodyExt;
use python_package_server::{config::Settings, s3::S3Backend, storage::Storage};
use std::path::PathBuf;

fn test_settings(endpoint: String, staging_dir: PathBuf) -> Settings {
    Settings {
        bind_addr: "127.0.0.1:0".to_string(),
        database_url: "postgres://localhost/packages".to_string(),
        storage_backend: "s3".to_string(),
        storage_dir: staging_dir,
        s3_bucket: Some(std::env::var("TEST_S3_BUCKET").unwrap_or_else(|_| "pps-test".to_string())),
        s3_region: Some(
            std::env::var("TEST_S3_REGION").unwrap_or_else(|_| "us-east-1".to_string()),
        ),
        s3_endpoint_url: Some(endpoint),
        auth_token_file: PathBuf::from("/dev/null"),
        max_upload_bytes: 1024 * 1024,
        upstream_url: None,
        upstream_index_ttl_secs: 300,
        upstream_private_only_projects: std::collections::HashSet::new(),
        policy_file: None,
        policy: python_package_server::config::Policy::default(),
    }
}

/// Create the test bucket with a raw SDK client using the same endpoint
/// and credentials the backend under test will resolve.
async fn ensure_bucket(settings: &Settings) {
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let client = aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::config::Builder::from(&sdk_config)
            .region(aws_sdk_s3::config::Region::new(
                settings
                    .s3_region
                    .clone()
                    .unwrap_or_else(|| "us-east-1".to_string()),
            ))
            .endpoint_url(settings.s3_endpoint_url.clone().unwrap())
            .force_path_style(true)
            .build(),
    );
    let bucket = settings.s3_bucket.as_deref().unwrap();
    match client.create_bucket().bucket(bucket).send().await {
        Ok(_) => {}
        Err(err) => {
            // Already-exists races with reruns are fine.
            let code = err
                .as_service_error()
                .map(|svc| svc.meta().code().unwrap_or_default().to_string())
                .unwrap_or_default();
            assert!(
                code.contains("BucketAlready"),
                "create bucket failed: {err}"
            );
        }
    }
}

#[tokio::test]
async fn s3_storage_roundtrip() {
    let Ok(endpoint) = std::env::var("TEST_S3_ENDPOINT") else {
        eprintln!("TEST_S3_ENDPOINT unset; skipping S3 tests");
        return;
    };
    // Seed SDK credential resolution for MinIO (CI sets the same).
    if std::env::var_os("AWS_ACCESS_KEY_ID").is_none() {
        std::env::set_var(
            "AWS_ACCESS_KEY_ID",
            std::env::var("TEST_S3_ACCESS_KEY_ID").unwrap_or_else(|_| "minioadmin".to_string()),
        );
        std::env::set_var(
            "AWS_SECRET_ACCESS_KEY",
            std::env::var("TEST_S3_SECRET_ACCESS_KEY").unwrap_or_else(|_| "minioadmin".to_string()),
        );
    }

    let tmp = tempfile::tempdir().unwrap();
    let settings = test_settings(endpoint, tmp.path().to_path_buf());
    ensure_bucket(&settings).await;
    let backend = S3Backend::from_settings(&settings)
        .await
        .expect("build s3 backend");
    let storage = Storage::s3(backend);
    storage.ensure_dirs().await.expect("staging dirs");
    storage.health_check().await.expect("bucket health");

    // Unique project per run so reruns against one bucket never collide.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let project = format!("ci-s3-{}-{nanos}", std::process::id());
    let filename = "demo_pkg-1.0-py3-none-any.whl";
    let bytes: &[u8] = b"s3-wheel-bytes-0123456789";

    // Publish from a staged file; success consumes the staging file.
    let (staged, mut file) = storage.create_staging_file().await.expect("staging");
    tokio::io::AsyncWriteExt::write_all(&mut file, bytes)
        .await
        .unwrap();
    drop(file);
    let size = storage
        .put_file(&project, filename, &staged)
        .await
        .expect("put object");
    assert_eq!(size, bytes.len() as u64);
    assert!(!staged.exists(), "staging file must be consumed");

    assert_eq!(
        storage.stat(&project, filename).await.unwrap(),
        Some(bytes.len() as u64)
    );

    let (total, body) = storage
        .get(&project, filename)
        .await
        .unwrap()
        .expect("object present");
    assert_eq!(total, bytes.len() as u64);
    let got = body.collect().await.unwrap().to_bytes();
    assert_eq!(&got[..], bytes);

    let (total, served, body) = storage
        .get_range(&project, filename, 3, 5)
        .await
        .unwrap()
        .expect("ranged object present");
    assert_eq!(total, bytes.len() as u64);
    assert_eq!(served, 5);
    let got = body.collect().await.unwrap().to_bytes();
    assert_eq!(&got[..], &bytes[3..8]);

    storage.delete(&project, filename).await.expect("delete");
    assert_eq!(storage.stat(&project, filename).await.unwrap(), None);
    assert!(storage.get(&project, filename).await.unwrap().is_none());
    // Deleting again is a no-op.
    storage.delete(&project, filename).await.expect("re-delete");
}
