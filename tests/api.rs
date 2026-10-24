//! Integration tests: full router with in-memory metadata and tempdir storage.
//!
//! No network or live Postgres required.

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use python_package_server::{
    auth::Auth,
    build_router,
    config::Settings,
    db::{MemoryStore, MetadataBackend, MetadataStore, NewFile},
    state::AppState,
    storage::Storage,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tower::ServiceExt;

fn test_settings(storage_dir: PathBuf) -> Settings {
    Settings {
        bind_addr: "127.0.0.1:0".to_string(),
        database_url: "postgres://localhost/packages".to_string(),
        storage_backend: "filesystem".to_string(),
        storage_dir,
        auth_token_file: PathBuf::from("/dev/null"),
        max_upload_bytes: 1024 * 1024,
    }
}

async fn test_app() -> (Router, AppState, tempfile::TempDir) {
    test_app_with_cap(1024 * 1024).await
}

async fn test_app_with_cap(max_upload_bytes: u64) -> (Router, AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let mut settings = test_settings(tmp.path().to_path_buf());
    settings.max_upload_bytes = max_upload_bytes;
    let storage = Storage::filesystem(settings.storage_dir.clone());
    storage.ensure_dirs().await.unwrap();
    let db = MetadataBackend::Memory(MemoryStore::new());
    let auth = Auth::from_pairs(vec![("ci".to_string(), "secret".to_string())]);
    // build_recorder (not install) avoids global-recorder conflicts across tests.
    let metrics = metrics_exporter_prometheus::PrometheusBuilder::new()
        .build_recorder()
        .handle();
    let state = AppState {
        db,
        storage,
        auth,
        metrics,
        settings: Arc::new(settings),
    };
    let router = build_router(state.clone());
    (router, state, tmp)
}

fn basic_auth(user: &str, pass: &str) -> String {
    use base64::Engine;
    let raw = format!("{user}:{pass}");
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
    )
}

fn bearer_auth(token: &str) -> String {
    format!("Bearer {token}")
}

fn good_auth() -> String {
    basic_auth("ci", "secret")
}

/// Build a multipart/form-data body with text fields plus an optional file part.
fn build_multipart(
    boundary: &str,
    text_fields: &[(&str, &str)],
    file: Option<(&str, &str, &[u8])>,
) -> Vec<u8> {
    let mut body = build_multipart_no_close(boundary, text_fields, file);
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

/// Build a multipart body with text fields both before AND after the file part.
fn build_multipart_trailing(
    boundary: &str,
    leading_fields: &[(&str, &str)],
    file: Option<(&str, &str, &[u8])>,
    trailing_fields: &[(&str, &str)],
) -> Vec<u8> {
    let mut body = build_multipart_no_close(boundary, leading_fields, file);
    for (name, value) in trailing_fields {
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
                .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

fn build_multipart_no_close(
    boundary: &str,
    text_fields: &[(&str, &str)],
    file: Option<(&str, &str, &[u8])>,
) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, value) in text_fields {
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
                .as_bytes(),
        );
    }
    if let Some((field, filename, bytes)) = file {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    body
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

async fn body_bytes(body: Body) -> Vec<u8> {
    body.collect().await.unwrap().to_bytes().to_vec()
}

async fn body_text(body: Body) -> String {
    String::from_utf8(body_bytes(body).await).unwrap()
}

fn staging_is_empty(storage_dir: &Path) -> bool {
    let tmp = storage_dir.join(".tmp");
    match std::fs::read_dir(&tmp) {
        Ok(entries) => entries.count() == 0,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
    }
}

fn get_request(uri: &str, auth: Option<String>, accept: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(value) = auth {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    if let Some(accept) = accept {
        builder = builder.header(header::ACCEPT, accept);
    }
    builder.body(Body::empty()).unwrap()
}

fn post_upload_request(auth: Option<String>, body: Vec<u8>, boundary: &str) -> Request<Body> {
    let mut builder = Request::builder().method("POST").uri("/legacy/");
    if let Some(value) = auth {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    builder
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap()
}

const BOUNDARY: &str = "testboundary123";
const PROJECT: &str = "Demo-Pkg";
const NORMALIZED: &str = "demo-pkg";
const VERSION: &str = "1.2.3";
const FILENAME: &str = "demo-pkg-1.2.3.tar.gz";
const FILE_BYTES: &[u8] = b"fake-sdist-bytes-for-testing-123";
const REQUIRES_PYTHON: &str = ">=3.8";
const JSON_ACCEPT: &str = "application/vnd.pypi.simple.v1+json";

fn upload_fields(digest: &str) -> Vec<(&'static str, String)> {
    vec![
        (":action", "file_upload".to_string()),
        ("name", PROJECT.to_string()),
        ("version", VERSION.to_string()),
        ("sha256_digest", digest.to_string()),
        ("requires_python", REQUIRES_PYTHON.to_string()),
    ]
}

fn upload_body(file_bytes: &[u8], digest_override: Option<&str>) -> Vec<u8> {
    let digest = digest_override.map_or_else(|| sha256_hex(file_bytes), |s| s.to_string());
    let fields = upload_fields(&digest);
    let refs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    build_multipart(BOUNDARY, &refs, Some(("content", FILENAME, file_bytes)))
}

#[tokio::test]
async fn health_is_open() {
    let (app, _state, _tmp) = test_app().await;
    let res = app
        .oneshot(get_request("/health", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["db"], "up");
    assert_eq!(json["storage"], "up");
    assert!(json["version"].is_string());
}

#[tokio::test]
async fn liveness_is_open() {
    let (app, _state, _tmp) = test_app().await;
    let res = app.oneshot(get_request("/live", None, None)).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert!(json["version"].is_string());
}

#[tokio::test]
async fn metrics_is_open() {
    let (app, _state, _tmp) = test_app().await;
    let res = app
        .oneshot(get_request("/metrics", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn root_is_open() {
    let (app, _state, _tmp) = test_app().await;
    let res = app.oneshot(get_request("/", None, None)).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["service"], "python-package-server");
    assert!(json["version"].is_string());
    let endpoints = json["endpoints"].as_array().unwrap();
    assert!(endpoints.iter().any(|e| e == "/health"));
}

#[tokio::test]
async fn auth_matrix_rejects_unauthorized() {
    let bad_basic = basic_auth("ci", "wrong");
    let bad_bearer = bearer_auth("wrong-token");
    let empty = String::new();
    let cases: Vec<Option<String>> = vec![None, Some(bad_basic), Some(bad_bearer), Some(empty)];
    for auth in &cases {
        // GET /simple/
        {
            let (app, _, _tmp) = test_app().await;
            let res = app
                .oneshot(get_request("/simple/", auth.clone(), None))
                .await
                .unwrap();
            assert_eq!(
                res.status(),
                StatusCode::UNAUTHORIZED,
                "GET /simple/ auth={auth:?}"
            );
        }
        // GET /simple/{project}/
        {
            let (app, _, _tmp) = test_app().await;
            let res = app
                .oneshot(get_request("/simple/demo-pkg/", auth.clone(), None))
                .await
                .unwrap();
            assert_eq!(
                res.status(),
                StatusCode::UNAUTHORIZED,
                "GET /simple/demo-pkg/ auth={auth:?}"
            );
        }
        // GET /files/a/b
        {
            let (app, _, _tmp) = test_app().await;
            let res = app
                .oneshot(get_request("/files/a/b", auth.clone(), None))
                .await
                .unwrap();
            assert_eq!(
                res.status(),
                StatusCode::UNAUTHORIZED,
                "GET /files/a/b auth={auth:?}"
            );
        }
        // POST /legacy/
        {
            let (app, _, _tmp) = test_app().await;
            let req = Request::builder().method("POST").uri("/legacy/").header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={BOUNDARY}"),
            );
            let req = if let Some(value) = auth.clone() {
                req.header(header::AUTHORIZATION, value)
            } else {
                req
            };
            let req = req.body(Body::empty()).unwrap();
            let res = app.oneshot(req).await.unwrap();
            assert_eq!(
                res.status(),
                StatusCode::UNAUTHORIZED,
                "POST /legacy/ auth={auth:?}"
            );
        }
    }
    // Sanity: valid auth reaches the handler (empty index is 200, not 401).
    let (app, _, _tmp) = test_app().await;
    let res = app
        .oneshot(get_request("/simple/", Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn upload_happy_path_index_and_download() {
    let (app, state, _tmp) = test_app().await;
    let expected_digest = sha256_hex(FILE_BYTES);
    let body = upload_body(FILE_BYTES, None);

    // Upload.
    let res = app
        .oneshot(post_upload_request(Some(good_auth()), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["name"], PROJECT);
    assert_eq!(json["version"], VERSION);
    assert_eq!(json["filename"], FILENAME);
    assert_eq!(json["sha256"], expected_digest);
    assert_eq!(json["size_bytes"], FILE_BYTES.len() as u64);

    // Project HTML contains filename + sha256 fragment.
    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/simple/{NORMALIZED}/"),
            Some(good_auth()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res.into_body()).await;
    assert!(html.contains(FILENAME), "html missing filename: {html}");
    assert!(
        html.contains(&format!("#sha256={expected_digest}")),
        "html missing sha256 fragment: {html}"
    );

    // Project JSON shape incl. requires-python + content-type.
    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/simple/{NORMALIZED}/"),
            Some(good_auth()),
            Some(JSON_ACCEPT),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let content_type = res
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        content_type.contains("application/vnd.pypi.simple.v1+json"),
        "unexpected content-type: {content_type}"
    );
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["name"], PROJECT);
    assert_eq!(json["files"][0]["filename"], FILENAME);
    assert_eq!(json["files"][0]["hashes"]["sha256"], expected_digest);
    assert_eq!(json["files"][0]["requires-python"], REQUIRES_PYTHON);

    // Index HTML lists the project.
    let res = build_router(state.clone())
        .oneshot(get_request("/simple/", Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res.into_body()).await;
    assert!(html.contains(PROJECT), "index html missing project: {html}");
    assert!(html.contains(NORMALIZED));

    // Index JSON lists the project.
    let res = build_router(state.clone())
        .oneshot(get_request(
            "/simple/",
            Some(good_auth()),
            Some(JSON_ACCEPT),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let names: Vec<String> = json["projects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_string())
        .collect();
    assert!(names.contains(&PROJECT.to_string()), "names={names:?}");

    // Download returns exact bytes.
    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/files/{NORMALIZED}/{FILENAME}"),
            Some(good_auth()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = body_bytes(res.into_body()).await;
    assert_eq!(bytes, FILE_BYTES);
}

fn download_request(
    range: Option<&str>,
    if_none_match: Option<&str>,
    if_range: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method("GET")
        .uri(format!("/files/{NORMALIZED}/{FILENAME}"))
        .header(header::AUTHORIZATION, good_auth());
    if let Some(value) = range {
        builder = builder.header(header::RANGE, value);
    }
    if let Some(value) = if_none_match {
        builder = builder.header(header::IF_NONE_MATCH, value);
    }
    if let Some(value) = if_range {
        builder = builder.header(header::IF_RANGE, value);
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn range_downloads_serve_single_ranges() {
    let (app, state, _tmp) = test_app().await;
    let body = upload_body(FILE_BYTES, None);
    let res = app
        .oneshot(post_upload_request(Some(good_auth()), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let total = FILE_BYTES.len();

    // Bounded range.
    let res = build_router(state.clone())
        .oneshot(download_request(Some("bytes=0-4"), None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        res.headers().get(header::CONTENT_RANGE).unwrap(),
        &format!("bytes 0-4/{total}")
    );
    assert_eq!(res.headers().get(header::ACCEPT_RANGES).unwrap(), "bytes");
    let bytes = body_bytes(res.into_body()).await;
    assert_eq!(bytes, FILE_BYTES[0..5]);

    // Open-ended and suffix ranges.
    let res = build_router(state.clone())
        .oneshot(download_request(Some("bytes=10-"), None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
    let bytes = body_bytes(res.into_body()).await;
    assert_eq!(bytes, FILE_BYTES[10..]);
    let res = build_router(state.clone())
        .oneshot(download_request(Some("bytes=-4"), None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
    let bytes = body_bytes(res.into_body()).await;
    assert_eq!(bytes, FILE_BYTES[total - 4..]);

    // Out-of-range starts are unsatisfiable.
    let res = build_router(state.clone())
        .oneshot(download_request(Some("bytes=1000-2000"), None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        res.headers().get(header::CONTENT_RANGE).unwrap(),
        &format!("bytes */{total}")
    );

    // Malformed and multipart ranges fall back to a full download.
    for range in ["items=0-3", "bytes=abc-def", "bytes=0-1,3-4"] {
        let res = build_router(state.clone())
            .oneshot(download_request(Some(range), None, None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "range {range}");
        let bytes = body_bytes(res.into_body()).await;
        assert_eq!(bytes, FILE_BYTES, "range {range}");
    }
}

#[tokio::test]
async fn conditional_downloads_honor_etags() {
    let (app, state, _tmp) = test_app().await;
    let body = upload_body(FILE_BYTES, None);
    let res = app
        .oneshot(post_upload_request(Some(good_auth()), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Capture the validator from a plain download.
    let res = build_router(state.clone())
        .oneshot(download_request(None, None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let etag = res
        .headers()
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Matching If-None-Match (exact and star) yields an empty 304.
    for value in [etag.as_str(), "*"] {
        let res = build_router(state.clone())
            .oneshot(download_request(None, Some(value), None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_MODIFIED, "value {value}");
        assert!(body_bytes(res.into_body()).await.is_empty());
    }

    // A stale validator gets the full body.
    let res = build_router(state.clone())
        .oneshot(download_request(None, Some("\"stale\""), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = body_bytes(res.into_body()).await;
    assert_eq!(bytes, FILE_BYTES);

    // HEAD mirrors GET headers with no body.
    let head = Request::builder()
        .method("HEAD")
        .uri(format!("/files/{NORMALIZED}/{FILENAME}"))
        .header(header::AUTHORIZATION, good_auth())
        .body(Body::empty())
        .unwrap();
    let res = build_router(state.clone()).oneshot(head).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::CONTENT_LENGTH).unwrap(),
        &FILE_BYTES.len().to_string()
    );
    assert!(body_bytes(res.into_body()).await.is_empty());

    // If-Range: fresh validator ranges, stale validator downloads fully.
    let res = build_router(state.clone())
        .oneshot(download_request(Some("bytes=0-4"), None, Some(&etag)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
    let res = build_router(state.clone())
        .oneshot(download_request(Some("bytes=0-4"), None, Some("\"stale\"")))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = body_bytes(res.into_body()).await;
    assert_eq!(bytes, FILE_BYTES);
}

#[tokio::test]
async fn reupload_conflicts_and_cleans_staging() {
    let (app, state, _tmp) = test_app().await;
    let body = upload_body(FILE_BYTES, None);
    let res = app
        .oneshot(post_upload_request(Some(good_auth()), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = upload_body(FILE_BYTES, None);
    let res = build_router(state.clone())
        .oneshot(post_upload_request(Some(good_auth()), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
    assert!(
        staging_is_empty(&state.settings.storage_dir),
        "staging not empty after 409"
    );
}

#[tokio::test]
async fn bad_digest_rejected_and_cleans_staging() {
    let (app, state, _tmp) = test_app().await;
    let body = upload_body(FILE_BYTES, Some(&"0".repeat(64)));
    let res = app
        .oneshot(post_upload_request(Some(good_auth()), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(
        staging_is_empty(&state.settings.storage_dir),
        "staging not empty after bad digest"
    );
}

#[tokio::test]
async fn version_mismatch_rejected() {
    let (app, _state, _tmp) = test_app().await;
    let digest = sha256_hex(FILE_BYTES);
    let fields = vec![
        (":action", "file_upload"),
        ("name", PROJECT),
        ("version", "2.0.0"),
        ("sha256_digest", digest.as_str()),
    ];
    let body = build_multipart(BOUNDARY, &fields, Some(("content", FILENAME, FILE_BYTES)));
    let res = app
        .oneshot(post_upload_request(Some(good_auth()), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_project_returns_404() {
    let (app, _state, _tmp) = test_app().await;
    let res = app
        .oneshot(get_request(
            "/simple/does-not-exist-xyz/",
            Some(good_auth()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn row_without_object_returns_404() {
    let (app, state, _tmp) = test_app().await;
    state
        .db
        .claim_project(PROJECT, NORMALIZED, "ci")
        .await
        .unwrap();
    state
        .db
        .insert_file(&NewFile {
            project_normalized: NORMALIZED.to_string(),
            project_display: PROJECT.to_string(),
            filename: FILENAME.to_string(),
            version: VERSION.to_string(),
            sha256: sha256_hex(FILE_BYTES),
            size_bytes: FILE_BYTES.len() as i64,
            requires_python: None,
            uploaded_by: "ci".to_string(),
        })
        .await
        .unwrap();
    let res = app
        .oneshot(get_request(
            &format!("/files/{NORMALIZED}/{FILENAME}"),
            Some(good_auth()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    // Drop state explicitly to keep tempdir alive until after request.
    drop(state);
}

#[tokio::test]
async fn unknown_text_field_too_large_rejected() {
    // Over-cap unknown text field BEFORE the content part.
    {
        let (app, state, _tmp) = test_app().await;
        let big = "a".repeat(200 * 1024);
        let digest = sha256_hex(FILE_BYTES);
        let fields: Vec<(&str, &str)> = vec![
            (":action", "file_upload"),
            ("name", PROJECT),
            ("version", VERSION),
            ("sha256_digest", digest.as_str()),
            ("comment", big.as_str()),
        ];
        let body = build_multipart(BOUNDARY, &fields, Some(("content", FILENAME, FILE_BYTES)));
        let res = app
            .oneshot(post_upload_request(Some(good_auth()), body, BOUNDARY))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            staging_is_empty(&state.settings.storage_dir),
            "staging not empty after oversized text field (before content)"
        );
    }
    // Over-cap unknown text field AFTER the content part: content is already
    // staged when the oversized field is read, so the staging-empty assertion
    // below is non-vacuous (it proves the staged file was cleaned up).
    {
        let (app, state, _tmp) = test_app().await;
        let big = "a".repeat(200 * 1024);
        let digest = sha256_hex(FILE_BYTES);
        let leading: Vec<(&str, &str)> = vec![
            (":action", "file_upload"),
            ("name", PROJECT),
            ("version", VERSION),
            ("sha256_digest", digest.as_str()),
        ];
        let trailing: Vec<(&str, &str)> = vec![("comment", big.as_str())];
        let body = build_multipart_trailing(
            BOUNDARY,
            &leading,
            Some(("content", FILENAME, FILE_BYTES)),
            &trailing,
        );
        let res = app
            .oneshot(post_upload_request(Some(good_auth()), body, BOUNDARY))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            staging_is_empty(&state.settings.storage_dir),
            "staging not empty after oversized text field (after content)"
        );
    }
}

#[tokio::test]
async fn oversized_content_rejected() {
    let (app, state, _tmp) = test_app().await;
    let big_bytes = vec![b'a'; 1024 * 1024 + 1];
    let body = upload_body(&big_bytes, None);
    let res = app
        .oneshot(post_upload_request(Some(good_auth()), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        staging_is_empty(&state.settings.storage_dir),
        "staging not empty after oversized content"
    );
}

#[tokio::test]
async fn truncated_multipart_rejected_and_cleans_staging() {
    let (app, state, _tmp) = test_app().await;
    let truncated =
        format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nDemo")
            .into_bytes();
    let res = app
        .oneshot(post_upload_request(Some(good_auth()), truncated, BOUNDARY))
        .await
        .unwrap();
    assert!(
        res.status().is_client_error(),
        "expected 4xx for truncated body, got {}",
        res.status()
    );
    assert!(
        staging_is_empty(&state.settings.storage_dir),
        "staging not empty after truncated body"
    );
}

#[tokio::test]
async fn concurrent_identical_uploads_one_wins() {
    let (_app, state, _tmp) = test_app().await;
    let body1 = upload_body(FILE_BYTES, None);
    let body2 = upload_body(FILE_BYTES, None);
    let req1 = post_upload_request(Some(good_auth()), body1, BOUNDARY);
    let req2 = post_upload_request(Some(good_auth()), body2, BOUNDARY);
    let router1 = build_router(state.clone());
    let router2 = build_router(state.clone());
    let (res1, res2) = tokio::join!(router1.oneshot(req1), router2.oneshot(req2));
    let (res1, res2) = (res1.unwrap(), res2.unwrap());
    let mut statuses = vec![res1.status(), res2.status()];
    statuses.sort();
    assert_eq!(
        statuses,
        vec![StatusCode::OK, StatusCode::CONFLICT],
        "expected exactly one 200 + one 409"
    );

    // Download matches winner bytes.
    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/files/{NORMALIZED}/{FILENAME}"),
            Some(good_auth()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = body_bytes(res.into_body()).await;
    assert_eq!(bytes, FILE_BYTES);
}

#[tokio::test]
async fn unknown_path_without_auth_returns_404() {
    // Auth wraps only the package routes via route_layer, so an unknown path
    // without credentials must 404 (not 401).
    let (app, _state, _tmp) = test_app().await;
    let res = app.oneshot(get_request("/nope", None, None)).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn over_two_mib_upload_succeeds_with_raised_cap() {
    // 3 MiB content clears axum's 2 MiB default body limit only because the
    // route disables it; the 8 MiB app cap still applies. Proves
    // DefaultBodyLimit::disable() is wired on POST /legacy/.
    let (app, _state, _tmp) = test_app_with_cap(8 * 1024 * 1024).await;
    let big_bytes = vec![b'b'; 3 * 1024 * 1024];
    let body = upload_body(&big_bytes, None);
    let res = app
        .oneshot(post_upload_request(Some(good_auth()), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["size_bytes"], big_bytes.len() as u64);
}

#[tokio::test]
async fn upload_happy_path_with_bearer_auth() {
    let (app, state, _tmp) = test_app().await;
    let expected_digest = sha256_hex(FILE_BYTES);
    let body = upload_body(FILE_BYTES, None);
    let res = app
        .oneshot(post_upload_request(
            Some(bearer_auth("secret")),
            body,
            BOUNDARY,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["name"], PROJECT);
    assert_eq!(json["version"], VERSION);
    assert_eq!(json["filename"], FILENAME);
    assert_eq!(json["sha256"], expected_digest);
    // The Bearer [REDACTED] resolves to user "ci" for the uploaded_by attribution.
    let record = state
        .db
        .get_file(NORMALIZED, FILENAME)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.uploaded_by, "ci");

    // Download round-trips the bytes under Bearer [REDACTED] too.
    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/files/{NORMALIZED}/{FILENAME}"),
            Some(bearer_auth("secret")),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = body_bytes(res.into_body()).await;
    assert_eq!(bytes, FILE_BYTES);
}

/// App with two upload users, for project-ownership checks.
async fn test_app_two_users() -> (Router, AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let settings = test_settings(tmp.path().to_path_buf());
    let storage = Storage::filesystem(settings.storage_dir.clone());
    storage.ensure_dirs().await.unwrap();
    let db = MetadataBackend::Memory(MemoryStore::new());
    let auth = Auth::from_pairs(vec![
        ("alice".to_string(), "alice-token".to_string()),
        ("bob".to_string(), "bob-token".to_string()),
    ]);
    let metrics = metrics_exporter_prometheus::PrometheusBuilder::new()
        .build_recorder()
        .handle();
    let state = AppState {
        db,
        storage,
        auth,
        metrics,
        settings: Arc::new(settings),
    };
    let router = build_router(state.clone());
    (router, state, tmp)
}

fn upload_body_for(version: &str, filename: &str, file_bytes: &[u8]) -> Vec<u8> {
    let digest = sha256_hex(file_bytes);
    let fields: Vec<(&str, &str)> = vec![
        (":action", "file_upload"),
        ("name", PROJECT),
        ("version", version),
        ("sha256_digest", digest.as_str()),
    ];
    build_multipart(BOUNDARY, &fields, Some(("content", filename, file_bytes)))
}

#[tokio::test]
async fn only_project_owner_can_publish() {
    let (app, state, _tmp) = test_app_two_users().await;
    let alice = basic_auth("alice", "alice-token");
    let bob = basic_auth("bob", "bob-token");

    // First upload claims the project for alice.
    let body = upload_body_for(VERSION, FILENAME, FILE_BYTES);
    let res = app
        .oneshot(post_upload_request(Some(alice.clone()), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Bob cannot publish a new version to alice's project.
    let body = upload_body_for("1.2.4", "demo-pkg-1.2.4.tar.gz", b"bob-bytes");
    let res = build_router(state.clone())
        .oneshot(post_upload_request(Some(bob.clone()), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(
        staging_is_empty(&state.settings.storage_dir),
        "staging not empty after 403"
    );

    // The owner can publish the same new version.
    let body = upload_body_for("1.2.4", "demo-pkg-1.2.4.tar.gz", b"bob-bytes");
    let res = build_router(state.clone())
        .oneshot(post_upload_request(Some(alice), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Reads stay open to every authenticated user, including bob.
    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/files/{NORMALIZED}/{FILENAME}"),
            Some(bob),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = body_bytes(res.into_body()).await;
    assert_eq!(bytes, FILE_BYTES);
}

fn admin_request(
    method: &str,
    uri: &str,
    auth: Option<String>,
    json_body: Option<String>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(value) = auth {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    match json_body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

const YANK_URI: &str = "/admin/projects/demo-pkg/files/demo-pkg-1.2.3.tar.gz/yank";
const UNYANK_URI: &str = "/admin/projects/demo-pkg/files/demo-pkg-1.2.3.tar.gz/unyank";
const FILE_ADMIN_URI: &str = "/admin/projects/demo-pkg/files/demo-pkg-1.2.3.tar.gz";
const TRANSFER_URI: &str = "/admin/projects/demo-pkg/transfer";

#[tokio::test]
async fn admin_yank_unyank_delete_flow() {
    let (app, state, _tmp) = test_app_two_users().await;
    let alice = basic_auth("alice", "alice-token");
    let bob = basic_auth("bob", "bob-token");

    // Alice uploads and thereby owns the project.
    let body = upload_body_for(VERSION, FILENAME, FILE_BYTES);
    let res = app
        .oneshot(post_upload_request(Some(alice.clone()), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Non-owner cannot yank.
    let res = build_router(state.clone())
        .oneshot(admin_request(
            "POST",
            YANK_URI,
            Some(bob.clone()),
            Some(r#"{"reason":"broken"}"#.to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // Owner yanks with a reason.
    let res = build_router(state.clone())
        .oneshot(admin_request(
            "POST",
            YANK_URI,
            Some(alice.clone()),
            Some(r#"{"reason":"broken metadata"}"#.to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["yanked"], true);
    assert_eq!(json["reason"], "broken metadata");

    // The index advertises the yank to every reader, in both formats.
    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/simple/{NORMALIZED}/"),
            Some(bob.clone()),
            Some(JSON_ACCEPT),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["files"][0]["yanked"], "broken metadata");
    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/simple/{NORMALIZED}/"),
            Some(bob.clone()),
            None,
        ))
        .await
        .unwrap();
    let html = body_text(res.into_body()).await;
    assert!(html.contains("data-yanked=\"broken metadata\""), "{html}");

    // Yanked files remain downloadable by direct URL (PEP 592).
    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/files/{NORMALIZED}/{FILENAME}"),
            Some(bob.clone()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Unyank restores normal state.
    let res = build_router(state.clone())
        .oneshot(admin_request("POST", UNYANK_URI, Some(alice.clone()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/simple/{NORMALIZED}/"),
            Some(alice.clone()),
            Some(JSON_ACCEPT),
        ))
        .await
        .unwrap();
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["files"][0]["yanked"], false);

    // Non-owner cannot delete; owner can. Afterwards everything 404s.
    let res = build_router(state.clone())
        .oneshot(admin_request("DELETE", FILE_ADMIN_URI, Some(bob), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = build_router(state.clone())
        .oneshot(admin_request("DELETE", FILE_ADMIN_URI, Some(alice), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/files/{NORMALIZED}/{FILENAME}"),
            Some(basic_auth("alice", "alice-token")),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/simple/{NORMALIZED}/"),
            Some(basic_auth("alice", "alice-token")),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_transfer_flow() {
    let (app, state, _tmp) = test_app_two_users().await;
    let alice = basic_auth("alice", "alice-token");
    let bob = basic_auth("bob", "bob-token");

    let body = upload_body_for(VERSION, FILENAME, FILE_BYTES);
    let res = app
        .oneshot(post_upload_request(Some(alice.clone()), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Unknown target users are rejected; the project stays alice's.
    let res = build_router(state.clone())
        .oneshot(admin_request(
            "POST",
            TRANSFER_URI,
            Some(alice.clone()),
            Some(r#"{"new_owner":"mallory"}"#.to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let res = build_router(state.clone())
        .oneshot(admin_request(
            "POST",
            TRANSFER_URI,
            Some(alice),
            Some(r#"{"new_owner":"bob"}"#.to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["owner"], "bob");

    // The previous owner loses admin rights; the new owner has them.
    let res = build_router(state.clone())
        .oneshot(admin_request(
            "POST",
            YANK_URI,
            Some(basic_auth("alice", "alice-token")),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = build_router(state.clone())
        .oneshot(admin_request("POST", YANK_URI, Some(bob), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn admin_not_found_and_auth() {
    let (app, state, _tmp) = test_app_two_users().await;
    let alice = basic_auth("alice", "alice-token");

    // Unauthenticated admin calls are rejected by the auth layer.
    let res = app
        .oneshot(admin_request("POST", YANK_URI, None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Missing project 404s.
    let res = build_router(state.clone())
        .oneshot(admin_request("POST", YANK_URI, Some(alice.clone()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // Existing project, missing file 404s.
    let body = upload_body_for(VERSION, FILENAME, FILE_BYTES);
    let res = build_router(state.clone())
        .oneshot(post_upload_request(Some(alice.clone()), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let res = build_router(state.clone())
        .oneshot(admin_request(
            "POST",
            "/admin/projects/demo-pkg/files/missing-9.9.tar.gz/yank",
            Some(alice),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_ownerless_claim_and_body_rules() {
    let (app, state, _tmp) = test_app_two_users().await;
    let alice = basic_auth("alice", "alice-token");
    let bob = basic_auth("bob", "bob-token");

    // Seed a pre-ownership (ownerless) project row directly.
    state
        .db
        .insert_file(&NewFile {
            project_normalized: NORMALIZED.to_string(),
            project_display: PROJECT.to_string(),
            filename: FILENAME.to_string(),
            version: VERSION.to_string(),
            sha256: sha256_hex(FILE_BYTES),
            size_bytes: FILE_BYTES.len() as i64,
            requires_python: None,
            uploaded_by: "legacy".to_string(),
        })
        .await
        .unwrap();
    let _ = app;

    // First administrator (bob) claims the ownerless project by yanking.
    let res = build_router(state.clone())
        .oneshot(admin_request("POST", YANK_URI, Some(bob.clone()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Alice is now a non-owner: forbidden even with a malformed body,
    // because authorization runs before body parsing.
    let res = build_router(state.clone())
        .oneshot(admin_request(
            "POST",
            YANK_URI,
            Some(alice),
            Some("not json".to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // The owner gets a clean 400 for malformed JSON and unknown fields.
    let res = build_router(state.clone())
        .oneshot(admin_request(
            "POST",
            YANK_URI,
            Some(bob.clone()),
            Some("not json".to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = build_router(state.clone())
        .oneshot(admin_request(
            "POST",
            YANK_URI,
            Some(bob.clone()),
            Some(r#"{"reasons":"typo"}"#.to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Transferring to the current owner is a no-op and rejected.
    let res = build_router(state.clone())
        .oneshot(admin_request(
            "POST",
            TRANSFER_URI,
            Some(bob),
            Some(r#"{"new_owner":"bob"}"#.to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}
