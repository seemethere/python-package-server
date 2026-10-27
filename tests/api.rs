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
    config::{Policy, Settings},
    db::{MemoryStore, MetadataBackend, MetadataStore, NewFile},
    state::AppState,
    storage::Storage,
    upstream::UpstreamClient,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tower::ServiceExt;

fn test_settings(storage_dir: PathBuf) -> Settings {
    Settings {
        bind_addr: "127.0.0.1:0".to_string(),
        database_url: "postgres://localhost/packages".to_string(),
        storage_backend: "filesystem".to_string(),
        storage_dir,
        s3_bucket: None,
        s3_region: None,
        s3_endpoint_url: None,
        auth_token_file: PathBuf::from("/dev/null"),
        max_upload_bytes: 1024 * 1024,
        upstream_url: None,
        upstream_index_ttl_secs: 300,
        upstream_cache_max_age_days: 30,
        upstream_private_only_projects: std::collections::HashSet::new(),
        policy_file: None,
        policy: python_package_server::config::Policy::default(),
        oidc_issuer_url: None,
        oidc_audience: None,
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
        upstream: None,
    };
    let router = build_router(state.clone());
    (router, state, tmp)
}

async fn test_app_with_upstream(
    upstream: Option<UpstreamClient>,
) -> (Router, AppState, tempfile::TempDir) {
    test_app_with_upstream_and_policy(upstream, Policy::default()).await
}

async fn test_app_with_upstream_and_policy(
    upstream: Option<UpstreamClient>,
    policy: Policy,
) -> (Router, AppState, tempfile::TempDir) {
    test_app_with_upstream_policy_and_cache_ttl(upstream, policy, 30).await
}

async fn test_app_with_upstream_policy_and_cache_ttl(
    upstream: Option<UpstreamClient>,
    policy: Policy,
    cache_max_age_days: u32,
) -> (Router, AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let mut settings = test_settings(tmp.path().to_path_buf());
    settings.policy = policy;
    settings.upstream_cache_max_age_days = cache_max_age_days;
    let storage = Storage::filesystem(settings.storage_dir.clone());
    storage.ensure_dirs().await.unwrap();
    let db = MetadataBackend::Memory(MemoryStore::new());
    let auth = Auth::from_pairs(vec![("ci".to_string(), "secret".to_string())]);
    let metrics = metrics_exporter_prometheus::PrometheusBuilder::new()
        .build_recorder()
        .handle();
    let state = AppState {
        db,
        storage,
        auth,
        metrics,
        settings: Arc::new(settings),
        upstream,
    };
    let router = build_router(state.clone());
    (router, state, tmp)
}

async fn seed_hosted(
    state: &AppState,
    normalized: &str,
    display: &str,
    filename: &str,
    sha256: &str,
    requires_python: Option<&str>,
) {
    state
        .db
        .insert_file(&NewFile {
            project_normalized: normalized.to_string(),
            project_display: display.to_string(),
            filename: filename.to_string(),
            version: "1.2.3".to_string(),
            sha256: sha256.to_string(),
            size_bytes: 42,
            requires_python: requires_python.map(str::to_string),
            uploaded_by: "ci".to_string(),
        })
        .await
        .unwrap();
}

async fn spawn_fake_upstream() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use axum::response::IntoResponse;
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter_clone = counter.clone();
    let app = Router::new().route(
        "/{project}/",
        axum::routing::get(
            move |axum::extract::Path(project): axum::extract::Path<String>| {
                let counter = counter_clone.clone();
                async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    match project.as_str() {
                        "demo-pkg" => axum::Json(serde_json::json!({
                            "meta": {"api-version": "1.1"},
                            "name": "demo-pkg",
                            "files": [
                                {"filename":"demo-pkg-1.2.3.tar.gz","url":"https://upstream.example/files/demo-pkg-1.2.3.tar.gz","hashes":{"sha256":"0000000000000000000000000000000000000000000000000000000000000000"},"requires-python":">=2.7","yanked":false},
                                {"filename":"demo-pkg-9.9.9.tar.gz","url":"https://upstream.example/files/demo-pkg-9.9.9.tar.gz","hashes":{"sha256":"9999999999999999999999999999999999999999999999999999999999999999"},"requires-python":">=3.10","yanked":"bad upstream"}
                            ]
                        })).into_response(),
                        "purepkg" => axum::Json(serde_json::json!({
                            "meta": {"api-version": "1.1"},
                            "name": "purepkg",
                            "files": [
                                {"filename":"purepkg-1.0.tar.gz","url":"https://upstream.example/files/purepkg-1.0.tar.gz","hashes":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"requires-python":">=3.9","yanked":false},
                                {"filename":"purepkg-2.0.tar.gz","url":"https://upstream.example/files/purepkg-2.0.tar.gz","hashes":{"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"requires-python":null,"yanked":true}
                            ]
                        })).into_response(),
                        "secret-pkg" => axum::Json(serde_json::json!({
                            "meta": {"api-version": "1.1"},
                            "name": "secret-pkg",
                            "files": [
                                {"filename":"secret-pkg-9.9.tar.gz","url":"https://upstream.example/files/secret-pkg-9.9.tar.gz","hashes":{"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"requires-python":null,"yanked":false}
                            ]
                        })).into_response(),
                        "htmlpkg" => (
                            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                            "<!DOCTYPE html><html><body><a href=\"https://files.example/htmlpkg-1.0.tar.gz#sha256=htmlsha123\" data-requires-python=\"&gt;=3.8\">htmlpkg-1.0.tar.gz</a><br/><a href=\"https://files.example/htmlpkg-2.0.tar.gz#sha256=htmlsha456\" data-yanked=\"html yank\">htmlpkg-2.0.tar.gz</a><br/></body></html>".to_string(),
                        ).into_response(),
                        "boompkg" => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                        _ => StatusCode::NOT_FOUND.into_response(),
                    }
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/"), counter)
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
        upstream: None,
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

#[tokio::test]
async fn upstream_merged_hosted_wins_html_json_parity() {
    let (base, _counter) = spawn_fake_upstream().await;
    let client = UpstreamClient::new(
        base,
        std::time::Duration::from_secs(60),
        std::collections::HashSet::new(),
    );
    let (app, state, _tmp) = test_app_with_upstream(Some(client)).await;
    let hosted_sha = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    seed_hosted(
        &state,
        NORMALIZED,
        PROJECT,
        FILENAME,
        hosted_sha,
        Some(REQUIRES_PYTHON),
    )
    .await;
    let _ = &app;

    // JSON: hosted first + upstream-only file, hosted wins on duplicate.
    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/simple/{NORMALIZED}/"),
            Some(good_auth()),
            Some(JSON_ACCEPT),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let files = json["files"].as_array().unwrap();
    assert_eq!(files.len(), 2, "json: {text}");
    assert_eq!(files[0]["filename"], FILENAME);
    assert_eq!(files[0]["hashes"]["sha256"], hosted_sha);
    assert_eq!(files[0]["requires-python"], REQUIRES_PYTHON);
    assert_eq!(files[1]["filename"], "demo-pkg-9.9.9.tar.gz");
    assert_eq!(files[1]["url"], "/files/demo-pkg/demo-pkg-9.9.9.tar.gz");
    assert_eq!(
        files[1]["hashes"]["sha256"],
        "9999999999999999999999999999999999999999999999999999999999999999"
    );
    assert_eq!(files[1]["requires-python"], ">=3.10");
    assert_eq!(files[1]["yanked"], "bad upstream");

    // HTML: same files, local /files/ URLs with #sha256=, yanked/requires passthrough.
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
    assert!(html.contains(FILENAME), "{html}");
    assert!(html.contains(&format!("#sha256={hosted_sha}")), "{html}");
    assert!(
        !html.contains("0000000000000000000000000000000000000000000000000000000000000000"),
        "upstream duplicate leaked: {html}"
    );
    assert!(html.contains("demo-pkg-9.9.9.tar.gz"), "{html}");
    assert!(
        html.contains("/files/demo-pkg/demo-pkg-9.9.9.tar.gz#sha256=9999"),
        "{html}"
    );
    assert!(
        html.contains("data-requires-python=\"&gt;=3.10\""),
        "{html}"
    );
    assert!(html.contains("data-yanked=\"bad upstream\""), "{html}");
    // Duplicate filename appears once in HTML too.
    assert_eq!(html.matches(FILENAME).count(), 2, "{html}");
}

#[tokio::test]
async fn upstream_pure_proxy_and_html_fallback() {
    let (base, _counter) = spawn_fake_upstream().await;
    let client = UpstreamClient::new(
        base,
        std::time::Duration::from_secs(60),
        std::collections::HashSet::new(),
    );
    let (_app, state, _tmp) = test_app_with_upstream(Some(client)).await;

    // Pure proxy JSON for unhosted project.
    let res = build_router(state.clone())
        .oneshot(get_request(
            "/simple/purepkg/",
            Some(good_auth()),
            Some(JSON_ACCEPT),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["files"].as_array().unwrap().len(), 2);
    assert_eq!(json["files"][0]["filename"], "purepkg-1.0.tar.gz");
    assert_eq!(json["files"][0]["requires-python"], ">=3.9");
    assert_eq!(json["files"][1]["yanked"], true);

    // Pure proxy HTML parity.
    let res = build_router(state.clone())
        .oneshot(get_request("/simple/purepkg/", Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res.into_body()).await;
    assert!(html.contains("purepkg-1.0.tar.gz"), "{html}");
    assert!(html.contains("data-yanked=\"\""), "{html}");

    // HTML upstream fallback rendered as JSON and HTML.
    let res = build_router(state.clone())
        .oneshot(get_request(
            "/simple/htmlpkg/",
            Some(good_auth()),
            Some(JSON_ACCEPT),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["files"][0]["filename"], "htmlpkg-1.0.tar.gz");
    assert_eq!(json["files"][0]["hashes"]["sha256"], "htmlsha123");
    assert_eq!(json["files"][0]["requires-python"], ">=3.8");
    assert_eq!(json["files"][1]["yanked"], "html yank");
    let res = build_router(state.clone())
        .oneshot(get_request("/simple/htmlpkg/", Some(good_auth()), None))
        .await
        .unwrap();
    let html = body_text(res.into_body()).await;
    assert!(html.contains("#sha256=htmlsha123"), "{html}");
    assert!(html.contains("data-yanked=\"html yank\""), "{html}");
}

#[tokio::test]
async fn upstream_private_only_never_fetches() {
    let (base, counter) = spawn_fake_upstream().await;
    let mut private = std::collections::HashSet::new();
    private.insert("secret-pkg".to_string());
    let client = UpstreamClient::new(base, std::time::Duration::from_secs(60), private);
    let (_app, state, _tmp) = test_app_with_upstream(Some(client)).await;
    seed_hosted(
        &state,
        "secret-pkg",
        "Secret-Pkg",
        "secret-pkg-1.0.tar.gz",
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        None,
    )
    .await;

    let res = build_router(state.clone())
        .oneshot(get_request(
            "/simple/secret-pkg/",
            Some(good_auth()),
            Some(JSON_ACCEPT),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["files"].as_array().unwrap().len(), 1);
    assert_eq!(json["files"][0]["filename"], "secret-pkg-1.0.tar.gz");
    assert_eq!(
        counter.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "private-only project must not call upstream"
    );

    // Private-only with no hosted files 404s without calling upstream.
    let res = build_router(state.clone())
        .oneshot(get_request("/simple/secret-pkg/", Some(good_auth()), None))
        .await
        .unwrap();
    // Still hosted file exists, so HTML also hosted-only.
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res.into_body()).await;
    assert!(!html.contains("secret-pkg-9.9"), "{html}");
    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn upstream_404_and_500_mapping() {
    let (base, _counter) = spawn_fake_upstream().await;
    let client = UpstreamClient::new(
        base,
        std::time::Duration::from_secs(60),
        std::collections::HashSet::new(),
    );
    let (_app, state, _tmp) = test_app_with_upstream(Some(client)).await;

    // Upstream 404 with no hosted => 404.
    let res = build_router(state.clone())
        .oneshot(get_request("/simple/missing/", Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // Upstream 500 => 502.
    let res = build_router(state.clone())
        .oneshot(get_request("/simple/boompkg/", Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    let res = build_router(state.clone())
        .oneshot(get_request(
            "/simple/boompkg/",
            Some(good_auth()),
            Some(JSON_ACCEPT),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
}

/// A file served by the fake file-upstream: the index advertises
/// `index_sha256` for `filename` under `project`, while `GET /files/{filename}`
/// serves `bytes`. Divergence between the two models a corrupt upstream.
/// `upload_time` is the PEP 691 `upload-time` string (`None` omits it,
/// modelling an upstream without timestamps).
struct FakeUpstreamFile {
    project: &'static str,
    filename: &'static str,
    index_sha256: String,
    bytes: Vec<u8>,
    upload_time: Option<String>,
}

struct FakeFileUpstream {
    base: String,
    index_hits: Arc<AtomicUsize>,
    file_hits: Arc<AtomicUsize>,
}

impl FakeFileUpstream {
    fn index_hits(&self) -> usize {
        self.index_hits.load(Ordering::SeqCst)
    }

    fn file_hits(&self) -> usize {
        self.file_hits.load(Ordering::SeqCst)
    }
}

/// Fake upstream serving both a JSON index and downloadable file bytes, with
/// separate request counters so tests can prove (non-)fetching. Index file
/// URLs point back at this server's own `/files/` route.
async fn spawn_fake_file_upstream(files: Vec<FakeUpstreamFile>) -> FakeFileUpstream {
    use axum::response::IntoResponse;
    // Bind first so the index URLs can point at our own address.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}/");
    let index_hits = Arc::new(AtomicUsize::new(0));
    let file_hits = Arc::new(AtomicUsize::new(0));
    let files = Arc::new(files);
    let index_files = files.clone();
    let index_base = base.clone();
    let index_hits_clone = index_hits.clone();
    let file_hits_clone = file_hits.clone();
    let app = Router::new()
        .route(
            "/{project}/",
            axum::routing::get(
                move |axum::extract::Path(project): axum::extract::Path<String>| {
                    let index_hits = index_hits_clone.clone();
                    let files = index_files.clone();
                    let base = index_base.clone();
                    async move {
                        index_hits.fetch_add(1, Ordering::SeqCst);
                        let entries: Vec<serde_json::Value> = files
                            .iter()
                            .filter(|f| f.project == project)
                            .map(|f| {
                                let mut entry = serde_json::json!({
                                    "filename": f.filename,
                                    "url": format!("{base}files/{}", f.filename),
                                    "hashes": {"sha256": f.index_sha256},
                                    "requires-python": null,
                                    "yanked": false,
                                });
                                if let Some(upload_time) = &f.upload_time {
                                    entry["upload-time"] =
                                        serde_json::Value::String(upload_time.clone());
                                }
                                entry
                            })
                            .collect();
                        if entries.is_empty() {
                            return StatusCode::NOT_FOUND.into_response();
                        }
                        axum::Json(serde_json::json!({
                            "meta": {"api-version": "1.1"},
                            "name": project,
                            "files": entries,
                        }))
                        .into_response()
                    }
                },
            ),
        )
        .route(
            "/files/{filename}",
            axum::routing::get(
                move |axum::extract::Path(filename): axum::extract::Path<String>| {
                    let file_hits = file_hits_clone.clone();
                    let files = files.clone();
                    async move {
                        file_hits.fetch_add(1, Ordering::SeqCst);
                        match files.iter().find(|f| f.filename == filename) {
                            Some(f) => (
                                [(header::CONTENT_TYPE, "application/octet-stream")],
                                f.bytes.clone(),
                            )
                                .into_response(),
                            None => StatusCode::NOT_FOUND.into_response(),
                        }
                    }
                },
            ),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    FakeFileUpstream {
        base,
        index_hits,
        file_hits,
    }
}

async fn test_app_with_file_upstream(
    files: Vec<FakeUpstreamFile>,
) -> (Router, AppState, tempfile::TempDir, FakeFileUpstream) {
    test_app_with_file_upstream_and_policy(files, Policy::default()).await
}

async fn test_app_with_file_upstream_and_policy(
    files: Vec<FakeUpstreamFile>,
    policy: Policy,
) -> (Router, AppState, tempfile::TempDir, FakeFileUpstream) {
    let fake = spawn_fake_file_upstream(files).await;
    let client = UpstreamClient::new(
        fake.base.clone(),
        std::time::Duration::from_secs(60),
        std::collections::HashSet::new(),
    );
    let (router, state, tmp) = test_app_with_upstream_and_policy(Some(client), policy).await;
    (router, state, tmp, fake)
}

async fn test_app_with_file_upstream_and_cache_ttl(
    files: Vec<FakeUpstreamFile>,
    cache_max_age_days: u32,
) -> (Router, AppState, tempfile::TempDir, FakeFileUpstream) {
    let fake = spawn_fake_file_upstream(files).await;
    let client = UpstreamClient::new(
        fake.base.clone(),
        std::time::Duration::from_secs(60),
        std::collections::HashSet::new(),
    );
    let (router, state, tmp) = test_app_with_upstream_policy_and_cache_ttl(
        Some(client),
        Policy::default(),
        cache_max_age_days,
    )
    .await;
    (router, state, tmp, fake)
}

const CACHE_PROJECT: &str = "cachepkg";
const CACHE_FILE: &str = "cachepkg-1.0.tar.gz";
const CACHE_BYTES: &[u8] =
    b"upstream cached wheel bytes v1.0 - predictable content for range tests!";

fn cache_fixture() -> FakeUpstreamFile {
    FakeUpstreamFile {
        project: CACHE_PROJECT,
        filename: CACHE_FILE,
        index_sha256: sha256_hex(CACHE_BYTES),
        bytes: CACHE_BYTES.to_vec(),
        upload_time: Some("2020-01-01T00:00:00Z".to_string()),
    }
}

fn cache_url() -> String {
    format!("/files/{CACHE_PROJECT}/{CACHE_FILE}")
}

#[tokio::test]
async fn upstream_cold_miss_caches_and_serves() {
    let (_app, state, _tmp, fake) = test_app_with_file_upstream(vec![cache_fixture()]).await;
    let expected_etag = format!("\"{}\"", sha256_hex(CACHE_BYTES));

    let res = build_router(state.clone())
        .oneshot(get_request(&cache_url(), Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::ETAG).unwrap(),
        expected_etag.as_str()
    );
    let bytes = body_bytes(res.into_body()).await;
    assert_eq!(bytes, CACHE_BYTES);

    // Exactly one index lookup + one file fetch, then bytes are cached.
    assert_eq!(fake.index_hits(), 1);
    assert_eq!(fake.file_hits(), 1);
    assert_eq!(
        state.storage.stat(CACHE_PROJECT, CACHE_FILE).await.unwrap(),
        Some(CACHE_BYTES.len() as u64)
    );
    assert!(
        staging_is_empty(&state.settings.storage_dir),
        "staging not empty after cache fill"
    );
}

#[tokio::test]
async fn upstream_warm_hit_skips_upstream() {
    let (_app, state, _tmp, fake) = test_app_with_file_upstream(vec![cache_fixture()]).await;

    let res = build_router(state.clone())
        .oneshot(get_request(&cache_url(), Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let first_etag = res
        .headers()
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(body_bytes(res.into_body()).await, CACHE_BYTES);

    let res = build_router(state.clone())
        .oneshot(get_request(&cache_url(), Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get(header::ETAG).unwrap(), &first_etag);
    assert_eq!(body_bytes(res.into_body()).await, CACHE_BYTES);

    // The second request served from cache: no further upstream calls.
    assert_eq!(fake.index_hits(), 1);
    assert_eq!(fake.file_hits(), 1);
}

#[tokio::test]
async fn upstream_cold_miss_range_serves_slice() {
    let (_app, state, _tmp, fake) = test_app_with_file_upstream(vec![cache_fixture()]).await;
    let total = CACHE_BYTES.len();

    let ranged = Request::builder()
        .method("GET")
        .uri(cache_url())
        .header(header::AUTHORIZATION, good_auth())
        .header(header::RANGE, "bytes=0-4")
        .body(Body::empty())
        .unwrap();
    let res = build_router(state.clone()).oneshot(ranged).await.unwrap();
    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        res.headers().get(header::CONTENT_RANGE).unwrap(),
        &format!("bytes 0-4/{total}")
    );
    assert_eq!(body_bytes(res.into_body()).await, CACHE_BYTES[0..5]);

    // The ranged cold miss still filled the cache: a full GET fetches nothing.
    let res = build_router(state.clone())
        .oneshot(get_request(&cache_url(), Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_bytes(res.into_body()).await, CACHE_BYTES);
    assert_eq!(fake.file_hits(), 1);
}

#[tokio::test]
async fn upstream_corrupt_bytes_rejected_with_502() {
    let genuine = b"the genuine upstream bytes";
    let tampered = b"tampered bytes that fail verification!!!";
    assert_ne!(sha256_hex(genuine), sha256_hex(tampered));
    let (_app, state, _tmp, fake) = test_app_with_file_upstream(vec![FakeUpstreamFile {
        project: "badpkg",
        filename: "badpkg-1.0.tar.gz",
        index_sha256: sha256_hex(genuine),
        bytes: tampered.to_vec(),
        upload_time: None,
    }])
    .await;
    let url = "/files/badpkg/badpkg-1.0.tar.gz";

    let res = build_router(state.clone())
        .oneshot(get_request(url, Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);

    // Nothing cached: no object, no sidecar, empty staging.
    assert_eq!(
        state
            .storage
            .stat("badpkg", "badpkg-1.0.tar.gz")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        state
            .storage
            .stat(".upstream-cache", "badpkg--badpkg-1.0.tar.gz.sha256")
            .await
            .unwrap(),
        None
    );
    assert!(
        staging_is_empty(&state.settings.storage_dir),
        "staging not empty after corrupt rejection"
    );

    // Failures are not cached either: the retry fetches upstream again.
    let res = build_router(state.clone())
        .oneshot(get_request(url, Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(fake.index_hits(), 1, "index is TTL-cached");
    assert_eq!(fake.file_hits(), 2, "file fetch retried, not cached");
}

#[tokio::test]
async fn upstream_concurrent_cold_miss_fetches_once() {
    let (_app, state, _tmp, fake) = test_app_with_file_upstream(vec![cache_fixture()]).await;

    let mut handles = Vec::new();
    for _ in 0..8 {
        let router = build_router(state.clone());
        let url = cache_url();
        handles.push(tokio::spawn(async move {
            router
                .oneshot(get_request(&url, Some(good_auth()), None))
                .await
                .unwrap()
        }));
    }
    for handle in handles {
        let res = handle.await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(body_bytes(res.into_body()).await, CACHE_BYTES);
    }

    // Single-flight: one leader resolved + fetched while waiters served cache.
    assert_eq!(fake.index_hits(), 1);
    assert_eq!(fake.file_hits(), 1);
}

#[tokio::test]
async fn upstream_down_warm_cache_still_serves() {
    let (_app, mut state, _tmp, fake) = test_app_with_file_upstream(vec![cache_fixture()]).await;

    let res = build_router(state.clone())
        .oneshot(get_request(&cache_url(), Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_bytes(res.into_body()).await, CACHE_BYTES);

    // Point a FRESH client (empty index cache) at a dead port: any upstream
    // call at all would fail, so a 200 proves the warm path is self-sufficient.
    let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead_listener.local_addr().unwrap().port();
    drop(dead_listener);
    state.upstream = Some(UpstreamClient::new(
        format!("http://127.0.0.1:{dead_port}/"),
        std::time::Duration::from_secs(60),
        std::collections::HashSet::new(),
    ));
    let res = build_router(state.clone())
        .oneshot(get_request(&cache_url(), Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_bytes(res.into_body()).await, CACHE_BYTES);
    assert_eq!(fake.index_hits(), 1, "no further index calls");
    assert_eq!(fake.file_hits(), 1, "no further file fetches");
}

#[tokio::test]
async fn upstream_private_only_download_never_fetches() {
    let fake = spawn_fake_file_upstream(vec![cache_fixture()]).await;
    let mut private = std::collections::HashSet::new();
    private.insert(CACHE_PROJECT.to_string());
    let client = UpstreamClient::new(
        fake.base.clone(),
        std::time::Duration::from_secs(60),
        private,
    );
    let (_app, state, _tmp) = test_app_with_upstream(Some(client)).await;

    let res = build_router(state.clone())
        .oneshot(get_request(&cache_url(), Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(fake.index_hits(), 0);
    assert_eq!(fake.file_hits(), 0);
    assert_eq!(
        state.storage.stat(CACHE_PROJECT, CACHE_FILE).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn upstream_unknown_filename_is_404() {
    let (_app, state, _tmp, fake) = test_app_with_file_upstream(vec![cache_fixture()]).await;

    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/files/{CACHE_PROJECT}/definitely-missing-9.9.tar.gz"),
            Some(good_auth()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    // The index was consulted (and cached) but no file fetch was attempted.
    assert_eq!(fake.index_hits(), 1);
    assert_eq!(fake.file_hits(), 0);
}

#[tokio::test]
async fn download_miss_without_upstream_is_404() {
    let (app, _state, _tmp) = test_app().await;
    let res = app
        .oneshot(get_request(
            "/files/nothing/nothing-1.0.tar.gz",
            Some(good_auth()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn hosted_upload_shadows_cached_upstream_file() {
    const PROJECT: &str = "shadowpkg";
    const FILE: &str = "shadowpkg-1.0.tar.gz";
    const UPSTREAM_BYTES: &[u8] = b"upstream bytes for the shadowed file";
    const HOSTED_BYTES: &[u8] = b"hosted bytes that win after shadowing upload";
    let (_app, state, _tmp, _fake) = test_app_with_file_upstream(vec![FakeUpstreamFile {
        project: PROJECT,
        filename: FILE,
        index_sha256: sha256_hex(UPSTREAM_BYTES),
        bytes: UPSTREAM_BYTES.to_vec(),
        upload_time: None,
    }])
    .await;
    let url = format!("/files/{PROJECT}/{FILE}");

    // Cold miss caches + serves the upstream bytes.
    let res = build_router(state.clone())
        .oneshot(get_request(&url, Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_bytes(res.into_body()).await, UPSTREAM_BYTES);

    // A later hosted upload of the same key wins immediately.
    let digest = sha256_hex(HOSTED_BYTES);
    let fields: Vec<(&str, &str)> = vec![
        (":action", "file_upload"),
        ("name", "ShadowPkg"),
        ("version", "1.0"),
        ("sha256_digest", digest.as_str()),
    ];
    let body = build_multipart(BOUNDARY, &fields, Some(("content", FILE, HOSTED_BYTES)));
    let res = build_router(state.clone())
        .oneshot(post_upload_request(Some(good_auth()), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = build_router(state.clone())
        .oneshot(get_request(&url, Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::ETAG).unwrap(),
        &format!("\"{digest}\"")
    );
    assert_eq!(body_bytes(res.into_body()).await, HOSTED_BYTES);
}

#[tokio::test]
async fn upstream_concurrent_failing_fetch_never_overlaps() {
    use axum::response::IntoResponse;
    // Slow failing file endpoint with peak-concurrency tracking: a broken
    // single-flight lets waiters mint fresh slots and overlap here.
    let index_hits = Arc::new(AtomicUsize::new(0));
    let file_hits = Arc::new(AtomicUsize::new(0));
    let current = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}/");
    let index_base = base.clone();
    let ih = index_hits.clone();
    let fh = file_hits.clone();
    let cur = current.clone();
    let max = max_seen.clone();
    let app = Router::new()
        .route(
            "/{project}/",
            axum::routing::get(
                move |axum::extract::Path(project): axum::extract::Path<String>| {
                    let base = index_base.clone();
                    let ih = ih.clone();
                    async move {
                        ih.fetch_add(1, Ordering::SeqCst);
                        if project != "failpkg" {
                            return StatusCode::NOT_FOUND.into_response();
                        }
                        axum::Json(serde_json::json!({
                            "meta": {"api-version": "1.1"},
                            "name": "failpkg",
                            "files": [{
                                "filename": "failpkg-1.0.tar.gz",
                                "url": format!("{base}files/failpkg-1.0.tar.gz"),
                                "hashes": {"sha256": "0000000000000000000000000000000000000000000000000000000000000000"},
                                "requires-python": null,
                                "yanked": false,
                            }]
                        }))
                        .into_response()
                    }
                },
            ),
        )
        .route(
            "/files/{filename}",
            axum::routing::get(
                move |axum::extract::Path(filename): axum::extract::Path<String>| {
                    let fh = fh.clone();
                    let cur = cur.clone();
                    let max = max.clone();
                    async move {
                        if filename != "failpkg-1.0.tar.gz" {
                            return StatusCode::NOT_FOUND.into_response();
                        }
                        fh.fetch_add(1, Ordering::SeqCst);
                        let n = cur.fetch_add(1, Ordering::SeqCst) + 1;
                        max.fetch_max(n, Ordering::SeqCst);
                        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                        cur.fetch_sub(1, Ordering::SeqCst);
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    }
                },
            ),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = UpstreamClient::new(
        base,
        std::time::Duration::from_secs(60),
        std::collections::HashSet::new(),
    );
    let (_app, state, _tmp) = test_app_with_upstream(Some(client)).await;
    let url = "/files/failpkg/failpkg-1.0.tar.gz";

    let mut handles = Vec::new();
    for _ in 0..4 {
        let router = build_router(state.clone());
        let url = url.to_string();
        handles.push(tokio::spawn(async move {
            router
                .oneshot(get_request(&url, Some(good_auth()), None))
                .await
                .unwrap()
        }));
    }
    for handle in handles {
        let res = handle.await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    }

    // Failures are retried per waiter but strictly serially: peak overlap 1.
    assert_eq!(index_hits.load(Ordering::SeqCst), 1, "index TTL-cached");
    assert_eq!(
        file_hits.load(Ordering::SeqCst),
        4,
        "each waiter retries serially"
    );
    assert_eq!(
        max_seen.load(Ordering::SeqCst),
        1,
        "failing fetches must never overlap"
    );
    assert!(
        staging_is_empty(&state.settings.storage_dir),
        "staging not empty after failing fetches"
    );
}

#[tokio::test]
async fn cold_fill_aborts_when_hosted_upload_wins_race() {
    use axum::response::IntoResponse;
    const PROJECT: &str = "racepkg";
    const FILE: &str = "racepkg-1.0.tar.gz";
    const UPSTREAM_BYTES: &[u8] = b"upstream bytes that must lose the race";
    const HOSTED_BYTES: &[u8] = b"hosted bytes that win the race";
    // Slow success endpoint: the 500ms window lets the test upload land
    // deterministically mid-flight (after file_hits==1, before streaming ends).
    let file_hits = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}/");
    let index_base = base.clone();
    let upstream_sha = sha256_hex(UPSTREAM_BYTES);
    let fh = file_hits.clone();
    let app = Router::new()
        .route(
            "/{project}/",
            axum::routing::get(
                move |axum::extract::Path(project): axum::extract::Path<String>| {
                    let base = index_base.clone();
                    let sha = upstream_sha.clone();
                    async move {
                        if project != PROJECT {
                            return StatusCode::NOT_FOUND.into_response();
                        }
                        axum::Json(serde_json::json!({
                            "meta": {"api-version": "1.1"},
                            "name": PROJECT,
                            "files": [{
                                "filename": FILE,
                                "url": format!("{base}files/{FILE}"),
                                "hashes": {"sha256": sha},
                                "requires-python": null,
                                "yanked": false,
                            }]
                        }))
                        .into_response()
                    }
                },
            ),
        )
        .route(
            "/files/{filename}",
            axum::routing::get(
                move |axum::extract::Path(filename): axum::extract::Path<String>| {
                    let fh = fh.clone();
                    async move {
                        if filename != FILE {
                            return StatusCode::NOT_FOUND.into_response();
                        }
                        fh.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        (
                            [(header::CONTENT_TYPE, "application/octet-stream")],
                            UPSTREAM_BYTES.to_vec(),
                        )
                            .into_response()
                    }
                },
            ),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = UpstreamClient::new(
        base,
        std::time::Duration::from_secs(60),
        std::collections::HashSet::new(),
    );
    let (_app, state, _tmp) = test_app_with_upstream(Some(client)).await;
    let url = format!("/files/{PROJECT}/{FILE}");

    // Start the cold download in the background.
    let bg_state = state.clone();
    let bg_url = url.clone();
    let bg = tokio::spawn(async move {
        build_router(bg_state)
            .oneshot(get_request(&bg_url, Some(good_auth()), None))
            .await
            .unwrap()
    });
    // Wait until the upstream fetch is inside its slow window.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while file_hits.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("upstream fetch never started");

    // Hosted upload of the same key lands mid-flight and must win.
    let digest = sha256_hex(HOSTED_BYTES);
    let fields: Vec<(&str, &str)> = vec![
        (":action", "file_upload"),
        ("name", "RacePkg"),
        ("version", "1.0"),
        ("sha256_digest", digest.as_str()),
    ];
    let body = build_multipart(BOUNDARY, &fields, Some(("content", FILE, HOSTED_BYTES)));
    let res = build_router(state.clone())
        .oneshot(post_upload_request(Some(good_auth()), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // The in-flight download serves hosted bytes, not the stale upstream fill.
    let res = bg.await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::ETAG).unwrap(),
        &format!("\"{digest}\"")
    );
    assert_eq!(body_bytes(res.into_body()).await, HOSTED_BYTES);

    // And the cache fill never overwrote the hosted object.
    let res = build_router(state.clone())
        .oneshot(get_request(&url, Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_bytes(res.into_body()).await, HOSTED_BYTES);
    assert_eq!(
        state
            .storage
            .stat(".upstream-cache", &format!("{PROJECT}--{FILE}.sha256"))
            .await
            .unwrap(),
        None,
        "aborted fill must not write a sidecar"
    );
    assert!(
        staging_is_empty(&state.settings.storage_dir),
        "staging not empty after aborted fill"
    );
}

#[tokio::test]
async fn warm_cache_normalizes_uppercase_sidecar() {
    const PROJECT: &str = "casepkg";
    const FILE: &str = "casepkg-1.0.tar.gz";
    const BYTES: &[u8] = b"bytes for uppercase sidecar test";
    // Empty upstream: any index/file call proves the warm path leaked.
    let fake = spawn_fake_file_upstream(vec![]).await;
    let client = UpstreamClient::new(
        fake.base.clone(),
        std::time::Duration::from_secs(60),
        std::collections::HashSet::new(),
    );
    let (_app, state, _tmp) = test_app_with_upstream(Some(client)).await;

    // Seed cached bytes plus an UPPERCASE hex sidecar directly, stamped
    // fresh so age expiry (not the case fold) is what this test exercises.
    let upper = sha256_hex(BYTES).to_ascii_uppercase();
    let body = format!("{upper}\n{}\n", unix_now());
    seed_warm_cache_with_sidecar(&state, PROJECT, FILE, BYTES, &body).await;

    let url = format!("/files/{PROJECT}/{FILE}");
    let res = build_router(state.clone())
        .oneshot(get_request(&url, Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let expected_etag = format!("\"{}\"", sha256_hex(BYTES));
    assert_eq!(
        res.headers().get(header::ETAG).unwrap(),
        expected_etag.as_str(),
        "warm ETag must be lowercase hex"
    );
    assert_eq!(body_bytes(res.into_body()).await, BYTES);
    assert_eq!(fake.index_hits(), 0, "warm hit must skip the index");
    assert_eq!(fake.file_hits(), 0, "warm hit must skip file fetch");
}

#[tokio::test]
async fn health_ok_while_upstream_down() {
    // Dead port: nothing listens here, so any upstream call would fail fast.
    // /health checks only db + storage, never upstream.
    let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead_listener.local_addr().unwrap().port();
    drop(dead_listener);
    let client = UpstreamClient::new(
        format!("http://127.0.0.1:{dead_port}/"),
        std::time::Duration::from_secs(60),
        std::collections::HashSet::new(),
    );
    let (app, _state, _tmp) = test_app_with_upstream(Some(client)).await;
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
}

#[tokio::test]
async fn upstream_file_redirect_is_followed_and_verified() {
    use axum::response::IntoResponse;
    const PROJECT: &str = "redirpkg";
    const FILE: &str = "redirpkg-1.0.tar.gz";
    const BYTES: &[u8] = b"redirected upstream bytes verified by sha256";
    let sha = sha256_hex(BYTES);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}/");
    let index_base = base.clone();
    let redirect_base = base.clone();
    let index_sha = sha.clone();
    let index_hits = Arc::new(AtomicUsize::new(0));
    let redirect_hits = Arc::new(AtomicUsize::new(0));
    let file_hits = Arc::new(AtomicUsize::new(0));
    let ih = index_hits.clone();
    let rh = redirect_hits.clone();
    let fh = file_hits.clone();
    let app = Router::new()
        .route(
            "/{project}/",
            axum::routing::get(
                move |axum::extract::Path(project): axum::extract::Path<String>| {
                    let ih = ih.clone();
                    let base = index_base.clone();
                    let sha = index_sha.clone();
                    async move {
                        ih.fetch_add(1, Ordering::SeqCst);
                        if project != PROJECT {
                            return StatusCode::NOT_FOUND.into_response();
                        }
                        axum::Json(serde_json::json!({
                            "meta": {"api-version": "1.1"},
                            "name": PROJECT,
                            "files": [{
                                "filename": FILE,
                                "url": format!("{base}redirect/{FILE}"),
                                "hashes": {"sha256": sha},
                                "requires-python": null,
                                "yanked": false,
                            }]
                        }))
                        .into_response()
                    }
                },
            ),
        )
        .route(
            "/redirect/{filename}",
            axum::routing::get(
                move |axum::extract::Path(filename): axum::extract::Path<String>| {
                    let rh = rh.clone();
                    let base = redirect_base.clone();
                    async move {
                        rh.fetch_add(1, Ordering::SeqCst);
                        if filename != FILE {
                            return StatusCode::NOT_FOUND.into_response();
                        }
                        (
                            StatusCode::FOUND,
                            [(header::LOCATION, format!("{base}files/{FILE}"))],
                        )
                            .into_response()
                    }
                },
            ),
        )
        .route(
            "/files/{filename}",
            axum::routing::get(
                move |axum::extract::Path(filename): axum::extract::Path<String>| {
                    let fh = fh.clone();
                    async move {
                        fh.fetch_add(1, Ordering::SeqCst);
                        if filename != FILE {
                            return StatusCode::NOT_FOUND.into_response();
                        }
                        (
                            [(header::CONTENT_TYPE, "application/octet-stream")],
                            BYTES.to_vec(),
                        )
                            .into_response()
                    }
                },
            ),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = UpstreamClient::new(
        base,
        std::time::Duration::from_secs(60),
        std::collections::HashSet::new(),
    );
    let (_app, state, _tmp) = test_app_with_upstream(Some(client)).await;
    let url = format!("/files/{PROJECT}/{FILE}");
    let res = build_router(state.clone())
        .oneshot(get_request(&url, Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::ETAG).unwrap(),
        &format!("\"{sha}\"")
    );
    assert_eq!(body_bytes(res.into_body()).await, BYTES);
    assert_eq!(index_hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        redirect_hits.load(Ordering::SeqCst),
        1,
        "redirect must be followed"
    );
    assert_eq!(
        file_hits.load(Ordering::SeqCst),
        1,
        "redirect target must be fetched"
    );
}

#[tokio::test]
async fn upstream_percent_encoded_filename_round_trips() {
    // '+' percent-encodes as %2B in our index URLs and must decode back
    // to the exact upstream filename on download.
    const PROJECT: &str = "encpkg";
    const FILE: &str = "encpkg-1.0+local.tar.gz";
    const BYTES: &[u8] = b"bytes for percent-encoded filename round-trip";
    let (_app, state, _tmp, fake) = test_app_with_file_upstream(vec![FakeUpstreamFile {
        project: PROJECT,
        filename: FILE,
        index_sha256: sha256_hex(BYTES),
        bytes: BYTES.to_vec(),
        upload_time: None,
    }])
    .await;

    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/simple/{PROJECT}/"),
            Some(good_auth()),
            Some(JSON_ACCEPT),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["files"][0]["filename"], FILE);
    assert_eq!(
        json["files"][0]["url"],
        format!("/files/{PROJECT}/encpkg-1.0%2Blocal.tar.gz")
    );

    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/files/{PROJECT}/encpkg-1.0%2Blocal.tar.gz"),
            Some(good_auth()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_bytes(res.into_body()).await, BYTES);
    assert_eq!(fake.index_hits(), 1);
    assert_eq!(fake.file_hits(), 1);
}

#[tokio::test]
async fn upstream_empty_file_list_is_404() {
    use axum::response::IntoResponse;
    let app = Router::new().route(
        "/{project}/",
        axum::routing::get(
            |axum::extract::Path(project): axum::extract::Path<String>| async move {
                if project == "emptypkg" {
                    axum::Json(serde_json::json!({
                        "meta": {"api-version": "1.1"},
                        "name": "emptypkg",
                        "files": [],
                    }))
                    .into_response()
                } else {
                    StatusCode::NOT_FOUND.into_response()
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = UpstreamClient::new(
        format!("http://{addr}/"),
        std::time::Duration::from_secs(60),
        std::collections::HashSet::new(),
    );
    let (_app, state, _tmp) = test_app_with_upstream(Some(client)).await;

    // 200 with zero files and no hosted files is still a 404, both formats.
    for accept in [None, Some(JSON_ACCEPT)] {
        let res = build_router(state.clone())
            .oneshot(get_request("/simple/emptypkg/", Some(good_auth()), accept))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn upstream_private_only_denylist_is_normalized() {
    // Config-level: "Demo_Pkg" normalizes to "demo-pkg", so a denylist
    // entry in any spelling matches the normalized request path.
    let normalized = python_package_server::packaging::normalize_project("Demo_Pkg").unwrap();
    assert_eq!(normalized.as_str(), "demo-pkg");
    // Predicate-level via a Settings-built client (no env races).
    let mut settings = test_settings(std::env::temp_dir());
    settings.upstream_url = Some("http://127.0.0.1:9/".to_string());
    settings
        .upstream_private_only_projects
        .insert(normalized.to_string());
    let client = UpstreamClient::from_settings(&settings).expect("upstream client from settings");
    assert!(client.is_private_only("demo-pkg"));
    assert!(!client.is_private_only("other"));

    // End-to-end: a mixed-case request spelling still hits the denylist.
    let (base, counter) = spawn_fake_upstream().await;
    let mut private = std::collections::HashSet::new();
    private.insert("demo-pkg".to_string());
    let client = UpstreamClient::new(base, std::time::Duration::from_secs(60), private);
    let (_app, state, _tmp) = test_app_with_upstream(Some(client)).await;
    let res = build_router(state.clone())
        .oneshot(get_request(
            "/simple/Demo_Pkg/",
            Some(good_auth()),
            Some(JSON_ACCEPT),
        ))
        .await
        .unwrap();
    // No hosted files + denylisted => 404 without any upstream call
    // (the fake would otherwise serve two files for demo-pkg).
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Format unix seconds as a PEP 691 `upload-time` (RFC 3339 UTC).
fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn test_policy(default_days: u32, overrides: &[(&str, u32)]) -> Policy {
    Policy {
        quarantine_days_default: default_days,
        quarantine_days_by_project: overrides
            .iter()
            .map(|(project, days)| ((*project).to_string(), *days))
            .collect(),
    }
}

/// Fake upstream index with now-relative `upload-time` values, computed per
/// request: `youngpkg` (1h old), `oldpkg` (30d old), `mixedpkg` (one of
/// each), `requests` (5d old), `torch` (1h old), and `notimepkg` (no
/// `upload-time` key at all).
async fn spawn_quarantine_upstream() -> String {
    use axum::response::IntoResponse;
    const YOUNG_SHA: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const OLD_SHA: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    fn entry(filename: &str, sha: &str, age_secs: Option<u64>) -> serde_json::Value {
        let mut entry = serde_json::json!({
            "filename": filename,
            "url": format!("https://upstream.example/files/{filename}"),
            "hashes": {"sha256": sha},
            "requires-python": null,
            "yanked": false,
        });
        if let Some(age) = age_secs {
            entry["upload-time"] =
                serde_json::Value::String(rfc3339(unix_now().saturating_sub(age)));
        }
        entry
    }
    let app = Router::new().route(
        "/{project}/",
        axum::routing::get(
            |axum::extract::Path(project): axum::extract::Path<String>| async move {
                const HOUR: u64 = 3600;
                const DAY: u64 = 86_400;
                let files: Vec<serde_json::Value> = match project.as_str() {
                    "youngpkg" => vec![entry("youngpkg-2.0.tar.gz", YOUNG_SHA, Some(HOUR))],
                    "oldpkg" => vec![entry("oldpkg-1.0.tar.gz", OLD_SHA, Some(30 * DAY))],
                    "mixedpkg" => vec![
                        entry("mixedpkg-new.tar.gz", YOUNG_SHA, Some(HOUR)),
                        entry("mixedpkg-old.tar.gz", OLD_SHA, Some(30 * DAY)),
                    ],
                    "requests" => vec![entry("requests-9.9.tar.gz", YOUNG_SHA, Some(5 * DAY))],
                    "torch" => vec![entry("torch-9.9.tar.gz", YOUNG_SHA, Some(HOUR))],
                    "notimepkg" => vec![entry("notimepkg-1.0.tar.gz", OLD_SHA, None)],
                    _ => return StatusCode::NOT_FOUND.into_response(),
                };
                axum::Json(serde_json::json!({
                    "meta": {"api-version": "1.1"},
                    "name": project,
                    "files": files,
                }))
                .into_response()
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/")
}

async fn quarantine_index_app(policy: Policy) -> (AppState, tempfile::TempDir) {
    let base = spawn_quarantine_upstream().await;
    let client = UpstreamClient::new(
        base,
        std::time::Duration::from_secs(60),
        std::collections::HashSet::new(),
    );
    let (_router, state, tmp) = test_app_with_upstream_and_policy(Some(client), policy).await;
    (state, tmp)
}

/// Seed pull-through cache bytes + sidecar directly (lowercase hex hash,
/// stamped with the fetch time like a fresh cold fill).
async fn seed_warm_cache(state: &AppState, project: &str, filename: &str, bytes: &[u8]) {
    let body = format!("{}\n{}\n", sha256_hex(bytes), unix_now());
    seed_warm_cache_with_sidecar(state, project, filename, bytes, &body).await;
}

/// Seed cache bytes with a caller-crafted sidecar body (backdated stamps,
/// legacy plain-hash bodies) to control entry age without sleeping.
async fn seed_warm_cache_with_sidecar(
    state: &AppState,
    project: &str,
    filename: &str,
    bytes: &[u8],
    sidecar_body: &str,
) {
    use tokio::io::AsyncWriteExt;
    let (staging, mut dest) = state.storage.create_staging_file().await.unwrap();
    dest.write_all(bytes).await.unwrap();
    dest.flush().await.unwrap();
    drop(dest);
    state
        .storage
        .put_file(project, filename, &staging)
        .await
        .unwrap();
    overwrite_sidecar(state, project, filename, sidecar_body).await;
}

/// Overwrite just the sidecar for a cached `(project, filename)` key.
async fn overwrite_sidecar(state: &AppState, project: &str, filename: &str, sidecar_body: &str) {
    use tokio::io::AsyncWriteExt;
    let (staging, mut dest) = state.storage.create_staging_file().await.unwrap();
    dest.write_all(sidecar_body.as_bytes()).await.unwrap();
    dest.flush().await.unwrap();
    drop(dest);
    state
        .storage
        .put_file(
            ".upstream-cache",
            &format!("{project}--{filename}.sha256"),
            &staging,
        )
        .await
        .unwrap();
}

/// Read a cache sidecar body back as text.
async fn read_sidecar(state: &AppState, project: &str, filename: &str) -> String {
    let (_, body) = state
        .storage
        .get(".upstream-cache", &format!("{project}--{filename}.sha256"))
        .await
        .unwrap()
        .expect("sidecar must exist");
    String::from_utf8(body_bytes(body).await).unwrap()
}

#[tokio::test]
async fn quarantine_young_hidden_old_visible_index() {
    let (state, _tmp) = quarantine_index_app(test_policy(3, &[])).await;

    // Young-only project reads as missing in both formats.
    for accept in [None, Some(JSON_ACCEPT)] {
        let res = build_router(state.clone())
            .oneshot(get_request("/simple/youngpkg/", Some(good_auth()), accept))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "accept={accept:?}");
    }

    // Old file visible in both formats.
    let res = build_router(state.clone())
        .oneshot(get_request(
            "/simple/oldpkg/",
            Some(good_auth()),
            Some(JSON_ACCEPT),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["files"].as_array().unwrap().len(), 1, "{text}");
    assert_eq!(json["files"][0]["filename"], "oldpkg-1.0.tar.gz");
    let res = build_router(state.clone())
        .oneshot(get_request("/simple/oldpkg/", Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res.into_body()).await;
    assert!(html.contains("oldpkg-1.0.tar.gz"), "{html}");

    // Mixed project lists only the old file.
    let res = build_router(state.clone())
        .oneshot(get_request(
            "/simple/mixedpkg/",
            Some(good_auth()),
            Some(JSON_ACCEPT),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let files = json["files"].as_array().unwrap();
    assert_eq!(files.len(), 1, "{text}");
    assert_eq!(files[0]["filename"], "mixedpkg-old.tar.gz");
    let res = build_router(state.clone())
        .oneshot(get_request("/simple/mixedpkg/", Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res.into_body()).await;
    assert!(html.contains("mixedpkg-old.tar.gz"), "{html}");
    assert!(!html.contains("mixedpkg-new.tar.gz"), "{html}");
}

#[tokio::test]
async fn quarantine_per_package_override() {
    // Default 3d, requests held 10d, torch exempt: the 5d-old requests file
    // (visible under the default) stays hidden, while the 1h-old torch file
    // (hidden under the default) serves.
    let (state, _tmp) =
        quarantine_index_app(test_policy(3, &[("requests", 10), ("torch", 0)])).await;

    for accept in [None, Some(JSON_ACCEPT)] {
        let res = build_router(state.clone())
            .oneshot(get_request("/simple/requests/", Some(good_auth()), accept))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "accept={accept:?}");
    }

    let res = build_router(state.clone())
        .oneshot(get_request(
            "/simple/torch/",
            Some(good_auth()),
            Some(JSON_ACCEPT),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["files"].as_array().unwrap().len(), 1, "{text}");
    assert_eq!(json["files"][0]["filename"], "torch-9.9.tar.gz");
}

#[tokio::test]
async fn quarantine_download_blocked_even_when_warm() {
    const PROJECT: &str = "qdlpkg";
    const YOUNG_FILE: &str = "qdlpkg-2.0.tar.gz";
    const OLD_FILE: &str = "qdlpkg-1.0.tar.gz";
    const YOUNG_BYTES: &[u8] = b"young quarantined bytes must never serve";
    const OLD_BYTES: &[u8] = b"old released bytes serve normally";
    let now = unix_now();
    let (_app, state, _tmp, fake) = test_app_with_file_upstream_and_policy(
        vec![
            FakeUpstreamFile {
                project: PROJECT,
                filename: YOUNG_FILE,
                index_sha256: sha256_hex(YOUNG_BYTES),
                bytes: YOUNG_BYTES.to_vec(),
                upload_time: Some(rfc3339(now - 3600)),
            },
            FakeUpstreamFile {
                project: PROJECT,
                filename: OLD_FILE,
                index_sha256: sha256_hex(OLD_BYTES),
                bytes: OLD_BYTES.to_vec(),
                upload_time: Some(rfc3339(now - 30 * 86_400)),
            },
        ],
        test_policy(3, &[]),
    )
    .await;
    let young_url = format!("/files/{PROJECT}/{YOUNG_FILE}");

    // Young download 404s without fetching bytes.
    let res = build_router(state.clone())
        .oneshot(get_request(&young_url, Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(fake.file_hits(), 0, "quarantined file must not fetch");

    // A warm cache entry does not release it either.
    seed_warm_cache(&state, PROJECT, YOUNG_FILE, YOUNG_BYTES).await;
    let res = build_router(state.clone())
        .oneshot(get_request(&young_url, Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(fake.file_hits(), 0, "quarantined file must not fetch");

    // The old file still cold-fetches, caches, and serves with policy active.
    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/files/{PROJECT}/{OLD_FILE}"),
            Some(good_auth()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_bytes(res.into_body()).await, OLD_BYTES);
    assert_eq!(fake.file_hits(), 1);
}

#[tokio::test]
async fn quarantine_missing_upload_time_fail_closed() {
    // The legacy fake index omits upload-time entirely, and the HTML
    // fallback has no timestamps: under quarantine both read as missing.
    let (base, _counter) = spawn_fake_upstream().await;
    let client = UpstreamClient::new(
        base,
        std::time::Duration::from_secs(60),
        std::collections::HashSet::new(),
    );
    let (_app, state, _tmp) =
        test_app_with_upstream_and_policy(Some(client), test_policy(3, &[])).await;
    for project in ["purepkg", "htmlpkg", "demo-pkg"] {
        let res = build_router(state.clone())
            .oneshot(get_request(
                &format!("/simple/{project}/"),
                Some(good_auth()),
                Some(JSON_ACCEPT),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "project={project}");
    }
    // Same shape via the quarantine fake's explicit no-timestamp project.
    let (state, _tmp) = quarantine_index_app(test_policy(3, &[])).await;
    let res = build_router(state.clone())
        .oneshot(get_request("/simple/notimepkg/", Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // Download side: unknown age 404s without fetching bytes.
    const FILE: &str = "notimepkg-1.0.tar.gz";
    const BYTES: &[u8] = b"bytes with unknown age must not serve";
    let (_app, state, _tmp, fake) = test_app_with_file_upstream_and_policy(
        vec![FakeUpstreamFile {
            project: "notimepkg",
            filename: FILE,
            index_sha256: sha256_hex(BYTES),
            bytes: BYTES.to_vec(),
            upload_time: None,
        }],
        test_policy(3, &[]),
    )
    .await;
    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/files/notimepkg/{FILE}"),
            Some(good_auth()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(fake.file_hits(), 0);
}

#[tokio::test]
async fn quarantine_hosted_never_quarantined() {
    // Even a 365-day default cannot touch hosted files.
    let base = spawn_quarantine_upstream().await;
    let client = UpstreamClient::new(
        base,
        std::time::Duration::from_secs(60),
        std::collections::HashSet::new(),
    );
    let (_app, state, _tmp) =
        test_app_with_upstream_and_policy(Some(client), test_policy(365, &[])).await;

    // Upload a hosted file under the young-upstream project.
    const HOSTED_BYTES: &[u8] = b"hosted bytes always serve";
    const HOSTED_FILE: &str = "youngpkg-1.0.tar.gz";
    let digest = sha256_hex(HOSTED_BYTES);
    let fields: Vec<(&str, &str)> = vec![
        (":action", "file_upload"),
        ("name", "YoungPkg"),
        ("version", "1.0"),
        ("sha256_digest", digest.as_str()),
    ];
    let body = build_multipart(
        BOUNDARY,
        &fields,
        Some(("content", HOSTED_FILE, HOSTED_BYTES)),
    );
    let res = build_router(state.clone())
        .oneshot(post_upload_request(Some(good_auth()), body, BOUNDARY))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Index lists the hosted file (the young upstream file stays hidden).
    let res = build_router(state.clone())
        .oneshot(get_request(
            "/simple/youngpkg/",
            Some(good_auth()),
            Some(JSON_ACCEPT),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let files = json["files"].as_array().unwrap();
    assert_eq!(files.len(), 1, "{text}");
    assert_eq!(files[0]["filename"], HOSTED_FILE);

    // Download serves hosted bytes.
    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/files/youngpkg/{HOSTED_FILE}"),
            Some(good_auth()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_bytes(res.into_body()).await, HOSTED_BYTES);
}

#[tokio::test]
async fn quarantine_disabled_without_policy() {
    // POLICY_FILE unset is Policy::default(): young upstream files serve.
    let (state, _tmp) = quarantine_index_app(Policy::default()).await;
    let res = build_router(state.clone())
        .oneshot(get_request(
            "/simple/youngpkg/",
            Some(good_auth()),
            Some(JSON_ACCEPT),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["files"].as_array().unwrap().len(), 1, "{text}");

    const FILE: &str = "freshpkg-2.0.tar.gz";
    const BYTES: &[u8] = b"young bytes serve while quarantine is off";
    let (_app, state, _tmp, fake) = test_app_with_file_upstream(vec![FakeUpstreamFile {
        project: "freshpkg",
        filename: FILE,
        index_sha256: sha256_hex(BYTES),
        bytes: BYTES.to_vec(),
        upload_time: Some(rfc3339(unix_now() - 60)),
    }])
    .await;
    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/files/freshpkg/{FILE}"),
            Some(good_auth()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_bytes(res.into_body()).await, BYTES);
    assert_eq!(fake.file_hits(), 1);
}

const DAY_SECS: u64 = 86_400;

#[tokio::test]
async fn upstream_expired_warm_entry_refetches() {
    let (_app, state, _tmp, fake) = test_app_with_file_upstream(vec![cache_fixture()]).await;

    // Cold fill, then age the entry 31 days past the default 30-day TTL.
    let res = build_router(state.clone())
        .oneshot(get_request(&cache_url(), Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_bytes(res.into_body()).await, CACHE_BYTES);
    assert_eq!(fake.file_hits(), 1);
    let stale = format!(
        "{}\n{}\n",
        sha256_hex(CACHE_BYTES),
        unix_now() - 31 * DAY_SECS
    );
    overwrite_sidecar(&state, CACHE_PROJECT, CACHE_FILE, &stale).await;

    let res = build_router(state.clone())
        .oneshot(get_request(&cache_url(), Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_bytes(res.into_body()).await, CACHE_BYTES);
    assert_eq!(fake.file_hits(), 2, "expired entry must re-fetch");
    assert_eq!(fake.index_hits(), 1, "index stays TTL-cached");

    // The refill re-stamped the sidecar: same hash, now fresh.
    let sidecar = read_sidecar(&state, CACHE_PROJECT, CACHE_FILE).await;
    let mut lines = sidecar.lines();
    assert_eq!(lines.next().unwrap(), sha256_hex(CACHE_BYTES).as_str());
    let stamped: u64 = lines.next().unwrap().parse().unwrap();
    assert!(
        unix_now().saturating_sub(stamped) < 120,
        "sidecar must carry a fresh stamp"
    );
}

#[tokio::test]
async fn upstream_unexpired_warm_entry_serves_without_upstream() {
    let (_app, state, _tmp, fake) = test_app_with_file_upstream(vec![cache_fixture()]).await;
    let expected_etag = format!("\"{}\"", sha256_hex(CACHE_BYTES));

    let res = build_router(state.clone())
        .oneshot(get_request(&cache_url(), Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(fake.file_hits(), 1);

    // Age the entry 29 days: inside the 30-day TTL, still warm.
    let aged_stamp = unix_now() - 29 * DAY_SECS;
    let aged = format!("{}\n{aged_stamp}\n", sha256_hex(CACHE_BYTES));
    overwrite_sidecar(&state, CACHE_PROJECT, CACHE_FILE, &aged).await;

    let res = build_router(state.clone())
        .oneshot(get_request(&cache_url(), Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get(header::ETAG).unwrap(), &expected_etag);
    assert_eq!(body_bytes(res.into_body()).await, CACHE_BYTES);
    assert_eq!(fake.file_hits(), 1, "unexpired warm hit must not fetch");
    assert_eq!(
        fake.index_hits(),
        1,
        "unexpired warm hit must skip the index"
    );

    // A warm hit rewrites nothing: the aged stamp survives verbatim.
    let sidecar = read_sidecar(&state, CACHE_PROJECT, CACHE_FILE).await;
    assert_eq!(
        sidecar.lines().nth(1).unwrap().parse::<u64>().unwrap(),
        aged_stamp
    );
}

#[tokio::test]
async fn upstream_cache_ttl_zero_never_expires() {
    // Empty upstream: any fetch attempt proves the path leaked.
    let (_app, state, _tmp, fake) = test_app_with_file_upstream_and_cache_ttl(vec![], 0).await;
    const PROJECT: &str = "zeropkg";
    const FILE: &str = "zeropkg-1.0.tar.gz";
    const BYTES: &[u8] = b"bytes that never expire under TTL 0";
    // A legacy unstamped sidecar: unknown age, yet still served with TTL 0.
    seed_warm_cache_with_sidecar(&state, PROJECT, FILE, BYTES, &sha256_hex(BYTES)).await;

    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/files/{PROJECT}/{FILE}"),
            Some(good_auth()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_bytes(res.into_body()).await, BYTES);
    assert_eq!(fake.index_hits(), 0);
    assert_eq!(fake.file_hits(), 0);
    // And the legacy body is left untouched (no refresh, no stamp).
    assert_eq!(read_sidecar(&state, PROJECT, FILE).await, sha256_hex(BYTES));
}

#[tokio::test]
async fn upstream_cache_sweep_deletes_expired_and_keeps_fresh() {
    use python_package_server::reconcile::sweep_upstream_cache;
    let (_app, state, _tmp, _fake) = test_app_with_file_upstream(vec![]).await;
    const PROJECT: &str = "sweeppkg";
    const OLD_FILE: &str = "sweeppkg-old.tar.gz";
    const NEW_FILE: &str = "sweeppkg-new.tar.gz";
    const OLD_BYTES: &[u8] = b"stale bytes the sweep reclaims";
    const NEW_BYTES: &[u8] = b"fresh bytes the sweep keeps";
    seed_warm_cache_with_sidecar(
        &state,
        PROJECT,
        OLD_FILE,
        OLD_BYTES,
        &format!(
            "{}\n{}\n",
            sha256_hex(OLD_BYTES),
            unix_now() - 31 * DAY_SECS
        ),
    )
    .await;
    seed_warm_cache(&state, PROJECT, NEW_FILE, NEW_BYTES).await;

    assert_eq!(sweep_upstream_cache(&state.db, &state.storage, 30).await, 1);

    assert!(
        state
            .storage
            .stat(PROJECT, OLD_FILE)
            .await
            .unwrap()
            .is_none(),
        "expired bytes must be evicted"
    );
    assert!(
        state
            .storage
            .get(".upstream-cache", &format!("{PROJECT}--{OLD_FILE}.sha256"))
            .await
            .unwrap()
            .is_none(),
        "expired sidecar must be evicted"
    );
    assert!(
        state
            .storage
            .stat(PROJECT, NEW_FILE)
            .await
            .unwrap()
            .is_some(),
        "fresh bytes must survive"
    );
    assert!(
        state
            .storage
            .get(".upstream-cache", &format!("{PROJECT}--{NEW_FILE}.sha256"))
            .await
            .unwrap()
            .is_some(),
        "fresh sidecar must survive"
    );
}

#[tokio::test]
async fn upstream_cache_sweep_never_deletes_hosted() {
    use python_package_server::reconcile::sweep_upstream_cache;
    let (_app, state, _tmp, _fake) = test_app_with_file_upstream(vec![]).await;
    const PROJECT: &str = "sweephost";
    const FILE: &str = "sweephost-1.0.tar.gz";
    const BYTES: &[u8] = b"hosted bytes with a stale sidecar beside them";
    seed_hosted(&state, PROJECT, "SweepHost", FILE, &sha256_hex(BYTES), None).await;
    // Cached bytes plus an ancient sidecar under the same key, as a hosted
    // upload shadowing an older cache entry leaves behind.
    seed_warm_cache_with_sidecar(
        &state,
        PROJECT,
        FILE,
        BYTES,
        &format!("{}\n0\n", sha256_hex(BYTES)),
    )
    .await;

    assert_eq!(sweep_upstream_cache(&state.db, &state.storage, 30).await, 0);
    assert!(
        state.storage.stat(PROJECT, FILE).await.unwrap().is_some(),
        "hosted bytes must survive the sweep"
    );
    // Bytes byte-identical and the row untouched: the sweep deleted nothing.
    let (size, body) = state
        .storage
        .get(PROJECT, FILE)
        .await
        .unwrap()
        .expect("hosted bytes must survive the sweep");
    assert_eq!(size, BYTES.len() as u64);
    assert_eq!(body_bytes(body).await, BYTES);
    assert!(
        state.db.get_file(PROJECT, FILE).await.unwrap().is_some(),
        "hosted row must survive the sweep"
    );
    assert!(
        state
            .storage
            .get(".upstream-cache", &format!("{PROJECT}--{FILE}.sha256"))
            .await
            .unwrap()
            .is_some(),
        "hosted key sidecar must survive the sweep"
    );
}

#[tokio::test]
async fn upstream_legacy_sidecar_refreshes_once() {
    let (_app, state, _tmp, fake) = test_app_with_file_upstream(vec![cache_fixture()]).await;

    // Legacy plain-hash sidecar: unknown age reads as expired under TTL 30.
    seed_warm_cache_with_sidecar(
        &state,
        CACHE_PROJECT,
        CACHE_FILE,
        CACHE_BYTES,
        &sha256_hex(CACHE_BYTES),
    )
    .await;

    let res = build_router(state.clone())
        .oneshot(get_request(&cache_url(), Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_bytes(res.into_body()).await, CACHE_BYTES);
    assert_eq!(fake.file_hits(), 1, "legacy entry must refresh");

    // The refresh stamped the sidecar; the next request is a true warm hit.
    let sidecar = read_sidecar(&state, CACHE_PROJECT, CACHE_FILE).await;
    let mut lines = sidecar.lines();
    assert_eq!(lines.next().unwrap(), sha256_hex(CACHE_BYTES).as_str());
    let stamped: u64 = lines
        .next()
        .expect("refreshed sidecar must carry a stamp")
        .parse()
        .unwrap();
    assert!(unix_now().saturating_sub(stamped) < 120);

    let res = build_router(state.clone())
        .oneshot(get_request(&cache_url(), Some(good_auth()), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(fake.file_hits(), 1, "second request must be a warm hit");
}

#[tokio::test]
async fn upstream_expired_sidecar_with_hosted_row_serves_hosted() {
    // Empty upstream: any fetch attempt proves the path leaked.
    let (_app, state, _tmp, fake) = test_app_with_file_upstream(vec![]).await;
    const PROJECT: &str = "shadowpkg";
    const FILE: &str = "shadowpkg-1.0.tar.gz";
    const BYTES: &[u8] = b"hosted bytes shadowed by a stale sidecar";
    let sha = sha256_hex(BYTES);
    seed_hosted(&state, PROJECT, "ShadowPkg", FILE, &sha, None).await;
    // Hosted bytes plus an ancient sidecar under the same key, as an upload
    // racing lazy eviction leaves behind.
    seed_warm_cache_with_sidecar(&state, PROJECT, FILE, BYTES, &format!("{sha}\n0\n")).await;

    let res = build_router(state.clone())
        .oneshot(get_request(
            &format!("/files/{PROJECT}/{FILE}"),
            Some(good_auth()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::ETAG).unwrap(),
        &format!("\"{sha}\"")
    );
    assert_eq!(body_bytes(res.into_body()).await, BYTES);
    assert_eq!(fake.index_hits(), 0);
    assert_eq!(fake.file_hits(), 0);

    // Nothing deleted: row, bytes, and sidecar all intact afterwards.
    assert!(
        state.db.get_file(PROJECT, FILE).await.unwrap().is_some(),
        "hosted row must survive"
    );
    let (size, body) = state
        .storage
        .get(PROJECT, FILE)
        .await
        .unwrap()
        .expect("hosted bytes must survive");
    assert_eq!(size, BYTES.len() as u64);
    assert_eq!(body_bytes(body).await, BYTES);
    assert!(
        state
            .storage
            .get(".upstream-cache", &format!("{PROJECT}--{FILE}.sha256"))
            .await
            .unwrap()
            .is_some(),
        "sidecar beside a hosted key must survive"
    );
}

#[tokio::test]
async fn hosted_upload_removes_shadowing_cache_sidecar() {
    let (app, state, _tmp) = test_app().await;
    // A stale sidecar shadowing the key about to be hosted, as an older
    // pull-through cache entry leaves behind.
    overwrite_sidecar(
        &state,
        NORMALIZED,
        FILENAME,
        &format!("{}\n0\n", sha256_hex(b"older cached bytes")),
    )
    .await;

    let res = app
        .oneshot(post_upload_request(
            Some(good_auth()),
            upload_body(FILE_BYTES, None),
            BOUNDARY,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // The upload published hosted bytes and dropped the orphaned sidecar.
    let (size, body) = state
        .storage
        .get(NORMALIZED, FILENAME)
        .await
        .unwrap()
        .expect("hosted bytes must exist after upload");
    assert_eq!(size, FILE_BYTES.len() as u64);
    assert_eq!(body_bytes(body).await, FILE_BYTES);
    assert!(
        state
            .db
            .get_file(NORMALIZED, FILENAME)
            .await
            .unwrap()
            .is_some(),
        "hosted row must exist after upload"
    );
    assert!(
        state
            .storage
            .get(
                ".upstream-cache",
                &format!("{NORMALIZED}--{FILENAME}.sha256")
            )
            .await
            .unwrap()
            .is_none(),
        "shadowing sidecar must be removed by the upload"
    );
}
