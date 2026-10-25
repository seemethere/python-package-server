//! Upstream (PyPI) pull-through index client with in-memory TTL cache.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use thiserror::Error;
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};

use crate::config::Settings;

const JSON_ACCEPT: &str = "application/vnd.pypi.simple.v1+json";

/// Total timeout for upstream index fetches (small JSON/HTML bodies).
const INDEX_TIMEOUT_SECS: u64 = 10;

/// Total timeout for upstream file downloads. Streaming bodies are still
/// capped per chunk by `max_upload_bytes`, so this only bounds stalled
/// transfers — large files must not hit the 10s index budget.
const DOWNLOAD_TIMEOUT_SECS: u64 = 600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamFile {
    pub filename: String,
    pub url: String,
    pub sha256: String,
    pub requires_python: Option<String>,
    pub yanked: bool,
    pub yank_reason: Option<String>,
}

#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("upstream request failed: {0}")]
    Request(String),
    #[error("upstream returned status {0}")]
    Status(u16),
    #[error("failed to parse upstream response: {0}")]
    Parse(String),
}

#[derive(Clone)]
struct CacheEntry {
    fetched_at: Instant,
    files: Option<Vec<UpstreamFile>>,
}

#[derive(Clone)]
pub struct UpstreamClient {
    base_url: String,
    http: reqwest::Client,
    download_http: reqwest::Client,
    ttl: Duration,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    private_only: HashSet<String>,
    inflight: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

/// Single-flight permit for one upstream file fetch.
///
/// While held, no other holder for the same `(project, filename)` key runs a
/// fetch; holders that arrive later re-check the byte cache after acquiring,
/// so exactly one fetch fills the cache on success. On failure the next
/// waiter retries serially (never concurrently); dropping never poisons the
/// key because removal is identity-checked (see [`Drop`]).
pub struct FetchPermit {
    _guard: OwnedMutexGuard<()>,
    slot: Arc<Mutex<()>>,
    inflight: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    key: String,
}

impl Drop for FetchPermit {
    fn drop(&mut self) {
        // Remove only our own idle slot. An unconditional remove lets a
        // stale drop delete a newer live entry, and lets arrivals after a
        // failed fetch each mint a fresh slot and fetch concurrently.
        // A contended map leaves the entry behind; reuse is harmless
        // because waiters always re-check the cache after acquiring.
        if let Ok(mut inflight) = self.inflight.try_lock() {
            let is_ours = inflight
                .get(&self.key)
                .is_some_and(|existing| Arc::ptr_eq(existing, &self.slot));
            if !is_ours {
                return;
            }
            // Live refs with no waiters: map(1) + our `slot` field(1) + our
            // guard's Arc(1) = 3. Any waiter holds >=1 extra clone (its
            // local `slot` plus the queued lock future's Arc while pending),
            // so `> 3` means someone is queued on this slot: keep it.
            if Arc::strong_count(&self.slot) <= 3 {
                inflight.remove(&self.key);
            }
        }
    }
}

impl UpstreamClient {
    pub fn new(base_url: impl Into<String>, ttl: Duration, private_only: HashSet<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(INDEX_TIMEOUT_SECS))
            .build()
            .unwrap_or_default();
        Self::with_http(base_url, ttl, private_only, http)
    }

    pub fn with_http(
        base_url: impl Into<String>,
        ttl: Duration,
        private_only: HashSet<String>,
        http: reqwest::Client,
    ) -> Self {
        let base_url = base_url.into();
        let base_url = if base_url.ends_with('/') {
            base_url
        } else {
            format!("{base_url}/")
        };
        // Downloads always get the generous budget, even when the caller
        // injects a custom index client: streaming bodies must not share
        // the 10s index timeout.
        let download_http = reqwest::Client::builder()
            .timeout(Duration::from_secs(DOWNLOAD_TIMEOUT_SECS))
            .build()
            .unwrap_or_default();
        Self {
            base_url,
            http,
            download_http,
            ttl,
            cache: Arc::new(RwLock::new(HashMap::new())),
            private_only,
            inflight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn from_settings(settings: &Settings) -> Option<Self> {
        settings.upstream_url.as_ref().map(|url| {
            Self::new(
                url.clone(),
                Duration::from_secs(settings.upstream_index_ttl_secs),
                settings.upstream_private_only_projects.clone(),
            )
        })
    }

    pub fn is_private_only(&self, normalized: &str) -> bool {
        self.private_only.contains(normalized)
    }

    pub async fn fetch_project(
        &self,
        normalized: &str,
    ) -> Result<Option<Vec<UpstreamFile>>, UpstreamError> {
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(normalized) {
                if entry.fetched_at.elapsed() < self.ttl {
                    return Ok(entry.files.clone());
                }
            }
        }
        let url = format!("{}{}/", self.base_url, normalized);
        let response = self
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, JSON_ACCEPT)
            .send()
            .await
            .map_err(|e| UpstreamError::Request(e.to_string()))?;
        let status = response.status();
        if status.as_u16() == 404 {
            let mut cache = self.cache.write().await;
            cache.insert(
                normalized.to_string(),
                CacheEntry {
                    fetched_at: Instant::now(),
                    files: None,
                },
            );
            return Ok(None);
        }
        if !status.is_success() {
            return Err(UpstreamError::Status(status.as_u16()));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        let body = response
            .text()
            .await
            .map_err(|e| UpstreamError::Request(e.to_string()))?;
        let files = if content_type.contains("json") {
            Some(parse_json_index(&body)?)
        } else {
            Some(parse_html_index(&body))
        };
        {
            let mut cache = self.cache.write().await;
            cache.insert(
                normalized.to_string(),
                CacheEntry {
                    fetched_at: Instant::now(),
                    files: files.clone(),
                },
            );
        }
        Ok(files)
    }

    pub async fn file_for(
        &self,
        normalized: &str,
        filename: &str,
    ) -> Result<Option<UpstreamFile>, UpstreamError> {
        let files = self.fetch_project(normalized).await?;
        Ok(files.and_then(|files| files.into_iter().find(|f| f.filename == filename)))
    }

    /// Acquire the single-flight permit for `(project, filename)`.
    ///
    /// Callers must re-check the byte cache after acquiring: the previous
    /// holder may have filled it while this call was queued.
    pub async fn acquire_fetch(&self, project: &str, filename: &str) -> FetchPermit {
        let key = format!("{project}/{filename}");
        let slot = {
            let mut inflight = self.inflight.lock().await;
            inflight
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let guard = Arc::clone(&slot).lock_owned().await;
        FetchPermit {
            _guard: guard,
            slot,
            inflight: Arc::clone(&self.inflight),
            key,
        }
    }

    /// GET an upstream file URL for streaming; non-success statuses are errors.
    ///
    /// Uses the download client (`DOWNLOAD_TIMEOUT_SECS`), not the 10s index
    /// client, so large files can stream to completion.
    pub async fn download(&self, url: &str) -> Result<reqwest::Response, UpstreamError> {
        let response = self
            .download_http
            .get(url)
            .send()
            .await
            .map_err(|e| UpstreamError::Request(e.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(UpstreamError::Status(status.as_u16()));
        }
        Ok(response)
    }
}

#[derive(Debug, Deserialize)]
struct JsonIndex {
    files: Vec<JsonFile>,
}

#[derive(Debug, Deserialize)]
struct JsonFile {
    filename: String,
    url: String,
    hashes: Option<JsonHashes>,
    #[serde(default, rename = "requires-python")]
    requires_python: Option<String>,
    #[serde(default)]
    yanked: Option<YankedValue>,
}

#[derive(Debug, Deserialize)]
struct JsonHashes {
    sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum YankedValue {
    Bool(bool),
    Text(String),
}

fn parse_json_index(body: &str) -> Result<Vec<UpstreamFile>, UpstreamError> {
    let index: JsonIndex =
        serde_json::from_str(body).map_err(|e| UpstreamError::Parse(e.to_string()))?;
    Ok(index
        .files
        .into_iter()
        .map(|f| {
            let (yanked, yank_reason) = match f.yanked {
                None | Some(YankedValue::Bool(false)) => (false, None),
                Some(YankedValue::Bool(true)) => (true, None),
                Some(YankedValue::Text(s)) if s.is_empty() => (true, None),
                Some(YankedValue::Text(s)) => (true, Some(s)),
            };
            UpstreamFile {
                filename: f.filename,
                url: f.url,
                sha256: f.hashes.and_then(|h| h.sha256).unwrap_or_default(),
                requires_python: f.requires_python,
                yanked,
                yank_reason,
            }
        })
        .collect())
}

fn html_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(idx) = rest.find('&') {
        out.push_str(&rest[..idx]);
        let tail = &rest[idx..];
        let Some(semi) = tail.find(';') else {
            out.push_str(tail);
            rest = "";
            break;
        };
        let entity = &tail[1..semi];
        let decoded: Option<String> = match entity {
            "amp" => Some("&".to_string()),
            "lt" => Some("<".to_string()),
            "gt" => Some(">".to_string()),
            "quot" => Some("\"".to_string()),
            "apos" => Some("'".to_string()),
            _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                u32::from_str_radix(&entity[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
                    .map(|c| c.to_string())
            }
            _ if entity.starts_with('#') => entity[1..]
                .parse::<u32>()
                .ok()
                .and_then(char::from_u32)
                .map(|c| c.to_string()),
            _ => None,
        };
        if let Some(d) = decoded {
            out.push_str(&d);
        } else {
            out.push_str(&tail[..=semi]);
        }
        rest = &tail[semi + 1..];
    }
    out.push_str(rest);
    out
}

fn parse_attrs(tag: &str) -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    let bytes = tag.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let name_start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'/'
        {
            i += 1;
        }
        if name_start == i {
            i += 1;
            continue;
        }
        let name = tag[name_start..i].to_lowercase();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                value = tag[start..i].to_string();
                if i < bytes.len() {
                    i += 1;
                }
            } else {
                let start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                value = tag[start..i].to_string();
            }
        }
        attrs.insert(name, html_unescape(&value));
    }
    attrs
}

fn parse_html_index(body: &str) -> Vec<UpstreamFile> {
    let lower = body.to_lowercase();
    let mut files = Vec::new();
    let mut pos = 0;
    while let Some(rel) = lower[pos..].find("<a") {
        let start = pos + rel;
        let after_a = start + 2;
        // Ensure this is an anchor start, not e.g. <abbr>.
        if after_a < body.len() {
            let c = body.as_bytes()[after_a];
            if !(c.is_ascii_whitespace() || c == b'>' || c == b'/') {
                pos = after_a;
                continue;
            }
        }
        // Find end of opening tag respecting quotes.
        let mut i = after_a;
        let bytes = body.as_bytes();
        let mut in_double = false;
        let mut in_single = false;
        while i < bytes.len() {
            match bytes[i] {
                b'"' if !in_single => in_double = !in_double,
                b'\'' if !in_double => in_single = !in_single,
                b'>' if !in_double && !in_single => break,
                _ => {}
            }
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let tag_inner = &body[after_a..i];
        let attrs = parse_attrs(tag_inner);
        let Some(href_raw) = attrs.get("href").cloned() else {
            pos = i + 1;
            continue;
        };
        // Link text is between '>' and '</a>'.
        let text_start = i + 1;
        let Some(rel_close) = lower[text_start..].find("</a>") else {
            break;
        };
        let text_end = text_start + rel_close;
        let raw_text = &body[text_start..text_end];
        let text = {
            // Strip any inner tags.
            let mut stripped = String::new();
            let mut inner_bytes = raw_text;
            while let Some(lt) = inner_bytes.find('<') {
                stripped.push_str(&inner_bytes[..lt]);
                if let Some(gt) = inner_bytes[lt..].find('>') {
                    inner_bytes = &inner_bytes[lt + gt + 1..];
                } else {
                    inner_bytes = "";
                    break;
                }
            }
            stripped.push_str(inner_bytes);
            html_unescape(stripped.trim())
        };
        let (url_part, fragment) = match href_raw.split_once('#') {
            Some((u, f)) => (u.to_string(), Some(f.to_string())),
            None => (href_raw.clone(), None),
        };
        let sha256 = fragment
            .as_deref()
            .and_then(|frag| {
                frag.split('&')
                    .find_map(|part| part.strip_prefix("sha256=").map(|v| v.to_string()))
            })
            .unwrap_or_default();
        let filename = if !text.is_empty() {
            text
        } else {
            url_part
                .rsplit('/')
                .next()
                .unwrap_or("")
                .split('?')
                .next()
                .unwrap_or("")
                .to_string()
        };
        if filename.is_empty() {
            pos = text_end + 4;
            continue;
        }
        let requires_python = attrs
            .get("data-requires-python")
            .cloned()
            .filter(|v| !v.is_empty());
        let (yanked, yank_reason) = match attrs.get("data-yanked") {
            None => (false, None),
            Some(v) if v.is_empty() => (true, None),
            Some(v) => (true, Some(v.clone())),
        };
        files.push(UpstreamFile {
            filename,
            url: url_part,
            sha256,
            requires_python,
            yanked,
            yank_reason,
        });
        pos = text_end + 4;
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode, response::IntoResponse, routing::get, Json, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;

    async fn spawn(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/")
    }

    fn client(base: String) -> UpstreamClient {
        UpstreamClient::new(base, Duration::from_secs(60), HashSet::new())
    }

    #[tokio::test]
    async fn fetches_json_index() {
        let app = Router::new().route(
            "/{project}/",
            get(|axum::extract::Path(p): axum::extract::Path<String>| async move {
                assert_eq!(p, "demo-pkg");
                Json(serde_json::json!({
                    "meta": {"api-version": "1.1"},
                    "name": "demo-pkg",
                    "files": [
                        {"filename":"demo-pkg-1.0.tar.gz","url":"https://files.example/demo-pkg-1.0.tar.gz","hashes":{"sha256":"aaa"},"requires-python":">=3.8","yanked":false},
                        {"filename":"demo-pkg-2.0.tar.gz","url":"https://files.example/demo-pkg-2.0.tar.gz","hashes":{"sha256":"bbb"},"requires-python":null,"yanked":"bad build"}
                    ]
                }))
            }),
        );
        let base = spawn(app).await;
        let c = client(base);
        let files = c.fetch_project("demo-pkg").await.unwrap().unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].sha256, "aaa");
        assert_eq!(files[0].requires_python.as_deref(), Some(">=3.8"));
        assert!(!files[0].yanked);
        assert!(files[1].yanked);
        assert_eq!(files[1].yank_reason.as_deref(), Some("bad build"));
        // file_for uses cache.
        let f = c
            .file_for("demo-pkg", "demo-pkg-2.0.tar.gz")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(f.sha256, "bbb");
        assert!(c
            .file_for("demo-pkg", "nope.tar.gz")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn falls_back_to_html() {
        let html = r#"<!DOCTYPE html><html><body>
<a href="https://files.example/demo-pkg-1.0.tar.gz#sha256=abc123" data-requires-python="&gt;=3.8">demo-pkg-1.0.tar.gz</a><br/>
<a href="https://files.example/demo-pkg-2.0.tar.gz#sha256=def456" data-yanked="broken">demo-pkg-2.0.tar.gz</a><br/>
<a href="https://files.example/demo-pkg-3.0.tar.gz#sha256=111" data-yanked="">demo-pkg-3.0.tar.gz</a><br/>
</body></html>"#;
        let app = Router::new().route(
            "/{project}/",
            get(move || {
                let html = html.to_string();
                async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                        html,
                    )
                }
            }),
        );
        let base = spawn(app).await;
        let files = client(base)
            .fetch_project("demo-pkg")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(files.len(), 3);
        assert_eq!(files[0].sha256, "abc123");
        assert_eq!(files[0].requires_python.as_deref(), Some(">=3.8"));
        assert!(!files[0].yanked);
        assert!(files[1].yanked);
        assert_eq!(files[1].yank_reason.as_deref(), Some("broken"));
        assert!(files[2].yanked);
        assert_eq!(files[2].yank_reason, None);
    }

    #[tokio::test]
    async fn not_found_and_server_error() {
        let app = Router::new().route(
            "/{project}/",
            get(
                |axum::extract::Path(p): axum::extract::Path<String>| async move {
                    if p == "missing" {
                        StatusCode::NOT_FOUND.into_response()
                    } else {
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    }
                },
            ),
        );
        let base = spawn(app).await;
        let c = client(base);
        assert!(c.fetch_project("missing").await.unwrap().is_none());
        let err = c.fetch_project("boom").await.unwrap_err();
        assert!(matches!(err, UpstreamError::Status(500)), "{err}");
    }

    #[tokio::test]
    async fn caches_within_ttl() {
        let counter = StdArc::new(AtomicUsize::new(0));
        let counter2 = counter.clone();
        let app = Router::new().route(
            "/{project}/",
            get(move || {
                let counter = counter2.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!({"meta":{"api-version":"1.0"},"name":"x","files":[{"filename":"x-1.tar.gz","url":"https://e/x-1.tar.gz","hashes":{"sha256":"aa"},"requires-python":null,"yanked":false}]}))
                }
            }),
        );
        let base = spawn(app).await;
        let c = client(base);
        let _ = c.fetch_project("x").await.unwrap();
        let _ = c.fetch_project("x").await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn private_only_and_parse_helpers() {
        let mut set = HashSet::new();
        set.insert("secret-pkg".to_string());
        let c = UpstreamClient::new(
            "https://example.com/simple".to_string(),
            Duration::from_secs(5),
            set,
        );
        assert!(c.is_private_only("secret-pkg"));
        assert!(!c.is_private_only("other"));
        let files = parse_html_index(
            r#"<a href="/files/a-1.tar.gz#sha256=ff" data-requires-python=">=3.9">a-1.tar.gz</a>"#,
        );
        assert_eq!(files[0].filename, "a-1.tar.gz");
        assert_eq!(files[0].sha256, "ff");
        let files = parse_json_index(r#"{"files":[{"filename":"a-1.tar.gz","url":"https://e/a","hashes":{"sha256":"aa"},"requires-python":">=3.8","yanked":true}]}"#).unwrap();
        assert!(files[0].yanked);
        assert_eq!(files[0].yank_reason, None);
        assert!(parse_json_index("not json").is_err());
    }
}
