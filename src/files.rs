//! Artifact download handler with HTTP range and conditional support.

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use http_body_util::BodyExt;
use sha2::Digest;
use tokio::io::AsyncWriteExt;

use crate::{
    db::MetadataStore,
    error::{internal, AppError},
    packaging::normalize_project,
    state::AppState,
    upstream::UpstreamClient,
};

/// A parsed single byte range against a known object size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedRange {
    /// Inclusive `[start, end]` byte slice to serve with `206`.
    Single { start: u64, end: u64 },
    /// Syntactically valid range that cannot be satisfied (`416`).
    Unsatisfiable,
    /// Malformed or unsupported header; serve the full body (`200`).
    Ignore,
}

/// Parse a decimal range bound, saturating above `u64::MAX` instead of
/// failing, so enormous literals clamp or 416 like large in-range ones.
fn parse_bound(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(text.parse::<u64>().unwrap_or(u64::MAX))
}

/// Parse a `Range` header value for an object of `size` bytes.
///
/// Only single ranges are honored; multipart ranges and malformed values
/// are ignored (full download), as RFC 9110 permits. Ends are clamped to
/// the object; suffix ranges select trailing bytes. Syntax is validated
/// before the empty-object check so invalid specs are ignored even then.
fn parse_range(value: &str, size: u64) -> ParsedRange {
    let Some((unit, spec)) = value.split_once('=') else {
        return ParsedRange::Ignore;
    };
    if !unit.trim().eq_ignore_ascii_case("bytes") {
        return ParsedRange::Ignore;
    }
    let spec = spec.trim();
    // Multipart ranges are not supported; serve the whole object.
    if spec.contains(',') {
        return ParsedRange::Ignore;
    }
    let Some((first, last)) = spec.split_once('-') else {
        return ParsedRange::Ignore;
    };
    let (first, last) = (first.trim(), last.trim());
    if first.is_empty() {
        // Suffix range: the last N bytes.
        let Some(count) = parse_bound(last) else {
            return ParsedRange::Ignore;
        };
        if count == 0 || size == 0 {
            return ParsedRange::Unsatisfiable;
        }
        let count = count.min(size);
        return ParsedRange::Single {
            start: size - count,
            end: size - 1,
        };
    }
    let Some(start) = parse_bound(first) else {
        return ParsedRange::Ignore;
    };
    let end = if last.is_empty() {
        None
    } else {
        match parse_bound(last) {
            Some(end) => Some(end),
            None => return ParsedRange::Ignore,
        }
    };
    if let Some(end) = end {
        if end < start {
            return ParsedRange::Ignore;
        }
    }
    if size == 0 || start >= size {
        return ParsedRange::Unsatisfiable;
    }
    ParsedRange::Single {
        start,
        end: end.map_or(size - 1, |end| end.min(size - 1)),
    }
}

/// Whether an `If-None-Match` value matches `etag` (weak comparison).
fn etag_matches(value: &str, etag: &str) -> bool {
    value.split(',').any(|part| {
        let part = part.trim();
        part == "*" || part.strip_prefix("W/").unwrap_or(part) == etag
    })
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// All values of a list-valued header, combined per RFC 9110 list rules,
/// so repeated header fields are evaluated together.
fn header_list_str(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    let values: Vec<&str> = headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    if values.is_empty() {
        None
    } else {
        Some(values.join(", "))
    }
}

/// Stream a stored distribution file (`GET /files/{project}/{filename}`).
///
/// Honors a single `Range` (`206`/`416`), `If-None-Match` (`304`), and
/// `If-Range`. Yanked files download normally; yanking only affects
/// installer selection through the index. On a metadata miss with an upstream
/// configured, falls back to fetching the file from upstream, verifying its
/// sha256, caching the bytes, and serving them; warm cache hits never touch
/// upstream.
pub async fn download_file(
    State(state): State<AppState>,
    Path((project, filename)): Path<(String, String)>,
    method: axum::http::Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // HEAD mirrors GET headers without opening or counting a body.
    let is_head = method == axum::http::Method::HEAD;
    let normalized = normalize_project(&project)
        .map_err(|_| AppError::NotFound(format!("project {project} not found")))?;
    let project = normalized.as_str();
    // A DB row always wins: hosted files serve exactly as before, shadowing
    // any upstream-cached bytes stored under the same key.
    let (sha256, size) = match state.db.get_file(project, &filename).await? {
        Some(record) => {
            let size = match state.storage.stat(project, &filename).await? {
                Some(size) => size,
                None => {
                    tracing::warn!(
                        project,
                        filename = filename.as_str(),
                        "file row present but storage object missing"
                    );
                    return Err(AppError::NotFound(format!("file {filename} not found")));
                }
            };
            (record.sha256, size)
        }
        None => fetch_upstream(&state, project, &filename).await?,
    };
    serve_stored(&state, project, &filename, &sha256, size, &headers, is_head).await
}

/// Serve known-stored bytes with range/conditional/HEAD support.
///
/// Shared by the hosted and upstream-cache paths: `sha256` feeds the ETag and
/// `size` seeds the range parser, while response headers always come from the
/// opened object itself.
async fn serve_stored(
    state: &AppState,
    project: &str,
    filename: &str,
    sha256: &str,
    size: u64,
    headers: &HeaderMap,
    is_head: bool,
) -> Result<Response, AppError> {
    let etag = format!("\"{sha256}\"");

    // If-None-Match takes precedence over Range.
    if let Some(value) = header_list_str(headers, header::IF_NONE_MATCH) {
        if etag_matches(&value, &etag) {
            return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response());
        }
    }

    // If-Range guards the range against a changed object; a mismatch
    // (including the date form, which never equals our ETag) means the
    // client gets the full current object instead.
    let if_range_fresh = match header_str(headers, header::IF_RANGE) {
        None => true,
        Some(value) => value.trim() == etag,
    };
    let parsed = if if_range_fresh {
        header_str(headers, header::RANGE).map(|value| parse_range(value, size))
    } else {
        None
    };

    match parsed {
        Some(ParsedRange::Unsatisfiable) => Ok((
            StatusCode::RANGE_NOT_SATISFIABLE,
            [
                (header::CONTENT_RANGE, format!("bytes */{size}")),
                (header::ACCEPT_RANGES, "bytes".to_string()),
            ],
        )
            .into_response()),
        Some(ParsedRange::Single { start, end }) => {
            let len = end - start + 1;
            if is_head {
                return Ok((
                    StatusCode::PARTIAL_CONTENT,
                    [
                        (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                        (header::CONTENT_LENGTH, len.to_string()),
                        (header::CONTENT_RANGE, format!("bytes {start}-{end}/{size}")),
                        (header::ETAG, etag.clone()),
                        (header::ACCEPT_RANGES, "bytes".to_string()),
                    ],
                    axum::body::Body::empty(),
                )
                    .into_response());
            }
            // Headers come from the opened object's own size and served
            // count, so a concurrently replaced object can never produce
            // a Content-Range that disagrees with the body.
            let (total, served, body) = match state
                .storage
                .get_range(project, filename, start, len)
                .await?
            {
                Some(found) => found,
                None => {
                    return Err(AppError::NotFound(format!("file {filename} not found")));
                }
            };
            if served == 0 {
                // `size` is this request's own stat, the consistent
                // total to report when the object changed mid-flight.
                return Ok((
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    [
                        (header::CONTENT_RANGE, format!("bytes */{size}")),
                        (header::ACCEPT_RANGES, "bytes".to_string()),
                    ],
                )
                    .into_response());
            }
            let real_end = start + served - 1;
            metrics::counter!("file_downloads_total", "status" => "206").increment(1);
            Ok((
                StatusCode::PARTIAL_CONTENT,
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                    (header::CONTENT_LENGTH, served.to_string()),
                    (
                        header::CONTENT_RANGE,
                        format!("bytes {start}-{real_end}/{total}"),
                    ),
                    (header::ETAG, etag),
                    (header::ACCEPT_RANGES, "bytes".to_string()),
                ],
                body,
            )
                .into_response())
        }
        _ => {
            if is_head {
                return Ok((
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                        (header::CONTENT_LENGTH, size.to_string()),
                        (header::ETAG, etag.clone()),
                        (header::ACCEPT_RANGES, "bytes".to_string()),
                    ],
                    axum::body::Body::empty(),
                )
                    .into_response());
            }
            let (size, body) = match state.storage.get(project, filename).await? {
                Some(found) => found,
                None => {
                    return Err(AppError::NotFound(format!("file {filename} not found")));
                }
            };
            metrics::counter!("file_downloads_total", "status" => "200").increment(1);
            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                    (header::CONTENT_LENGTH, size.to_string()),
                    (header::ETAG, etag),
                    (header::ACCEPT_RANGES, "bytes".to_string()),
                ],
                body,
            )
                .into_response())
        }
    }
}

/// Storage project holding upstream-cache sha256 sidecars.
///
/// `.upstream-cache` can never be a normalized project name (names must start
/// with a letter or digit), so hosted uploads, admin deletes, and metadata
/// rows can never collide with these keys.
const SIDECAR_PROJECT: &str = ".upstream-cache";

/// Sidecar key for cached `(project, filename)` bytes; the content is the
/// lowercase hex sha256, letting warm hits build ETags without the index.
fn sidecar_filename(project: &str, filename: &str) -> String {
    format!("{project}--{filename}.sha256")
}

/// Best-effort removal of a staging file.
async fn cleanup(path: &std::path::Path) {
    let _ = tokio::fs::remove_file(path).await;
}

/// Resolve a DB-missed file through the upstream pull-through cache.
///
/// The guards (no upstream, private-only) 404 without any upstream call.
/// Otherwise serves warm bytes, or cold-fetches, verifies, and caches them.
/// Records exactly one `upstream_file_fetches_total` outcome per call: `hit`
/// (warm serve, no fetch), `miss` (fetched + cached), or `error` (any failure
/// to serve through this path, including unknown filenames, quarantine
/// blocks, and oversize or unverifiable upstream files).
async fn fetch_upstream(
    state: &AppState,
    project: &str,
    filename: &str,
) -> Result<(String, u64), AppError> {
    let Some(client) = state.upstream.as_ref() else {
        return Err(AppError::NotFound(format!("file {filename} not found")));
    };
    if client.is_private_only(project) {
        return Err(AppError::NotFound(format!("file {filename} not found")));
    }
    // Quarantine gate: resolve the index entry BEFORE warm cache or fetch,
    // so cached bytes are never served for a currently-quarantined file.
    // The lookup usually hits the TTL index cache (no extra upstream I/O).
    if state.settings.policy.quarantine_days_for(project) > 0 {
        let now = crate::upstream::now_unix_secs();
        let file = match client.file_for(project, filename).await {
            Ok(Some(file)) => file,
            Ok(None) => {
                metrics::counter!("upstream_file_fetches_total", "result" => "error").increment(1);
                return Err(AppError::NotFound(format!("file {filename} not found")));
            }
            Err(err) => {
                // Fail closed: without index metadata the file's age is
                // unknown, so a quarantined project cannot serve it — even
                // from warm cache. Outage tradeoff: while upstream (or its
                // cached index) is unavailable, quarantined-project downloads
                // 404; projects with 0 days keep serving warm bytes, since
                // they skip this gate entirely.
                tracing::warn!(
                    project,
                    filename,
                    "quarantine fail-closed: upstream index unavailable: {err}"
                );
                metrics::counter!("upstream_quarantine_filtered_total", "stage" => "download")
                    .increment(1);
                metrics::counter!("upstream_file_fetches_total", "result" => "error").increment(1);
                return Err(AppError::NotFound(format!("file {filename} not found")));
            }
        };
        if crate::upstream::is_quarantined(&state.settings.policy, &file, project, now) {
            metrics::counter!("upstream_quarantine_filtered_total", "stage" => "download")
                .increment(1);
            metrics::counter!("upstream_file_fetches_total", "result" => "error").increment(1);
            return Err(AppError::NotFound(format!("file {filename} not found")));
        }
    }
    // Warm bytes serve without touching upstream, so an expired index entry
    // or a downed upstream never breaks already-cached downloads.
    if let Some(hit) = warm_cache_checked(state, project, filename).await? {
        metrics::counter!("upstream_file_fetches_total", "result" => "hit").increment(1);
        return Ok(hit);
    }
    let permit = client.acquire_fetch(project, filename).await;
    // A waiter re-checks: the previous holder may have filled the cache.
    if let Some(hit) = warm_cache_checked(state, project, filename).await? {
        metrics::counter!("upstream_file_fetches_total", "result" => "hit").increment(1);
        drop(permit);
        return Ok(hit);
    }
    let outcome = cold_fetch(state, client, project, filename).await;
    drop(permit);
    match outcome {
        Ok(hit) => {
            metrics::counter!("upstream_file_fetches_total", "result" => "miss").increment(1);
            Ok(hit)
        }
        Err(err) => {
            metrics::counter!("upstream_file_fetches_total", "result" => "error").increment(1);
            Err(err)
        }
    }
}

/// Warm-hit probe: stored bytes plus a valid sidecar hash, with zero upstream
/// I/O. `None` means cold (or an unusable entry the cold path re-fetches).
async fn warm_cache(
    state: &AppState,
    project: &str,
    filename: &str,
) -> Result<Option<(String, u64)>, AppError> {
    let Some(size) = state.storage.stat(project, filename).await? else {
        return Ok(None);
    };
    let sidecar = sidecar_filename(project, filename);
    let Some((_, body)) = state.storage.get(SIDECAR_PROJECT, &sidecar).await? else {
        return Ok(None);
    };
    let bytes = body
        .collect()
        .await
        .map_err(|err| internal(format!("read cache sidecar: {err}")))?
        .to_bytes();
    let Ok(sha256) = std::str::from_utf8(&bytes) else {
        return Ok(None);
    };
    let sha256 = sha256.trim();
    if sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(Some((sha256.to_ascii_lowercase(), size)))
    } else {
        Ok(None)
    }
}

/// [`warm_cache`] that counts a storage failure as an `error` outcome, keeping
/// the one-outcome-per-fallback-request invariant.
async fn warm_cache_checked(
    state: &AppState,
    project: &str,
    filename: &str,
) -> Result<Option<(String, u64)>, AppError> {
    warm_cache(state, project, filename).await.map_err(|err| {
        metrics::counter!("upstream_file_fetches_total", "result" => "error").increment(1);
        err
    })
}

/// Cold-miss fill: resolve via the upstream index, stream-download to staging
/// with hashing + size cap, verify, then cache bytes + sidecar hash. Returns
/// the verified lowercase hex sha256 and cached size.
async fn cold_fetch(
    state: &AppState,
    client: &UpstreamClient,
    project: &str,
    filename: &str,
) -> Result<(String, u64), AppError> {
    // The index is consulted only to learn the file URL + expected hash.
    let file = match client.file_for(project, filename).await {
        Ok(Some(file)) => file,
        Ok(None) => return Err(AppError::NotFound(format!("file {filename} not found"))),
        Err(err) => return Err(AppError::BadGateway(err.to_string())),
    };
    let expected = file.sha256.trim().to_string();
    if expected.is_empty() {
        return Err(AppError::BadGateway(format!(
            "upstream file {filename} has no sha256"
        )));
    }
    let mut response = client
        .download(&file.url)
        .await
        .map_err(|err| AppError::BadGateway(err.to_string()))?;
    let (staging, mut dest) = state.storage.create_staging_file().await?;
    let mut hasher = sha2::Sha256::new();
    let mut size: u64 = 0;
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(err) => {
                drop(dest);
                cleanup(&staging).await;
                return Err(AppError::BadGateway(format!(
                    "upstream download failed: {err}"
                )));
            }
        };
        size += chunk.len() as u64;
        if size > state.settings.max_upload_bytes {
            drop(dest);
            cleanup(&staging).await;
            return Err(AppError::BadGateway(format!(
                "upstream file {filename} exceeds size limit"
            )));
        }
        if let Err(err) = dest.write_all(&chunk).await {
            drop(dest);
            cleanup(&staging).await;
            return Err(internal(format!("write staging file: {err}")));
        }
        hasher.update(&chunk);
    }
    if let Err(err) = dest.flush().await {
        drop(dest);
        cleanup(&staging).await;
        return Err(internal(format!("write staging file: {err}")));
    }
    drop(dest);
    let computed = hex::encode(hasher.finalize());
    if !computed.eq_ignore_ascii_case(&expected) {
        cleanup(&staging).await;
        return Err(AppError::BadGateway(format!(
            "upstream file {filename} failed sha256 verification"
        )));
    }
    // A hosted upload may have published this key while we streamed. Hosted
    // rows always win: abort the cache write instead of overwriting them.
    match hosted_during_fetch(state, project, filename).await {
        Ok(Some(hosted)) => {
            cleanup(&staging).await;
            return Ok(hosted);
        }
        Ok(None) => {}
        Err(err) => {
            cleanup(&staging).await;
            return Err(err);
        }
    }
    // Sidecar first, so cached bytes always carry their hash; a failed sidecar
    // write caches nothing at all.
    if let Err(err) = put_sidecar(state, project, filename, &computed).await {
        cleanup(&staging).await;
        return Err(err);
    }
    // Re-check immediately before the byte publish: an upload that landed
    // during the sidecar write must not have its bytes overwritten. A
    // leftover sidecar here is harmless (hosted rows shadow the cache).
    match hosted_during_fetch(state, project, filename).await {
        Ok(Some(hosted)) => {
            cleanup(&staging).await;
            return Ok(hosted);
        }
        Ok(None) => {}
        Err(err) => {
            cleanup(&staging).await;
            return Err(err);
        }
    }
    let size = match state.storage.put_file(project, filename, &staging).await {
        Ok(size) => size,
        Err(err) => {
            cleanup(&staging).await;
            return Err(AppError::from(err));
        }
    };
    Ok((computed, size))
}

/// Re-resolve `(project, filename)` as hosted after a cold download.
///
/// `Ok(Some)` means a hosted row appeared during the fetch: the caller must
/// abort its cache write and serve these hosted bytes instead. `Ok(None)`
/// means still unhosted (safe to cache). A row with no visible bytes yet is
/// an upload mid-publish: report 404 like the hosted path rather than
/// racing its imminent `put_file`.
async fn hosted_during_fetch(
    state: &AppState,
    project: &str,
    filename: &str,
) -> Result<Option<(String, u64)>, AppError> {
    let Some(record) = state.db.get_file(project, filename).await? else {
        return Ok(None);
    };
    match state.storage.stat(project, filename).await? {
        Some(size) => Ok(Some((record.sha256, size))),
        None => Err(AppError::NotFound(format!("file {filename} not found"))),
    }
}

/// Cache the verified hash sidecar for `(project, filename)`.
async fn put_sidecar(
    state: &AppState,
    project: &str,
    filename: &str,
    sha256: &str,
) -> Result<(), AppError> {
    let (staging, mut dest) = state.storage.create_staging_file().await?;
    if let Err(err) = dest.write_all(sha256.as_bytes()).await {
        drop(dest);
        cleanup(&staging).await;
        return Err(internal(format!("write sidecar staging file: {err}")));
    }
    if let Err(err) = dest.flush().await {
        drop(dest);
        cleanup(&staging).await;
        return Err(internal(format!("write sidecar staging file: {err}")));
    }
    drop(dest);
    let sidecar = sidecar_filename(project, filename);
    if let Err(err) = state
        .storage
        .put_file(SIDECAR_PROJECT, &sidecar, &staging)
        .await
    {
        cleanup(&staging).await;
        return Err(AppError::from(err));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_ranges() {
        assert_eq!(
            parse_range("bytes=0-4", 32),
            ParsedRange::Single { start: 0, end: 4 }
        );
        assert_eq!(
            parse_range("bytes=10-", 32),
            ParsedRange::Single { start: 10, end: 31 }
        );
        assert_eq!(
            parse_range("bytes=-5", 32),
            ParsedRange::Single { start: 27, end: 31 }
        );
        // Suffix longer than the object selects the whole object.
        assert_eq!(
            parse_range("bytes=-100", 32),
            ParsedRange::Single { start: 0, end: 31 }
        );
        // Ends clamp to the object.
        assert_eq!(
            parse_range("bytes=30-999", 32),
            ParsedRange::Single { start: 30, end: 31 }
        );
        // Unit is case-insensitive and spacing is tolerated.
        assert_eq!(
            parse_range(" Bytes = 0 - 4 ", 32),
            ParsedRange::Single { start: 0, end: 4 }
        );
    }

    #[test]
    fn rejects_unsatisfiable_ranges() {
        assert_eq!(parse_range("bytes=32-", 32), ParsedRange::Unsatisfiable);
        assert_eq!(parse_range("bytes=100-200", 32), ParsedRange::Unsatisfiable);
        assert_eq!(parse_range("bytes=-0", 32), ParsedRange::Unsatisfiable);
        assert_eq!(parse_range("bytes=0-", 0), ParsedRange::Unsatisfiable);
        // Literals beyond u64 saturate instead of being ignored.
        assert_eq!(
            parse_range("bytes=18446744073709551616-", 32),
            ParsedRange::Unsatisfiable
        );
    }

    #[test]
    fn saturates_huge_bounds() {
        assert_eq!(
            parse_range("bytes=0-18446744073709551616", 32),
            ParsedRange::Single { start: 0, end: 31 }
        );
        assert_eq!(
            parse_range("bytes=-18446744073709551616", 32),
            ParsedRange::Single { start: 0, end: 31 }
        );
    }

    #[test]
    fn ignores_malformed_and_multipart_ranges() {
        for value in [
            "items=0-4",
            "bytes=abc-def",
            "bytes=5-3",
            "bytes=0-1,3-4",
            "bytes=",
            "bytes=-",
            "0-4",
            "",
        ] {
            assert_eq!(
                parse_range(value, 32),
                ParsedRange::Ignore,
                "value {value:?}"
            );
        }
        // Invalid specs stay ignored even for empty objects.
        assert_eq!(parse_range("bytes=abc-def", 0), ParsedRange::Ignore);
        assert_eq!(parse_range("bytes=5-3", 0), ParsedRange::Ignore);
    }

    #[test]
    fn matches_etags_weakly() {
        assert!(etag_matches("\"abc\"", "\"abc\""));
        assert!(etag_matches("W/\"abc\"", "\"abc\""));
        assert!(etag_matches("\"x\", \"abc\"", "\"abc\""));
        assert!(etag_matches("*", "\"abc\""));
        assert!(!etag_matches("\"other\"", "\"abc\""));
        assert!(!etag_matches("", "\"abc\""));
    }
}
