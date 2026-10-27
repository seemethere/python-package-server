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
pub(crate) const SIDECAR_PROJECT: &str = ".upstream-cache";

/// Suffix of every cache sidecar key; the sweep lists these to enumerate entries.
pub(crate) const SIDECAR_SUFFIX: &str = ".sha256";

/// Sidecar key for cached `(project, filename)` bytes; the content is the
/// lowercase hex sha256 plus a fetch timestamp (see [`format_sidecar`]),
/// letting warm hits build ETags without the index.
pub(crate) fn sidecar_filename(project: &str, filename: &str) -> String {
    format!("{project}--{filename}{SIDECAR_SUFFIX}")
}

/// Sidecar body for a fresh cache fill: the lowercase hex sha256, then the
/// fetch time as unix seconds, one per line.
pub(crate) fn format_sidecar(sha256: &str, cached_at_unix_secs: u64) -> String {
    format!("{sha256}\n{cached_at_unix_secs}\n")
}

/// Parse a sidecar body into `(lowercase sha256, fetch time)`.
///
/// Legacy plain-hash sidecars (no second line) parse with unknown age
/// (`None`), so they refresh once under a live TTL instead of breaking.
/// Anything else malformed — bad hash or unparsable timestamp — is `None`
/// (cold), exactly like the pre-timestamp reader. Trailing lines are ignored.
pub(crate) fn parse_sidecar(text: &str) -> Option<(String, Option<u64>)> {
    let mut lines = text.lines();
    let sha256 = lines.next()?.trim();
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let cached_at = match lines.next() {
        None => None,
        Some(stamp) => Some(stamp.trim().parse::<u64>().ok()?),
    };
    Some((sha256.to_ascii_lowercase(), cached_at))
}

/// Whether a cached entry has outlived `max_age_days` at `now_unix_secs`.
///
/// `0` days never expires. Unknown-age (legacy) entries count as expired
/// whenever expiry is enabled, so they re-fetch once and gain a stamp.
/// Future stamps (clock skew) read as age zero, never expired.
pub(crate) fn cache_entry_expired(
    max_age_days: u32,
    cached_at: Option<u64>,
    now_unix_secs: u64,
) -> bool {
    const DAY_SECS: u64 = 86_400;
    if max_age_days == 0 {
        return false;
    }
    match cached_at {
        None => true,
        Some(stamped) => {
            now_unix_secs.saturating_sub(stamped) > u64::from(max_age_days).saturating_mul(DAY_SECS)
        }
    }
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
    // or a downed upstream never breaks already-cached downloads. Entries
    // past the age TTL evict here and refill below like a cold miss.
    if let Some(hit) = warm_cache_fresh_or_evict(state, project, filename).await? {
        metrics::counter!("upstream_file_fetches_total", "result" => "hit").increment(1);
        return Ok(hit);
    }
    let permit = client.acquire_fetch(project, filename).await;
    // A waiter re-checks: the previous holder may have filled the cache.
    if let Some(hit) = warm_cache_fresh_or_evict(state, project, filename).await? {
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

/// Warm-hit probe: stored bytes plus a valid sidecar, with zero upstream
/// I/O. Returns the lowercase hash, byte size, and fetch time (`None` for
/// legacy plain-hash sidecars). `None` means cold (or an unusable entry
/// the cold path re-fetches).
async fn warm_cache(
    state: &AppState,
    project: &str,
    filename: &str,
) -> Result<Option<(String, u64, Option<u64>)>, AppError> {
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
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Ok(None);
    };
    match parse_sidecar(text) {
        Some((sha256, cached_at)) => Ok(Some((sha256, size, cached_at))),
        None => Ok(None),
    }
}

/// [`warm_cache`] that counts a storage failure as an `error` outcome, keeping
/// the one-outcome-per-fallback-request invariant.
async fn warm_cache_checked(
    state: &AppState,
    project: &str,
    filename: &str,
) -> Result<Option<(String, u64, Option<u64>)>, AppError> {
    warm_cache(state, project, filename).await.map_err(|err| {
        metrics::counter!("upstream_file_fetches_total", "result" => "error").increment(1);
        err
    })
}

/// Fresh warm hit, or `None` when cold. Entries past the age TTL are evicted
/// here — bytes + sidecar deleted, `upstream_cache_evictions_total` counted
/// with `source="lazy"` — and read as cold so the caller re-fetches them.
/// Deletes are best-effort: the refill overwrites both keys regardless.
/// A hosted row always wins: before deleting, the DB is re-checked, since
/// an upload may have published this key between the handler's DB-miss and
/// this lazy delete. A newly hosted key is served, never deleted.
async fn warm_cache_fresh_or_evict(
    state: &AppState,
    project: &str,
    filename: &str,
) -> Result<Option<(String, u64)>, AppError> {
    let hit = warm_cache_checked(state, project, filename).await?;
    let Some((sha256, size, cached_at)) = hit else {
        return Ok(None);
    };
    if !cache_entry_expired(
        state.settings.upstream_cache_max_age_days,
        cached_at,
        crate::upstream::now_unix_secs(),
    ) {
        return Ok(Some((sha256, size)));
    }
    // Hosted re-check before ANY delete: an upload that landed after the
    // handler's DB-miss leaves hosted bytes beside this stale sidecar, and
    // deleting them would destroy hosted data. Serve the hosted entry
    // instead; a lookup failure also aborts (counted, like any error on
    // this path) so unverified keys are never deleted.
    match hosted_during_fetch(state, project, filename).await {
        Ok(Some(hosted)) => return Ok(Some(hosted)),
        Ok(None) => {}
        Err(err) => {
            metrics::counter!("upstream_file_fetches_total", "result" => "error").increment(1);
            return Err(err);
        }
    }
    tracing::info!(
        project,
        filename,
        "evicting expired upstream cache entry (lazy)"
    );
    metrics::counter!("upstream_cache_evictions_total", "source" => "lazy").increment(1);
    if let Err(err) = state.storage.delete(project, filename).await {
        tracing::warn!(
            project,
            filename,
            error = %err,
            "lazy eviction: failed to delete cached bytes"
        );
    }
    let sidecar = sidecar_filename(project, filename);
    if let Err(err) = state.storage.delete(SIDECAR_PROJECT, &sidecar).await {
        tracing::warn!(
            project,
            filename,
            error = %err,
            "lazy eviction: failed to delete cache sidecar"
        );
    }
    Ok(None)
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

/// Cache the verified hash sidecar for `(project, filename)`, stamped with
/// the fetch time so age eviction can tell fresh entries from stale ones.
async fn put_sidecar(
    state: &AppState,
    project: &str,
    filename: &str,
    sha256: &str,
) -> Result<(), AppError> {
    let (staging, mut dest) = state.storage.create_staging_file().await?;
    let body = format_sidecar(sha256, crate::upstream::now_unix_secs());
    if let Err(err) = dest.write_all(body.as_bytes()).await {
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
    fn sidecar_format_round_trips() {
        let hash = "ab".repeat(32);
        let body = format_sidecar(&hash, 1_672_574_400);
        assert_eq!(body, format!("{hash}\n1672574400\n"));
        assert_eq!(
            parse_sidecar(&body),
            Some((hash.clone(), Some(1_672_574_400)))
        );
        // Trailing lines are ignored; surrounding whitespace is tolerated.
        assert_eq!(
            parse_sidecar(&format!("  {hash}  \n  1672574400  \nignored\n")),
            Some((hash.clone(), Some(1_672_574_400)))
        );
    }

    #[test]
    fn sidecar_read_stays_backward_compatible() {
        let hash = "ab".repeat(32);
        // Legacy plain-hash sidecars parse with unknown age ...
        assert_eq!(parse_sidecar(&hash), Some((hash.clone(), None)));
        assert_eq!(
            parse_sidecar(&format!("{hash}\n")),
            Some((hash.clone(), None))
        );
        // ... and keep the lowercase ETag normalization.
        let upper = hash.to_ascii_uppercase();
        assert_eq!(
            parse_sidecar(&format!("{upper}\n1672574400")),
            Some((hash.clone(), Some(1_672_574_400)))
        );
        // Garbage stays cold, exactly like the pre-timestamp reader.
        for bad in [
            "",
            "   ",
            "not-a-hash",
            &"zz".repeat(32),
            &"ab".repeat(31),
            &format!("{}\nnot-a-number", hash),
            &format!("{}\n-5", hash),
            &format!("{}\n", "x".repeat(64)),
        ] {
            assert_eq!(parse_sidecar(bad), None, "accepted {bad:?}");
        }
    }

    #[test]
    fn cache_expiry_matrix() {
        const DAY: u64 = 86_400;
        let now = 1_700_000_000;
        // TTL 0 never expires, even for unknown-age entries.
        assert!(!cache_entry_expired(0, None, now));
        assert!(!cache_entry_expired(0, Some(0), now));
        // Legacy unknown-age entries expire whenever a TTL applies.
        assert!(cache_entry_expired(30, None, now));
        // Fresh and boundary ages serve; only ages past the TTL evict.
        assert!(!cache_entry_expired(30, Some(now), now));
        assert!(!cache_entry_expired(30, Some(now - 29 * DAY), now));
        assert!(!cache_entry_expired(30, Some(now - 30 * DAY), now));
        assert!(cache_entry_expired(30, Some(now - 30 * DAY - 1), now));
        assert!(cache_entry_expired(30, Some(0), now));
        assert!(cache_entry_expired(1, Some(now - DAY - 1), now));
        assert!(!cache_entry_expired(1, Some(now - DAY), now));
        // Future stamps (clock skew) read as age zero, never expired.
        assert!(!cache_entry_expired(30, Some(now + DAY), now));
        assert!(!cache_entry_expired(30, Some(u64::MAX), now));
    }

    #[tokio::test]
    async fn lazy_eviction_serves_hosted_instead_of_deleting() {
        use crate::{
            auth::Auth,
            config::{Policy, Settings},
            db::{MemoryStore, MetadataBackend, MetadataStore, NewFile},
            state::AppState,
            storage::Storage,
        };

        const PROJECT: &str = "racepkg";
        const FILE: &str = "racepkg-1.0.tar.gz";
        const BYTES: &[u8] = b"hosted bytes beside a stale sidecar";

        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::filesystem(dir.path().to_path_buf());
        storage.ensure_dirs().await.unwrap();
        // Hosted bytes plus an ancient sidecar: the state an upload that
        // landed between the handler's DB-miss and the lazy delete leaves.
        let staged = storage.stage_path().unwrap();
        tokio::fs::write(&staged, BYTES).await.unwrap();
        storage.put_file(PROJECT, FILE, &staged).await.unwrap();
        let staged = storage.stage_path().unwrap();
        let stale = format_sidecar(&"ab".repeat(32), 0);
        tokio::fs::write(&staged, stale.as_bytes()).await.unwrap();
        storage
            .put_file(SIDECAR_PROJECT, &sidecar_filename(PROJECT, FILE), &staged)
            .await
            .unwrap();

        let db = MetadataBackend::Memory(MemoryStore::new());
        // Hosted sha deliberately differs from the stale sidecar hash: the
        // served entry must come from the row, proving the hosted path won.
        let hosted_sha = "cd".repeat(32);
        db.insert_file(&NewFile {
            project_normalized: PROJECT.to_string(),
            project_display: "RacePkg".to_string(),
            filename: FILE.to_string(),
            version: "1.0".to_string(),
            sha256: hosted_sha.clone(),
            size_bytes: BYTES.len() as i64,
            requires_python: None,
            uploaded_by: "ci".to_string(),
        })
        .await
        .unwrap();

        let settings = Settings {
            bind_addr: "127.0.0.1:0".to_string(),
            database_url: "postgres://localhost/packages".to_string(),
            storage_backend: "filesystem".to_string(),
            storage_dir: dir.path().to_path_buf(),
            s3_bucket: None,
            s3_region: None,
            s3_endpoint_url: None,
            auth_token_file: std::path::PathBuf::from("/dev/null"),
            max_upload_bytes: 1024 * 1024,
            upstream_url: None,
            upstream_index_ttl_secs: 300,
            upstream_cache_max_age_days: 30,
            upstream_private_only_projects: std::collections::HashSet::new(),
            policy_file: None,
            policy: Policy::default(),
            oidc_issuer_url: None,
            oidc_audience: None,
        };
        let state = AppState {
            db: db.clone(),
            storage: storage.clone(),
            auth: Auth::from_pairs(vec![("ci".to_string(), "secret".to_string())]),
            metrics: metrics_exporter_prometheus::PrometheusBuilder::new()
                .build_recorder()
                .handle(),
            settings: std::sync::Arc::new(settings),
            upstream: None,
            oidc: None,
        };

        // Expired sidecar, but the hosted row wins: served, never deleted.
        let hit = warm_cache_fresh_or_evict(&state, PROJECT, FILE)
            .await
            .unwrap();
        assert_eq!(hit, Some((hosted_sha, BYTES.len() as u64)));

        assert!(
            db.get_file(PROJECT, FILE).await.unwrap().is_some(),
            "hosted row must survive lazy eviction"
        );
        let (size, body) = storage
            .get(PROJECT, FILE)
            .await
            .unwrap()
            .expect("hosted bytes must survive lazy eviction");
        assert_eq!(size, BYTES.len() as u64);
        assert_eq!(
            body.collect().await.unwrap().to_bytes().as_ref(),
            BYTES,
            "hosted bytes must be intact after lazy eviction"
        );
        assert!(
            storage
                .stat(SIDECAR_PROJECT, &sidecar_filename(PROJECT, FILE))
                .await
                .unwrap()
                .is_some(),
            "sidecar beside a hosted key must not be deleted"
        );
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
