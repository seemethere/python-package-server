//! Artifact download handler with HTTP range and conditional support.

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{db::MetadataStore, error::AppError, packaging::normalize_project, state::AppState};

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
/// installer selection through the index.
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
    let record = state
        .db
        .get_file(normalized.as_str(), &filename)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("file {filename} not found")))?;
    let etag = format!("\"{}\"", record.sha256);
    let size = match state.storage.stat(normalized.as_str(), &filename).await? {
        Some(size) => size,
        None => {
            tracing::warn!(
                project = normalized.as_str(),
                filename = filename.as_str(),
                "file row present but storage object missing"
            );
            return Err(AppError::NotFound(format!("file {filename} not found")));
        }
    };

    // If-None-Match takes precedence over Range.
    if let Some(value) = header_list_str(&headers, header::IF_NONE_MATCH) {
        if etag_matches(&value, &etag) {
            return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response());
        }
    }

    // If-Range guards the range against a changed object; a mismatch
    // (including the date form, which never equals our ETag) means the
    // client gets the full current object instead.
    let if_range_fresh = match header_str(&headers, header::IF_RANGE) {
        None => true,
        Some(value) => value.trim() == etag,
    };
    let parsed = if if_range_fresh {
        header_str(&headers, header::RANGE).map(|value| parse_range(value, size))
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
                .get_range(normalized.as_str(), &filename, start, len)
                .await?
            {
                Some(found) => found,
                None => {
                    return Err(AppError::NotFound(format!("file {filename} not found")));
                }
            };
            if served == 0 {
                return Ok((
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    [
                        (header::CONTENT_RANGE, format!("bytes */{total}")),
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
            let (size, body) = match state.storage.get(normalized.as_str(), &filename).await? {
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
