//! Legacy twine-compatible upload handler (`POST /legacy/`).

use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use axum::{
    extract::{multipart::Field, Extension, Multipart, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use sha2::Digest;
use tokio::io::AsyncWriteExt;

use crate::{
    auth::AuthenticatedUser,
    db::{DbError, MetadataStore, NewFile},
    error::{internal, AppError},
    packaging::{check_requires_python, normalize_project, parse_filename},
    state::AppState,
};

/// Maximum bytes buffered for one multipart text field (`name`, `version`,
/// digests, and unknown fields, which are all tiny).
const MAX_TEXT_FIELD_BYTES: usize = 64 * 1024;

/// Maximum multipart parts accepted per upload (twine sends ~15); beyond
/// this the request is rejected as too large.
const MAX_FIELD_COUNT: usize = 100;

/// Fields validated before a staged upload is published.
#[derive(Debug)]
struct ValidatedUpload {
    normalized: String,
    display: String,
    version: String,
    requires_python: Option<String>,
}

/// Accept a twine `file_upload` multipart request and publish the artifact.
///
/// NOTE (wiring agent): this handler enforces `MAX_UPLOAD_BYTES` itself while
/// streaming `content` to disk, so the route MUST be built with
/// `DefaultBodyLimit::disable()` — otherwise the default 2 MiB body limit
/// rejects legitimate uploads before this code runs.
pub async fn legacy_upload(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    mut multipart: Multipart,
) -> Result<Response, AppError> {
    let mut action: Option<String> = None;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut sha256_digest: Option<String> = None;
    let mut requires_python: Option<String> = None;
    let mut filename: Option<String> = None;
    let mut staged: Option<PathBuf> = None;
    let mut hasher = sha2::Sha256::new();
    let mut size: u64 = 0;
    let mut field_count: usize = 0;

    loop {
        let field_opt = match multipart.next_field().await {
            Ok(opt) => opt,
            Err(_) => {
                cleanup_opt(&mut staged).await;
                return Err(AppError::BadRequest("invalid multipart body".to_string()));
            }
        };
        let Some(mut field) = field_opt else {
            break;
        };
        field_count += 1;
        if field_count > MAX_FIELD_COUNT {
            cleanup_opt(&mut staged).await;
            return Err(AppError::PayloadTooLarge);
        }
        let field_name = field.name().unwrap_or_default().to_string();
        if field_name == "content" {
            let content_name = match field.file_name() {
                Some(content_name) => content_name.to_string(),
                None => {
                    cleanup_opt(&mut staged).await;
                    return Err(AppError::BadRequest("missing filename".to_string()));
                }
            };
            // A second content part replaces the first; drop the stale staging file.
            if let Some(previous) = staged.take() {
                cleanup(&previous).await;
            }
            // Exclusive create with collision retries; `staged` is None here,
            // so a failure here has nothing to clean up.
            let (staging, mut dest) = state.storage.create_staging_file().await?;
            let mut part_size: u64 = 0;
            let mut part_hasher = sha2::Sha256::new();
            loop {
                let chunk = match field.chunk().await {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => break,
                    Err(_) => {
                        drop(dest);
                        cleanup(&staging).await;
                        return Err(AppError::BadRequest("invalid multipart body".to_string()));
                    }
                };
                part_size += chunk.len() as u64;
                if part_size > state.settings.max_upload_bytes {
                    drop(dest);
                    cleanup(&staging).await;
                    return Err(AppError::PayloadTooLarge);
                }
                if let Err(err) = dest.write_all(&chunk).await {
                    drop(dest);
                    cleanup(&staging).await;
                    return Err(internal(format!("write staging file: {err}")));
                }
                part_hasher.update(&chunk);
            }
            if let Err(err) = dest.flush().await {
                drop(dest);
                cleanup(&staging).await;
                return Err(internal(format!("write staging file: {err}")));
            }
            drop(dest);
            filename = Some(content_name);
            hasher = part_hasher;
            size = part_size;
            staged = Some(staging);
        } else {
            let text = match read_capped_text(&mut field).await {
                Ok(text) => text,
                Err(err) => {
                    cleanup_opt(&mut staged).await;
                    return Err(err);
                }
            };
            match field_name.as_str() {
                ":action" => action = Some(text),
                "name" => name = Some(text),
                "version" => version = Some(text),
                "sha256_digest" => sha256_digest = Some(text),
                "requires_python" => requires_python = Some(text),
                _ => {}
            }
        }
    }

    let (filename, staging) = match (filename, staged) {
        (Some(filename), Some(staging)) => (filename, staging),
        (_, staged) => {
            if let Some(staging) = staged {
                cleanup(&staging).await;
            }
            return Err(AppError::BadRequest("missing content".to_string()));
        }
    };
    let computed_hex = hex::encode(hasher.finalize());

    let validated = match validate_upload(action, name, version, requires_python, &filename) {
        Ok(validated) => validated,
        Err(err) => {
            cleanup(&staging).await;
            return Err(err);
        }
    };
    if let Some(expected) = sha256_digest
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !computed_hex.eq_ignore_ascii_case(expected) {
            cleanup(&staging).await;
            return Err(AppError::BadRequest("sha256 digest mismatch".to_string()));
        }
    }

    let size_bytes = match i64::try_from(size) {
        Ok(size_bytes) => size_bytes,
        Err(_) => {
            cleanup(&staging).await;
            return Err(AppError::PayloadTooLarge);
        }
    };

    if let Err(err) = state
        .db
        .upsert_project(&validated.display, &validated.normalized)
        .await
    {
        cleanup(&staging).await;
        return Err(AppError::from(err));
    }
    let new_file = NewFile {
        project_normalized: validated.normalized.clone(),
        project_display: validated.display.clone(),
        filename: filename.clone(),
        version: validated.version.clone(),
        sha256: computed_hex.clone(),
        size_bytes,
        requires_python: validated.requires_python.clone(),
        uploaded_by: user.0.clone(),
    };
    match state.db.insert_file(&new_file).await {
        Ok(()) => {}
        Err(DbError::Conflict(message)) => {
            cleanup(&staging).await;
            return Err(AppError::Conflict(message));
        }
        Err(err) => {
            cleanup(&staging).await;
            return Err(AppError::from(err));
        }
    }
    if let Err(err) = state
        .storage
        .put_file(&validated.normalized, &filename, &staging)
        .await
    {
        let _ = state.db.delete_file(&validated.normalized, &filename).await;
        cleanup(&staging).await;
        return Err(AppError::from(err));
    }

    metrics::counter!("uploads_total").increment(1);
    metrics::counter!("upload_bytes_total").increment(size);
    Ok((
        StatusCode::OK,
        Json(json!({
            "name": validated.display,
            "version": validated.version,
            "filename": filename,
            "sha256": computed_hex,
            "size_bytes": size,
        })),
    )
        .into_response())
}

/// Read one multipart text field through a chunk loop capped at
/// [`MAX_TEXT_FIELD_BYTES`]; unknown fields use this same reader so no text
/// field is ever buffered unbounded.
async fn read_capped_text(field: &mut Field<'_>) -> Result<String, AppError> {
    let mut buf = Vec::new();
    loop {
        match field.chunk().await {
            Ok(Some(chunk)) => grow_capped(&mut buf, &chunk)?,
            Ok(None) => break,
            Err(_) => return Err(AppError::BadRequest("invalid multipart body".to_string())),
        }
    }
    decode_text(buf)
}

/// Append a chunk to a capped text buffer; overflow is [`AppError::PayloadTooLarge`].
fn grow_capped(buf: &mut Vec<u8>, chunk: &[u8]) -> Result<(), AppError> {
    if buf.len() + chunk.len() > MAX_TEXT_FIELD_BYTES {
        return Err(AppError::PayloadTooLarge);
    }
    buf.extend_from_slice(chunk);
    Ok(())
}

/// Decode buffered text-field bytes as UTF-8.
fn decode_text(buf: Vec<u8>) -> Result<String, AppError> {
    String::from_utf8(buf)
        .map_err(|_| AppError::BadRequest("invalid text field encoding".to_string()))
}

/// Check required fields and filename/version consistency (no I/O).
fn validate_upload(
    action: Option<String>,
    name: Option<String>,
    version: Option<String>,
    requires_python: Option<String>,
    filename: &str,
) -> Result<ValidatedUpload, AppError> {
    match action.as_deref() {
        Some("file_upload") => {}
        _ => {
            return Err(AppError::BadRequest(
                "invalid :action (want 'file_upload')".to_string(),
            ))
        }
    }
    let name = name
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::BadRequest("missing name".to_string()))?;
    let version = version
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::BadRequest("missing version".to_string()))?;
    let package = normalize_project(&name)?;
    let parsed = parse_filename(filename, &package)?;
    let declared = pep440_rs::Version::from_str(version.trim())
        .map_err(|err| AppError::BadRequest(format!("invalid version '{version}': {err}")))?;
    if declared != parsed.version {
        return Err(AppError::BadRequest(format!(
            "version {declared} does not match filename {filename}"
        )));
    }
    Ok(ValidatedUpload {
        normalized: package.as_str().to_string(),
        display: name.trim().to_string(),
        version: declared.to_string(),
        requires_python: check_requires_python(requires_python.as_deref())?,
    })
}

/// Best-effort removal of a staging file.
async fn cleanup(path: &Path) {
    let _ = tokio::fs::remove_file(path).await;
}

/// Best-effort removal of whatever staging file is tracked, if any.
async fn cleanup_opt(staged: &mut Option<PathBuf>) {
    if let Some(path) = staged.take() {
        cleanup(&path).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_args() -> (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) {
        (
            Some("file_upload".to_string()),
            Some("Demo-Pkg".to_string()),
            Some("1.2.3".to_string()),
            Some(">=3.8".to_string()),
        )
    }

    #[test]
    fn accepts_matching_version() {
        let (action, name, version, requires_python) = valid_args();
        let validated = validate_upload(
            action,
            name,
            version,
            requires_python,
            "demo-pkg-1.2.3.tar.gz",
        )
        .unwrap();
        assert_eq!(validated.normalized, "demo-pkg");
        assert_eq!(validated.display, "Demo-Pkg");
        assert_eq!(validated.version, "1.2.3");
        assert_eq!(validated.requires_python, Some(">=3.8".to_string()));
    }

    #[test]
    fn rejects_bad_action_and_missing_fields() {
        let (_, name, version, requires_python) = valid_args();
        assert!(matches!(
            validate_upload(
                Some("submit".to_string()),
                name.clone(),
                version.clone(),
                requires_python.clone(),
                "demo-pkg-1.2.3.tar.gz",
            ),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            validate_upload(
                None,
                name,
                version,
                requires_python,
                "demo-pkg-1.2.3.tar.gz"
            ),
            Err(AppError::BadRequest(_))
        ));

        let (action, _, version, requires_python) = valid_args();
        assert!(matches!(
            validate_upload(
                action,
                None,
                version,
                requires_python,
                "demo-pkg-1.2.3.tar.gz",
            ),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn rejects_version_mismatch() {
        let (action, name, _, requires_python) = valid_args();
        let err = validate_upload(
            action,
            name,
            Some("2.0.0".to_string()),
            requires_python,
            "demo-pkg-1.2.3.tar.gz",
        )
        .unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
        assert!(err.to_string().contains("does not match filename"));
    }

    #[test]
    fn rejects_invalid_version_and_filename() {
        let (action, name, _, requires_python) = valid_args();
        assert!(matches!(
            validate_upload(
                action,
                name,
                Some("bogus!!!".to_string()),
                requires_python,
                "demo-pkg-1.2.3.tar.gz",
            ),
            Err(AppError::BadRequest(_))
        ));

        let (action, name, version, requires_python) = valid_args();
        assert!(matches!(
            validate_upload(action, name, version, requires_python, "other-1.2.3.tar.gz"),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn capped_text_reader_enforces_64kib() {
        let mut buf = Vec::new();
        grow_capped(&mut buf, &vec![b'a'; MAX_TEXT_FIELD_BYTES - 1]).unwrap();
        grow_capped(&mut buf, b"b").unwrap();
        assert_eq!(buf.len(), MAX_TEXT_FIELD_BYTES);
        assert!(matches!(
            grow_capped(&mut buf, b"c"),
            Err(AppError::PayloadTooLarge)
        ));

        let mut buf = Vec::new();
        assert!(matches!(
            grow_capped(&mut buf, &vec![0u8; MAX_TEXT_FIELD_BYTES + 1]),
            Err(AppError::PayloadTooLarge)
        ));
    }

    #[test]
    fn text_decode_rejects_invalid_utf8() {
        assert_eq!(decode_text(b"name".to_vec()).unwrap(), "name");
        assert!(matches!(
            decode_text(vec![0xff, 0xfe]),
            Err(AppError::BadRequest(_))
        ));
    }
}
