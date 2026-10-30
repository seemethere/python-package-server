//! Owner-only project administration.
//!
//! Routes (all behind token auth; see `lib.rs`):
//! - `POST /admin/projects/{project}/files/{filename}/yank`
//! - `POST /admin/projects/{project}/files/{filename}/unyank`
//! - `DELETE /admin/projects/{project}/files/{filename}`
//! - `POST /admin/projects/{project}/transfer`
//!
//! Only the project owner may administer it. An ownerless project
//! (pre-ownership data) is atomically claimed by the first user who
//! administers it, mirroring claim-on-upload; everyone else then needs
//! the new owner's rights. Yanked files stay downloadable by direct
//! URL; installers skip them unless pinned (PEP 592).

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    auth::AuthenticatedUser,
    db::{MetadataStore, ProjectRecord},
    error::AppError,
    files::{sidecar_filename, SIDECAR_PROJECT},
    packaging::normalize_project,
    state::AppState,
};

/// Maximum accepted yank-reason length, in characters.
const MAX_REASON_CHARS: usize = 512;

/// Max transfer-target length; matches the OIDC principal cap so the new owner can always authenticate.
const MAX_OWNER_CHARS: usize = 256;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YankRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferRequest {
    pub new_owner: String,
}

/// Resolve the project and authorize `user` as its administrator.
///
/// Returns the normalized name and project row. An ownerless project is
/// atomically claimed for `user` first (the claim returns the winning
/// owner, so concurrent first-administrators cannot both pass); owned
/// projects require the owner.
async fn administered_project(
    state: &AppState,
    project: &str,
    user: &str,
) -> Result<(String, ProjectRecord), AppError> {
    let normalized = normalize_project(project)
        .map_err(|_| AppError::NotFound(format!("project {project} not found")))?;
    let mut record = state
        .db
        .get_project(normalized.as_str())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("project {} not found", normalized.as_str())))?;
    if record.owner.is_none() {
        let owner = state
            .db
            .claim_project(&record.display_name, normalized.as_str(), user)
            .await?;
        record.owner = Some(owner);
    }
    if record.owner.as_deref() != Some(user) {
        return Err(AppError::Forbidden(format!(
            "project {} is owned by another user",
            normalized.as_str()
        )));
    }
    Ok((normalized.as_str().to_string(), record))
}

/// Parse an optional JSON body after authorization.
///
/// Empty bodies mean no payload; malformed JSON is a client error in the
/// standard error shape, never an extractor rejection that would bypass
/// the ownership check or leak a different response format.
fn parse_optional_json<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<Option<T>, AppError> {
    if body.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(None);
    }
    serde_json::from_slice(body)
        .map(Some)
        .map_err(|err| AppError::BadRequest(format!("invalid JSON body: {err}")))
}

/// Parse a required JSON body after authorization; see [`parse_optional_json`].
fn parse_json<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, AppError> {
    parse_optional_json(body)?.ok_or_else(|| AppError::BadRequest("missing JSON body".to_string()))
}

/// Normalize an optional yank reason: trimmed, empty means none.
fn clean_reason(request: Option<YankRequest>) -> Result<Option<String>, AppError> {
    let Some(reason) = request.and_then(|req| req.reason) else {
        return Ok(None);
    };
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().count() > MAX_REASON_CHARS {
        return Err(AppError::BadRequest(format!(
            "yank reason exceeds {MAX_REASON_CHARS} characters"
        )));
    }
    Ok(Some(trimmed.to_string()))
}

/// Normalize a transfer target: trimmed, non-empty, no control chars, capped.
fn clean_new_owner(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("missing new_owner".to_string()));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(AppError::BadRequest("invalid new_owner".to_string()));
    }
    if trimmed.chars().count() > MAX_OWNER_CHARS {
        return Err(AppError::BadRequest(format!(
            "new_owner exceeds {MAX_OWNER_CHARS} characters"
        )));
    }
    Ok(trimmed.to_string())
}

/// Yank one file (`POST .../yank`), optionally with `{"reason": "..."}`.
pub async fn yank_file(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path((project, filename)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let (normalized, _) = administered_project(&state, &project, &user.0).await?;
    let reason = clean_reason(parse_optional_json::<YankRequest>(&body)?)?;
    let updated = state
        .db
        .set_yanked(&normalized, &filename, true, reason.as_deref())
        .await?;
    if !updated {
        return Err(AppError::NotFound(format!("file {filename} not found")));
    }
    metrics::counter!("file_yanks_total").increment(1);
    Ok((
        StatusCode::OK,
        Json(json!({
            "project": normalized,
            "filename": filename,
            "yanked": true,
            "reason": reason,
        })),
    )
        .into_response())
}

/// Clear a file's yank (`POST .../unyank`).
pub async fn unyank_file(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path((project, filename)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let (normalized, _) = administered_project(&state, &project, &user.0).await?;
    let updated = state
        .db
        .set_yanked(&normalized, &filename, false, None)
        .await?;
    if !updated {
        return Err(AppError::NotFound(format!("file {filename} not found")));
    }
    metrics::counter!("file_unyanks_total").increment(1);
    Ok((
        StatusCode::OK,
        Json(json!({
            "project": normalized,
            "filename": filename,
            "yanked": false,
        })),
    )
        .into_response())
}

/// Permanently delete one file: index row first, then stored bytes.
///
/// Deleting the row first keeps the index authoritative. A failed byte
/// removal only leaves an invisible orphan object and is logged. Any
/// shadowing upstream-cache sidecar is removed best-effort as well.
pub async fn delete_file(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path((project, filename)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let (normalized, _) = administered_project(&state, &project, &user.0).await?;
    if state.db.get_file(&normalized, &filename).await?.is_none() {
        return Err(AppError::NotFound(format!("file {filename} not found")));
    }
    state.db.delete_file(&normalized, &filename).await?;
    if let Err(err) = state.storage.delete(&normalized, &filename).await {
        tracing::warn!(
            project = normalized.as_str(),
            filename = filename.as_str(),
            error = %err,
            "file row deleted but object removal failed"
        );
    }
    // Mirror hosted upload: drop any shadowing cache sidecar so no stale
    // stamp outlives the deleted bytes. Best-effort, like the bytes removal.
    let sidecar = sidecar_filename(&normalized, &filename);
    if let Err(err) = state.storage.delete(SIDECAR_PROJECT, &sidecar).await {
        tracing::warn!(
            project = normalized.as_str(),
            filename = filename.as_str(),
            error = %err,
            "file row deleted but sidecar removal failed"
        );
    }
    metrics::counter!("file_deletes_total").increment(1);
    Ok((
        StatusCode::OK,
        Json(json!({
            "project": normalized,
            "filename": filename,
            "deleted": true,
        })),
    )
        .into_response())
}

/// Transfer project ownership (`POST .../transfer`, `{"new_owner": "..."}`).
pub async fn transfer_project(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(project): Path<String>,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let (normalized, record) = administered_project(&state, &project, &user.0).await?;
    let request: TransferRequest = parse_json(&body)?;
    let new_owner = clean_new_owner(&request.new_owner)?;
    if record.owner.as_deref() == Some(new_owner.as_str()) {
        return Err(AppError::BadRequest(format!(
            "project {normalized} is already owned by '{new_owner}'"
        )));
    }
    // When OIDC is enabled the IdP is the user directory, so any non-empty
    // name is accepted and spelling is the operator's responsibility.
    if !state.auth.has_user(&new_owner) && state.oidc.is_none() {
        return Err(AppError::BadRequest(format!("unknown user '{new_owner}'")));
    }
    if !state.db.set_project_owner(&normalized, &new_owner).await? {
        return Err(AppError::NotFound(format!(
            "project {normalized} not found"
        )));
    }
    metrics::counter!("project_transfers_total").increment(1);
    Ok((
        StatusCode::OK,
        Json(json!({
            "project": normalized,
            "owner": new_owner,
        })),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(reason: Option<&str>) -> Option<YankRequest> {
        reason.map(|reason| YankRequest {
            reason: Some(reason.to_string()),
        })
    }

    #[test]
    fn cleans_yank_reasons() {
        assert_eq!(clean_reason(None).unwrap(), None);
        assert_eq!(clean_reason(request(None)).unwrap(), None);
        assert_eq!(clean_reason(request(Some(""))).unwrap(), None);
        assert_eq!(clean_reason(request(Some("   "))).unwrap(), None);
        assert_eq!(
            clean_reason(request(Some("  bad build  "))).unwrap(),
            Some("bad build".to_string())
        );
        let too_long = "x".repeat(MAX_REASON_CHARS + 1);
        assert!(matches!(
            clean_reason(request(Some(too_long.as_str()))),
            Err(AppError::BadRequest(_))
        ));
        let at_cap = "x".repeat(MAX_REASON_CHARS);
        assert!(clean_reason(request(Some(at_cap.as_str()))).is_ok());
    }

    #[test]
    fn cleans_new_owners() {
        assert_eq!(clean_new_owner("  alice  ").unwrap(), "alice".to_string());
        assert!(matches!(clean_new_owner(""), Err(AppError::BadRequest(_))));
        assert!(matches!(
            clean_new_owner("   "),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            clean_new_owner("ali\nce"),
            Err(AppError::BadRequest(_))
        ));
        let too_long = "x".repeat(257);
        assert!(matches!(
            clean_new_owner(too_long.as_str()),
            Err(AppError::BadRequest(_))
        ));
        // Hardcoded 256 pins parity with the OIDC principal cap.
        let at_cap = "x".repeat(256);
        assert_eq!(clean_new_owner(at_cap.as_str()).unwrap(), at_cap);
        // Multibyte chars count once each (chars, not bytes).
        let wide = "é".repeat(256);
        assert_eq!(clean_new_owner(wide.as_str()).unwrap(), wide);
        assert!(matches!(
            clean_new_owner("é".repeat(257).as_str()),
            Err(AppError::BadRequest(_))
        ));
    }
}
