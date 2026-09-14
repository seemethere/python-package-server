//! Artifact download handler.

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{db::MetadataStore, error::AppError, packaging::normalize_project, state::AppState};

/// Stream a stored distribution file (`GET /files/{project}/{filename}`).
pub async fn download_file(
    State(state): State<AppState>,
    Path((project, filename)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let normalized = normalize_project(&project)
        .map_err(|_| AppError::NotFound(format!("project {project} not found")))?;
    let record = state
        .db
        .get_file(normalized.as_str(), &filename)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("file {filename} not found")))?;
    let (size, body) = match state.storage.get(normalized.as_str(), &filename).await? {
        Some(found) => found,
        None => {
            tracing::warn!(
                project = normalized.as_str(),
                filename = filename.as_str(),
                "file row present but storage object missing"
            );
            return Err(AppError::NotFound(format!("file {filename} not found")));
        }
    };
    metrics::counter!("file_downloads_total").increment(1);
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_LENGTH, size.to_string()),
            (header::ETAG, format!("\"{}\"", record.sha256)),
        ],
        body,
    )
        .into_response())
}
