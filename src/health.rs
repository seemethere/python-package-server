//! Public observability handlers: health, metrics, and service info.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::{db::MetadataStore, state::AppState};

/// Liveness/readiness probe: 200 when both deps are up, else 503 degraded.
pub async fn health(State(state): State<AppState>) -> Response {
    let (db_result, storage_result) =
        tokio::join!(state.db.health_check(), state.storage.health_check());
    let db_up = db_result.is_ok();
    let storage_up = storage_result.is_ok();
    let version = env!("CARGO_PKG_VERSION");
    let db = if db_up { "up" } else { "down" };
    let storage = if storage_up { "up" } else { "down" };
    if db_up && storage_up {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ok",
                "version": version,
                "db": db,
                "storage": storage,
            })),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "degraded",
                "version": version,
                "db": db,
                "storage": storage,
            })),
        )
            .into_response()
    }
}

/// Prometheus text exposition.
pub async fn metrics(State(state): State<AppState>) -> String {
    state.metrics.render()
}

/// Service info and endpoint catalogue.
pub async fn root() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "python-package-server",
        "version": env!("CARGO_PKG_VERSION"),
        "endpoints": [
            "/",
            "/health",
            "/metrics",
            "/simple/",
            "/simple/{project}/",
            "/files/{project}/{filename}",
            "/legacy/",
        ],
    }))
}
