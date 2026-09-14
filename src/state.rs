//! Shared application state.

/// Cloneable state injected into every handler via [`axum::extract::State`].
#[derive(Clone)]
pub struct AppState {
    pub db: crate::db::MetadataBackend,
    pub storage: crate::storage::Storage,
    pub auth: crate::auth::Auth,
    pub metrics: metrics_exporter_prometheus::PrometheusHandle,
    pub settings: std::sync::Arc<crate::config::Settings>,
}
