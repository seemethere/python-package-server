pub mod admin;
pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod files;
pub mod health;
pub mod oidc;
pub mod packaging;
pub mod reconcile;
pub mod s3;
pub mod simple;
pub mod state;
pub mod storage;
pub mod upload;
pub mod upstream;

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, MatchedPath},
    http::Request,
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post},
};

/// Record per-request latency and count, labelled by method/route/status.
///
/// `MatchedPath` is set by the router before this layer runs for matched
/// routes; unmatched (404) requests fall back to `"unknown"`.
async fn metrics_middleware(req: Request<Body>, next: Next) -> Response {
    let start = std::time::Instant::now();
    // Allowlist the method label so arbitrary method tokens can't blow up cardinality;
    // route is a matched template or "unknown" and status is server-generated, both bounded.
    let method = match req.method().as_str() {
        "GET" | "POST" | "HEAD" | "OPTIONS" => req.method().to_string(),
        _ => "OTHER".to_string(),
    };
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unknown".to_string(), |path| path.as_str().to_string());
    let response = next.run(req).await;
    let status = response.status().as_u16().to_string();
    let elapsed = start.elapsed().as_secs_f64();
    metrics::counter!(
        "http_requests_total",
        "method" => method.clone(),
        "route" => route.clone(),
        "status" => status,
    )
    .increment(1);
    metrics::histogram!(
        "http_request_duration_seconds",
        "method" => method,
        "route" => route,
    )
    .record(elapsed);
    response
}

/// Build the full router.
///
/// Public (open): `GET /`, `/health`, `/live`, `/metrics`.
/// Protected (token auth): `GET /simple/`, `GET /simple/{project}/`,
/// `GET /files/{project}/{filename}`, `POST /legacy/`, and the
/// owner-only `/admin/*` routes.
pub fn build_router(state: state::AppState) -> axum::Router {
    // Auth only wraps the four package routes so unknown paths still 404
    // instead of 401; route_layer preserves that 404 behavior.
    let protected = axum::Router::new()
        .route("/simple/", get(crate::simple::simple_index))
        .route("/simple/{project}/", get(crate::simple::simple_project))
        .route(
            "/files/{project}/{filename}",
            get(crate::files::download_file),
        )
        .route(
            "/legacy/",
            // Bounds concurrent disk-staging usage.
            post(crate::upload::legacy_upload)
                .route_layer(DefaultBodyLimit::disable())
                .route_layer(tower::limit::ConcurrencyLimitLayer::new(8)),
        )
        .route(
            "/admin/projects/{project}/files/{filename}/yank",
            post(crate::admin::yank_file),
        )
        .route(
            "/admin/projects/{project}/files/{filename}/unyank",
            post(crate::admin::unyank_file),
        )
        .route(
            "/admin/projects/{project}/files/{filename}",
            delete(crate::admin::delete_file),
        )
        .route(
            "/admin/projects/{project}/transfer",
            post(crate::admin::transfer_project),
        )
        .route_layer(middleware::from_fn_with_state(
            state.auth.clone(),
            crate::auth::require_auth,
        ));

    axum::Router::new()
        .route("/", get(crate::health::root))
        .route("/health", get(crate::health::health))
        .route("/live", get(crate::health::liveness))
        .route("/metrics", get(crate::health::metrics))
        .merge(protected)
        .layer(middleware::from_fn(metrics_middleware))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}
