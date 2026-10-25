//! Binary entrypoint: configure, migrate, reconcile, then serve.

use std::sync::Arc;

use metrics_exporter_prometheus::PrometheusBuilder;
use tracing_subscriber::EnvFilter;

use python_package_server::{
    auth::Auth,
    build_router,
    config::Settings,
    db::{MetadataBackend, PgStore},
    reconcile::{reconcile, sweep_upstream_cache},
    state::AppState,
    storage::Storage,
};

/// Interval between background upstream-cache eviction sweeps.
///
/// Lazy expiry on the download path keeps serving correct; this loop only
/// reclaims disk from entries nobody requests anymore.
const UPSTREAM_CACHE_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(6 * 3600);

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let settings = match Settings::from_env() {
        Ok(settings) => Arc::new(settings),
        Err(err) => {
            eprintln!("configuration error: {err}");
            std::process::exit(1);
        }
    };

    let pg = match PgStore::connect(&settings.database_url).await {
        Ok(store) => store,
        Err(err) => {
            // DATABASE_URL echo risk considered: stderr is operator-owned; sqlx connect errors carry host, not credentials, per its Display.
            eprintln!("database connection failed: {err}");
            std::process::exit(1);
        }
    };
    if let Err(err) = pg.run_migrations().await {
        eprintln!("database migration failed: {err}");
        std::process::exit(1);
    }
    let db = MetadataBackend::Postgres(pg);

    let storage = match settings.storage_backend.as_str() {
        "s3" => match python_package_server::s3::S3Backend::from_settings(&settings).await {
            Ok(backend) => Storage::s3(backend),
            Err(err) => {
                eprintln!("storage initialization failed: {err}");
                std::process::exit(1);
            }
        },
        _ => Storage::filesystem(settings.storage_dir.clone()),
    };
    if let Err(err) = storage.ensure_dirs().await {
        eprintln!("storage initialization failed: {err}");
        std::process::exit(1);
    }

    let auth = match Auth::from_file(&settings.auth_token_file) {
        Ok(auth) => auth,
        Err(err) => {
            eprintln!(
                "auth token file error ({}): {err}",
                settings.auth_token_file.display()
            );
            std::process::exit(1);
        }
    };
    if auth.is_empty() {
        eprintln!(
            "auth token file error ({}): no users found; refusing to start with zero credentials",
            settings.auth_token_file.display()
        );
        std::process::exit(1);
    }

    reconcile(&db, &storage).await;

    // Install before serving so request-time counters register.
    let metrics = match PrometheusBuilder::new().install_recorder() {
        Ok(handle) => handle,
        Err(err) => {
            eprintln!("metrics recorder installation failed: {err}");
            std::process::exit(1);
        }
    };

    // Age out stale pull-through cache entries once at startup, after the
    // metrics install so the sweep's eviction counter registers. Infallible
    // by design: failures log and startup continues.
    sweep_upstream_cache(&db, &storage, settings.upstream_cache_max_age_days).await;

    // The same sweep repeats in the background; a 0-day TTL disables both.
    if settings.upstream_cache_max_age_days > 0 {
        let sweep_db = db.clone();
        let sweep_storage = storage.clone();
        let sweep_max_age_days = settings.upstream_cache_max_age_days;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(UPSTREAM_CACHE_SWEEP_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // The first tick completes immediately; consume it so the loop
            // sweeps on the interval instead of re-running the startup sweep.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                sweep_upstream_cache(&sweep_db, &sweep_storage, sweep_max_age_days).await;
            }
        });
    }

    let upstream = python_package_server::upstream::UpstreamClient::from_settings(&settings);
    let state = AppState {
        db,
        storage,
        auth,
        metrics,
        settings: Arc::clone(&settings),
        upstream,
    };
    let app = build_router(state);

    let listener = match tokio::net::TcpListener::bind(settings.bind_addr.clone()).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("failed to bind {}: {err}", settings.bind_addr);
            std::process::exit(1);
        }
    };
    tracing::info!("listening on {}", settings.bind_addr);

    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        eprintln!("server error: {err}");
        std::process::exit(1);
    }
}

/// Resolve when SIGTERM or Ctrl-C (SIGINT) arrives, portably.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
