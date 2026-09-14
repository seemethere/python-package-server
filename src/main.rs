//! Binary entrypoint: configure, migrate, reconcile, then serve.

use std::sync::Arc;

use metrics_exporter_prometheus::PrometheusBuilder;
use tracing_subscriber::EnvFilter;

use python_package_server::{
    auth::Auth,
    build_router,
    config::Settings,
    db::{MetadataBackend, PgStore},
    reconcile::reconcile,
    state::AppState,
    storage::Storage,
};

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

    let storage = Storage::filesystem(settings.storage_dir.clone());
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

    let state = AppState {
        db,
        storage,
        auth,
        metrics,
        settings: Arc::clone(&settings),
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
