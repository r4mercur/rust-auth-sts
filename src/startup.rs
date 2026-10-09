use crate::{
    config::AppConfig,
    crypto::keys::load_keys,
    http::{routes::routes, handlers::AppState},
    repository::memory::{ClientStore, UserStore},
    service::{token_service::TokenService, client_service::ClientService, user_service::UserService},
};
use axum::Router;
use tower_http::trace::TraceLayer;

pub async fn run() -> anyhow::Result<()> {
    let cfg = AppConfig::from_env()?;
    let keys = load_keys(&cfg.keys_dir, &cfg.active_kid)?;
    let kids: Vec<&str> = keys.jwks.keys.iter().map(|k| k.kid.as_str()).collect();
    tracing::info!("signing with kid {}, publishing {:?}", keys.active.kid, kids);

    let clients = ClientStore::from_file(&cfg.clients_path)?;
    if clients.is_empty() {
        tracing::warn!("no clients configured in {}", cfg.clients_path.display());
    }
    tracing::info!("loaded {} client(s)", clients.len());

    let user_svc = match &cfg.users_path {
        Some(path) => {
            let users = UserStore::from_file(path)?;
            tracing::info!("loaded {} user(s), /auth/login enabled", users.len());
            Some(UserService::new(users))
        }
        None => {
            tracing::info!("USERS_PATH not set, /auth/login disabled");
            None
        }
    };

    let token_svc = TokenService::new(cfg.clone(), keys.active);
    let client_svc = ClientService::new(clients);

    let app_state = AppState { token_svc, client_svc, user_svc, jwks: keys.jwks };
    let app: Router = routes(app_state).layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!("STS listening on {}", cfg.bind_addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    tracing::info!("STS stopped");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %e, "failed to listen for ctrl+c");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => { sig.recv().await; }
            Err(e) => {
                tracing::error!(error = %e, "failed to listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received, draining connections");
}
