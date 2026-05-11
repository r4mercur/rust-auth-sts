use crate::{
    config::AppConfig,
    crypto::{keys::load_key, jwks::Jwks},
    http::{routes::routes, handlers::AppState},
    repository::memory::{ClientStore, UserStore},
    service::{token_service::TokenService, client_service::ClientService, user_service::UserService},
};
use axum::Router;
use tower_http::trace::TraceLayer;

pub async fn run() -> anyhow::Result<()> {
    let cfg = AppConfig::from_env()?;
    let keys = load_key(&cfg.key_path)?;
    let jwks = Jwks::single_rsa(&cfg.kid, keys.n_b64.clone(), keys.e_b64.clone());

    let token_svc = TokenService::new(cfg.clone(), keys);
    let client_svc = ClientService::new(ClientStore::with_example());
    let user_svc = UserService::new(UserStore::with_example());

    let app_state = AppState { token_svc, client_svc, user_svc, jwks };
    let app: Router = routes(app_state).layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!("STS listening on {}", cfg.bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}
