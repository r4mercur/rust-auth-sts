use axum::{Router, routing::{get, post}};
use super::handlers::{jwks_handler, token_handler, login_handler, openid_cfg_handler};
use crate::http::handlers::AppState;

pub fn routes(state: AppState) -> Router {
    Router::new()
        .route("/oauth/jwks.json", get(jwks_handler))
        .route("/.well-known/openid-configuration", get(openid_cfg_handler))
        .route("/oauth/token", post(token_handler))
        .route("/auth/login", post(login_handler))
        .with_state(state)
}
