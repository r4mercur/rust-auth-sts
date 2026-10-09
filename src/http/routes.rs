use axum::{Router, routing::{get, post}};
use super::handlers::{jwks_handler, token_handler, login_handler, metadata_handler, healthz_handler};
use crate::http::handlers::AppState;

pub fn routes(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/readyz", get(healthz_handler))
        .route("/oauth/jwks.json", get(jwks_handler))
        .route("/.well-known/oauth-authorization-server", get(metadata_handler))
        .route("/oauth/token", post(token_handler));
    if state.user_svc.is_some() {
        router = router.route("/auth/login", post(login_handler));
    }
    router.with_state(state)
}
