use axum::{extract::State, Json, Form};
use serde_json::json;
use crate::{
    error::ApiError,
    models::token::{TokenRequest, TokenResponse, LoginRequest},
    service::{token_service::TokenService, client_service::ClientService, user_service::UserService},
    crypto::jwks::Jwks,
};

#[derive(Clone)]
pub struct AppState {
    pub token_svc: TokenService,
    pub client_svc: ClientService,
    pub user_svc: UserService,
    pub jwks: Jwks,
}

pub async fn jwks_handler(State(st): State<AppState>) -> Json<Jwks> {
    Json(st.jwks)
}

pub async fn token_handler(
    State(st): State<AppState>,
    Form(req): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    if req.grant_type != "client_credentials" {
        return Err(ApiError::BadRequest("unsupported_grant_type".into()));
    }
    let client = st.client_svc
        .authenticate(&req.client_id, req.client_secret.as_deref())
        .ok_or(ApiError::Unauthorized)?;

    let scope = req.scope.unwrap_or_else(|| "service.read".into());
    if !st.client_svc.is_scope_allowed(client, &scope) {
        return Err(ApiError::Unauthorized);
    }
    let aud = req.audience.unwrap_or_else(|| "service-b".into());
    if !st.client_svc.is_aud_allowed(client, &aud) {
        return Err(ApiError::Unauthorized);
    }

    let (token, exp) = st.token_svc
        .mint(client.id.clone(), "service".into(), aud, scope.clone())
        .map_err(ApiError::Internal)?;

    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "Bearer".into(),
        expires_in: exp,
        scope: Some(scope),
    }))
}

pub async fn login_handler(
    State(st): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    let user = st.user_svc
        .authenticate(&req.username, &req.password)
        .ok_or(ApiError::Unauthorized)?;

    let scope = req.scope.unwrap_or_else(|| "profile".into());
    if !st.user_svc.is_scope_allowed(user, &scope) {
        return Err(ApiError::Unauthorized);
    }

    let aud = req.audience.unwrap_or_else(|| "general".into());

    let (token, exp) = st.token_svc
        .mint(user.id.clone(), "user".into(), aud, scope.clone())
        .map_err(ApiError::Internal)?;

    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "Bearer".into(),
        expires_in: exp,
        scope: Some(scope),
    }))
}

pub async fn openid_cfg_handler(State(st): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "issuer": st.token_svc.get_issuer(),
        "jwks_uri": format!("{}/oauth/jwks.json", st.token_svc.get_issuer()),
        "token_endpoint": format!("{}/oauth/token", st.token_svc.get_issuer()),
        "grant_types_supported": ["client_credentials", "user_password"]
    }))
}