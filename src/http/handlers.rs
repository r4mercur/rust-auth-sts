use axum::{
    extract::{rejection::{FormRejection, JsonRejection}, State},
    http::{header, HeaderMap},
    response::{IntoResponse, Response},
    Form, Json,
};
use base64ct::{Base64, Encoding};
use serde_json::json;
use crate::{
    error::{no_store, ApiError},
    models::token::{TokenRequest, TokenResponse, LoginRequest},
    service::{
        client_service::ClientService,
        scope,
        token_service::{TokenService, TokenSubject},
        user_service::UserService,
    },
    crypto::jwks::Jwks,
};

#[derive(Clone)]
pub struct AppState {
    pub token_svc: TokenService,
    pub client_svc: ClientService,
    pub user_svc: Option<UserService>,
    pub jwks: Jwks,
}

const METADATA_CACHE_CONTROL: &str = "public, max-age=300";

pub async fn jwks_handler(State(st): State<AppState>) -> Response {
    ([(header::CACHE_CONTROL, METADATA_CACHE_CONTROL)], Json(st.jwks)).into_response()
}

pub async fn healthz_handler() -> &'static str {
    "ok"
}

pub async fn token_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<TokenRequest>, FormRejection>,
) -> Result<Response, ApiError> {
    let Form(req) = form.map_err(|e| ApiError::InvalidRequest(e.body_text()))?;

    match req.grant_type.as_deref() {
        None => return Err(ApiError::InvalidRequest("grant_type is required".into())),
        Some("client_credentials") => {}
        Some(_) => return Err(ApiError::UnsupportedGrantType),
    }

    let (client_id, client_secret) = client_credentials(&headers, &req)?;
    let svc = st.client_svc.clone();
    let client = tokio::task::spawn_blocking(move || svc.authenticate(&client_id, &client_secret))
        .await
        .map_err(|e| ApiError::Internal(e.into()))?
        .ok_or(ApiError::InvalidClient)?;

    let scope = scope::normalize(req.scope.as_deref().unwrap_or_default())
        .ok_or_else(|| ApiError::InvalidScope("scope is required".into()))?;
    if !st.client_svc.is_scope_allowed(&client, &scope) {
        return Err(ApiError::InvalidScope(format!("scope not allowed: {scope}")));
    }
    let aud = required_audience(req.audience)?;
    if !st.client_svc.is_aud_allowed(&client, &aud) {
        return Err(ApiError::InvalidTarget(format!("audience not allowed: {aud}")));
    }

    let subject = TokenSubject { sub: client.id.clone(), sub_type: "service", client_id: Some(client.id) };
    issue(&st.token_svc, subject, aud, scope)
}

pub async fn login_handler(
    State(st): State<AppState>,
    body: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(req) = body.map_err(|e| ApiError::InvalidRequest(e.body_text()))?;
    let user_svc = st.user_svc
        .ok_or_else(|| ApiError::InvalidRequest("user login is disabled".into()))?;

    let svc = user_svc.clone();
    let (username, password) = (req.username, req.password);
    let user = tokio::task::spawn_blocking(move || svc.authenticate(&username, &password))
        .await
        .map_err(|e| ApiError::Internal(e.into()))?
        .ok_or(ApiError::InvalidGrant)?;

    let scope = scope::normalize(req.scope.as_deref().unwrap_or_default())
        .ok_or_else(|| ApiError::InvalidScope("scope is required".into()))?;
    if !user_svc.is_scope_allowed(&user, &scope) {
        return Err(ApiError::InvalidScope(format!("scope not allowed: {scope}")));
    }
    let aud = required_audience(req.audience)?;
    if !user_svc.is_aud_allowed(&user, &aud) {
        return Err(ApiError::InvalidTarget(format!("audience not allowed: {aud}")));
    }

    let subject = TokenSubject { sub: user.id, sub_type: "user", client_id: None };
    issue(&st.token_svc, subject, aud, scope)
}

pub async fn metadata_handler(State(st): State<AppState>) -> Response {
    let issuer = st.token_svc.get_issuer();
    let mut grant_types = vec!["client_credentials"];
    if st.user_svc.is_some() {
        grant_types.push("urn:rust-auth-sts:login");
    }
    let body = json!({
        "issuer": issuer,
        "token_endpoint": format!("{issuer}/oauth/token"),
        "jwks_uri": format!("{issuer}/oauth/jwks.json"),
        "grant_types_supported": grant_types,
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "response_types_supported": [],
    });
    ([(header::CACHE_CONTROL, METADATA_CACHE_CONTROL)], Json(body)).into_response()
}

fn issue(token_svc: &TokenService, subject: TokenSubject, aud: String, scope: String) -> Result<Response, ApiError> {
    let (token, expires_in) = token_svc.mint(subject, aud, scope.clone())?;
    Ok(no_store(Json(TokenResponse {
        access_token: token,
        token_type: "Bearer".into(),
        expires_in,
        scope: Some(scope),
    })))
}

fn required_audience(audience: Option<String>) -> Result<String, ApiError> {
    audience
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .ok_or_else(|| ApiError::InvalidRequest("audience is required".into()))
}

fn client_credentials(headers: &HeaderMap, req: &TokenRequest) -> Result<(String, String), ApiError> {
    let Some(authorization) = headers.get(header::AUTHORIZATION) else {
        let id = req.client_id.clone().ok_or(ApiError::InvalidClient)?;
        let secret = req.client_secret.clone().ok_or(ApiError::InvalidClient)?;
        return Ok((id, secret));
    };

    let (id, secret) = parse_basic(authorization.to_str().map_err(|_| ApiError::InvalidClient)?)
        .ok_or(ApiError::InvalidClient)?;
    if req.client_secret.is_some() {
        return Err(ApiError::InvalidRequest("multiple client authentication methods".into()));
    }
    if req.client_id.as_deref().is_some_and(|body_id| body_id != id) {
        return Err(ApiError::InvalidRequest("client_id does not match Authorization header".into()));
    }
    Ok((id, secret))
}

fn parse_basic(value: &str) -> Option<(String, String)> {
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = String::from_utf8(Base64::decode_vec(encoded.trim()).ok()?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((form_decode(id)?, form_decode(secret)?))
}

fn form_decode(s: &str) -> Option<String> {
    percent_encoding::percent_decode_str(&s.replace('+', " "))
        .decode_utf8()
        .ok()
        .map(|c| c.into_owned())
}
