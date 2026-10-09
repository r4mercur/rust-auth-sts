use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("invalid_request: {0}")]
    InvalidRequest(String),
    #[error("invalid_client")]
    InvalidClient,
    #[error("invalid_grant")]
    InvalidGrant,
    #[error("invalid_scope: {0}")]
    InvalidScope(String),
    #[error("invalid_target: {0}")]
    InvalidTarget(String),
    #[error("unsupported_grant_type")]
    UnsupportedGrantType,
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl ApiError {
    fn parts(&self) -> (StatusCode, &'static str, Option<&str>) {
        match self {
            ApiError::InvalidRequest(d) => (StatusCode::BAD_REQUEST, "invalid_request", Some(d)),
            ApiError::InvalidClient => (StatusCode::UNAUTHORIZED, "invalid_client", Some("client authentication failed")),
            ApiError::InvalidGrant => (StatusCode::BAD_REQUEST, "invalid_grant", Some("invalid credentials")),
            ApiError::InvalidScope(d) => (StatusCode::BAD_REQUEST, "invalid_scope", Some(d)),
            ApiError::InvalidTarget(d) => (StatusCode::BAD_REQUEST, "invalid_target", Some(d)),
            ApiError::UnsupportedGrantType => (StatusCode::BAD_REQUEST, "unsupported_grant_type", None),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error", None),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let ApiError::Internal(e) = &self {
            tracing::error!(error = %e, "internal");
        }
        let (status, code, description) = self.parts();
        let body = match description {
            Some(d) => json!({ "error": code, "error_description": d }),
            None => json!({ "error": code }),
        };
        let mut response = no_store((status, Json(body)));
        if matches!(self, ApiError::InvalidClient) {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Basic realm=\"rust-auth-sts\""),
            );
        }
        response
    }
}

pub fn no_store(body: impl IntoResponse) -> Response {
    (
        [(header::CACHE_CONTROL, "no-store"), (header::PRAGMA, "no-cache")],
        body,
    )
        .into_response()
}
