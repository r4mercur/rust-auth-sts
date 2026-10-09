use std::{collections::HashMap, sync::Arc, time::{Duration, Instant}};
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::RwLock;

const JWKS_MAX_AGE: Duration = Duration::from_secs(300);
const JWKS_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    pub iss: String,
    pub sub: String,
    pub sub_type: String,
    #[serde(default)]
    pub client_id: Option<String>,
    pub aud: String,
    pub scope: String,
    pub exp: i64,
    pub jti: String,
}

pub struct Verifier {
    http: reqwest::Client,
    jwks_uri: String,
    validation: Validation,
    cache: RwLock<KeyCache>,
}

struct KeyCache {
    keys: HashMap<String, DecodingKey>,
    refresh_at: Instant,
    unknown_kid_refresh_at: Instant,
}

impl KeyCache {
    fn lookup(&self, kid: &str, now: Instant) -> Lookup {
        match self.keys.get(kid) {
            Some(key) if now < self.refresh_at => Lookup::Hit(key.clone()),
            None if now < self.unknown_kid_refresh_at => Lookup::Miss,
            _ => Lookup::Refresh,
        }
    }
}

enum Lookup {
    Hit(DecodingKey),
    Miss,
    Refresh,
}

impl Verifier {
    pub async fn new(http: reqwest::Client, jwks_uri: String, issuer: &str, audience: &str) -> anyhow::Result<Self> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.leeway = 30;

        let keys = fetch_jwks(&http, &jwks_uri).await?;
        let now = Instant::now();
        Ok(Self {
            http,
            jwks_uri,
            validation,
            cache: RwLock::new(KeyCache { keys, refresh_at: now + JWKS_MAX_AGE, unknown_kid_refresh_at: now }),
        })
    }

    pub async fn verify(&self, token: &str) -> Result<AccessClaims, AuthError> {
        let header = decode_header(token).map_err(|e| AuthError::InvalidToken(format!("malformed token: {e}")))?;
        if header.alg != Algorithm::RS256 {
            return Err(AuthError::InvalidToken(format!("unexpected algorithm {:?}", header.alg)));
        }
        if header.typ.as_deref() != Some("at+jwt") {
            return Err(AuthError::InvalidToken("token is not an access token (typ != at+jwt)".into()));
        }
        let kid = header.kid.ok_or_else(|| AuthError::InvalidToken("missing kid".into()))?;
        let key = self.key_for(&kid).await
            .ok_or_else(|| AuthError::InvalidToken(format!("unknown signing key {kid}")))?;

        decode::<AccessClaims>(token, &key, &self.validation)
            .map(|data| data.claims)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))
    }

    async fn key_for(&self, kid: &str) -> Option<DecodingKey> {
        match self.cache.read().await.lookup(kid, Instant::now()) {
            Lookup::Hit(key) => return Some(key),
            Lookup::Miss => return None,
            Lookup::Refresh => {}
        }

        let mut cache = self.cache.write().await;
        let now = Instant::now();
        match cache.lookup(kid, now) {
            Lookup::Hit(key) => return Some(key),
            Lookup::Miss => return None,
            Lookup::Refresh => {}
        }
        if !cache.keys.contains_key(kid) {
            cache.unknown_kid_refresh_at = now + JWKS_MIN_REFRESH_INTERVAL;
        }
        match fetch_jwks(&self.http, &self.jwks_uri).await {
            Ok(keys) => {
                tracing::info!(kids = ?keys.keys().collect::<Vec<_>>(), "refreshed JWKS");
                cache.keys = keys;
                cache.refresh_at = now + JWKS_MAX_AGE;
            }
            Err(e) => {
                tracing::warn!(error = %e, "JWKS refresh failed, keeping cached keys");
                cache.refresh_at = now + JWKS_MIN_REFRESH_INTERVAL;
            }
        }
        cache.keys.get(kid).cloned()
    }
}

async fn fetch_jwks(http: &reqwest::Client, jwks_uri: &str) -> anyhow::Result<HashMap<String, DecodingKey>> {
    let set: JwkSet = http.get(jwks_uri).send().await?.error_for_status()?.json().await?;
    let mut keys = HashMap::new();
    for jwk in &set.keys {
        if let Some(kid) = &jwk.common.key_id {
            keys.insert(kid.clone(), DecodingKey::from_jwk(jwk)?);
        }
    }
    Ok(keys)
}

pub struct Caller(pub AccessClaims);

impl Caller {
    pub fn require_scope(&self, scope: &'static str) -> Result<(), AuthError> {
        if self.0.scope.split_whitespace().any(|s| s == scope) {
            Ok(())
        } else {
            Err(AuthError::InsufficientScope(scope))
        }
    }
}

impl<S> FromRequestParts<S> for Caller
where
    Arc<Verifier>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token = parts.headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AuthError::MissingToken)?;
        let verifier = Arc::<Verifier>::from_ref(state);
        let claims = verifier.verify(token.trim()).await?;
        Ok(Caller(claims))
    }
}

#[derive(Debug)]
pub enum AuthError {
    MissingToken,
    InvalidToken(String),
    InsufficientScope(&'static str),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, challenge, body) = match &self {
            AuthError::MissingToken => (
                StatusCode::UNAUTHORIZED,
                "Bearer".to_string(),
                json!({ "error": "missing_token" }),
            ),
            AuthError::InvalidToken(reason) => (
                StatusCode::UNAUTHORIZED,
                "Bearer error=\"invalid_token\"".to_string(),
                json!({ "error": "invalid_token", "error_description": reason }),
            ),
            AuthError::InsufficientScope(scope) => (
                StatusCode::FORBIDDEN,
                format!("Bearer error=\"insufficient_scope\", scope=\"{scope}\""),
                json!({ "error": "insufficient_scope", "required_scope": scope }),
            ),
        };
        tracing::warn!(?self, "rejected request");
        let mut response = (status, Json(body)).into_response();
        if let Ok(value) = HeaderValue::from_str(&challenge) {
            response.headers_mut().insert(header::WWW_AUTHENTICATE, value);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(refresh_in: Duration, unknown_in: Duration) -> (KeyCache, Instant) {
        let now = Instant::now();
        let keys = HashMap::from([("known".to_string(), DecodingKey::from_secret(b"k"))]);
        (KeyCache { keys, refresh_at: now + refresh_in, unknown_kid_refresh_at: now + unknown_in }, now)
    }

    #[test]
    fn known_kid_is_served_from_cache_until_max_age() {
        let (cache, now) = cache(Duration::from_secs(60), Duration::ZERO);
        assert!(matches!(cache.lookup("known", now), Lookup::Hit(_)));
        assert!(matches!(cache.lookup("known", now + Duration::from_secs(61)), Lookup::Refresh));
    }

    #[test]
    fn unknown_kid_refreshes_immediately_after_initial_load() {
        let (cache, now) = cache(Duration::from_secs(60), Duration::ZERO);
        assert!(matches!(cache.lookup("new", now), Lookup::Refresh));
    }

    #[test]
    fn unknown_kid_refreshes_are_rate_limited() {
        let (cache, now) = cache(Duration::from_secs(60), Duration::from_secs(10));
        assert!(matches!(cache.lookup("new", now), Lookup::Miss));
        assert!(matches!(cache.lookup("new", now + Duration::from_secs(11)), Lookup::Refresh));
    }
}
