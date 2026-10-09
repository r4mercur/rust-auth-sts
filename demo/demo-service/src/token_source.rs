use std::time::{Duration, Instant};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::Deserialize;
use tokio::sync::Mutex;

const REFRESH_BEFORE_EXPIRY: Duration = Duration::from_secs(30);

pub struct TokenSource {
    http: reqwest::Client,
    token_endpoint: String,
    client_id: String,
    client_secret: String,
    audience: String,
    scope: String,
    cached: Mutex<Option<CachedToken>>,
}

struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

impl TokenSource {
    pub fn new(
        http: reqwest::Client,
        token_endpoint: String,
        client_id: String,
        client_secret: String,
        audience: String,
        scope: String,
    ) -> Self {
        Self { http, token_endpoint, client_id, client_secret, audience, scope, cached: Mutex::new(None) }
    }

    pub async fn token(&self) -> anyhow::Result<String> {
        let mut cached = self.cached.lock().await;
        if let Some(t) = cached.as_ref() {
            if t.expires_at > Instant::now() + REFRESH_BEFORE_EXPIRY {
                return Ok(t.access_token.clone());
            }
        }

        let response = self.http
            .post(&self.token_endpoint)
            .basic_auth(
                utf8_percent_encode(&self.client_id, NON_ALPHANUMERIC),
                Some(utf8_percent_encode(&self.client_secret, NON_ALPHANUMERIC)),
            )
            .form(&[
                ("grant_type", "client_credentials"),
                ("scope", self.scope.as_str()),
                ("audience", self.audience.as_str()),
            ])
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("token request failed ({status}): {}", response.text().await.unwrap_or_default());
        }
        let token: TokenResponse = response.json().await?;
        tracing::info!(audience = %self.audience, scope = %self.scope, expires_in = token.expires_in, "fetched access token from STS");

        *cached = Some(CachedToken {
            access_token: token.access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(token.expires_in),
        });
        Ok(token.access_token)
    }
}
