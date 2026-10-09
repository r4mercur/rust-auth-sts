use std::time::Duration;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    pub issuer: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

pub async fn discover(http: &reqwest::Client, sts_url: &str, expected_issuer: &str) -> anyhow::Result<Metadata> {
    let url = format!("{}/.well-known/oauth-authorization-server", sts_url.trim_end_matches('/'));
    let mut attempt = 0;
    loop {
        attempt += 1;
        match fetch(http, &url).await {
            Ok(meta) => {
                anyhow::ensure!(
                    meta.issuer == expected_issuer,
                    "issuer mismatch: expected {expected_issuer}, STS reports {}",
                    meta.issuer
                );
                tracing::info!(issuer = %meta.issuer, jwks_uri = %meta.jwks_uri, "discovered STS metadata");
                return Ok(meta);
            }
            Err(e) if attempt < 30 => {
                tracing::warn!(error = %e, attempt, "STS discovery failed, retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

async fn fetch(http: &reqwest::Client, url: &str) -> anyhow::Result<Metadata> {
    Ok(http.get(url).send().await?.error_for_status()?.json().await?)
}
