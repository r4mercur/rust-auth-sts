use std::path::PathBuf;
use anyhow::Context;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub issuer: String,
    pub keys_dir: PathBuf,
    pub active_kid: String,
    pub bind_addr: String,
    pub token_ttl_seconds: u64,
    pub clients_path: PathBuf,
    pub users_path: Option<PathBuf>,
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();
        let issuer = std::env::var("ISSUER").context("ISSUER must be set")?;
        let keys_dir = std::env::var("KEYS_DIR").context("KEYS_DIR must be set")?.into();
        let active_kid = std::env::var("ACTIVE_KID").context("ACTIVE_KID must be set")?;
        let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
        let token_ttl_seconds = std::env::var("TOKEN_TTL_SECONDS").ok()
            .and_then(|s| s.parse().ok()).unwrap_or(120);
        let clients_path = std::env::var("CLIENTS_PATH").context("CLIENTS_PATH must be set")?.into();
        let users_path = std::env::var("USERS_PATH").ok().filter(|s| !s.is_empty()).map(Into::into);
        Ok(Self { issuer, keys_dir, active_kid, bind_addr, token_ttl_seconds, clients_path, users_path })
    }
}
