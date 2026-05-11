use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub issuer: String,          // z.B. https://auth.internal
    pub key_path: PathBuf,       // PEM Private Key (PKCS8 RSA)
    pub kid: String,             // Key ID für Rotation
    pub bind_addr: String,       // 0.0.0.0:8080
    pub token_ttl_seconds: u64,  // z.B. 120
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();
        let issuer = std::env::var("ISSUER")?;
        let kid = std::env::var("KID")?;
        let key_path = std::env::var("KEY_PATH")?.into();
        let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
        let token_ttl_seconds = std::env::var("TOKEN_TTL_SECONDS").ok()
            .and_then(|s| s.parse().ok()).unwrap_or(120);
        Ok(Self { issuer, key_path, kid, bind_addr, token_ttl_seconds })
    }
}
