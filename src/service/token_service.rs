use crate::{config::AppConfig, crypto::keys::{KeyMaterial, header_with_kid}, models::claims::Claims};
use jsonwebtoken::encode;
use time::{OffsetDateTime, Duration};
use uuid::Uuid;

#[derive(Clone)]
pub struct TokenService {
    cfg: AppConfig,
    keys: KeyMaterial,
}

impl TokenService {
    pub fn new(cfg: AppConfig, keys: KeyMaterial) -> Self { Self { cfg, keys } }

    pub fn mint(
        &self,
        sub: String,
        sub_type: String,
        aud: String,
        scope: String,
    ) -> anyhow::Result<(String, u64)> {
        let now = OffsetDateTime::now_utc();
        let exp = now + Duration::seconds(self.cfg.token_ttl_seconds as i64);

        let claims = Claims {
            iss: self.cfg.issuer.clone(),
            sub,
            sub_type,
            aud,
            scope: scope.clone(),
            exp: exp.unix_timestamp(),
            iat: now.unix_timestamp(),
            jti: Uuid::new_v4().to_string(),
        };

        let header = header_with_kid(&self.cfg.kid);
        let token = encode(&header, &claims, &self.keys.enc_key)?;
        Ok((token, self.cfg.token_ttl_seconds))
    }
}

impl TokenService {
    pub fn get_issuer(&self) -> &str {
        &self.cfg.issuer
    }
}