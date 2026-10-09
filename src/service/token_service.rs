use crate::{config::AppConfig, crypto::keys::SigningKey, models::claims::Claims};
use jsonwebtoken::{encode, Algorithm, Header};
use time::{OffsetDateTime, Duration};
use uuid::Uuid;

#[derive(Clone)]
pub struct TokenService {
    cfg: AppConfig,
    key: SigningKey,
}

pub struct TokenSubject {
    pub sub: String,
    pub sub_type: &'static str,
    pub client_id: Option<String>,
}

impl TokenService {
    pub fn new(cfg: AppConfig, key: SigningKey) -> Self { Self { cfg, key } }

    pub fn mint(
        &self,
        subject: TokenSubject,
        aud: String,
        scope: String,
    ) -> anyhow::Result<(String, u64)> {
        let now = OffsetDateTime::now_utc();
        let exp = now + Duration::seconds(self.cfg.token_ttl_seconds as i64);

        let claims = Claims {
            iss: self.cfg.issuer.clone(),
            sub: subject.sub,
            sub_type: subject.sub_type.into(),
            client_id: subject.client_id,
            aud,
            scope,
            exp: exp.unix_timestamp(),
            iat: now.unix_timestamp(),
            jti: Uuid::new_v4().to_string(),
        };

        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some(self.key.kid.clone());
        let token = encode(&header, &claims, &self.key.enc_key)?;
        Ok((token, self.cfg.token_ttl_seconds))
    }

    pub fn get_issuer(&self) -> &str {
        &self.cfg.issuer
    }
}
