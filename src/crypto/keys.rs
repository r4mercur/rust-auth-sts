use anyhow::Context;
use jsonwebtoken::EncodingKey;
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey, traits::PublicKeyParts};
use base64ct::{Base64UrlUnpadded, Encoding};
use std::{fs, path::Path};
use crate::crypto::jwks::{Jwk, Jwks};

#[derive(Clone)]
pub struct SigningKey {
    pub kid: String,
    pub enc_key: EncodingKey,
}

#[derive(Clone)]
pub struct KeyRing {
    pub active: SigningKey,
    pub jwks: Jwks,
}

pub fn load_keys(dir: &Path, active_kid: &str) -> anyhow::Result<KeyRing> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("reading key directory {}", dir.display()))?
        .collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());

    let mut active = None;
    let mut jwks = Jwks { keys: Vec::new() };
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || path.extension().and_then(|e| e.to_str()) != Some("pem") {
            continue;
        }
        let kid = name.trim_end_matches(".pem").to_string();
        let (jwk, enc_key) = load_key(&path, &kid)?;
        jwks.keys.push(jwk);
        if kid == active_kid {
            active = Some(SigningKey { kid, enc_key });
        }
    }

    let active = active.with_context(|| {
        format!("active key {active_kid}.pem not found in {}", dir.display())
    })?;
    Ok(KeyRing { active, jwks })
}

fn load_key(path: &Path, kid: &str) -> anyhow::Result<(Jwk, EncodingKey)> {
    let pem = fs::read_to_string(path)
        .with_context(|| format!("reading key {}", path.display()))?;
    let private = RsaPrivateKey::from_pkcs8_pem(&pem)
        .with_context(|| format!("parsing PKCS#8 RSA key {}", path.display()))?;
    let public = private.to_public_key();

    let jwk = Jwk::rsa(
        kid,
        Base64UrlUnpadded::encode_string(&public.n().to_bytes_be()),
        Base64UrlUnpadded::encode_string(&public.e().to_bytes_be()),
    );
    let enc_key = EncodingKey::from_rsa_pem(pem.as_bytes())?;
    Ok((jwk, enc_key))
}
