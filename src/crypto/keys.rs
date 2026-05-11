use anyhow::Context;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey, traits::PublicKeyParts};
use base64ct::{Base64UrlUnpadded, Encoding};
use std::fs;

#[derive(Clone)]
pub struct KeyMaterial {
    pub enc_key: EncodingKey,
    pub n_b64: String,
    pub e_b64: String,
}

pub fn load_key(pkcs8_pem_path: &std::path::Path) -> anyhow::Result<KeyMaterial> {
    let pem = fs::read_to_string(pkcs8_pem_path)
        .with_context(|| format!("reading key {}", pkcs8_pem_path.display()))?;
    let private = RsaPrivateKey::from_pkcs8_pem(&pem)?;
    let public = private.to_public_key();

    let n = public.n().to_bytes_be();
    let e = public.e().to_bytes_be();

    let n_b64 = Base64UrlUnpadded::encode_string(&n);
    let e_b64 = Base64UrlUnpadded::encode_string(&e);

    let enc_key = EncodingKey::from_rsa_pem(pem.as_bytes())?;
    Ok(KeyMaterial { enc_key, n_b64, e_b64 })
}

pub fn header_with_kid(kid: &str) -> Header {
    let mut h = Header::new(Algorithm::RS256);
    h.kid = Some(kid.to_string());
    h
}
