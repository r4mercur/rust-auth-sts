use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

pub fn hash_secret(secret: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing secret: {e}"))?;
    Ok(hash.to_string())
}

pub fn verify_secret(phc_hash: &str, secret: &str) -> bool {
    match PasswordHash::new(phc_hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(secret.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

pub fn validate_hash(phc_hash: &str) -> anyhow::Result<()> {
    PasswordHash::new(phc_hash).map_err(|e| anyhow::anyhow!("invalid password hash: {e}"))?;
    Ok(())
}
