use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub sub_type: String, // "user" | "service"
    pub aud: String,
    pub scope: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
}
