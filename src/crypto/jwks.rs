use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct Jwk {
    pub kty: String,
    pub kid: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub n: String,
    pub e: String,
}
#[derive(Serialize, Clone)]
pub struct Jwks { pub keys: Vec<Jwk> }

impl Jwks {
    pub fn single_rsa(kid: &str, n_b64: String, e_b64: String) -> Self {
        Self {

            keys: vec![Jwk {
                kty: "RSA".into(),
                kid: kid.into(),
                alg: "RS256".into(),
                use_: "sig".into(),
                n: n_b64,
                e: e_b64,
            }]
        }
    }
}
