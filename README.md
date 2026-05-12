# rust-auth-sts

Lightweight Authorization Server (STS) built with Rust + Axum.
This service issues RS256 JWT access tokens, exposes JWKS for signature validation, and provides a simple user login flow.

## What this service does

- Issues access tokens via `client_credentials` (`POST /oauth/token`)
- Issues access tokens via user login (`POST /auth/login`)
- Exposes JWKS (`GET /oauth/jwks.json`)
- Exposes OpenID discovery metadata (`GET /.well-known/openid-configuration`)

## Important notes

- The current implementation uses in-memory demo data (`service-a`, `alice`) from `src/repository/memory.rs`.
- Token signing uses an RSA private key in **PKCS#8 PEM** format (`-----BEGIN PRIVATE KEY-----`).
- This project is intentionally minimal (no refresh tokens, revocation, database, or admin UI).

## Prerequisites

- Rust toolchain (stable)
- OpenSSL (to generate dev/test keys)
- Optional: Docker

## Local quickstart

### 1) Generate an RSA key

```bash
cd /path/to/rust-auth-sts
mkdir -p ./secrets
openssl genpkey -algorithm RSA -out ./secrets/private_rsa_pkcs8.pem -pkeyopt rsa_keygen_bits:2048
```

### 2) Set environment variables

Example `.env`:

```dotenv
ISSUER=http://localhost:8080
KID=key-2025-08
KEY_PATH=./secrets/private_rsa_pkcs8.pem
BIND_ADDR=0.0.0.0:8080
TOKEN_TTL_SECONDS=120
```

### 3) Start the service

```bash
cd /path/to/rust-auth-sts
cargo run
```

## API usage

### 1) Request a token via client credentials (`service-a`)

```bash
curl -X POST "http://localhost:8080/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=service-a&client_secret=super-secret&scope=service.read&audience=service-b"
```

Expected: `200 OK` with JSON like:

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 120,
  "scope": "service.read"
}
```

### 2) Error case (wrong secret)

```bash
curl -X POST "http://localhost:8080/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=service-a&client_secret=wrong&scope=service.read&audience=service-b"
```

Expected: `401 Unauthorized`

### 3) User login flow

```bash
curl -X POST "http://localhost:8080/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"alice\",\"password\":\"hunter2\",\"scope\":\"profile\",\"audience\":\"general\"}"
```

### 4) Fetch JWKS

```bash
curl "http://localhost:8080/oauth/jwks.json"
```

### 5) Fetch discovery metadata

```bash
curl "http://localhost:8080/.well-known/openid-configuration"
```

## Using it as a central Authorization Server

Recommended internal-service pattern:

1. **Service A** requests an access token from the auth server (`/oauth/token`).
2. The auth server validates `client_id`, `client_secret`, `scope`, and `audience`.
3. The auth server signs and returns an RS256 JWT.
4. **Service B** validates the JWT using the public key from discovery/JWKS:
   `/.well-known/openid-configuration` -> `jwks_uri` -> `/oauth/jwks.json`.

Key JWT claims:

- `iss`: issuer (auth server URL)
- `sub`: identity (client/user)
- `sub_type`: `service` or `user`
- `aud`: target service
- `scope`: permission scope
- `exp`, `iat`, `jti`

## Docker

### Build image

```bash
cd /path/to/rust-auth-sts
docker build -t rust-auth-sts .
```

### Run container

```bash
docker run --rm -p 8080:8080 \
  -e ISSUER=http://localhost:8080 \
  -e KID=key-2025-08 \
  -e KEY_PATH=/app/secrets/private_rsa_pkcs8.pem \
  -e TOKEN_TTL_SECONDS=120 \
  -v "$(pwd)/secrets:/app/secrets:ro" \
  rust-auth-sts
```

Note: the code reads `KEY_PATH` (not `JWT_SECRET_FILE`), so set `KEY_PATH` explicitly when running in Docker.

## Tests

Integration tests for the token endpoint are in `tests/oauth_token.rs`.

```bash
cd /path/to/rust-auth-sts
cargo test --test oauth_token
```

Currently covered:

- `200` for valid `service-a` client credentials
- `401` for wrong secret
- `401` for disallowed scope
- `400` for unsupported grant type

## Recommended production hardening

- Replace in-memory repositories with DB/secret store
- Do not store client secrets in plaintext
- Enforce TLS (ingress/reverse proxy)
- Implement key rotation (multiple active `kid`s)
- Add audit logging + rate limiting
- Optional: token introspection / revocation
