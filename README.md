# rust-auth-sts

A small, stateless **Security Token Service** for service-to-service authentication in Kubernetes, written in Rust (Axum).

Every microservice gets its own client credentials. Before calling another service it requests a short-lived access token from the STS, scoped to exactly one target service and a set of permissions. The target service validates the token locally with the STS's public keys, so the STS is not on the hot path of every request.

- OAuth 2.0 `client_credentials` grant ([RFC 6749](https://www.rfc-editor.org/rfc/rfc6749)), `client_secret_basic` and `client_secret_post`
- RS256-signed JWT access tokens ([RFC 9068](https://www.rfc-editor.org/rfc/rfc9068), `typ: at+jwt`)
- JWKS with multiple keys for zero-downtime key rotation
- Authorization server metadata ([RFC 8414](https://www.rfc-editor.org/rfc/rfc8414))
- Client secrets stored only as Argon2id hashes
- Per-client allowlists for scopes and audiences
- Health probes, graceful shutdown, ~9 MB distroless image running as non-root

**Contents:**
[How it works](#how-it-works) ·
[Quickstart](#quickstart) ·
[Configuration](#configuration) ·
[API](#api) ·
[Deploying to Kubernetes](#deploying-to-kubernetes) ·
[Connecting a microservice](#connecting-a-microservice) ·
[Operations](#operations) ·
[Demo](#demo) ·
[Development](#development) ·
[Security notes](#security-notes)

---

## How it works

```
 ┌───────────────┐  1. POST /oauth/token                      ┌──────────────────┐
 │               │     Basic orders-service:<secret>          │                  │
 │ orders-service│     scope=inventory.read&audience=...      │  rust-auth-sts   │
 │  (client)     │ ─────────────────────────────────────────▶ │                  │
 │               │ ◀───────────────────────────────────────── │  checks secret,  │
 │               │  2. access_token (JWT, 120s)               │  scope + audience│
 └───────┬───────┘                                            │  allowlists      │
         │                                                    └────────▲─────────┘
         │ 3. GET /stock/42                                            │
         │    Authorization: Bearer <JWT>                              │ 4. GET /oauth/jwks.json
         ▼                                                             │    (cached, refreshed on
 ┌───────────────────┐                                                 │     unknown kid)
 │ inventory-service │ ────────────────────────────────────────────────┘
 │  (resource server)│  5. verifies signature, typ, iss, aud, exp locally,
 └───────────────────┘     then checks the scope the endpoint requires
```

A token looks like this:

```json
// header
{ "alg": "RS256", "typ": "at+jwt", "kid": "key-2026-10" }
// payload
{
  "iss": "http://rust-auth-sts.auth.svc.cluster.local",
  "sub": "orders-service",
  "sub_type": "service",
  "client_id": "orders-service",
  "aud": "inventory-service",
  "scope": "inventory.read inventory.write",
  "iat": 1791561131,
  "exp": 1791561251,
  "jti": "b5928418-8434-4383-85ee-ee03eec4f9b7"
}
```

## Quickstart

Requirements: Rust (stable), OpenSSL. Docker is optional.

```bash
# 1. signing key (file name without .pem = kid)
mkdir -p secrets/keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out secrets/keys/key-2026-10.pem

# 2. hash a client secret
printf '%s' 'change-me' | cargo run -q -- hash-secret
```

Put the hash into `secrets/clients.json`:

```json
[
  {
    "id": "service-a",
    "secret_hash": "$argon2id$v=19$m=19456,t=2,p=1$...",
    "allowed_scopes": ["service.read"],
    "allowed_audiences": ["service-b"]
  }
]
```

```bash
# 3. configure and start
cp .env.example .env
cargo run

# 4. get a token
curl -u service-a:change-me \
  -d grant_type=client_credentials -d scope=service.read -d audience=service-b \
  http://localhost:8080/oauth/token
```

## Configuration

All configuration is read from environment variables (a local `.env` file is loaded if present).

| Variable | Required | Default | Description |
|---|---|---|---|
| `ISSUER` | yes | | Value of the `iss` claim and base URL in the metadata. Must be the URL services use to reach the STS. |
| `KEYS_DIR` | yes | `/app/keys` in the image | Directory with `<kid>.pem` RSA keys (PKCS#8). All keys are published in the JWKS. |
| `ACTIVE_KID` | yes | | Key used to sign new tokens. `<ACTIVE_KID>.pem` must exist in `KEYS_DIR`. |
| `CLIENTS_PATH` | yes | `/app/config/clients.json` in the image | Registered service clients. |
| `USERS_PATH` | no | | Registered users. Unset = `/auth/login` is disabled. |
| `TOKEN_TTL_SECONDS` | no | `120` | Lifetime of issued tokens. |
| `BIND_ADDR` | no | `0.0.0.0:8080` | Listen address. |
| `RUST_LOG` | no | `info` | Log filter. |

### Clients (`CLIENTS_PATH`)

```json
[
  {
    "id": "orders-service",
    "secret_hash": "$argon2id$...",
    "allowed_scopes": ["inventory.read", "inventory.write"],
    "allowed_audiences": ["inventory-service"]
  }
]
```

- `id` is the `client_id` and becomes the token's `sub`.
- `allowed_audiences` lists the services this client may call. Use the target service's name, e.g. its Kubernetes Service name.
- `allowed_scopes` lists the permissions it may request. A convention like `<service>.<action>` keeps them readable.
- Generate hashes with `rust-auth-sts hash-secret` (reads the secret from stdin). The plaintext secret is never stored in the STS.

The STS refuses to start on unreadable files, invalid hashes, unknown fields or duplicate IDs.

### Users (`USERS_PATH`, optional)

`POST /auth/login` issues user tokens (`sub_type: user`) for simple cases. Same format with `username`, `password_hash`, `allowed_scopes` and `allowed_audiences`. For real end-user authentication, use a dedicated identity provider (Keycloak, Zitadel, ...) and keep this STS for service-to-service traffic.

## API

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/oauth/token` | Issue a token (`client_credentials`) |
| `GET` | `/oauth/jwks.json` | Public keys (`Cache-Control: public, max-age=300`) |
| `GET` | `/.well-known/oauth-authorization-server` | Metadata: issuer, token endpoint, JWKS URI |
| `POST` | `/auth/login` | User token, only if `USERS_PATH` is set |
| `GET` | `/healthz`, `/readyz` | Liveness / readiness |

### `POST /oauth/token`

Form-encoded body. Client authentication via HTTP Basic (preferred) or `client_id` + `client_secret` in the body, not both.

| Parameter | Required | |
|---|---|---|
| `grant_type` | yes | `client_credentials` |
| `scope` | yes | Space-separated, every scope must be allowed for the client |
| `audience` | yes | Target service, must be allowed for the client |

```json
{ "access_token": "<jwt>", "token_type": "Bearer", "expires_in": 120, "scope": "inventory.read" }
```

Errors ([RFC 6749 §5.2](https://www.rfc-editor.org/rfc/rfc6749#section-5.2)), always with `Cache-Control: no-store`:

| Situation | Status | `error` |
|---|---|---|
| Missing `grant_type` / `audience`, malformed body, two auth methods | 400 | `invalid_request` |
| Unknown client, wrong or missing secret | 401 + `WWW-Authenticate: Basic` | `invalid_client` |
| Grant type other than `client_credentials` | 400 | `unsupported_grant_type` |
| Missing or disallowed scope | 400 | `invalid_scope` |
| Disallowed audience | 400 | `invalid_target` |
| Wrong credentials on `/auth/login` | 400 | `invalid_grant` |

```json
{ "error": "invalid_target", "error_description": "audience not allowed: orders-service" }
```

## Deploying to Kubernetes

The manifest [`demo/k8s/10-rust-auth-sts.yaml`](demo/k8s/10-rust-auth-sts.yaml) is a complete starting point: 2 replicas, PodDisruptionBudget, probes, `preStop` drain, restricted security context, keys and clients from Secrets. The steps below use a dedicated namespace `auth`.

### 1. Build and push the image

```bash
docker build -t registry.example.com/platform/rust-auth-sts:1.0.0 .
docker push registry.example.com/platform/rust-auth-sts:1.0.0
```

### 2. Create the signing key

```bash
kubectl create namespace auth
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key-2026-10.pem
kubectl -n auth create secret generic sts-signing-keys --from-file=key-2026-10.pem
kubectl -n auth create configmap sts-config --from-literal=active-kid=key-2026-10
rm key-2026-10.pem   # or store it in your secret manager
```

### 3. Register the clients

```bash
kubectl -n auth create secret generic sts-clients --from-file=clients.json
```

### 4. Deploy

Copy `demo/k8s/10-rust-auth-sts.yaml` and adapt:

- `metadata.namespace` → `auth`
- `image` → your registry image, `imagePullPolicy: IfNotPresent` or `Always`
- `ISSUER` → `http://rust-auth-sts.auth.svc.cluster.local` (or your HTTPS URL behind a mesh/ingress). Every service must use exactly this value.
- add `topologySpreadConstraints` so the replicas run on different nodes

```bash
kubectl apply -f rust-auth-sts.yaml
kubectl -n auth rollout status deployment/rust-auth-sts
kubectl -n auth run curl --rm -it --image=curlimages/curl --restart=Never -- \
  curl -s http://rust-auth-sts.auth.svc.cluster.local/.well-known/oauth-authorization-server
```

### 5. Restrict network access

The STS only needs to be reachable from namespaces that run microservices. Example:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: rust-auth-sts-ingress
  namespace: auth
spec:
  podSelector:
    matchLabels:
      app: rust-auth-sts
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              sts-access: "true"
      ports:
        - port: 8080
```

Label every namespace that may use the STS with `sts-access=true`.

## Connecting a microservice

### Onboarding checklist

For a new service `orders-service` that needs to call `inventory-service`:

1. **Agree on names and scopes.** Audience = name of the called service (`inventory-service`), scopes = what the caller needs (`inventory.read`).
2. **Create a secret** and register its hash:
   ```bash
   SECRET=$(openssl rand -hex 32)
   printf '%s' "$SECRET" | docker run --rm -i registry.example.com/platform/rust-auth-sts:1.0.0 hash-secret
   ```
   Add the client to `clients.json`, update the Secret and restart the STS:
   ```bash
   kubectl -n auth create secret generic sts-clients --from-file=clients.json --dry-run=client -o yaml | kubectl apply -f -
   kubectl -n auth rollout restart deployment/rust-auth-sts
   ```
3. **Give the plaintext secret to the calling service only**, in its own namespace:
   ```bash
   kubectl -n shop create secret generic orders-sts-credentials --from-literal=client-secret="$SECRET"
   ```
   Mount it as a file (see [`demo/k8s/30-orders-service.yaml`](demo/k8s/30-orders-service.yaml)) rather than an env var.
4. **Calling service:** fetch and cache tokens (below).
5. **Called service:** validate tokens and check scopes per endpoint (below).

### Calling another service (token client)

Rules:

- Request one token per target audience and reuse it until shortly before `expires_in`. Do not request a token per call.
- Discover the token endpoint from `/.well-known/oauth-authorization-server` and verify that the reported `issuer` matches your configuration.
- Send the token as `Authorization: Bearer <token>`.

Rust reference implementation: [`demo/demo-service/src/token_source.rs`](demo/demo-service/src/token_source.rs)

```rust
let http = reqwest::Client::new();
let metadata = discovery::discover(&http, STS_URL, ISSUER).await?;
let tokens = TokenSource::new(
    http.clone(),
    metadata.token_endpoint,
    "orders-service".into(),
    client_secret,
    "inventory-service".into(),
    "inventory.read".into(),
);

let response = http
    .get("http://inventory-service.shop.svc.cluster.local/stock/sku-42")
    .bearer_auth(tokens.token().await?)
    .send()
    .await?;
```

Other languages: any OAuth 2.0 client-credentials library works (Spring Security `client_credentials`, `golang.org/x/oauth2/clientcredentials`, ...). Pass `audience` as an extra token request parameter.

### Protecting a service (resource server)

Every service that receives calls must check:

| Check | Why |
|---|---|
| Signature with the JWKS key matching `kid` | token was issued by the STS |
| `alg == RS256`, fixed in your code | never trust the algorithm from the token |
| `typ == at+jwt` | rejects other JWTs (e.g. ID tokens) |
| `iss == <ISSUER>` | token comes from your STS |
| `aud == <own service name>` | token was meant for you, not replayed from another service |
| `exp` (small leeway) | token is still valid |
| required scope per endpoint | caller is allowed to do *this* |

Cache the JWKS (≈5 min) and refetch it once when a token has an unknown `kid`. That makes key rotation transparent.

Rust/Axum reference implementation: [`demo/demo-service/src/verifier.rs`](demo/demo-service/src/verifier.rs), an extractor you can drop into any handler:

```rust
let verifier = Arc::new(Verifier::new(http, metadata.jwks_uri, ISSUER, "inventory-service").await?);

async fn reserve(caller: Caller, Path(sku): Path<String>) -> Result<Json<Value>, AuthError> {
    caller.require_scope("inventory.write")?;
    // caller.0.sub == "orders-service"
    Ok(Json(json!({ "sku": sku, "reserved": true })))
}
```

Rejections follow [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750): `401` with `WWW-Authenticate: Bearer error="invalid_token"`, `403` with `error="insufficient_scope"`.

Other languages: use a JWT library with JWKS support (Spring Security resource server, `github.com/MicahParks/keyfunc` for Go, `jose` for Node.js) and configure issuer, audience and the RS256 algorithm explicitly.

## Operations

### Changing clients

The STS reads `clients.json` at startup. After updating the Secret, run `kubectl -n auth rollout restart deployment/rust-auth-sts`. The rollout is zero-downtime (2 replicas, PDB, readiness probe, `preStop` drain).

### Rotating the signing key

Do it in two phases. During a rolling update the old replicas still serve the old JWKS for a few seconds.

1. **Publish:** add the new key to the `sts-signing-keys` Secret, restart, wait until the old pods are gone. The JWKS now contains both keys, tokens are still signed with the old one.
2. **Switch:** set `active-kid` in `sts-config` to the new key, restart. Services pick up the new `kid` via JWKS refresh.
3. **Retire:** after `TOKEN_TTL_SECONDS` plus the JWKS cache time, remove the old key from the Secret and restart.

[`demo/rotate-key.sh`](demo/rotate-key.sh) automates exactly these steps.

### Scaling and resources

The STS is stateless, so replicas can be added freely. The expensive part is Argon2 secret verification (~19 MiB memory and tens of milliseconds of CPU per token request). Clients cache tokens, so the request rate is roughly *number of client instances × audiences / token TTL*. The demo limits (32 Mi request, 256 Mi limit) are plenty for that.

### Logs

Logs go to stdout. Startup logs the active `kid`, all published `kid`s and the number of loaded clients. Per-request logs (method, path, status, latency) are emitted at debug level: set `RUST_LOG=info,tower_http=debug` to see them, including rejected token requests.

## Demo

[`demo/`](demo/README.md) contains a complete local setup with minikube: the STS plus two microservices (`orders-service` calls `inventory-service`) in one namespace with restricted PodSecurity and NetworkPolicies. It also includes a scripted tour of the success and failure cases and a live key rotation.

```bash
cd demo
./up.sh && ./scenarios.sh
```

## Development

```bash
cargo test                 # unit + integration tests (tests/oauth_token.rs)
cargo clippy --all-targets
docker build -t rust-auth-sts .
```

The integration tests use test-only credentials and keys in `tests/fixtures/` (`service-a` / `super-secret`, `alice` / `hunter2`).

```
src/
  main.rs              CLI entry (server or `hash-secret`)
  startup.rs           wiring, graceful shutdown
  config.rs            environment configuration
  crypto/              keys + JWKS, Argon2 hashing
  http/                routes and handlers (token, login, JWKS, metadata, health)
  service/             token minting, client/user checks, scope handling
  repository/          client/user stores loaded from JSON
  error.rs             RFC 6749 error responses
demo/                  minikube demo, demo microservice, Kubernetes manifests
```

## Security notes

- **Transport:** the STS speaks plain HTTP. In a cluster, run it behind a service mesh with mTLS (Linkerd, Istio) or terminate TLS in front of it. Otherwise client secrets and tokens travel unencrypted.
- **Static secrets:** client secrets have to be distributed and rotated by hand. Using projected Kubernetes ServiceAccount tokens as client credentials would remove that, but it is not implemented yet.
- **Not yet implemented:** rate limiting on `/oauth/token`, audit logging, token revocation/introspection. Keep `TOKEN_TTL_SECONDS` short to compensate.
- Never put `secrets/`, `.env` or `demo/.secrets/` into git. The `.gitignore` covers them, and `*.pem` is ignored everywhere except the test fixtures.
