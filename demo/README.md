# Demo: rust-auth-sts in a minikube cluster

A mini cluster with one namespace (`auth-demo`) where the STS secures the calls between two microservices.

```
                     namespace auth-demo  (PodSecurity: restricted, default-deny NetworkPolicy)
 ┌──────────────────────────────────────────────────────────────────────────────────────────┐
 │                                                                                          │
 │   ┌──────────────────┐   1. client_credentials (Basic auth)   ┌──────────────────────┐   │
 │   │  orders-service  │ ─────────────────────────────────────▶ │  rust-auth-sts  x2   │   │
 │   │  (token client)  │ ◀───────────────────────────────────── │  /oauth/token        │   │
 │   └────────┬─────────┘   2. JWT  aud=inventory-service        │  /oauth/jwks.json    │   │
 │            │                  scope=inventory.read/.write     └──────────▲───────────┘   │
 │            │ 3. Bearer <JWT>                                             │               │
 │            ▼                                                             │ 4. JWKS       │
 │   ┌──────────────────────┐                                               │   (cached)    │
 │   │  inventory-service   │ ──────────────────────────────────────────────┘               │
 │   │  (resource server)   │  verifies signature, typ, iss, aud, exp, scope per endpoint   │
 │   └──────────────────────┘                                                               │
 │                                                                                          │
 │   toolbox  (curl, holds reporting-job credentials, scope inventory.read only)            │
 │   intruder (curl, no credentials, not allowed to reach inventory by NetworkPolicy)       │
 └──────────────────────────────────────────────────────────────────────────────────────────┘
```

| Workload | Image | Role |
|---|---|---|
| `rust-auth-sts` | `rust-auth-sts:demo` | Issues tokens, publishes JWKS. 2 replicas + PodDisruptionBudget |
| `orders-service` | `demo-service:demo` (`MODE=orders`) | Gets tokens for `inventory-service` and calls it (`GET /orders/{id}`, `POST /orders/{id}/reserve`) |
| `inventory-service` | `demo-service:demo` (`MODE=inventory`) | Accepts only valid tokens with `aud=inventory-service`. `GET /stock/{sku}` needs `inventory.read`, `POST /stock/{sku}/reserve` needs `inventory.write` |
| `toolbox` | `curlimages/curl` | Plays the `reporting-job` client to show scope and allowlist checks |
| `intruder` | `curlimages/curl` | Pod without credentials or NetworkPolicy permission |

The demo service ([`demo-service/`](demo-service)) is also the reference for how a microservice should use the STS:
[`token_source.rs`](demo-service/src/token_source.rs) caches tokens and refreshes them before expiry,
[`verifier.rs`](demo-service/src/verifier.rs) is an axum extractor that validates tokens with a cached JWKS.

## Prerequisites

- Docker Desktop (running)
- minikube, kubectl, openssl
- Bash (Git Bash on Windows)

## Run it

```bash
cd demo
./up.sh            # cluster (profile auth-demo, Calico CNI), images, secrets, deployments
./scenarios.sh     # walk through the scenarios below
./rotate-key.sh    # rotate the signing key without downtime
./rotate-key.sh retire   # remove the old key after the token TTL
./down.sh          # delete the cluster (--purge also deletes demo/.secrets)
```

`up.sh` is idempotent: run it again after code changes to rebuild the images and restart the deployments.
Generated keys and client secrets live in `demo/.secrets/` (gitignored). Only Argon2 hashes go into the STS Secret; each service only gets its own plaintext secret.

All scripts use `kubectl --context auth-demo` and never touch other clusters.

## Scenarios (`scenarios.sh`)

| # | What happens | Expected |
|---|---|---|
| 1 | Fetch authorization server metadata | `200` |
| 2 | Fetch JWKS | `200`, active key |
| 3 | `orders` → `inventory` GET with token | `200`, inventory sees caller `orders-service` |
| 4 | `orders` → `inventory` reserve (`inventory.write`) | `200` |
| 5 | Call `inventory` without token | `401`, `WWW-Authenticate: Bearer` |
| 6 | Forged token with valid-looking claims | `401 invalid_token` (signature) |
| 7 | `reporting-job` token: GET stock / reserve | `200` / `403 insufficient_scope` |
| 8 | `reporting-job` asks for `inventory.write`, for audience `orders-service`, with wrong secret | `400 invalid_scope` / `400 invalid_target` / `401 invalid_client` |
| 9 | `intruder` → STS / → inventory | `401 invalid_client` / blocked by NetworkPolicy |

## Key rotation (`rotate-key.sh`)

1. **Publish:** a new key is added to the `sts-signing-keys` Secret and the STS is restarted (rolling, the PDB keeps one replica up). The JWKS now contains both keys, tokens are still signed with the old one.
2. **Switch:** `ACTIVE_KID` in the `sts-config` ConfigMap points to the new key, the STS is restarted again. New tokens carry the new `kid`; `inventory-service` sees an unknown `kid`, refetches the JWKS once and accepts the token.
3. **Retire:** tokens signed with the old key stay valid until they expire. `./rotate-key.sh retire` then removes the old key.

The script waits after each restart until the old STS pods are gone. During a rolling update old replicas keep serving for the `preStop` drain window (5s) and still return the previous JWKS. Switching the signing key in the same step as publishing it can therefore make a service fetch an outdated JWKS and reject a brand-new token. The first version of this demo ran into exactly that, which is why rotation is done in two phases.

## Exploring manually

```bash
kubectl --context auth-demo -n auth-demo get pods
kubectl --context auth-demo -n auth-demo logs deploy/inventory-service -f

# call orders-service from your machine
kubectl --context auth-demo -n auth-demo port-forward svc/orders-service 8081:80
curl http://localhost:8081/orders/42
curl -X POST http://localhost:8081/orders/42/reserve

# shell with the reporting-job credentials inside the cluster
kubectl --context auth-demo -n auth-demo exec -it deploy/toolbox -- sh
curl -u "reporting-job:$REPORTING_CLIENT_SECRET" -d grant_type=client_credentials \
  -d scope=inventory.read -d audience=inventory-service \
  http://rust-auth-sts.auth-demo.svc.cluster.local/oauth/token
```

Each `POST .../reserve` lowers the stock of that SKU (every SKU starts at 3). After three reservations inventory answers `409 out_of_stock`.

## Files

| Path | Content |
|---|---|
| `up.sh`, `scenarios.sh`, `rotate-key.sh`, `down.sh` | Demo lifecycle |
| `common.sh` | Shared settings (profile, namespace, URLs) and helpers |
| `k8s/` | Namespace, STS, services, curl pods, NetworkPolicies |
| `demo-service/` | One Rust binary for both demo services (`MODE=orders` / `MODE=inventory`) |
| `.secrets/` | Generated keys, client secrets, `clients.json`. Gitignored, deleted by `./down.sh --purge` |

## Troubleshooting

- **`minikube image load` fails with `"wmic": executable file not found`:** this is a bug in minikube ≤ 1.34 on current Windows 11 builds. `up.sh` avoids it by loading the images directly into the minikube node (`docker save | docker exec -i auth-demo docker load`).
- **Your kubectl context switched to `auth-demo`:** `minikube start` does that unless started with `--keep-context` (which `up.sh` uses). Switch back with `kubectl config use-context <name>`.
- **Pods stuck in `CreateContainerConfigError`:** the Secrets are missing. Run `./up.sh` again, it recreates them from `.secrets/`.
- **`inventory-service` restarts at startup:** it waits up to 60s for the STS (discovery with retries). Check `kubectl logs deploy/rust-auth-sts`.

## Simplifications compared to production

- Plain HTTP inside the cluster. In production use a service mesh with mTLS (Linkerd, Istio) or TLS on the STS.
- Static client secrets. In Kubernetes, projected ServiceAccount tokens are the better client credential (no secrets to distribute).
- Single minikube node; on a real cluster add `topologySpreadConstraints` so the STS replicas land on different nodes.
- `orders-service` endpoints are unauthenticated (it plays the edge service). In reality it would sit behind an ingress/gateway that authenticates users.
