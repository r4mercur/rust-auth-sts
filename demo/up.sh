#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

step "minikube cluster '$PROFILE' (Calico CNI for NetworkPolicy enforcement)"
if minikube status -p "$PROFILE" >/dev/null 2>&1; then
    info "already running"
else
    minikube start -p "$PROFILE" --driver=docker --cni=calico --keep-context
fi

step "build images"
docker build -t rust-auth-sts:demo "$REPO_DIR"
docker build -t demo-service:demo "$DEMO_DIR/demo-service"

docker image inspect curlimages/curl:8.16.0 >/dev/null 2>&1 || docker pull curlimages/curl:8.16.0

step "load images into minikube"
for image in rust-auth-sts:demo demo-service:demo curlimages/curl:8.16.0; do
    docker save "$image" | docker exec -i "$PROFILE" docker load
done

step "generate secrets in $SECRETS (gitignored)"
mkdir -p "$SECRETS"
if [ ! -f "$SECRETS/active-kid" ]; then
    new_signing_key > "$SECRETS/active-kid"
fi
for client in orders-service reporting-job; do
    [ -f "$SECRETS/$client.secret" ] || openssl rand -hex 32 | tr -d '\r\n' > "$SECRETS/$client.secret"
done
hash() { tr -d '\r\n' < "$SECRETS/$1.secret" | docker run --rm -i rust-auth-sts:demo hash-secret; }
cat > "$SECRETS/clients.json" <<EOF
[
  {
    "id": "orders-service",
    "secret_hash": "$(hash orders-service)",
    "allowed_scopes": ["inventory.read", "inventory.write"],
    "allowed_audiences": ["inventory-service"]
  },
  {
    "id": "reporting-job",
    "secret_hash": "$(hash reporting-job)",
    "allowed_scopes": ["inventory.read"],
    "allowed_audiences": ["inventory-service"]
  }
]
EOF
info "active signing key: $(cat "$SECRETS/active-kid")"

step "deploy to namespace $NS"
already_deployed=false
k get deployment rust-auth-sts >/dev/null 2>&1 && already_deployed=true
kubectl --context "$PROFILE" apply -f "$DEMO_DIR/k8s/00-namespace.yaml"
apply_secrets
k create secret generic sts-clients --from-file=clients.json="$SECRETS/clients.json" --dry-run=client -o yaml | k apply -f -
k create secret generic orders-sts-credentials --from-file=client-secret="$SECRETS/orders-service.secret" --dry-run=client -o yaml | k apply -f -
k create secret generic reporting-sts-credentials --from-file=client-secret="$SECRETS/reporting-job.secret" --dry-run=client -o yaml | k apply -f -
kubectl --context "$PROFILE" apply -f "$DEMO_DIR/k8s/"

if $already_deployed; then
    k rollout restart deployment
fi
for d in rust-auth-sts inventory-service orders-service toolbox intruder; do
    k rollout status "deployment/$d" --timeout=180s
done

step "ready"
k get pods -o wide
info "run ./scenarios.sh to walk through the demo"
