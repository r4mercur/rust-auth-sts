#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

show_jwks() {
    in_pod toolbox <<'EOF'
curl -s "$STS/oauth/jwks.json" | tr ',' '\n' | grep '"kid"'
EOF
}

reporting_call() {
    in_pod toolbox <<'EOF'
TOKEN=$(curl -s -u "reporting-job:$REPORTING_CLIENT_SECRET" \
  -d grant_type=client_credentials -d scope=inventory.read -d audience=inventory-service \
  "$STS/oauth/token" | token_from)
echo "new token header:"; header "$TOKEN"
call -H "Authorization: Bearer $TOKEN" "$INVENTORY/stock/sku-1"
EOF
}

restart_sts() {
    local old_pods
    old_pods=$(k get pods -l app=rust-auth-sts -o name)
    k rollout restart deployment/rust-auth-sts
    k rollout status deployment/rust-auth-sts --timeout=120s
    info "waiting for old STS pods to finish draining (preStop) ..."
    k wait --for=delete $old_pods --timeout=60s >/dev/null
}

case "${1:-rotate}" in
    rotate)
        old_kid=$(cat "$SECRETS/active-kid")
        new_kid=$(new_signing_key)

        step "phase 1: publish new key $new_kid (still signing with $old_kid)"
        apply_secrets
        restart_sts
        show_jwks

        step "phase 2: sign with $new_kid"
        echo "$new_kid" > "$SECRETS/active-kid"
        apply_secrets
        restart_sts

        step "fresh token carries the new kid - inventory refreshes its JWKS cache on the unknown kid"
        reporting_call

        step "orders-service keeps working (its cached token may still use $old_kid)"
        in_pod toolbox <<'EOF'
call "$ORDERS/orders/1"
EOF
        info "once all old tokens have expired (TOKEN_TTL_SECONDS=120), run: ./rotate-key.sh retire"
        ;;
    retire)
        active=$(cat "$SECRETS/active-kid")
        step "retire all keys except $active"
        find "$SECRETS/keys" -name '*.pem' ! -name "$active.pem" -print -delete
        apply_secrets
        restart_sts
        step "JWKS now contains"
        show_jwks
        ;;
    *)
        echo "usage: $0 [rotate|retire]" >&2
        exit 1
        ;;
esac
