#!/usr/bin/env bash
set -euo pipefail
export MSYS_NO_PATHCONV=1

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && (pwd -W 2>/dev/null || pwd))"
REPO_DIR="$(cd "$DEMO_DIR/.." && (pwd -W 2>/dev/null || pwd))"
PROFILE=auth-demo
NS=auth-demo
SECRETS="$DEMO_DIR/.secrets"

STS=http://rust-auth-sts.auth-demo.svc.cluster.local
INVENTORY=http://inventory-service.auth-demo.svc.cluster.local
ORDERS=http://orders-service.auth-demo.svc.cluster.local

k() { kubectl --context "$PROFILE" -n "$NS" "$@"; }

step() { printf '\n\033[1;36m=== %s\033[0m\n' "$*"; }
info() { printf '\033[2m%s\033[0m\n' "$*"; }

in_pod() {
    local pod=$1
    {
        printf 'STS=%s\nINVENTORY=%s\nORDERS=%s\n' "$STS" "$INVENTORY" "$ORDERS"
        printf 'ACTIVE_KID=%s\n' "$(cat "$SECRETS/active-kid" 2>/dev/null)"
        cat <<'PRELUDE'
call() { curl -s -m 3 -w '\n-> HTTP %{http_code}\n' "$@" || echo "-> no response (connection blocked or timed out)"; }
claims() { p=$(echo "$1" | cut -d. -f2 | tr '_-' '/+'); while [ $(( ${#p} % 4 )) -ne 0 ]; do p="$p="; done; echo "$p" | base64 -d; echo; }
header() { p=$(echo "$1" | cut -d. -f1 | tr '_-' '/+'); while [ $(( ${#p} % 4 )) -ne 0 ]; do p="$p="; done; echo "$p" | base64 -d; echo; }
token_from() { sed -E 's/.*"access_token":"([^"]+)".*/\1/'; }
PRELUDE
        cat
        echo true
    } | k exec -i "deploy/$pod" -- sh -s
}

apply_secrets() {
    k create secret generic sts-signing-keys --from-file="$SECRETS/keys" --dry-run=client -o yaml | k apply -f -
    k create configmap sts-config --from-literal=active-kid="$(cat "$SECRETS/active-kid")" --dry-run=client -o yaml | k apply -f -
}

new_signing_key() {
    local kid="key-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$SECRETS/keys"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$SECRETS/keys/$kid.pem" 2>/dev/null
    echo "$kid"
}
