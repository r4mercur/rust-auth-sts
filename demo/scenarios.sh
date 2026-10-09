#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

step "1. Discovery: authorization server metadata (RFC 8414)"
in_pod toolbox <<'EOF'
call "$STS/.well-known/oauth-authorization-server"
EOF

step "2. JWKS: public keys the services use to verify tokens"
in_pod toolbox <<'EOF'
call "$STS/oauth/jwks.json" | sed -E 's/"n":"(.{12})[^"]*"/"n":"\1..."/g'
EOF

step "3. Happy path: orders-service -> inventory-service"
info "orders-service gets a client_credentials token from the STS (client_secret_basic) and calls inventory with it."
info "inventory-service validates signature (JWKS), typ, iss, aud, exp and the scope inventory.read."
in_pod toolbox <<'EOF'
call "$ORDERS/orders/42"
EOF

step "4. orders-service reserves an item (scope inventory.write)"
in_pod toolbox <<'EOF'
call -X POST "$ORDERS/orders/42/reserve"
EOF

step "5. Direct call to inventory without a token"
in_pod toolbox <<'EOF'
call -i "$INVENTORY/stock/sku-42" | grep -iE '^(www-authenticate|\{|->)'
EOF

step "6. Forged token: valid-looking claims, signed with an attacker's own key"
info "header uses the real kid, payload claims scope inventory.write - signature does not match the STS key."
in_pod toolbox <<'EOF'
b64url() { base64 | tr -d '\n=' | tr '+/' '-_'; }
h=$(printf '{"alg":"RS256","typ":"at+jwt","kid":"%s"}' "$ACTIVE_KID" | b64url)
p=$(printf '{"iss":"%s","sub":"attacker","sub_type":"service","aud":"inventory-service","scope":"inventory.write","exp":4102444800,"iat":0,"jti":"x"}' "$STS" | b64url)
s=$(head -c 256 /dev/urandom | b64url)
call -X POST -H "Authorization: Bearer $h.$p.$s" "$INVENTORY/stock/sku-42/reserve"
EOF

step "7. reporting-job (toolbox) only has scope inventory.read"
in_pod toolbox <<'EOF'
TOKEN=$(curl -s -u "reporting-job:$REPORTING_CLIENT_SECRET" \
  -d grant_type=client_credentials -d scope=inventory.read -d audience=inventory-service \
  "$STS/oauth/token" | token_from)
echo "token header:"; header "$TOKEN"
echo "token claims:"; claims "$TOKEN"
echo; echo "GET /stock/sku-7 (needs inventory.read):"
call -H "Authorization: Bearer $TOKEN" "$INVENTORY/stock/sku-7"
echo; echo "POST /stock/sku-7/reserve (needs inventory.write):"
call -X POST -H "Authorization: Bearer $TOKEN" "$INVENTORY/stock/sku-7/reserve"
EOF

step "8. The STS enforces each client's allowlist"
in_pod toolbox <<'EOF'
echo "reporting-job asks for inventory.write:"
call -u "reporting-job:$REPORTING_CLIENT_SECRET" -d grant_type=client_credentials \
  -d scope=inventory.write -d audience=inventory-service "$STS/oauth/token"
echo; echo "reporting-job asks for a token for orders-service:"
call -u "reporting-job:$REPORTING_CLIENT_SECRET" -d grant_type=client_credentials \
  -d scope=inventory.read -d audience=orders-service "$STS/oauth/token"
echo; echo "wrong client secret:"
call -u "reporting-job:guessed" -d grant_type=client_credentials \
  -d scope=inventory.read -d audience=inventory-service "$STS/oauth/token"
EOF

step "9. NetworkPolicy: a pod without the inventory-client label"
info "intruder can reach the STS (needs credentials it does not have) but not inventory-service at all."
in_pod intruder <<'EOF'
echo "intruder -> STS token endpoint:"
call -u "orders-service:guessed" -d grant_type=client_credentials \
  -d scope=inventory.read -d audience=inventory-service "$STS/oauth/token"
echo; echo "intruder -> inventory-service:"
call "$INVENTORY/stock/sku-42"
EOF

step "10. Server-side view"
k logs deploy/inventory-service --tail=8
