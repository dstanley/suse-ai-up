#!/usr/bin/env bash
# 01 — OAuth Discovery and Dynamic Client Registration
# Demonstrates RFC 9728, RFC 8414, and RFC 7591 endpoints
set -euo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8911}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:3000/callback}"
CURL_INSECURE="${CURL_INSECURE:--k}"  # Use -k for self-signed certs; set to "" to disable

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

step() { echo -e "\n${CYAN}=== Step $1: $2 ===${NC}\n"; }
ok()   { echo -e "${GREEN}OK${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }
info() { echo -e "${YELLOW}INFO${NC}: $1"; }

echo -e "${CYAN}OAuth Discovery & Dynamic Client Registration${NC}"
echo "Proxy: ${PROXY_URL}"
echo ""

# ─── Step 1: Protected Resource Metadata (RFC 9728) ──────────────────

step 1 "Protected Resource Metadata (RFC 9728)"

info "An MCP client first needs to discover the authorization server."
info "GET ${PROXY_URL}/.well-known/oauth-protected-resource"
echo ""

RESOURCE_META=$(curl -sf ${CURL_INSECURE} "${PROXY_URL}/.well-known/oauth-protected-resource") \
  || fail "Protected resource metadata unavailable — is the proxy running?"
echo "$RESOURCE_META" | jq .

AS_URL=$(echo "$RESOURCE_META" | jq -r '.authorization_servers[0]')
RESOURCE=$(echo "$RESOURCE_META" | jq -r '.resource')
SCOPES=$(echo "$RESOURCE_META" | jq -r '.scopes_supported | join(", ")')

ok "Resource: ${RESOURCE}"
ok "Authorization Server: ${AS_URL}"
ok "Scopes: ${SCOPES}"

# ─── Step 2: Authorization Server Metadata (RFC 8414) ────────────────

step 2 "Authorization Server Metadata (RFC 8414)"

info "Now the client fetches the AS metadata to discover all endpoints."
info "GET ${PROXY_URL}/.well-known/oauth-authorization-server"
echo ""

AS_META=$(curl -sf ${CURL_INSECURE} "${PROXY_URL}/.well-known/oauth-authorization-server") \
  || fail "AS metadata unavailable"
echo "$AS_META" | jq .

AUTH_ENDPOINT=$(echo "$AS_META" | jq -r '.authorization_endpoint')
TOKEN_ENDPOINT=$(echo "$AS_META" | jq -r '.token_endpoint')
REG_ENDPOINT=$(echo "$AS_META" | jq -r '.registration_endpoint')
REVOKE_ENDPOINT=$(echo "$AS_META" | jq -r '.revocation_endpoint')
CHALLENGE_METHODS=$(echo "$AS_META" | jq -r '.code_challenge_methods_supported | join(", ")')
GRANT_TYPES=$(echo "$AS_META" | jq -r '.grant_types_supported | join(", ")')

ok "Authorization:  ${AUTH_ENDPOINT}"
ok "Token:          ${TOKEN_ENDPOINT}"
ok "Registration:   ${REG_ENDPOINT}"
ok "Revocation:     ${REVOKE_ENDPOINT}"
ok "PKCE Methods:   ${CHALLENGE_METHODS}"
ok "Grant Types:    ${GRANT_TYPES}"

# ─── Step 3: Dynamic Client Registration (RFC 7591) ──────────────────

step 3 "Dynamic Client Registration (RFC 7591)"

info "MCP clients register dynamically — no pre-shared credentials needed."
info "POST ${REG_ENDPOINT}"
echo ""

REG_RESPONSE=$(curl -sf ${CURL_INSECURE} -X POST "${REG_ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_name\": \"Discovery Demo Client\",
    \"redirect_uris\": [\"${REDIRECT_URI}\"],
    \"grant_types\": [\"authorization_code\"],
    \"response_types\": [\"code\"],
    \"token_endpoint_auth_method\": \"none\"
  }") || fail "Client registration failed"

echo "$REG_RESPONSE" | jq .

CLIENT_ID=$(echo "$REG_RESPONSE" | jq -r '.client_id')
CLIENT_NAME=$(echo "$REG_RESPONSE" | jq -r '.client_name')

ok "Registered client '${CLIENT_NAME}' with ID: ${CLIENT_ID}"

# ─── Step 4: 401 Challenge ───────────────────────────────────────────

step 4 "Unauthenticated Request — 401 Challenge"

info "When a client hits a protected endpoint without a token,"
info "the proxy returns 401 with a WWW-Authenticate header pointing"
info "to the resource metadata URL (per RFC 9728)."
echo ""

HTTP_CODE=$(curl -sf ${CURL_INSECURE} -o /dev/null -w "%{http_code}" "${PROXY_URL}/api/v1/adapters" 2>/dev/null || true)
WWW_AUTH=$(curl -sf ${CURL_INSECURE} -D - -o /dev/null "${PROXY_URL}/api/v1/adapters" 2>/dev/null | grep -i "www-authenticate" || true)

if [ "$HTTP_CODE" = "401" ]; then
  ok "Got 401 Unauthorized (expected)"
  if [ -n "$WWW_AUTH" ]; then
    info "WWW-Authenticate: ${WWW_AUTH}"
  fi
else
  info "Got HTTP ${HTTP_CODE} (proxy may not require auth in current config)"
fi

# ─── Summary ─────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}=== Discovery Demo Complete ===${NC}"
echo ""
echo "What we demonstrated:"
echo "  1. Protected Resource Metadata (RFC 9728) — tells clients where to authenticate"
echo "  2. Authorization Server Metadata (RFC 8414) — exposes all OAuth endpoints"
echo "  3. Dynamic Client Registration (RFC 7591) — no pre-shared client credentials"
echo "  4. 401 WWW-Authenticate challenge — standard OAuth error response"
echo ""
echo "Next: Run 02-pkce-auth-flow to complete the full authorization flow."
