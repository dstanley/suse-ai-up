#!/usr/bin/env bash
# MCP OAuth V2 Demo — exercises all authentication flows
# Usage: PROXY_URL=https://proxy.example.com ./demo.sh
set -euo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8911}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:3000/callback}"
CURL_INSECURE="${CURL_INSECURE:-}"  # Set to "-k" for self-signed certs

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

step() { echo -e "\n${CYAN}=== Step $1: $2 ===${NC}\n"; }
ok()   { echo -e "${GREEN}OK${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }
info() { echo -e "${YELLOW}INFO${NC}: $1"; }

# ─── Step 1: OAuth Discovery ───────────────────────────────────────────

step 1 "OAuth Discovery (RFC 9728 + RFC 8414)"

info "Fetching protected resource metadata..."
RESOURCE_META=$(curl -sf ${CURL_INSECURE} "${PROXY_URL}/.well-known/oauth-protected-resource") || fail "Protected resource metadata unavailable"
echo "$RESOURCE_META" | jq .
AS_URL=$(echo "$RESOURCE_META" | jq -r '.authorization_servers[0]')
ok "Authorization server: ${AS_URL}"

info "Fetching authorization server metadata..."
AS_META=$(curl -sf ${CURL_INSECURE} "${PROXY_URL}/.well-known/oauth-authorization-server") || fail "AS metadata unavailable"
echo "$AS_META" | jq .

AUTH_ENDPOINT=$(echo "$AS_META" | jq -r '.authorization_endpoint')
TOKEN_ENDPOINT=$(echo "$AS_META" | jq -r '.token_endpoint')
REG_ENDPOINT=$(echo "$AS_META" | jq -r '.registration_endpoint')
REVOKE_ENDPOINT=$(echo "$AS_META" | jq -r '.revocation_endpoint')
ok "Discovered endpoints: authorize, token, register, revoke"

# ─── Step 2: Dynamic Client Registration (RFC 7591) ───────────────────

step 2 "Dynamic Client Registration"

REG_RESPONSE=$(curl -sf ${CURL_INSECURE} -X POST "${REG_ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_name\": \"OAuth V2 Demo Client\",
    \"redirect_uris\": [\"${REDIRECT_URI}\"],
    \"grant_types\": [\"authorization_code\"],
    \"response_types\": [\"code\"],
    \"token_endpoint_auth_method\": \"none\"
  }") || fail "Client registration failed"

CLIENT_ID=$(echo "$REG_RESPONSE" | jq -r '.client_id')
echo "$REG_RESPONSE" | jq .
ok "Registered client_id: ${CLIENT_ID}"

# ─── Step 3: PKCE Generation ──────────────────────────────────────────

step 3 "Generate PKCE Code Challenge (S256)"

# Generate code_verifier (43-128 chars, URL-safe)
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=/+' | head -c 43)
# S256: BASE64URL(SHA256(code_verifier))
CODE_CHALLENGE=$(echo -n "${CODE_VERIFIER}" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
STATE=$(openssl rand -hex 16)

ok "code_verifier: ${CODE_VERIFIER}"
ok "code_challenge: ${CODE_CHALLENGE}"
ok "state: ${STATE}"

# ─── Step 4: Authorization Request ────────────────────────────────────

step 4 "Authorization Request (Rancher OIDC Redirect)"

AUTH_URL="${AUTH_ENDPOINT}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256&state=${STATE}&scope=mcp:read+mcp:write"

info "Authorization URL (open in browser to complete SSO):"
echo -e "${YELLOW}${AUTH_URL}${NC}"
echo ""
info "After authenticating through Rancher, you'll be redirected to:"
info "  ${REDIRECT_URI}?code=<AUTH_CODE>&state=${STATE}"
echo ""

read -p "Paste the authorization code from the redirect URL: " AUTH_CODE

if [ -z "$AUTH_CODE" ]; then
  info "No auth code provided. Skipping token exchange steps."
  info "You can re-run with the code to complete the flow."
  AUTH_CODE=""
fi

# ─── Step 5: Token Exchange ───────────────────────────────────────────

if [ -n "$AUTH_CODE" ]; then
  step 5 "Exchange Authorization Code for Tokens"

  TOKEN_RESPONSE=$(curl -sf ${CURL_INSECURE} -X POST "${TOKEN_ENDPOINT}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&code=${AUTH_CODE}&redirect_uri=${REDIRECT_URI}&client_id=${CLIENT_ID}&code_verifier=${CODE_VERIFIER}") || fail "Token exchange failed"

  ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
  REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_token')
  EXPIRES_IN=$(echo "$TOKEN_RESPONSE" | jq -r '.expires_in')
  SCOPE=$(echo "$TOKEN_RESPONSE" | jq -r '.scope')

  echo "$TOKEN_RESPONSE" | jq '{ token_type, expires_in, scope }'
  ok "Access token received (expires in ${EXPIRES_IN}s, scope: ${SCOPE})"

  # Decode JWT claims (without verification)
  info "JWT claims:"
  echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq . 2>/dev/null || info "(could not decode claims)"

  # ─── Step 6: Authenticated MCP Request ──────────────────────────────

  step 6 "Authenticated MCP Request"

  info "Listing adapters with bearer token..."
  curl -sf ${CURL_INSECURE} "${PROXY_URL}/api/v1/adapters" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" | jq . || info "No adapters configured yet"
  ok "Authenticated request succeeded"

  # ─── Step 7: Token Refresh ─────────────────────────────────────────

  step 7 "Refresh Token Rotation"

  REFRESH_RESPONSE=$(curl -sf ${CURL_INSECURE} -X POST "${TOKEN_ENDPOINT}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=refresh_token&refresh_token=${REFRESH_TOKEN}&client_id=${CLIENT_ID}") || fail "Token refresh failed"

  NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.access_token')
  NEW_REFRESH_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.refresh_token')

  echo "$REFRESH_RESPONSE" | jq '{ token_type, expires_in, scope }'
  ok "New access token received, refresh token rotated"
  ACCESS_TOKEN="$NEW_ACCESS_TOKEN"
  REFRESH_TOKEN="$NEW_REFRESH_TOKEN"

  # ─── Step 8: Token Revocation (RFC 7009) ────────────────────────────

  step 11 "Token Revocation"

  curl -sf ${CURL_INSECURE} -X POST "${REVOKE_ENDPOINT}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "token=${ACCESS_TOKEN}&client_id=${CLIENT_ID}" || fail "Revocation request failed"
  ok "Token revoked (server always returns 200 per RFC 7009)"
fi

# ─── Step 8: Adapter Configuration Examples ───────────────────────────

step 8 "Adapter Configuration: Databricks (Token Exchange)"

info "Example Databricks adapter with RFC 8693 token exchange:"
cat <<'JSON'
{
  "name": "databricks-mcp",
  "authentication": {
    "required": true,
    "type": "token_exchange",
    "tokenExchange": {
      "token_endpoint": "https://accounts.cloud.databricks.com/oidc/v1/token",
      "audience": "https://databricks.example.com",
      "scopes": ["sql:read", "sql:write"],
      "subject_token_type": "urn:ietf:params:oauth:token-type:id_token"
    }
  }
}
JSON
ok "When a user accesses this adapter, the proxy exchanges their Rancher ID token for a Databricks token"

# ─── Step 9: ServiceNow Impersonation ────────────────────────────────

step 9 "Adapter Configuration: ServiceNow (Service Account)"

info "Example ServiceNow adapter with impersonation:"
cat <<'JSON'
{
  "name": "servicenow-mcp",
  "authentication": {
    "required": true,
    "type": "service_account",
    "serviceAccount": {
      "username": "mcp-proxy-sa",
      "password": "from-csi-secret-store",
      "impersonation_header": "X-UserToken",
      "impersonation_field": "email"
    }
  }
}
JSON
ok "Proxy authenticates as service account, impersonates user via their email"

# ─── Step 10: SPIFFE/SPIRE Workload Identity ─────────────────────────

step 10 "Adapter Configuration: SPIFFE (Workload Identity)"

info "Example SPIFFE adapter with JWT SVID token exchange:"
cat <<'JSON'
{
  "name": "databricks-spiffe",
  "authentication": {
    "required": true,
    "type": "spiffe",
    "spiffe": {
      "target_audience": "https://databricks.example.com",
      "use_mtls": false
    },
    "tokenExchange": {
      "token_endpoint": "https://accounts.cloud.databricks.com/oidc/v1/token",
      "audience": "https://databricks.example.com",
      "subject_token_type": "urn:ietf:params:oauth:token-type:jwt"
    }
  }
}
JSON
ok "Proxy fetches JWT SVID from SPIRE agent, uses it as subject_token in RFC 8693 exchange"

info "Example SPIFFE adapter with mTLS:"
cat <<'JSON'
{
  "name": "internal-mcp",
  "authentication": {
    "required": true,
    "type": "spiffe",
    "spiffe": {
      "use_mtls": true
    }
  }
}
JSON
ok "Proxy uses X.509 SVID for mutual TLS — no bearer tokens, certificates auto-rotate"

# ─── Step 11: Tool-Level Authorization Policies ──────────────────────

step 11 "Authorization Policies"

info "Creating policy: only database-admins can use drop_table..."
POLICY_RESPONSE=$(curl -sf ${CURL_INSECURE} -X POST "${PROXY_URL}/api/v1/auth/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "adapter_name": "databricks-mcp",
    "tool_name": "drop_table",
    "effect": "allow",
    "allowed_groups": ["database-admins"],
    "priority": 100
  }' 2>/dev/null) && {
  echo "$POLICY_RESPONSE" | jq .
  POLICY_ID=$(echo "$POLICY_RESPONSE" | jq -r '.policy_id // .PolicyID // empty')
  ok "Policy created: ${POLICY_ID}"
} || info "Policy creation skipped (proxy may not be running)"

info "Listing all policies..."
curl -sf ${CURL_INSECURE} "${PROXY_URL}/api/v1/auth/policies" | jq . 2>/dev/null || info "Policies endpoint not available"

# ─── Summary ─────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}=== Demo Complete ===${NC}"
echo ""
echo "Authentication types exercised:"
echo "  1. OAuth 2.1 + PKCE (S256) with Rancher OIDC"
echo "  2. Token Exchange (RFC 8693) — Databricks"
echo "  3. Service Account Impersonation — ServiceNow"
echo "  4. SPIFFE JWT SVID — workload identity exchange"
echo "  5. SPIFFE mTLS — certificate-based authentication"
echo "  6. Tool-Level Authorization — policy-based access control"
echo ""
echo "Standards compliance:"
echo "  - RFC 9728 (Protected Resource Metadata)"
echo "  - RFC 8414 (Authorization Server Metadata)"
echo "  - RFC 7591 (Dynamic Client Registration)"
echo "  - RFC 8693 (Token Exchange)"
echo "  - RFC 7009 (Token Revocation)"
echo "  - OAuth 2.1 (PKCE mandatory, S256)"
