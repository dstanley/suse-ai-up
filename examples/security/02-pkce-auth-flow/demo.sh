#!/usr/bin/env bash
# 02 — Full PKCE Authorization Code Flow
# Demonstrates OAuth 2.1 PKCE (S256) with upstream OIDC provider
set -euo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8911}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:3000/callback}"
CURL_INSECURE="${CURL_INSECURE:--k}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

step() { echo -e "\n${CYAN}=== Step $1: $2 ===${NC}\n"; }
ok()   { echo -e "${GREEN}OK${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }
info() { echo -e "${YELLOW}INFO${NC}: $1"; }

echo -e "${CYAN}OAuth 2.1 PKCE Authorization Code Flow${NC}"
echo "Proxy: ${PROXY_URL}"
echo ""

# ─── Step 1: Discover endpoints ──────────────────────────────────────

step 1 "Discover OAuth Endpoints"

AS_META=$(curl ${CURL_INSECURE} -sf "${PROXY_URL}/.well-known/oauth-authorization-server") \
  || fail "AS metadata unavailable"

AUTH_ENDPOINT=$(echo "$AS_META" | jq -r '.authorization_endpoint')
TOKEN_ENDPOINT=$(echo "$AS_META" | jq -r '.token_endpoint')
REG_ENDPOINT=$(echo "$AS_META" | jq -r '.registration_endpoint')
REVOKE_ENDPOINT=$(echo "$AS_META" | jq -r '.revocation_endpoint')

ok "Endpoints discovered"
info "  Authorization: ${AUTH_ENDPOINT}"
info "  Token:         ${TOKEN_ENDPOINT}"
info "  Registration:  ${REG_ENDPOINT}"
info "  Revocation:    ${REVOKE_ENDPOINT}"

# ─── Step 2: Register client ─────────────────────────────────────────

step 2 "Dynamic Client Registration"

REG_BODY="{
  \"client_name\": \"PKCE Demo Client\",
  \"redirect_uris\": [\"${REDIRECT_URI}\"],
  \"grant_types\": [\"authorization_code\"],
  \"response_types\": [\"code\"],
  \"token_endpoint_auth_method\": \"none\"
}"

info "Request: POST ${REG_ENDPOINT}"
echo "$REG_BODY" | jq .
echo ""

REG_RESPONSE=$(curl ${CURL_INSECURE} -sf -X POST "${REG_ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d "$REG_BODY") || fail "Client registration failed"

info "Response:"
echo "$REG_RESPONSE" | jq .
echo ""

CLIENT_ID=$(echo "$REG_RESPONSE" | jq -r '.client_id')
ok "Registered client_id: ${CLIENT_ID}"

# ─── Step 3: Generate PKCE pair ──────────────────────────────────────

step 3 "Generate PKCE Code Challenge (S256)"

info "The client generates a random code_verifier and computes"
info "code_challenge = BASE64URL(SHA256(code_verifier))."
info "The verifier is a secret that never leaves the client until token exchange."
echo ""

# code_verifier: 43-128 char URL-safe random string
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=/+' | head -c 43)
# S256: BASE64URL(SHA256(code_verifier))
CODE_CHALLENGE=$(echo -n "${CODE_VERIFIER}" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
STATE=$(openssl rand -hex 16)

ok "code_verifier:  ${CODE_VERIFIER}"
ok "code_challenge: ${CODE_CHALLENGE}"
ok "state:          ${STATE}"

# ─── Step 4: Build authorization URL ─────────────────────────────────

step 4 "Authorization Request (OIDC Redirect)"

AUTH_URL="${AUTH_ENDPOINT}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256&state=${STATE}&scope=mcp:read+mcp:write"

info "The client opens this URL in a browser. The proxy stores the PKCE"
info "challenge in an encrypted session cookie, then redirects to the identity provider."
echo ""
echo -e "${YELLOW}${AUTH_URL}${NC}"
echo ""
info "After authenticating through the identity provider, the user is redirected to:"
info "  ${REDIRECT_URI}?code=<AUTH_CODE>&state=${STATE}"
echo ""

read -p "Paste the authorization code from the redirect URL (or Enter to skip): " AUTH_CODE

if [ -z "$AUTH_CODE" ]; then
  info "No auth code provided. Skipping token exchange."
  info "Re-run with the code to complete the flow."
  echo ""
  echo -e "${GREEN}=== PKCE Setup Complete ===${NC}"
  echo ""
  echo "What we demonstrated:"
  echo "  1. Endpoint discovery (RFC 8414)"
  echo "  2. Dynamic client registration (RFC 7591)"
  echo "  3. PKCE generation (S256 — one-way hash protects the verifier)"
  echo "  4. Authorization URL construction"
  echo ""
  echo "To complete the flow, authenticate with your identity provider and paste the code."
  exit 0
fi

# ─── Step 5: Exchange code for tokens ─────────────────────────────────

step 5 "Token Exchange (PKCE Verification)"

info "The client sends code + code_verifier to the token endpoint."
info "The proxy computes SHA256(verifier) and compares to the stored challenge."
info "If they match, the auth code is legitimate."
echo ""

TOKEN_RESPONSE=$(curl ${CURL_INSECURE} -sf -X POST "${TOKEN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=${AUTH_CODE}&redirect_uri=${REDIRECT_URI}&client_id=${CLIENT_ID}&code_verifier=${CODE_VERIFIER}") \
  || fail "Token exchange failed"

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_token')
EXPIRES_IN=$(echo "$TOKEN_RESPONSE" | jq -r '.expires_in')
SCOPE=$(echo "$TOKEN_RESPONSE" | jq -r '.scope')

echo "$TOKEN_RESPONSE" | jq '{ token_type, expires_in, scope }'
ok "Access token received (expires in ${EXPIRES_IN}s, scope: ${SCOPE})"

# Decode JWT claims (without verification)
info "JWT claims from proxy-issued token:"
# JWT payload is base64url-encoded; pad and decode (compatible with macOS and Linux)
JWT_PAYLOAD=$(echo "$ACCESS_TOKEN" | cut -d. -f2 | tr '_-' '/+')
PADDING=$(( 4 - ${#JWT_PAYLOAD} % 4 ))
[ "$PADDING" -lt 4 ] && JWT_PAYLOAD="${JWT_PAYLOAD}$(printf '%0.s=' $(seq 1 $PADDING))"
echo "$JWT_PAYLOAD" | base64 -D 2>/dev/null | jq . 2>/dev/null \
  || echo "$JWT_PAYLOAD" | base64 -d 2>/dev/null | jq . 2>/dev/null \
  || info "(could not decode claims)"

# ─── Step 6: Authenticated request ────────────────────────────────────

step 6 "Authenticated MCP Request"

info "Using the bearer token to access a protected endpoint."
echo ""

ADAPTERS=$(curl ${CURL_INSECURE} -sf "${PROXY_URL}/api/v1/adapters" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}") || fail "Authenticated request failed (expected 200, got error)"
ADAPTER_COUNT=$(echo "$ADAPTERS" | jq 'length')
echo "$ADAPTERS" | jq .
if [ "$ADAPTER_COUNT" -eq 0 ]; then
  info "No adapters configured yet — empty array is expected for a fresh deployment."
else
  info "${ADAPTER_COUNT} adapter(s) found."
fi
ok "Authenticated request succeeded (bearer token accepted)"

# ─── Step 7: Token refresh ────────────────────────────────────────────

step 7 "Refresh Token Rotation"

info "Access tokens are short-lived. The client uses the refresh token"
info "to get a new access/refresh pair without re-authenticating."
echo ""

REFRESH_RESPONSE=$(curl ${CURL_INSECURE} -sf -X POST "${TOKEN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=${REFRESH_TOKEN}&client_id=${CLIENT_ID}") \
  || fail "Token refresh failed"

echo "$REFRESH_RESPONSE" | jq '{ token_type, expires_in, scope }'
ok "New tokens issued, refresh token rotated"

NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.access_token')
NEW_REFRESH_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.refresh_token')


# ─── Step 8: Token revocation ─────────────────────────────────────────

step 8 "Token Revocation (RFC 7009)"

info "Revoking the original access token (the refreshed token remains valid)."
info "Per RFC 7009, the server always returns 200."
echo ""

curl ${CURL_INSECURE} -sf -o /dev/null -X POST "${REVOKE_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=${ACCESS_TOKEN}&client_id=${CLIENT_ID}" || fail "Revocation failed"
ok "Original token revoked (AUTH_TOKEN still valid)"

# ─── Summary ─────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}=== PKCE Flow Complete ===${NC}"
echo ""
echo "What we demonstrated:"
echo "  1. OAuth 2.1 PKCE (S256) — code verifier/challenge pair"
echo "  2. OIDC — delegated authentication to upstream identity provider"
echo "  3. Proxy-issued JWTs with enterprise identity claims"
echo "  4. Token refresh with rotation"
echo "  5. Token revocation (RFC 7009)"
echo ""
echo "Key security properties:"
echo "  - PKCE prevents authorization code interception attacks"
echo "  - S256 ensures the challenge is a one-way hash of the verifier"
echo "  - The upstream IdP token never leaves the proxy — clients only see proxy JWTs"
echo "  - Refresh tokens are rotated on each use"
echo ""
echo "To run subsequent demos (03-07), copy and paste these exports:"
echo ""
echo "  export PROXY_URL=\"${PROXY_URL}\""
echo "  export AUTH_TOKEN=\"${NEW_ACCESS_TOKEN}\""
echo "  export REFRESH_TOKEN=\"${NEW_REFRESH_TOKEN}\""
echo "  export CLIENT_ID=\"${CLIENT_ID}\""
echo "  export TOKEN_ENDPOINT=\"${TOKEN_ENDPOINT}\""
echo "  export CURL_INSECURE=\"${CURL_INSECURE}\""
echo ""
echo "AUTH_TOKEN expires in ~60 minutes. To get a fresh one:"
echo "  export AUTH_TOKEN=\$(curl ${CURL_INSECURE} -sf -X POST \"\${TOKEN_ENDPOINT}\" \\"
echo "    -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "    -d \"grant_type=refresh_token&refresh_token=\${REFRESH_TOKEN}&client_id=\${CLIENT_ID}\" \\"
echo "    | jq -r '.access_token')"
