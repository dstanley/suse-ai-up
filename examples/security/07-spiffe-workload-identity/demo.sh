#!/usr/bin/env bash
# 07 — SPIFFE/SPIRE Workload Identity Demo
# Demonstrates JWT SVID token exchange, mTLS modes, and live cluster verification.
# Run setup.sh first to install SPIRE.
set -euo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8911}"
CURL_INSECURE="${CURL_INSECURE:--k}"
SPIRE_NAMESPACE="${SPIRE_NAMESPACE:-spire-system}"
SPIRE_SERVER_POD="${SPIRE_SERVER_POD:-spire-server-0}"
MOCK_SERVER_URL="${MOCK_SERVER_URL:-http://localhost:8002}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

step() { echo -e "\n${CYAN}=== Step $1: $2 ===${NC}\n"; }
ok()   { echo -e "${GREEN}OK${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }
info() { echo -e "${YELLOW}INFO${NC}: $1"; }

echo -e "${CYAN}SPIFFE/SPIRE Workload Identity${NC}"
echo "Proxy: ${PROXY_URL}"
echo ""

info "Run setup.sh first if SPIRE is not yet installed."
echo ""

# ─── Step 1: SPIFFE Overview ─────────────────────────────────────────

step 1 "What is SPIFFE/SPIRE?"

cat <<'OVERVIEW'
SPIFFE (Secure Production Identity Framework for Everyone) provides
cryptographic workload identity without secrets management.

SPIRE (SPIFFE Runtime Environment) is the reference implementation:

  SPIRE Server
    |-- Issues identity documents (SVIDs) to workloads
    |-- Manages trust bundles and attestation policies
    |
  SPIRE Agent (runs on each node)
    |-- Attests workloads via kernel metadata, k8s API, etc.
    |-- Serves SVIDs via the Workload API (Unix domain socket)
    |
  Workload (SUSE AI Universal Proxy)
    |-- Calls SPIRE Agent to get SVIDs
    |-- Uses SVIDs for authentication to downstream services
OVERVIEW

ok "Identity without static secrets"

# ─── Step 2: JWT SVID Mode ──────────────────────────────────────────

step 2 "Mode 1: JWT SVID Token Exchange"

info "In JWT SVID mode, the proxy fetches a JWT from the SPIRE agent"
info "and uses it as the subject_token in an RFC 8693 token exchange."
info "This replaces the upstream ID token for workload-to-workload flows."
echo ""

info "Example adapter configuration:"
echo ""
cat <<'JSON'
{
  "name": "databricks_spiffe",
  "remoteUrl": "http://databricks-mcp:8001/mcp",
  "connectionType": "remote-http",
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
      "scopes": ["sql:read"],
      "subject_token_type": "urn:ietf:params:oauth:token-type:jwt"
    }
  }
}
JSON

echo ""

cat <<'FLOW'
Flow:
  1. User calls databricks_spiffe__execute_sql via the unified endpoint
  2. Proxy validates the user's OAuth token (same as always)
  3. Instead of using the user's upstream ID token, the proxy calls:
     SPIRE Agent -> FetchJWTSVID(audience="https://databricks.example.com")
  4. SPIRE returns a JWT SVID signed by the SPIRE server
  5. Proxy exchanges the JWT SVID at Databricks' token endpoint:
     POST https://accounts.cloud.databricks.com/oidc/v1/token
     grant_type=urn:ietf:params:oauth:token-type:token-exchange
     subject_token=<jwt-svid>
     subject_token_type=urn:ietf:params:oauth:token-type:jwt
  6. Databricks trusts the SPIRE CA and issues a Databricks token
  7. Proxy forwards the request with the Databricks token

Why use this over upstream ID token exchange?
  - Workload identity is independent of user session
  - Trust is based on workload attestation, not user credentials
  - Works for service-to-service flows without a user context
  - SPIRE handles credential rotation automatically
FLOW

ok "JWT SVID replaces the upstream ID token as the subject_token"

# ─── Step 3: mTLS Mode ──────────────────────────────────────────────

step 3 "Mode 2: X.509 SVID mTLS"

info "In mTLS mode, the proxy uses X.509 SVIDs for mutual TLS."
info "No bearer tokens needed — identity is at the transport layer."
echo ""

info "Example adapter configuration:"
echo ""
cat <<'JSON'
{
  "name": "internal_service",
  "remoteUrl": "https://internal-mcp.mesh.local/mcp",
  "connectionType": "remote-http",
  "authentication": {
    "required": true,
    "type": "spiffe",
    "spiffe": {
      "use_mtls": true
    }
  }
}
JSON

echo ""

cat <<'FLOW'
Flow:
  1. Proxy calls SPIRE Agent -> GetX509SVID()
  2. SPIRE returns:
     - X.509 certificate (with SPIFFE ID as SAN)
     - Private key
     - Trust bundle (CA certificates)
  3. Proxy creates a TLS client with the X.509 SVID
  4. Proxy connects to the downstream service via mTLS:
     - Client presents its SVID certificate
     - Server presents its SVID certificate
     - Both verify against the shared trust bundle
  5. No Authorization header needed — identity is the certificate

Advantages of mTLS:
  - Zero bearer tokens in transit — nothing to intercept or replay
  - Mutual authentication — both sides prove identity
  - Automatic rotation — SPIRE agent handles certificate renewal
  - Transport-layer security — cannot be bypassed by application code
  - Works with any protocol (HTTP, gRPC, TCP)
FLOW

ok "Certificate-based identity — no tokens to manage or leak"

# ─── Step 4: SPIRE Agent Workload API ─────────────────────────────

step 4 "SPIRE Agent Workload API"

info "The proxy communicates with the SPIRE agent via a Unix domain socket."
info "Default path: /run/spire/sockets/agent.sock"
echo ""

cat <<'API'
Proxy <-> SPIRE Agent communication:

  FetchJWTSVID(audience)
    Request:  audience = "https://databricks.example.com"
    Response: JWT signed by SPIRE server CA
              SPIFFE ID: spiffe://trust-domain/proxy

  GetX509SVID()
    Response: X.509 certificate + private key
              SAN: spiffe://trust-domain/proxy
              Trust bundle: SPIRE CA certificates
              Auto-rotated before expiry

  GetSVIDInfo()
    Response: Current SPIFFE ID, trust domain, certificate details
              Used for diagnostics and health checks
API

echo ""

# ─── Step 5: Live Cluster Verification ─────────────────────────────

step 5 "Live Cluster Verification"

if ! command -v kubectl &>/dev/null; then
  info "kubectl not found — skipping live verification"
else
  info "Checking SPIRE pods in ${SPIRE_NAMESPACE}..."
  echo ""
  PODS=$(kubectl -n "${SPIRE_NAMESPACE}" get pods --no-headers 2>/dev/null) || true
  if [ -z "$PODS" ]; then
    info "No SPIRE pods found in namespace ${SPIRE_NAMESPACE}"
    info "Run setup.sh first to install SPIRE"
  else
    echo "$PODS"
    echo ""
    ok "SPIRE pods found"

    # Check SPIRE server health
    info "Checking SPIRE server health..."
    HEALTH=$(kubectl -n "${SPIRE_NAMESPACE}" exec "${SPIRE_SERVER_POD}" -c spire-server -- \
      /opt/spire/bin/spire-server healthcheck 2>/dev/null) || true
    if echo "$HEALTH" | grep -qi "healthy"; then
      ok "SPIRE server is healthy"
    else
      info "SPIRE server health: ${HEALTH:-unknown}"
    fi

    # Count registered entries
    info "Querying registered workload entries..."
    ENTRY_COUNT=$(kubectl -n "${SPIRE_NAMESPACE}" exec "${SPIRE_SERVER_POD}" -c spire-server -- \
      /opt/spire/bin/spire-server entry count 2>/dev/null) || true
    if [ -n "$ENTRY_COUNT" ]; then
      echo "  $ENTRY_COUNT"
      ok "Workload entries registered"
    fi

    # List agents
    info "Listing SPIRE agents..."
    AGENTS=$(kubectl -n "${SPIRE_NAMESPACE}" exec "${SPIRE_SERVER_POD}" -c spire-server -- \
      /opt/spire/bin/spire-server agent list 2>/dev/null) || true
    if [ -n "$AGENTS" ]; then
      echo "$AGENTS" | head -10
      ok "SPIRE agents connected"
    else
      info "No agents found"
    fi

    # Check if proxy workload is registered
    info "Checking for proxy workload registration..."
    PROXY_ENTRY=$(kubectl -n "${SPIRE_NAMESPACE}" exec "${SPIRE_SERVER_POD}" -c spire-server -- \
      /opt/spire/bin/spire-server entry show -selector k8s:namespace:suse-ai-up 2>/dev/null) || true
    if echo "$PROXY_ENTRY" | grep -q "Found 0 entries"; then
      info "Proxy workload not yet registered. Run setup.sh to register."
    elif echo "$PROXY_ENTRY" | grep -q "Entry ID"; then
      echo "$PROXY_ENTRY" | head -10
      ok "Proxy workload is registered with SPIRE"
    else
      info "Could not check proxy registration: ${PROXY_ENTRY:-no response}"
    fi

    # Check Tornjak backend if available
    TORNJAK_SVC=$(kubectl -n "${SPIRE_NAMESPACE}" get svc spire-tornjak-backend --no-headers 2>/dev/null) || true
    if [ -n "$TORNJAK_SVC" ]; then
      echo ""
      info "Tornjak backend service detected"
      TORNJAK_API=$(kubectl -n "${SPIRE_NAMESPACE}" exec "${SPIRE_SERVER_POD}" -c tornjak -- \
        wget -q -O - http://localhost:10000/api/tornjak/serverinfo 2>/dev/null) || true
      if [ -n "$TORNJAK_API" ]; then
        echo "$TORNJAK_API" | jq . 2>/dev/null || echo "$TORNJAK_API"
        ok "Tornjak API is responding"
      else
        info "Tornjak API not reachable (may still be starting)"
      fi
    fi
  fi
fi

# ─── Step 6: Mint and Inspect a JWT SVID ───────────────────────────

step 6 "Mint a JWT SVID"

if ! command -v kubectl &>/dev/null; then
  info "kubectl not found — skipping"
else
  PODS=$(kubectl -n "${SPIRE_NAMESPACE}" get pods --no-headers 2>/dev/null) || true
  if [ -z "$PODS" ]; then
    info "SPIRE not running — skipping"
  else
    TEST_AUDIENCE="https://databricks.example.com"
    SPIFFE_ID="spiffe://$(kubectl -n "${SPIRE_NAMESPACE}" exec "${SPIRE_SERVER_POD}" -c spire-server -- \
      /opt/spire/bin/spire-server entry show -selector k8s:namespace:suse-ai-up 2>/dev/null \
      | grep "SPIFFE ID" | head -1 | awk '{print $NF}' | sed 's|spiffe://||')"

    if [ "$SPIFFE_ID" = "spiffe://" ]; then
      SPIFFE_ID="spiffe://marv.suse-ai.com/suse-ai-up"
      info "Using default SPIFFE ID: ${SPIFFE_ID}"
    fi

    info "Minting a JWT SVID for audience: ${TEST_AUDIENCE}"
    info "SPIFFE ID: ${SPIFFE_ID}"
    echo ""

    JWT_SVID=$(kubectl -n "${SPIRE_NAMESPACE}" exec "${SPIRE_SERVER_POD}" -c spire-server -- \
      /opt/spire/bin/spire-server jwt mint \
      -spiffeID "${SPIFFE_ID}" \
      -audience "${TEST_AUDIENCE}" 2>/dev/null) || true

    if [ -n "$JWT_SVID" ]; then
      # Show truncated token
      TOKEN_LEN=${#JWT_SVID}
      echo "  JWT SVID (${TOKEN_LEN} chars): ${JWT_SVID:0:80}..."
      echo ""

      # Decode and display claims
      PAYLOAD=$(echo "$JWT_SVID" | cut -d. -f2 | tr '_-' '/+' | \
        awk '{while(length($0)%4)$0=$0"=";print}' | base64 -D 2>/dev/null || \
        echo "$JWT_SVID" | cut -d. -f2 | tr '_-' '/+' | \
        awk '{while(length($0)%4)$0=$0"=";print}' | base64 -d 2>/dev/null) || true

      if [ -n "$PAYLOAD" ]; then
        info "Decoded JWT SVID claims:"
        echo "$PAYLOAD" | jq . 2>/dev/null || echo "  $PAYLOAD"
        echo ""

        ISS=$(echo "$PAYLOAD" | jq -r '.iss // empty' 2>/dev/null)
        SUB=$(echo "$PAYLOAD" | jq -r '.sub // empty' 2>/dev/null)
        AUD=$(echo "$PAYLOAD" | jq -r '.aud[0] // empty' 2>/dev/null)
        EXP=$(echo "$PAYLOAD" | jq -r '.exp // empty' 2>/dev/null)

        ok "Issuer:   ${ISS}"
        ok "Subject:  ${SUB}"
        ok "Audience: ${AUD}"
        if [ -n "$EXP" ]; then
          EXPIRY=$(date -r "$EXP" 2>/dev/null || date -d "@$EXP" 2>/dev/null || echo "$EXP")
          ok "Expires:  ${EXPIRY}"
        fi
      fi

      ok "JWT SVID minted successfully"
    else
      info "Could not mint JWT SVID. Is the proxy workload registered?"
      info "Run setup.sh to register it."
    fi
  fi
fi

# ─── Step 7: Token Exchange with Mock Server ─────────────────────

step 7 "RFC 8693 Token Exchange"

# Check if mock server is running
MOCK_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "${MOCK_SERVER_URL}/health" 2>/dev/null) || true

if [ "$MOCK_HEALTH" != "200" ]; then
  info "Mock server not running at ${MOCK_SERVER_URL}"
  info "Start it with: docker compose up -d (from this directory)"
  info "Or:            python3 mock-server/server.py &"
  echo ""
  info "Skipping live token exchange — showing what would happen:"
  echo ""
  echo "  1. POST ${MOCK_SERVER_URL}/token"
  echo "     grant_type=urn:ietf:params:oauth:token-type:token-exchange"
  echo "     subject_token=<jwt-svid>"
  echo "     subject_token_type=urn:ietf:params:oauth:token-type:jwt"
  echo "     audience=https://databricks.example.com"
  echo ""
  echo "  2. Receive bearer token from token exchange"
  echo ""
  echo "  3. POST ${MOCK_SERVER_URL}/mcp"
  echo "     Authorization: Bearer <exchanged-token>"
  echo "     {\"jsonrpc\": \"2.0\", \"method\": \"tools/call\", ...}"
  echo ""
  info "Set MOCK_SERVER_URL to override (default: http://localhost:8002)"
else
  ok "Mock server is running at ${MOCK_SERVER_URL}"
  echo ""

  # Use the minted JWT SVID if available, otherwise create a synthetic one
  if [ -z "${JWT_SVID:-}" ]; then
    info "No live JWT SVID available — creating a synthetic one for demo"
    # Create a minimal JWT with SPIFFE claims (header.payload.signature)
    JWT_HEADER=$(echo -n '{"alg":"RS256","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')
    JWT_CLAIMS=$(echo -n "{\"sub\":\"spiffe://marv.suse-ai.com/suse-ai-up\",\"aud\":[\"https://databricks.example.com\"],\"iss\":\"spire-server\",\"exp\":$(($(date +%s) + 3600))}" | base64 | tr -d '=' | tr '/+' '_-')
    JWT_SVID="${JWT_HEADER}.${JWT_CLAIMS}.mock-signature"
    info "Synthetic SPIFFE ID: spiffe://marv.suse-ai.com/suse-ai-up"
  fi

  # ── Step 7a: Exchange JWT SVID for bearer token ──
  info "Exchanging JWT SVID at mock token endpoint..."
  echo ""
  echo "  POST ${MOCK_SERVER_URL}/token"
  echo "  grant_type=urn:ietf:params:oauth:token-type:token-exchange"
  echo "  subject_token=<jwt-svid> (${#JWT_SVID} chars)"
  echo "  subject_token_type=urn:ietf:params:oauth:token-type:jwt"
  echo ""

  TOKEN_RESPONSE=$(curl -s -X POST "${MOCK_SERVER_URL}/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=urn:ietf:params:oauth:token-type:token-exchange&subject_token=${JWT_SVID}&subject_token_type=urn:ietf:params:oauth:token-type:jwt&audience=https://databricks.example.com&scope=sql:read" 2>&1) || true

  if echo "$TOKEN_RESPONSE" | jq -e '.access_token' &>/dev/null; then
    BEARER_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
    TOKEN_TYPE=$(echo "$TOKEN_RESPONSE" | jq -r '.token_type')
    EXPIRES_IN=$(echo "$TOKEN_RESPONSE" | jq -r '.expires_in')
    ISSUED_TYPE=$(echo "$TOKEN_RESPONSE" | jq -r '.issued_token_type')

    info "Token exchange response:"
    echo "$TOKEN_RESPONSE" | jq .
    echo ""
    ok "Received ${TOKEN_TYPE} token (expires in ${EXPIRES_IN}s)"
    ok "Issued token type: ${ISSUED_TYPE}"
  else
    echo -e "${RED}FAIL${NC}: Token exchange failed: ${TOKEN_RESPONSE:-no response}" >&2
    BEARER_TOKEN=""
  fi
fi

# ─── Step 8: Call Mock MCP Server ────────────────────────────────

step 8 "MCP Tool Call with Exchanged Token"

if [ -z "${BEARER_TOKEN:-}" ]; then
  info "No bearer token available — skipping MCP call"
  info "Run with mock server to see the full flow"
else
  # ── 8a: List available tools ──
  info "Listing available MCP tools..."
  echo ""

  TOOLS_RESPONSE=$(curl -s -X POST "${MOCK_SERVER_URL}/mcp" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${BEARER_TOKEN}" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' 2>&1) || true

  if echo "$TOOLS_RESPONSE" | jq -e '.result.tools' &>/dev/null; then
    TOOL_COUNT=$(echo "$TOOLS_RESPONSE" | jq '.result.tools | length')
    echo "$TOOLS_RESPONSE" | jq '.result.tools[] | {name, description}'
    echo ""
    ok "${TOOL_COUNT} tools available via SPIFFE-authenticated connection"
  fi

  # ── 8b: Execute a SQL query ──
  echo ""
  info "Calling execute_sql tool via MCP..."
  echo ""

  SQL_RESPONSE=$(curl -s -X POST "${MOCK_SERVER_URL}/mcp" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${BEARER_TOKEN}" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_sql","arguments":{"query":"SELECT * FROM sensor_data LIMIT 3"}}}' 2>&1) || true

  if echo "$SQL_RESPONSE" | jq -e '.result.content[0].text' &>/dev/null; then
    RESULT_TEXT=$(echo "$SQL_RESPONSE" | jq -r '.result.content[0].text')
    echo "$RESULT_TEXT" | jq .
    echo ""

    AUTH_VIA=$(echo "$RESULT_TEXT" | jq -r '.authenticated_via // empty')
    WORKLOAD_ID=$(echo "$RESULT_TEXT" | jq -r '.workload_identity // empty')
    ok "Query executed successfully"
    ok "Authenticated via: ${AUTH_VIA}"
    ok "Workload identity: ${WORKLOAD_ID}"
  else
    echo -e "${RED}FAIL${NC}: MCP call failed: ${SQL_RESPONSE:-no response}" >&2
  fi

  # ── 8c: Get workspace info ──
  echo ""
  info "Calling get_workspace_info tool..."
  echo ""

  WS_RESPONSE=$(curl -s -X POST "${MOCK_SERVER_URL}/mcp" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${BEARER_TOKEN}" \
    -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_workspace_info","arguments":{}}}' 2>&1) || true

  if echo "$WS_RESPONSE" | jq -e '.result.content[0].text' &>/dev/null; then
    echo "$WS_RESPONSE" | jq -r '.result.content[0].text' | jq .
    echo ""
    ok "Workspace info retrieved with workload identity"
  fi
fi

# ─── Step 9: Auth Strategy Comparison ─────────────────────────────

step 9 "Auth Strategy Comparison"

cat <<'TABLE'
+-------------------+------------------+------------------+------------------+
| Feature           | Token Exchange   | Service Account  | SPIFFE           |
+-------------------+------------------+------------------+------------------+
| Identity basis    | User's IdP token | Shared SA creds  | Workload cert/JWT|
| Per-user tokens   | Yes              | No (impersonate) | No (workload)    |
| Credential source | Upstream OIDC    | CSI Secret Store | SPIRE Agent      |
| Rotation          | Token expiry     | Manual           | Automatic        |
| Trust model       | IdP federation   | Shared secret    | PKI/attestation  |
| Use case          | Cross-IdP access | Legacy systems   | Zero-trust mesh  |
| Example           | Databricks       | ServiceNow       | Internal services|
+-------------------+------------------+------------------+------------------+
TABLE

ok "Choose based on downstream service capabilities and trust requirements"

# ─── Summary ─────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}=== SPIFFE Demo Complete ===${NC}"
echo ""
echo "What we demonstrated:"
echo "  1. JWT SVID mode — workload identity for token exchange"
echo "  2. mTLS mode — certificate-based transport authentication"
echo "  3. SPIRE Agent Workload API interaction"
echo "  4. Live cluster verification (pods, health, entries, agents)"
echo "  5. JWT SVID minting from SPIRE server"
echo "  6. RFC 8693 token exchange (JWT SVID -> bearer token)"
echo "  7. MCP tool calls authenticated via exchanged workload token"
echo "  8. Comparison of all three auth strategies"
echo ""
echo "End-to-end flow:"
echo "  SPIRE Agent -> JWT SVID -> Token Exchange -> Bearer Token -> MCP Server"
echo ""
echo "SPIFFE is best suited for:"
echo "  - Zero-trust service mesh environments"
echo "  - Internal service-to-service authentication"
echo "  - Environments where static secrets should be eliminated"
echo "  - Workload-to-workload flows without user context"
