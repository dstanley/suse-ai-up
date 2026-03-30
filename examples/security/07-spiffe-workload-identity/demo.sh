#!/usr/bin/env bash
# 07 — SPIFFE/SPIRE Workload Identity Demo
# Demonstrates JWT SVID token exchange, mTLS modes, and live cluster verification.
# Run setup.sh first to install SPIRE.
set -euo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8911}"
CURL_INSECURE="${CURL_INSECURE:--k}"
SPIRE_NAMESPACE="${SPIRE_NAMESPACE:-spire-system}"
SPIRE_SERVER_POD="${SPIRE_SERVER_POD:-spire-server-0}"
PROXY_NAMESPACE="${PROXY_NAMESPACE:-suse-ai-up}"
MOCK_SERVER_URL="${MOCK_SERVER_URL:-http://localhost:8002}"
# In-cluster URL the proxy pod uses to reach the mock server
MOCK_SERVER_CLUSTER_URL="${MOCK_SERVER_CLUSTER_URL:-http://spiffe-mock-server.${PROXY_NAMESPACE}.svc.cluster.local:8002}"

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
echo ""

# Prompt for proxy URL if not set or unreachable
if [ "$PROXY_URL" = "http://localhost:8911" ]; then
  if ! curl -sk --max-time 3 "${PROXY_URL}/.well-known/oauth-protected-resource" &>/dev/null; then
    echo -e "${YELLOW}PROXY_URL is not set and localhost:8911 is not reachable.${NC}"
    read -rp "Enter the proxy URL (e.g. https://suse-ai-up.192.168.5.61.nip.io): " USER_URL
    if [ -n "$USER_URL" ]; then
      PROXY_URL="${USER_URL}"
    fi
  fi
fi

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

# ─── Step 7: Register SPIFFE Adapter ─────────────────────────────

step 7 "Register SPIFFE Adapter with Proxy"

# Check proxy connectivity
PROXY_HEALTH=$(curl ${CURL_INSECURE} -s -o /dev/null -w "%{http_code}" "${PROXY_URL}/health" 2>/dev/null) || true

if [ "$PROXY_HEALTH" = "000" ]; then
  echo -e "${RED}FAIL${NC}: Cannot connect to proxy at ${PROXY_URL}" >&2
  info "Export PROXY_URL to override (e.g. export PROXY_URL=https://proxy.example.com:8911)"
  PROXY_AVAILABLE=false
elif [ "$PROXY_HEALTH" != "200" ]; then
  echo -e "${RED}FAIL${NC}: Proxy returned HTTP ${PROXY_HEALTH}" >&2
  PROXY_AVAILABLE=false
else
  ok "Proxy is reachable at ${PROXY_URL}"
  PROXY_AVAILABLE=true
fi

# Deploy mock server into the cluster if kubectl is available
MOCK_AVAILABLE=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v kubectl &>/dev/null; then
  # Check if mock server is already running in-cluster
  MOCK_POD=$(kubectl -n "${PROXY_NAMESPACE}" get pods -l app=spiffe-mock-server --no-headers 2>/dev/null | grep Running) || true

  if [ -z "$MOCK_POD" ]; then
    info "Deploying mock server into ${PROXY_NAMESPACE} namespace..."

    # Create ConfigMap from server.py
    kubectl -n "${PROXY_NAMESPACE}" create configmap spiffe-mock-server \
      --from-file=server.py="${SCRIPT_DIR}/mock-server/server.py" \
      --dry-run=client -o yaml | kubectl apply -f - 2>/dev/null

    # Deploy the mock server
    kubectl -n "${PROXY_NAMESPACE}" apply -f "${SCRIPT_DIR}/mock-server/k8s.yaml" 2>/dev/null

    # Wait for it to be ready
    info "Waiting for mock server pod to be ready..."
    if kubectl -n "${PROXY_NAMESPACE}" wait --for=condition=ready pod -l app=spiffe-mock-server --timeout=60s 2>/dev/null; then
      ok "Mock server deployed in-cluster"
      MOCK_AVAILABLE=true
    else
      info "Mock server pod not ready yet — check: kubectl get pods -n ${PROXY_NAMESPACE} -l app=spiffe-mock-server"
    fi
  else
    ok "Mock server already running in-cluster"
    MOCK_AVAILABLE=true
  fi
else
  info "kubectl not available — checking for local mock server"
fi

# Fall back to local mock server if not in-cluster
if [ "$MOCK_AVAILABLE" != "true" ]; then
  MOCK_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "${MOCK_SERVER_URL}/health" 2>/dev/null) || true
  if [ "$MOCK_HEALTH" = "200" ]; then
    ok "Mock server running locally at ${MOCK_SERVER_URL}"
    MOCK_AVAILABLE=true
    # Local mock — proxy can't reach localhost, so override cluster URL
    info "Note: proxy may not reach ${MOCK_SERVER_URL} from in-cluster"
  else
    info "Mock server not running locally either"
    info "Start with: docker compose up -d  OR  python3 mock-server/server.py &"
  fi
fi

# Set up auth header for proxy API calls
if [ -n "${AUTH_TOKEN:-}" ]; then
  AUTH_HEADER="Authorization: Bearer ${AUTH_TOKEN}"
else
  # Try to obtain a token automatically via Rancher OIDC
  info "No AUTH_TOKEN set — attempting automatic token generation..."
  AUTO_TOKEN=$(PROXY_URL="${PROXY_URL}" CURL_INSECURE="${CURL_INSECURE}" "${SCRIPT_DIR}/get-token.sh" 2>/dev/null) || true
  if [ -n "$AUTO_TOKEN" ]; then
    AUTH_TOKEN="$AUTO_TOKEN"
    AUTH_HEADER="Authorization: Bearer ${AUTH_TOKEN}"
    ok "OAuth token obtained automatically"
  else
    AUTH_HEADER="X-User-ID: admin"
    info "Could not obtain token automatically — using dev-mode auth"
    info "For OAuth: export AUTH_TOKEN=\$(./get-token.sh)"
  fi
fi

if [ "$PROXY_AVAILABLE" = "true" ] && [ "$MOCK_AVAILABLE" = "true" ]; then
  echo ""
  info "Registering MCP server and SPIFFE adapter with proxy..."
  info "Proxy will reach mock server at: ${MOCK_SERVER_CLUSTER_URL}"
  echo ""

  # Step 1: Register the MCP server in the registry
  info "Registering MCP server in proxy registry..."
  SERVER_REG=$(curl ${CURL_INSECURE} -s -X POST "${PROXY_URL}/api/v1/registry/upload" \
    -H "Content-Type: application/json" \
    -H "${AUTH_HEADER}" \
    -d "{
      \"id\": \"databricks-spiffe\",
      \"name\": \"databricks-spiffe\",
      \"type\": \"server\",
      \"url\": \"${MOCK_SERVER_CLUSTER_URL}/mcp\",
      \"about\": {
        \"title\": \"Databricks (SPIFFE)\",
        \"description\": \"Mock Databricks MCP server for SPIFFE demo\"
      },
      \"packages\": [{
        \"transport\": {
          \"type\": \"http\",
          \"url\": \"${MOCK_SERVER_CLUSTER_URL}/mcp\"
        }
      }]
    }" 2>&1) || true

  if echo "$SERVER_REG" | jq -e '.id // .name' &>/dev/null; then
    ok "MCP server registered: databricks-spiffe"
  else
    if echo "$SERVER_REG" | grep -qi "already exists\|duplicate\|conflict"; then
      ok "MCP server databricks-spiffe already registered"
    else
      info "Server registration response: ${SERVER_REG:-no response}"
    fi
  fi

  # Step 2: Create the adapter
  info "Example adapter configuration:"
  echo ""
  cat <<JSON
{
  "mcpServerId": "databricks-spiffe",
  "name": "databricks_spiffe",
  "remoteUrl": "${MOCK_SERVER_CLUSTER_URL}/mcp",
  "connectionType": "remote-http",
  "authentication": {
    "required": true,
    "type": "spiffe",
    "spiffe": {
      "target_audience": "https://databricks.example.com",
      "use_mtls": false
    },
    "tokenExchange": {
      "token_endpoint": "${MOCK_SERVER_CLUSTER_URL}/token",
      "audience": "https://databricks.example.com",
      "scopes": ["sql:read"],
      "subject_token_type": "urn:ietf:params:oauth:token-type:jwt"
    }
  }
}
JSON
  echo ""

  # Delete any existing adapter with this name (stale data from previous runs)
  curl ${CURL_INSECURE} -s -X DELETE "${PROXY_URL}/api/v1/adapters/databricks_spiffe" \
    -H "${AUTH_HEADER}" &>/dev/null || true

  info "Creating SPIFFE adapter..."
  REG_RESULT=$(curl ${CURL_INSECURE} -s -X POST "${PROXY_URL}/api/v1/adapters" \
    -H "Content-Type: application/json" \
    -H "${AUTH_HEADER}" \
    -d "{
      \"mcpServerId\": \"databricks-spiffe\",
      \"name\": \"databricks_spiffe\",
      \"remoteUrl\": \"${MOCK_SERVER_CLUSTER_URL}/mcp\",
      \"connectionType\": \"remote-http\",
      \"authentication\": {
        \"required\": true,
        \"type\": \"spiffe\",
        \"spiffe\": {
          \"target_audience\": \"https://databricks.example.com\",
          \"use_mtls\": false
        },
        \"tokenExchange\": {
          \"token_endpoint\": \"${MOCK_SERVER_CLUSTER_URL}/token\",
          \"audience\": \"https://databricks.example.com\",
          \"scopes\": [\"sql:read\"],
          \"subject_token_type\": \"urn:ietf:params:oauth:token-type:jwt\"
        }
      }
    }" 2>&1) || true

  if echo "$REG_RESULT" | jq -e '.id // .name' &>/dev/null; then
    ok "Adapter registered: databricks_spiffe"
    echo "$REG_RESULT" | jq '{id, name: (.name // .id), status: (.status // "registered")}' 2>/dev/null || true
  else
    # May already exist — that's fine
    if echo "$REG_RESULT" | grep -qi "already exists\|duplicate\|conflict"; then
      ok "Adapter databricks_spiffe already registered"
    else
      echo -e "${RED}FAIL${NC}: Could not register adapter: ${REG_RESULT:-no response}" >&2
    fi
  fi
else
  echo ""
  if [ "$PROXY_AVAILABLE" != "true" ]; then
    info "Proxy not available — skipping adapter registration"
  fi
  if [ "$MOCK_AVAILABLE" != "true" ]; then
    info "Mock server not available — skipping adapter registration"
  fi
fi

# ─── Step 8: End-to-End MCP via Proxy ────────────────────────────

step 8 "MCP Tool Calls via Proxy (SPIFFE Auth)"

if [ "$PROXY_AVAILABLE" = "true" ] && [ "$MOCK_AVAILABLE" = "true" ]; then

  cat <<'FLOW'
End-to-end flow for each request:

  Client                    Proxy                     SPIRE Agent         Mock Server
    |                         |                           |                   |
    |-- POST /api/v1/mcp ---->|                           |                   |
    |   (Bearer: OAuth JWT)   |-- FetchJWTSVID() -------->|                   |
    |                         |<-- JWT SVID --------------|                   |
    |                         |                                               |
    |                         |-- POST /token (RFC 8693) -------------------->|
    |                         |   subject_token=<jwt-svid>                    |
    |                         |<-- access_token ------------------------------|
    |                         |                                               |
    |                         |-- POST /mcp (Bearer: exchanged token) ------->|
    |                         |<-- tool result --------------------------------|
    |<-- tool result ---------|
FLOW
  echo ""

  # ── 8a: List tools through the proxy ──
  info "Listing tools through the proxy's unified endpoint..."
  echo ""
  echo "  POST ${PROXY_URL}/api/v1/mcp"
  echo "  Authorization: Bearer <oauth-token>"
  echo "  {\"method\": \"tools/list\"}"
  echo ""

  TOOLS_RESPONSE=$(curl ${CURL_INSECURE} -s -X POST "${PROXY_URL}/api/v1/mcp" \
    -H "Content-Type: application/json" \
    -H "${AUTH_HEADER}" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' 2>&1) || true

  if echo "$TOOLS_RESPONSE" | jq -e '.result.tools' &>/dev/null; then
    # Filter to just the SPIFFE adapter tools
    SPIFFE_TOOLS=$(echo "$TOOLS_RESPONSE" | jq '[.result.tools[] | select(.name | startswith("databricks_spiffe__"))]')
    TOOL_COUNT=$(echo "$SPIFFE_TOOLS" | jq 'length')

    if [ "$TOOL_COUNT" -gt 0 ]; then
      echo "$SPIFFE_TOOLS" | jq '.[] | {name, description}'
      echo ""
      ok "${TOOL_COUNT} tools available via databricks_spiffe adapter"
      info "Tool names are prefixed with adapter name (databricks_spiffe__)"
    else
      info "No databricks_spiffe tools found in tools/list response"
      info "The adapter may still be initializing — tools appear after first connection"
      echo "$TOOLS_RESPONSE" | jq '.result.tools[0:3] | .[] | {name}' 2>/dev/null || true
    fi
  else
    echo -e "${RED}FAIL${NC}: tools/list failed: $(echo "$TOOLS_RESPONSE" | jq -r '.error.message // .error // "unknown"' 2>/dev/null)" >&2
  fi

  # ── 8b: Execute SQL query through the proxy ──
  echo ""
  info "Calling databricks_spiffe__execute_sql through the proxy..."
  echo ""
  echo "  POST ${PROXY_URL}/api/v1/mcp"
  echo "  {\"method\": \"tools/call\", \"params\": {\"name\": \"databricks_spiffe__execute_sql\", ...}}"
  echo ""

  SQL_RESPONSE=$(curl ${CURL_INSECURE} -s -X POST "${PROXY_URL}/api/v1/mcp" \
    -H "Content-Type: application/json" \
    -H "${AUTH_HEADER}" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"databricks_spiffe__execute_sql","arguments":{"query":"SELECT * FROM sensor_data LIMIT 3"}}}' 2>&1) || true

  if echo "$SQL_RESPONSE" | jq -e '.result.content[0].text' &>/dev/null; then
    RESULT_TEXT=$(echo "$SQL_RESPONSE" | jq -r '.result.content[0].text')
    echo "$RESULT_TEXT" | jq .
    echo ""

    AUTH_VIA=$(echo "$RESULT_TEXT" | jq -r '.authenticated_via // empty')
    WORKLOAD_ID=$(echo "$RESULT_TEXT" | jq -r '.workload_identity // empty')
    ok "Query executed successfully"
    if [ -n "$AUTH_VIA" ]; then
      ok "Authenticated via: ${AUTH_VIA}"
    fi
    if [ -n "$WORKLOAD_ID" ]; then
      ok "Workload identity: ${WORKLOAD_ID}"
    fi
    echo ""
    ok "Request went: Client -> Proxy (OAuth) -> SPIRE (JWT SVID) -> Token Exchange -> Mock MCP"
  else
    echo -e "${RED}FAIL${NC}: tools/call failed: $(echo "$SQL_RESPONSE" | jq -r '.error.message // .error // "unknown"' 2>/dev/null)" >&2
    info "Full response:"
    echo "$SQL_RESPONSE" | jq . 2>/dev/null || echo "$SQL_RESPONSE"
  fi

  # ── 8c: Get workspace info through the proxy ──
  echo ""
  info "Calling databricks_spiffe__get_workspace_info through the proxy..."
  echo ""

  WS_RESPONSE=$(curl ${CURL_INSECURE} -s -X POST "${PROXY_URL}/api/v1/mcp" \
    -H "Content-Type: application/json" \
    -H "${AUTH_HEADER}" \
    -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"databricks_spiffe__get_workspace_info","arguments":{}}}' 2>&1) || true

  if echo "$WS_RESPONSE" | jq -e '.result.content[0].text' &>/dev/null; then
    echo "$WS_RESPONSE" | jq -r '.result.content[0].text' | jq .
    echo ""
    ok "Workspace info retrieved via SPIFFE workload identity"
  else
    echo -e "${RED}FAIL${NC}: tools/call failed: $(echo "$WS_RESPONSE" | jq -r '.error.message // .error // "unknown"' 2>/dev/null)" >&2
  fi

else
  info "Proxy or mock server not available — showing what the flow looks like:"
  echo ""
  cat <<'FLOW'
With proxy + mock server running, Step 8 would:

  1. POST ${PROXY_URL}/api/v1/mcp  (tools/list)
     → Proxy aggregates tools from all adapters including databricks_spiffe
     → Returns: databricks_spiffe__execute_sql, databricks_spiffe__get_cluster_status, etc.

  2. POST ${PROXY_URL}/api/v1/mcp  (tools/call: databricks_spiffe__execute_sql)
     → Proxy strips prefix, routes to databricks_spiffe adapter
     → Proxy fetches JWT SVID from SPIRE agent (workload identity)
     → Proxy exchanges SVID at mock /token endpoint (RFC 8693)
     → Proxy calls mock /mcp with exchanged bearer token
     → Returns: query results with authenticated_via=spiffe_token_exchange

Prerequisites:
  - Proxy running with SPIFFE enabled:  helm upgrade ... --set spiffe.enabled=true
  - Mock server deployed (demo auto-deploys to cluster, or: docker compose up -d)
  - OAuth token from demo 02:           export AUTH_TOKEN=<token>
FLOW
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
echo "  6. SPIFFE adapter registration on the proxy"
echo "  7. MCP tool calls routed through the proxy with SPIFFE auth"
echo "  8. Comparison of all three auth strategies"
echo ""
echo "End-to-end flow:"
echo "  Client -> Proxy (OAuth) -> SPIRE Agent (JWT SVID) -> Token Exchange -> MCP Server"
echo ""
echo "SPIFFE is best suited for:"
echo "  - Zero-trust service mesh environments"
echo "  - Internal service-to-service authentication"
echo "  - Environments where static secrets should be eliminated"
echo "  - Workload-to-workload flows without user context"
