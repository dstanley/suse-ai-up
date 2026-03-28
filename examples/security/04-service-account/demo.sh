#!/usr/bin/env bash
# 04 — ServiceNow Service Account Impersonation
# Demonstrates the proxy authenticating with a shared service account
# and impersonating the user via identity headers.
set -euo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8911}"
SERVICENOW_MCP_URL="${SERVICENOW_MCP_URL:-http://localhost:8000}"
CURL_INSECURE="${CURL_INSECURE:--k}"
AUTH_TOKEN="${AUTH_TOKEN:-}"  # Bearer token for OAuth-enabled deployments

# Auto-acquire a token from refresh token if available (exported by demo 02)
if [ -z "$AUTH_TOKEN" ] && [ -n "${REFRESH_TOKEN:-}" ] && [ -n "${CLIENT_ID:-}" ] && [ -n "${TOKEN_ENDPOINT:-}" ]; then
  AUTH_TOKEN=$(curl ${CURL_INSECURE} -sf -X POST "${TOKEN_ENDPOINT}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=refresh_token&refresh_token=${REFRESH_TOKEN}&client_id=${CLIENT_ID}" \
    | jq -r '.access_token // empty' 2>/dev/null) || true
  [ -n "$AUTH_TOKEN" ] && echo "Auto-acquired AUTH_TOKEN via refresh token"
fi

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

step() { echo -e "\n${CYAN}=== Step $1: $2 ===${NC}\n"; }
ok()   { echo -e "${GREEN}OK${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }
info() { echo -e "${YELLOW}INFO${NC}: $1"; }

echo -e "${CYAN}ServiceNow Service Account Impersonation${NC}"
echo "Proxy:          ${PROXY_URL}"
echo "ServiceNow MCP: ${SERVICENOW_MCP_URL}"
echo ""

# Verify proxy is reachable
HEALTH_CODE=$(curl ${CURL_INSECURE} -s -o /dev/null -w "%{http_code}" "${PROXY_URL}/health" 2>/dev/null) || true
if [ "$HEALTH_CODE" = "000" ]; then
  fail "Cannot connect to proxy at ${PROXY_URL}. Export PROXY_URL to override (e.g. export PROXY_URL=https://proxy.example.com:8911)"
elif [ "$HEALTH_CODE" != "200" ]; then
  info "Proxy returned HTTP ${HEALTH_CODE} on /health (may still work)"
fi

# ─── Step 1: Verify ServiceNow MCP server ────────────────────────────

step 1 "Verify ServiceNow MCP Server"

HEALTH=$(curl ${CURL_INSECURE} -sf "${SERVICENOW_MCP_URL}/health") || fail "ServiceNow MCP server not reachable"
echo "$HEALTH" | jq .
ok "ServiceNow MCP server is running"

# ─── Step 2: List available tools ────────────────────────────────────

step 2 "List Available ServiceNow Tools"

TOOLS_RESPONSE=$(curl ${CURL_INSECURE} -sf -X POST "${SERVICENOW_MCP_URL}/mcp" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}') || fail "Failed to list tools"

echo "$TOOLS_RESPONSE" | jq '.result.tools[] | .name'
TOOL_COUNT=$(echo "$TOOLS_RESPONSE" | jq '.result.tools | length')
ok "${TOOL_COUNT} tools available"

# ─── Step 3: Show adapter configuration ──────────────────────────────

step 3 "Adapter Configuration for Service Account Impersonation"

info "Unlike token exchange, service account auth uses a shared credential."
info "The proxy authenticates as the service account, then tells ServiceNow"
info "which user it's acting on behalf of via an impersonation header."
echo ""

info "Example adapter configuration:"
echo ""
cat <<'JSON'
{
  "name": "servicenow_mcp",
  "remoteUrl": "http://servicenow_mcp:8000/mcp",
  "connectionType": "remote-http",
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

echo ""
info "The outbound request from the proxy looks like:"
echo ""
echo "  POST http://servicenow_mcp:8000/mcp"
echo "  Authorization: Basic <base64(mcp-proxy-sa:password)>"
echo "  X-UserToken: jdoe@example.com"
echo "  Content-Type: application/json"
echo ""
ok "Service account credentials come from CSI Secret Store (Kubernetes)"

# ─── Step 4: Register adapter ────────────────────────────────────────

step 4 "Register ServiceNow Adapter"

if [ -n "$AUTH_TOKEN" ]; then
  AUTH_HEADER="Authorization: Bearer ${AUTH_TOKEN}"
  info "Using bearer token for authentication"
else
  AUTH_HEADER="X-User-ID: admin"
  info "Using dev-mode auth (set AUTH_TOKEN for OAuth-enabled deployments)"
fi

REG_RESULT=$(curl ${CURL_INSECURE} -sf -X POST "${PROXY_URL}/api/v1/adapters" \
  -H "Content-Type: application/json" \
  -H "${AUTH_HEADER}" \
  -d "{
    \"name\": \"servicenow_mcp\",
    \"remoteUrl\": \"${SERVICENOW_MCP_URL}/mcp\",
    \"connectionType\": \"remote-http\",
    \"authentication\": {
      \"required\": true,
      \"type\": \"service_account\",
      \"serviceAccount\": {
        \"username\": \"mcp-proxy-sa\",
        \"password\": \"demo-password\",
        \"impersonation_header\": \"X-UserToken\",
        \"impersonation_field\": \"email\"
      }
    }
  }" 2>/dev/null) && {
  echo "$REG_RESULT" | jq .
  ok "Adapter registered"
} || {
  if [ -z "$AUTH_TOKEN" ]; then
    info "Adapter registration failed — OAuth may be enabled on this deployment."
    info "Run demo 02 first to get a token, then: AUTH_TOKEN=<token> ./demo.sh"
  else
    info "Adapter registration skipped (may already exist)"
  fi
}

# ─── Step 5: Direct tool calls (mock mode) ───────────────────────────

step 5 "ServiceNow Tool Calls"

info "Searching for high-priority incidents..."
echo ""

SEARCH_RESULT=$(curl ${CURL_INSECURE} -sf -X POST "${SERVICENOW_MCP_URL}/mcp" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "search_incidents",
      "arguments": {"priority": "1"}
    }
  }') || fail "Incident search failed"

echo "$SEARCH_RESULT" | jq -r '.result.content[0].text // empty' 2>/dev/null | jq . 2>/dev/null \
  || echo "$SEARCH_RESULT" | jq '.result'
ok "Incident search succeeded"

# Extract an incident number from the search results to use for the detail call
INCIDENT_NUM=$(echo "$SEARCH_RESULT" | jq -r '.result.content[0].text // empty' 2>/dev/null \
  | jq -r '.incidents[0].number // .[0].number // empty' 2>/dev/null)
if [ -z "$INCIDENT_NUM" ]; then
  INCIDENT_NUM="INC0010001"  # fallback
fi

info "Getting incident details for ${INCIDENT_NUM}..."
echo ""

INCIDENT_RESULT=$(curl ${CURL_INSECURE} -sf -X POST "${SERVICENOW_MCP_URL}/mcp" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"id\": 3,
    \"method\": \"tools/call\",
    \"params\": {
      \"name\": \"get_incident\",
      \"arguments\": {\"incident_number\": \"${INCIDENT_NUM}\"}
    }
  }") || fail "Get incident failed"

IS_ERROR=$(echo "$INCIDENT_RESULT" | jq -r '.result.isError // false' 2>/dev/null)
echo "$INCIDENT_RESULT" | jq -r '.result.content[0].text // empty' 2>/dev/null | jq . 2>/dev/null \
  || echo "$INCIDENT_RESULT" | jq '.result'
if [ "$IS_ERROR" = "true" ]; then
  info "Incident not found in mock data (expected with demo IDs)"
else
  ok "Incident detail retrieved"
fi

# ─── Step 6: Explain the impersonation flow ──────────────────────────

step 6 "Impersonation Flow Detail"

cat <<'FLOW'
When user jdoe@example.com calls servicenow_mcp__search_incidents:

  1. Client sends: POST /api/v1/mcp
     Authorization: Bearer <proxy-jwt with sub=jdoe, email=jdoe@example.com>

  2. Proxy validates JWT, extracts email claim: jdoe@example.com

  3. Proxy authenticates to ServiceNow as the service account:
     Authorization: Basic <base64(mcp-proxy-sa:password)>

  4. Proxy adds impersonation header from the user's email claim:
     X-UserToken: jdoe@example.com

  5. ServiceNow processes the request as if jdoe made it directly

Key differences from token exchange:
  - One shared credential (service account) vs per-user tokens
  - Simpler setup — no external IdP token endpoint needed
  - User identity conveyed via header, not embedded in a token
  - ServiceNow must trust the proxy's impersonation header

When to use each:
  - Token Exchange: when the downstream IdP supports it (Databricks, Azure AD)
  - Service Account: when the downstream service uses header-based impersonation
FLOW

ok "Service account impersonation preserves user identity without per-user tokens"

# ─── Summary ─────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}=== Service Account Demo Complete ===${NC}"
echo ""
echo "What we demonstrated:"
echo "  1. ServiceNow MCP server with mock incident data"
echo "  2. Service account adapter configuration"
echo "  3. Impersonation flow: shared credential + user identity header"
echo "  4. Incident search and detail retrieval"
echo ""
echo "Cleanup:"
echo "  docker compose down    # stop and remove the mock servers"
echo ""
echo "Next: Run 05-unified-oauth for both adapters behind a single OAuth-protected endpoint."
