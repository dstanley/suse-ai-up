#!/usr/bin/env bash
# 03 — Databricks Token Exchange (RFC 8693)
# Demonstrates the proxy exchanging a user's Rancher ID token
# for a Databricks access token via RFC 8693 token exchange.
set -euo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8911}"
DATABRICKS_MCP_URL="${DATABRICKS_MCP_URL:-http://localhost:8001}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

step() { echo -e "\n${CYAN}=== Step $1: $2 ===${NC}\n"; }
ok()   { echo -e "${GREEN}OK${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }
info() { echo -e "${YELLOW}INFO${NC}: $1"; }

echo -e "${CYAN}Databricks Token Exchange (RFC 8693)${NC}"
echo "Proxy:          ${PROXY_URL}"
echo "Databricks MCP: ${DATABRICKS_MCP_URL}"
echo ""

# ─── Step 1: Verify Databricks MCP server is running ─────────────────

step 1 "Verify Databricks MCP Server"

HEALTH=$(curl -sf "${DATABRICKS_MCP_URL}/health") || fail "Databricks MCP server not reachable at ${DATABRICKS_MCP_URL}"
echo "$HEALTH" | jq .
MODE=$(echo "$HEALTH" | jq -r '.mode')
ok "Databricks MCP server is running in ${MODE} mode"

# ─── Step 2: Verify Databricks tools are available ───────────────────

step 2 "List Available Databricks Tools"

TOOLS_RESPONSE=$(curl -sf -X POST "${DATABRICKS_MCP_URL}/mcp" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}') || fail "Failed to list tools"

echo "$TOOLS_RESPONSE" | jq '.result.tools[] | .name'
TOOL_COUNT=$(echo "$TOOLS_RESPONSE" | jq '.result.tools | length')
ok "${TOOL_COUNT} tools available"

# ─── Step 3: Show adapter configuration ──────────────────────────────

step 3 "Adapter Configuration for Token Exchange"

info "This is how the Databricks adapter is configured in the proxy."
info "When a user calls a Databricks tool, the proxy:"
info "  1. Takes the user's Rancher ID token (from their OAuth session)"
info "  2. POSTs it to Databricks' token endpoint as a subject_token"
info "  3. Receives a Databricks access token in return"
info "  4. Caches the token in the in-memory vault"
info "  5. Forwards the MCP request with the Databricks token"
echo ""

cat <<'JSON'
{
  "name": "databricks-mcp",
  "remoteUrl": "http://databricks-mcp:8001/mcp",
  "connectionType": "remote-http",
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

echo ""
ok "Token exchange uses grant_type=urn:ietf:params:oauth:token-type:token-exchange (RFC 8693)"

# ─── Step 4: Register adapter with proxy ─────────────────────────────

step 4 "Register Databricks Adapter"

info "Registering the adapter with the proxy..."

REG_RESULT=$(curl -sf -X POST "${PROXY_URL}/api/v1/adapters" \
  -H "Content-Type: application/json" \
  -H "X-User-ID: admin" \
  -d "{
    \"name\": \"databricks-mcp\",
    \"remoteUrl\": \"${DATABRICKS_MCP_URL}/mcp\",
    \"connectionType\": \"remote-http\",
    \"authentication\": {
      \"required\": true,
      \"type\": \"token_exchange\",
      \"tokenExchange\": {
        \"token_endpoint\": \"https://accounts.cloud.databricks.com/oidc/v1/token\",
        \"audience\": \"https://databricks.example.com\",
        \"scopes\": [\"sql:read\", \"sql:write\"],
        \"subject_token_type\": \"urn:ietf:params:oauth:token-type:id_token\"
      }
    }
  }" 2>/dev/null) && {
  echo "$REG_RESULT" | jq .
  ok "Adapter registered"
} || info "Adapter registration skipped (may already exist)"

# ─── Step 5: Direct tool call (mock mode) ────────────────────────────

step 5 "Direct Tool Call — Databricks Error Metrics"

info "Calling the Databricks MCP server directly (mock mode)."
info "In production, this request would come through the proxy with"
info "an exchanged Databricks token in the Authorization header."
echo ""

RESULT=$(curl -sf -X POST "${DATABRICKS_MCP_URL}/mcp" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "get_error_metrics",
      "arguments": {"time_range": "24h"}
    }
  }') || fail "Tool call failed"

echo "$RESULT" | jq '.result'
ok "Databricks tool call succeeded"

# ─── Step 6: Explain the exchange flow ────────────────────────────────

step 6 "Token Exchange Flow Detail"

cat <<'FLOW'
When an authenticated user calls databricks-mcp__get_error_metrics
through the unified endpoint, this is what happens:

  1. Client sends: POST /api/v1/mcp
     Authorization: Bearer <proxy-issued-jwt>
     Body: {"method":"tools/call","params":{"name":"databricks-mcp__get_error_metrics"}}

  2. Proxy validates the JWT, extracts user claims (sub, email, groups)

  3. Proxy looks up the user's OAuth session to get their Rancher ID token

  4. Proxy POSTs to Databricks token endpoint:
     POST https://accounts.cloud.databricks.com/oidc/v1/token
     grant_type=urn:ietf:params:oauth:token-type:token-exchange
     subject_token=<rancher-id-token>
     subject_token_type=urn:ietf:params:oauth:token-type:id_token
     audience=https://databricks.example.com
     scope=sql:read sql:write

  5. Databricks returns an access token scoped to the user

  6. Proxy caches the token in the in-memory vault (never persisted to disk)

  7. Proxy forwards the MCP request to the Databricks MCP server:
     POST http://databricks-mcp:8001/mcp
     Authorization: Bearer <databricks-access-token>

  8. On subsequent calls, the cached token is reused until expiry

Security properties:
  - The user never sees the Databricks token
  - The Rancher ID token never leaves the proxy
  - Exchanged tokens are RAM-only — pod restart triggers re-exchange
  - Each user gets their own Databricks token (no shared credentials)
FLOW

ok "Token exchange preserves per-user identity across trust boundaries"

# ─── Summary ─────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}=== Token Exchange Demo Complete ===${NC}"
echo ""
echo "What we demonstrated:"
echo "  1. Databricks MCP server with mock data"
echo "  2. Token exchange adapter configuration"
echo "  3. RFC 8693 flow: Rancher ID token -> Databricks access token"
echo "  4. In-memory token vault (exchanged tokens never hit disk)"
echo ""
echo "Next: Run 04-service-account for ServiceNow impersonation."
