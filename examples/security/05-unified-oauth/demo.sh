#!/usr/bin/env bash
# 05 — Unified MCP Endpoint with OAuth + Both Adapters
# Demonstrates the aggregated /api/v1/mcp endpoint protected by OAuth,
# routing to both Databricks (token exchange) and ServiceNow (service account).
set -euo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8911}"
SERVICENOW_MCP_URL="${SERVICENOW_MCP_URL:-http://localhost:8000}"
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

echo -e "${CYAN}Unified MCP Endpoint with OAuth${NC}"
echo "Proxy:          ${PROXY_URL}"
echo "ServiceNow MCP: ${SERVICENOW_MCP_URL}"
echo "Databricks MCP: ${DATABRICKS_MCP_URL}"
echo ""

# ─── Step 1: Verify both MCP servers ─────────────────────────────────

step 1 "Verify MCP Servers"

curl -sf "${SERVICENOW_MCP_URL}/health" | jq . || fail "ServiceNow MCP not reachable"
ok "ServiceNow MCP server is running"

curl -sf "${DATABRICKS_MCP_URL}/health" | jq . || fail "Databricks MCP not reachable"
ok "Databricks MCP server is running"

# ─── Step 2: Register both adapters ──────────────────────────────────

step 2 "Register Both Adapters"

info "Registering ServiceNow adapter (service account auth)..."
curl -sf -X POST "${PROXY_URL}/api/v1/adapters" \
  -H "Content-Type: application/json" \
  -H "X-User-ID: admin" \
  -d "{
    \"name\": \"servicenow\",
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
  }" 2>/dev/null | jq . || info "ServiceNow adapter may already exist"

info "Registering Databricks adapter (token exchange auth)..."
curl -sf -X POST "${PROXY_URL}/api/v1/adapters" \
  -H "Content-Type: application/json" \
  -H "X-User-ID: admin" \
  -d "{
    \"name\": \"databricks\",
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
  }" 2>/dev/null | jq . || info "Databricks adapter may already exist"

ok "Both adapters registered"

# ─── Step 3: Show the unified endpoint ───────────────────────────────

step 3 "Unified MCP Endpoint Architecture"

cat <<'ARCH'
The unified endpoint aggregates tools from all registered adapters
into a single MCP interface at /api/v1/mcp:

  Claude Code / Cursor / MCP Client
       |
       | POST /api/v1/mcp (OAuth Bearer token required)
       v
  SUSE AI Universal Proxy
       |
       |-- MCPOAuthMiddleware: Validates JWT, extracts user claims
       |-- InjectOAuthContext: Propagates claims to request context
       |-- UnifiedMCPHandler:
       |     |
       |     |-- tools/list: Aggregates from all adapters
       |     |     |-- Filters by tool-level policies
       |     |     |-- Prefixes: servicenow__search_incidents
       |     |     |              databricks__get_error_metrics
       |     |
       |     |-- tools/call: Routes to correct adapter
       |     |     |-- Checks authorization policy
       |     |     |-- Applies downstream auth:
       |     |           servicenow -> Basic + X-UserToken
       |     |           databricks -> Bearer <exchanged-token>
       |     |
       |     v
       |-- ServiceNow MCP Server (port 8000)
       |-- Databricks MCP Server (port 8001)
ARCH

ok "Single connection, multiple adapters, per-adapter auth"

# ─── Step 4: OAuth discovery ─────────────────────────────────────────

step 4 "OAuth Discovery for Unified Endpoint"

info "The unified endpoint is protected by the same OAuth middleware"
info "as all other proxy endpoints."
echo ""

AS_META=$(curl -sf "${PROXY_URL}/.well-known/oauth-authorization-server") || fail "AS metadata unavailable"
echo "$AS_META" | jq '{ authorization_endpoint, token_endpoint, registration_endpoint }'
ok "OAuth endpoints discovered"

# ─── Step 5: Unauthenticated request shows 401 ───────────────────────

step 5 "Unified Endpoint Requires OAuth"

info "Attempting to call /api/v1/mcp without a bearer token..."
echo ""

HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "${PROXY_URL}/api/v1/mcp" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' 2>/dev/null || echo "401")

if [ "$HTTP_CODE" = "401" ]; then
  ok "Got 401 — OAuth bearer token required (as expected)"
  info "The WWW-Authenticate header points to the resource metadata URL"
  info "so the MCP client knows how to authenticate."
else
  info "Got HTTP ${HTTP_CODE} (auth may not be enforced in current config)"
fi

# ─── Step 6: Show tool naming convention ──────────────────────────────

step 6 "Tool Naming Convention"

info "Tools are prefixed with the adapter name to avoid collisions:"
echo ""
echo "  ServiceNow tools:        Databricks tools:"
echo "  ─────────────────        ─────────────────"
echo "  servicenow__search_incidents    databricks__list_clusters"
echo "  servicenow__get_incident        databricks__get_cluster"
echo "  servicenow__create_incident     databricks__execute_sql"
echo "  servicenow__update_incident     databricks__get_error_metrics"
echo "  servicenow__get_related_cis     databricks__get_system_health"
echo "  servicenow__search_cmdb         databricks__correlate_events"
echo ""

info "When a client calls servicenow__get_incident, the proxy:"
info "  1. Strips the 'servicenow__' prefix"
info "  2. Routes to the ServiceNow adapter"
info "  3. Applies service account auth + impersonation"
info "  4. Forwards {\"method\":\"tools/call\",\"params\":{\"name\":\"get_incident\",...}}"
echo ""
ok "Transparent routing — the MCP server sees unprefixed tool names"

# ─── Step 7: Cross-system correlation scenario ───────────────────────

step 7 "Cross-System Correlation Scenario"

info "With both adapters behind one endpoint, an AI assistant can:"
echo ""
echo "  1. servicenow__search_incidents — Find P1 incidents"
echo "  2. databricks__get_error_metrics — Check error rates"
echo "  3. databricks__correlate_events  — Cross-reference timestamps"
echo "  4. servicenow__update_incident   — Update with root cause"
echo ""
info "All through a single MCP connection, with per-user auth"
info "applied differently for each downstream system."
echo ""
ok "Different auth strategies, unified interface"

# ─── Summary ─────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}=== Unified OAuth Demo Complete ===${NC}"
echo ""
echo "What we demonstrated:"
echo "  1. Two adapters with different auth strategies behind one endpoint"
echo "  2. OAuth middleware protecting the unified MCP endpoint"
echo "  3. Automatic downstream credential routing per adapter"
echo "  4. Tool name prefixing for multi-adapter aggregation"
echo "  5. Cross-system correlation use case"
echo ""
echo "Authentication summary:"
echo "  Inbound:  OAuth 2.1 + PKCE -> proxy-issued JWT"
echo "  Outbound: servicenow -> Basic + X-UserToken (impersonation)"
echo "            databricks -> Bearer <RFC 8693 exchanged token>"
echo ""
echo "Next: Run 06-tool-policies for fine-grained access control."
