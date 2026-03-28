#!/usr/bin/env bash
# 06 — Tool-Level Authorization Policies
# Demonstrates deny-takes-precedence policies, tool filtering, and call enforcement.
set -euo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8911}"
CURL_INSECURE="${CURL_INSECURE:--k}"
AUTH_TOKEN="${AUTH_TOKEN:-}"  # Bearer token for OAuth-enabled deployments

# Auto-acquire a token from refresh token if available (exported by demo 02)
if [ -z "$AUTH_TOKEN" ] && [ -n "${REFRESH_TOKEN:-}" ] && [ -n "${CLIENT_ID:-}" ] && [ -n "${TOKEN_ENDPOINT:-}" ]; then
  AUTH_TOKEN=$(curl ${CURL_INSECURE} -s -X POST "${TOKEN_ENDPOINT}" \
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

echo -e "${CYAN}Tool-Level Authorization Policies${NC}"
echo "Proxy: ${PROXY_URL}"
echo ""

# Verify proxy is reachable
HEALTH_CODE=$(curl ${CURL_INSECURE} -s -o /dev/null -w "%{http_code}" "${PROXY_URL}/health" 2>/dev/null) || true
if [ "$HEALTH_CODE" = "000" ]; then
  fail "Cannot connect to proxy at ${PROXY_URL}. Export PROXY_URL to override (e.g. export PROXY_URL=https://proxy.example.com:8911)"
elif [ "$HEALTH_CODE" != "200" ]; then
  info "Proxy returned HTTP ${HEALTH_CODE} on /health (may still work)"
fi

# ─── Step 1: Explain the policy model ────────────────────────────────

step 1 "Policy Model"

cat <<'MODEL'
The proxy enforces tool-level access control with these rules:

  1. Deny takes precedence — any matching deny policy blocks access,
     regardless of allow policies.

  2. Tool list filtering — unauthorized tools are hidden from tools/list.
     Users don't even see tools they can't use.

  3. Tool call enforcement — direct calls to unauthorized tools return
     an error, even if the caller knows the tool name.

  4. Priority ordering — higher priority policies are evaluated first.

Policy fields:
  - adapter_name: which adapter (or "*" for all)
  - tool_name:    which tool (or "drop_*" for wildcards)
  - effect:       "allow" or "deny"
  - allowed_groups / denied_groups: group-based access
  - priority:     evaluation order (higher = first)
MODEL

ok "Deny-takes-precedence with priority ordering"

# Set up auth header for policy API calls
if [ -n "$AUTH_TOKEN" ]; then
  AUTH_HEADER="Authorization: Bearer ${AUTH_TOKEN}"
else
  AUTH_HEADER="X-User-ID: admin"
fi

# Helper: make an API call and handle auth errors
api_call() {
  local RESPONSE HTTP_CODE
  RESPONSE=$(curl ${CURL_INSECURE} -s -w "\n%{http_code}" -X "$1" "${PROXY_URL}$2" \
    -H "Content-Type: application/json" \
    -H "${AUTH_HEADER}" \
    ${3:+-d "$3"} 2>&1) || true
  HTTP_CODE=$(echo "$RESPONSE" | tail -1)
  RESPONSE=$(echo "$RESPONSE" | sed '$d')

  if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    echo -e "${RED}FAIL${NC}: Authentication required (HTTP ${HTTP_CODE}). Run demo 02 first and export AUTH_TOKEN." >&2
    return 1
  elif [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    echo "$RESPONSE"
    return 0
  else
    echo -e "${RED}FAIL${NC}: Request failed (HTTP ${HTTP_CODE}): ${RESPONSE:-no response}" >&2
    return 1
  fi
}

# ─── Step 2: Create restrictive policy ───────────────────────────────

step 2 "Create Policy: Only database-admins Can Use drop_table"

info "This policy restricts the drop_table tool on the Databricks adapter"
info "to members of the database-admins group."
echo ""

if POLICY_1=$(api_call POST "/api/v1/auth/policies" '{
    "adapter_name": "databricks",
    "tool_name": "drop_table",
    "effect": "allow",
    "allowed_groups": ["database-admins"],
    "priority": 100
  }'); then
  echo "$POLICY_1" | jq .
  POLICY_1_ID=$(echo "$POLICY_1" | jq -r '.policy_id // empty')
  ok "Policy created: ${POLICY_1_ID:-ok}"
fi

# ─── Step 3: Create deny policy ─────────────────────────────────────

step 3 "Create Policy: Deny Interns from All Destructive Tools"

info "This deny policy matches any tool starting with 'drop_' on any adapter."
info "Because deny takes precedence, even if an intern is also in"
info "database-admins, they cannot use these tools."
echo ""

if POLICY_2=$(api_call POST "/api/v1/auth/policies" '{
    "adapter_name": "*",
    "tool_name": "drop_*",
    "effect": "deny",
    "denied_groups": ["interns"],
    "priority": 200
  }'); then
  echo "$POLICY_2" | jq .
  ok "Deny policy created"
fi

# ─── Step 4: Create read-only policy ────────────────────────────────

step 4 "Create Policy: Read-Only Group Cannot Modify Incidents"

info "Deny update_incident and create_incident for the read-only group."
echo ""

if POLICY_3=$(api_call POST "/api/v1/auth/policies" '{
    "adapter_name": "servicenow",
    "tool_name": "update_incident",
    "effect": "deny",
    "denied_groups": ["read-only"],
    "priority": 150
  }'); then
  echo "$POLICY_3" | jq .
  ok "Read-only deny policy created (update_incident)"
fi

if POLICY_4=$(api_call POST "/api/v1/auth/policies" '{
    "adapter_name": "servicenow",
    "tool_name": "create_incident",
    "effect": "deny",
    "denied_groups": ["read-only"],
    "priority": 150
  }'); then
  echo "$POLICY_4" | jq .
  ok "Read-only deny policy created (create_incident)"
fi

# ─── Step 5: List all policies ───────────────────────────────────────

step 5 "List All Policies"

if POLICIES=$(api_call GET "/api/v1/auth/policies"); then
  echo "$POLICIES" | jq .
  POLICY_COUNT=$(echo "$POLICIES" | jq 'if type == "array" then length elif .policies then .policies | length else 0 end')
  ok "${POLICY_COUNT} policies configured"
fi

# ─── Step 6: Explain evaluation scenarios ────────────────────────────

step 6 "Policy Evaluation Scenarios"

cat <<'SCENARIOS'
Scenario 1: User in "database-admins" calls databricks__drop_table
  -> Policy 1 (priority 100): ALLOW (user in allowed_groups)
  -> No deny policies match
  -> Result: ALLOWED

Scenario 2: User in "interns" AND "database-admins" calls databricks__drop_table
  -> Policy 2 (priority 200, evaluated first): DENY (user in denied_groups)
  -> Deny takes precedence over Policy 1's allow
  -> Result: DENIED

Scenario 3: User in "interns" calls servicenow__search_incidents
  -> Policy 2: No match (tool "search_incidents" doesn't match "drop_*")
  -> No other deny policies match
  -> Default: ALLOWED (no explicit deny)
  -> Result: ALLOWED

Scenario 4: User in "read-only" calls servicenow__update_incident
  -> Policy 3 (priority 150): DENY (user in denied_groups)
  -> Result: DENIED
  -> Also: update_incident is hidden from this user's tools/list

Scenario 5: User in "read-only" calls servicenow__search_incidents
  -> No deny policies match for search_incidents
  -> Result: ALLOWED
SCENARIOS

ok "Policies are evaluated per-request using the user's JWT claims"

# ─── Step 7: Audit logging ──────────────────────────────────────────

step 7 "Audit Trail"

info "Every policy decision is logged for compliance:"
echo ""
echo '  {"event":"tool_access_denied","user_id":"intern-42",'
echo '   "adapter":"databricks","tool":"drop_table",'
echo '   "detail":"denied_by_policy=pol-abc123",'
echo '   "timestamp":"2026-03-27T10:15:00Z"}'
echo ""
info "Audit events include: login, token_issued, access_denied, policy_changed"
ok "Structured audit logging for compliance requirements"

# ─── Summary ─────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}=== Tool Policies Demo Complete ===${NC}"
echo ""
echo "What we demonstrated:"
echo "  1. Allow policies with group restrictions"
echo "  2. Deny policies with wildcard matching"
echo "  3. Deny-takes-precedence evaluation"
echo "  4. Tool list filtering (unauthorized tools hidden)"
echo "  5. Tool call enforcement (direct calls blocked)"
echo "  6. Priority-based evaluation ordering"
echo "  7. Structured audit logging"
echo ""
echo "Policy enforcement points:"
echo "  - tools/list:  Unauthorized tools are removed from the response"
echo "  - tools/call:  Returns error before the request reaches the adapter"
echo "  - Audit log:   All denials logged with policy ID and user context"
echo ""
echo "Next: Run 07-spiffe-workload-identity for zero-trust workload auth."
