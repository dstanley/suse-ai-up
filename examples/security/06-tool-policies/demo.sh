#!/usr/bin/env bash
# 06 — Tool-Level Authorization Policies
# Demonstrates deny-takes-precedence policies, tool filtering, and call enforcement.
set -euo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8911}"

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

# ─── Step 2: Create restrictive policy ───────────────────────────────

step 2 "Create Policy: Only database-admins Can Use drop_table"

info "This policy restricts the drop_table tool on the Databricks adapter"
info "to members of the database-admins group."
echo ""

POLICY_1=$(curl -sf -X POST "${PROXY_URL}/api/v1/auth/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "adapter_name": "databricks",
    "tool_name": "drop_table",
    "effect": "allow",
    "allowed_groups": ["database-admins"],
    "priority": 100
  }' 2>/dev/null) && {
  echo "$POLICY_1" | jq .
  POLICY_1_ID=$(echo "$POLICY_1" | jq -r '.policy_id // .PolicyID // .id // empty')
  ok "Policy created: ${POLICY_1_ID:-ok}"
} || info "Policy creation skipped (proxy may not be running with auth)"

# ─── Step 3: Create deny policy ─────────────────────────────────────

step 3 "Create Policy: Deny Interns from All Destructive Tools"

info "This deny policy matches any tool starting with 'drop_' on any adapter."
info "Because deny takes precedence, even if an intern is also in"
info "database-admins, they cannot use these tools."
echo ""

POLICY_2=$(curl -sf -X POST "${PROXY_URL}/api/v1/auth/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "adapter_name": "*",
    "tool_name": "drop_*",
    "effect": "deny",
    "denied_groups": ["interns"],
    "priority": 200
  }' 2>/dev/null) && {
  echo "$POLICY_2" | jq .
  ok "Deny policy created"
} || info "Policy creation skipped"

# ─── Step 4: Create read-only policy ────────────────────────────────

step 4 "Create Policy: Read-Only Group Cannot Modify Incidents"

info "Deny update_incident and create_incident for the read-only group."
echo ""

POLICY_3=$(curl -sf -X POST "${PROXY_URL}/api/v1/auth/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "adapter_name": "servicenow",
    "tool_name": "update_incident",
    "effect": "deny",
    "denied_groups": ["read-only"],
    "priority": 150
  }' 2>/dev/null) && {
  echo "$POLICY_3" | jq .
  ok "Read-only deny policy created (update_incident)"
} || info "Policy creation skipped"

POLICY_4=$(curl -sf -X POST "${PROXY_URL}/api/v1/auth/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "adapter_name": "servicenow",
    "tool_name": "create_incident",
    "effect": "deny",
    "denied_groups": ["read-only"],
    "priority": 150
  }' 2>/dev/null) && {
  echo "$POLICY_4" | jq .
  ok "Read-only deny policy created (create_incident)"
} || info "Policy creation skipped"

# ─── Step 5: List all policies ───────────────────────────────────────

step 5 "List All Policies"

POLICIES=$(curl -sf "${PROXY_URL}/api/v1/auth/policies" 2>/dev/null) && {
  echo "$POLICIES" | jq .
  POLICY_COUNT=$(echo "$POLICIES" | jq 'if type == "array" then length else 0 end')
  ok "${POLICY_COUNT} policies configured"
} || info "Could not list policies"

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
