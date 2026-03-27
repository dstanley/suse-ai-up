# OAuth V2 Example: End-to-End MCP Authentication

This example exercises all authentication flows implemented in the MCP OAuth feature: OAuth 2.1 discovery, Rancher SSO, Databricks token exchange, ServiceNow impersonation, SPIFFE workload identity, and tool-level policies.

## Prerequisites

- Running `suse-ai-up` proxy with OAuth configured
- Rancher instance with OIDC enabled
- `curl` and `jq` installed

## Quick Start

```bash
# Set your proxy endpoint
export PROXY_URL="https://proxy.example.com"

# Run the full demo
./demo.sh
```

## What This Demo Covers

| Step | Flow | What It Tests |
|------|------|---------------|
| 1 | OAuth Discovery | RFC 9728 + RFC 8414 well-known endpoints |
| 2 | Client Registration | RFC 7591 dynamic registration with rate limiting |
| 3 | PKCE Authorization | OAuth 2.1 + Rancher OIDC redirect |
| 4 | Token Exchange | Code-for-token exchange with PKCE verification |
| 5 | Authenticated Access | Bearer token validation, claim extraction |
| 6 | Token Refresh | Refresh token rotation |
| 7 | Databricks Adapter | RFC 8693 token exchange configuration |
| 8 | ServiceNow Adapter | Service account impersonation configuration |
| 9 | SPIFFE Adapter | Workload identity (JWT SVID + mTLS) configuration |
| 10 | Tool Policies | Create, list, evaluate authorization policies |
| 11 | Token Revocation | RFC 7009 revocation |

## Adapter Configuration Examples

### Databricks (Token Exchange)

```json
{
  "name": "databricks-mcp",
  "authentication": {
    "required": true,
    "type": "token_exchange",
    "tokenExchange": {
      "token_endpoint": "https://accounts.cloud.databricks.com/oidc/v1/token",
      "audience": "https://databricks.example.com",
      "resource": "https://databricks.example.com/api/2.0",
      "scopes": ["sql:read", "sql:write", "clusters:read"],
      "subject_token_type": "urn:ietf:params:oauth:token-type:id_token"
    }
  }
}
```

### ServiceNow (Service Account Impersonation)

```json
{
  "name": "servicenow-mcp",
  "authentication": {
    "required": true,
    "type": "service_account",
    "serviceAccount": {
      "username": "mcp-proxy-sa",
      "password": "from-secret-store",
      "impersonation_header": "X-UserToken",
      "impersonation_field": "email"
    }
  }
}
```

### SPIFFE — JWT SVID Token Exchange

Uses a SPIRE-issued JWT SVID as the subject token for RFC 8693 exchange (instead of the user's Rancher ID token). Best for environments where workload identity should be the basis for downstream trust.

```json
{
  "name": "databricks-spiffe-mcp",
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
```

### SPIFFE — mTLS Direct Authentication

Uses X.509 SVIDs for mutual TLS to downstream services. No bearer tokens needed — identity established at transport layer. Certificates auto-rotate via SPIRE agent.

```json
{
  "name": "internal-service-mcp",
  "authentication": {
    "required": true,
    "type": "spiffe",
    "spiffe": {
      "use_mtls": true
    }
  }
}
```

## Authorization Policies

```bash
# Allow only database-admins to use drop_table
curl -X POST "${PROXY_URL}/api/v1/auth/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "adapter_name": "databricks-mcp",
    "tool_name": "drop_table",
    "effect": "allow",
    "allowed_groups": ["database-admins"],
    "priority": 100
  }'

# Deny interns from all destructive tools on all adapters
curl -X POST "${PROXY_URL}/api/v1/auth/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "adapter_name": "*",
    "tool_name": "drop_*",
    "effect": "deny",
    "denied_groups": ["interns"],
    "priority": 200
  }'
```
