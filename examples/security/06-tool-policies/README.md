# 06 - Tool-Level Authorization Policies

Demonstrates deny-takes-precedence access control policies, tool list filtering, and tool call enforcement against a running proxy.

## What It Shows

1. Deny-takes-precedence policy evaluation model
2. Allow policies with group-based restrictions
3. Deny policies with wildcard tool matching (e.g., `drop_*`)
4. Tool list filtering (unauthorized tools hidden from `tools/list`)
5. Tool call enforcement (direct calls to blocked tools return errors)
6. Priority-based policy evaluation ordering
7. Structured audit logging for compliance
8. **Zero trust architecture patterns** using wildcard policies

## Prerequisites

- A running proxy instance
- `curl` and `jq`

## Quick Start

```bash
# Ensure the proxy is running, then:
./demo.sh
```

There is no `docker-compose.yml` for this example. The script creates policies against a live proxy and walks through evaluation scenarios.

## Zero Trust Architecture

The wildcard support in tool policies enables a **zero trust architecture** where nothing is trusted by default:

### Default Deny Everything

Create a baseline policy that blocks all tools on all adapters:

```bash
curl -X POST "${PROXY_URL}/api/v1/auth/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "adapter_name": "*",
    "tool_name": "*",
    "effect": "deny",
    "priority": 0
  }'
```

### Explicitly Allow What's Needed

Then add higher-priority policies to grant specific access:

```bash
curl -X POST "${PROXY_URL}/api/v1/auth/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "adapter_name": "databricks",
    "tool_name": "run_query",
    "effect": "allow",
    "allowed_groups": ["analysts"],
    "required_scopes": ["sql:read"],
    "priority": 10
  }'
```

### Zero Trust Principles Implemented

| Principle | Implementation |
|-----------|----------------|
| Never trust, always verify | Every tool call checked against policy engine |
| Least privilege | Scope policies map groups → minimum required scopes |
| Assume breach | Default deny; explicit allow required for each tool |
| Defense in depth | JWT → scope resolution → tool authz → downstream auth |

## Defense in Depth

Tool policies are one layer in a multi-layer security architecture:

```
Request arrives
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. JWT Validation                                               │
│     Validates signature, expiration, audience                    │
│     Extracts: UserID, Email, Groups, Roles                      │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. Scope Resolution                                             │
│     User's OIDC groups → backend-specific scopes                │
│     e.g., "data-engineers" → ["sql:write", "clusters:manage"]   │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. Tool Authorization (THIS EXAMPLE)                            │
│     Policy engine evaluates: allowed_groups, denied_groups,      │
│     required_scopes against user context                        │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. Downstream Authentication                                    │
│     Token exchange / service account / SPIFFE                   │
│     User's resolved scopes sent to backend                      │
└─────────────────────────────────────────────────────────────────┘
```

## How It Works

The proxy evaluates tool-level policies on every `tools/list` and `tools/call` request:

1. Policies are created via `POST /api/v1/auth/policies` with an adapter name, tool name (supports wildcards), effect (`allow` or `deny`), group lists, and a priority
2. On each request the proxy collects all matching policies, ordered by priority (highest first)
3. **Deny takes precedence** -- if any deny policy matches, access is blocked regardless of allow policies
4. For `tools/list`, denied tools are removed from the response so users never see tools they cannot use
5. For `tools/call`, a direct call to a denied tool returns an error before the request reaches the adapter
6. Every policy decision is written to the audit log with the policy ID, user context, and timestamp

## Policy Fields

| Field | Description |
|-------|-------------|
| `adapter_name` | Target adapter or `*` for all |
| `tool_name` | Target tool, supports wildcards like `drop_*` |
| `effect` | `allow` or `deny` |
| `allowed_groups` | User must be in one of these groups |
| `denied_groups` | User must NOT be in any of these groups |
| `allowed_users` | User ID/email must match |
| `denied_users` | User ID/email must NOT match |
| `required_scopes` | User must have ALL of these resolved scopes |
| `priority` | Higher priority evaluated first |

## Combining Groups and Scopes

Policies can require both group membership AND specific scopes:

```json
{
  "adapter_name": "databricks",
  "tool_name": "drop_table",
  "effect": "allow",
  "allowed_groups": ["data-engineers"],
  "required_scopes": ["sql:write"],
  "priority": 10
}
```

This means:
- User must be in `data-engineers` group (from OIDC claims)
- User must have `sql:write` scope (resolved from scope policies)
- Both conditions must be true for access

## Security Note: Header Injection Protection

The proxy creates fresh HTTP requests to backend adapters. Client-supplied headers (like a spoofed `X-User-Scopes`) are **never** forwarded. The scope header sent to backends is set by the proxy based on validated JWT claims and scope policy resolution.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_URL` | `http://localhost:8911` | Proxy base URL |
| `CURL_INSECURE` | `-k` | Set to empty string to enforce TLS verification |
| `AUTH_TOKEN` | | Bearer token for OAuth-enabled deployments |

## Next Steps

- **07-spiffe-workload-identity**: Zero-trust workload authentication with SPIFFE/SPIRE
- See `SECURITY.md` in the repository root for comprehensive security documentation
