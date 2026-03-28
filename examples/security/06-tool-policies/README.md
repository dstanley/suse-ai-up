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

## Prerequisites

- A running proxy instance
- `curl` and `jq`

## Quick Start

```bash
# Ensure the proxy is running, then:
./demo.sh
```

There is no `docker-compose.yml` for this example. The script creates policies against a live proxy and walks through evaluation scenarios.

## How It Works

The proxy evaluates tool-level policies on every `tools/list` and `tools/call` request:

1. Policies are created via `POST /api/v1/auth/policies` with an adapter name, tool name (supports wildcards), effect (`allow` or `deny`), group lists, and a priority
2. On each request the proxy collects all matching policies, ordered by priority (highest first)
3. **Deny takes precedence** -- if any deny policy matches, access is blocked regardless of allow policies
4. For `tools/list`, denied tools are removed from the response so users never see tools they cannot use
5. For `tools/call`, a direct call to a denied tool returns an error before the request reaches the adapter
6. Every policy decision is written to the audit log with the policy ID, user context, and timestamp

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_URL` | `http://localhost:8911` | Proxy base URL |
| `CURL_INSECURE` | `-k` | Set to empty string to enforce TLS verification |
