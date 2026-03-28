# 05 - Unified OAuth Endpoint

Demonstrates the aggregated `/api/v1/mcp` endpoint protected by OAuth, routing tool calls to multiple adapters with different downstream authentication strategies.

## What It Shows

1. Two adapters (token exchange and service account) registered behind a single MCP endpoint
2. OAuth middleware protecting the unified endpoint (401 without a bearer token)
3. Automatic downstream credential routing per adapter
4. Tool name prefixing (`servicenow__search_incidents`, `databricks__execute_sql`) to avoid collisions
5. Cross-system correlation scenario using both adapters in one session

## Prerequisites

- Docker and Docker Compose
- `curl` and `jq`

## Quick Start

```bash
# Start the proxy, mock ServiceNow, and mock Databricks MCP servers
docker compose up -d

# Run the demo
./demo.sh

# Clean up
docker compose down
```

## How It Works

The proxy exposes a single MCP endpoint that aggregates tools from all registered adapters:

1. Client connects to `/api/v1/mcp` with an OAuth bearer token
2. Proxy validates the JWT and extracts user claims
3. `tools/list` returns tools from all adapters, prefixed with the adapter name
4. `tools/call` strips the prefix, routes to the correct adapter, and applies the appropriate downstream auth:
   - **ServiceNow** -- Basic auth (service account) + `X-UserToken` impersonation header
   - **Databricks** -- Bearer token from RFC 8693 token exchange
5. The MCP server receives unprefixed tool names and its expected auth headers

This lets an AI assistant query incidents in ServiceNow and error metrics in Databricks through a single connection, with per-user authorization applied differently for each downstream system.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_URL` | `http://localhost:8911` | Proxy base URL |
| `SERVICENOW_MCP_URL` | `http://localhost:8000` | ServiceNow MCP server URL |
| `DATABRICKS_MCP_URL` | `http://localhost:8001` | Databricks MCP server URL |
| `CURL_INSECURE` | `-k` | Set to empty string to enforce TLS verification |
