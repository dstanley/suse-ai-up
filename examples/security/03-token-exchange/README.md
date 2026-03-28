# 03 - Token Exchange (RFC 8693)

Demonstrates how the proxy exchanges a user's upstream OIDC ID token for a downstream service token using the RFC 8693 token exchange flow.

## What It Shows

1. Databricks MCP server health check and tool discovery
2. Adapter configuration for token exchange auth
3. The full RFC 8693 exchange flow (upstream ID token -> Databricks access token)
4. In-memory token vault (exchanged tokens are never persisted to disk)

## Prerequisites

- Docker and Docker Compose
- `curl` and `jq`

## Quick Start

```bash
# Start the proxy and mock Databricks MCP server
docker compose up -d

# Run the demo
./demo.sh

# Clean up
docker compose down
```

## How It Works

When an authenticated user calls a Databricks tool through the proxy:

1. Proxy validates the user's bearer token (proxy-issued JWT)
2. Looks up the user's OAuth session to retrieve their upstream ID token
3. POSTs to the Databricks token endpoint with `grant_type=urn:ietf:params:oauth:token-type:token-exchange`
4. Receives a Databricks-scoped access token in return
5. Caches the token in the in-memory vault
6. Forwards the MCP request with the Databricks token

The upstream ID token never leaves the proxy, and each user gets their own downstream token.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_URL` | `http://localhost:8911` | Proxy base URL |
| `DATABRICKS_MCP_URL` | `http://localhost:8001` | Databricks MCP server URL |
| `CURL_INSECURE` | `-k` | Set to empty string to enforce TLS verification |
