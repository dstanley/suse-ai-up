# 04 - Service Account Impersonation

Demonstrates how the proxy authenticates to a downstream MCP server using a shared service account and conveys user identity via an impersonation header.

## What It Shows

1. ServiceNow MCP server health check and tool discovery
2. Adapter configuration for service account authentication
3. The impersonation flow (shared credential + per-user identity header)
4. Incident search and detail retrieval through the proxy

## Prerequisites

- Docker and Docker Compose
- `curl` and `jq`

## Quick Start

```bash
# Start the proxy and mock ServiceNow MCP server
docker compose up -d

# Run the demo
./demo.sh

# Clean up
docker compose down
```

## How It Works

When an authenticated user calls a ServiceNow tool through the proxy:

1. Proxy validates the user's bearer token (proxy-issued JWT)
2. Extracts the user's email claim from the JWT
3. Authenticates to ServiceNow using the shared service account (Basic auth)
4. Adds an impersonation header (`X-UserToken: jdoe@example.com`) so ServiceNow processes the request as that user
5. ServiceNow trusts the proxy's impersonation header and applies per-user access control

Unlike token exchange, this pattern uses a single shared credential for all users. User identity is conveyed via a header rather than embedded in a per-user token.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_URL` | `http://localhost:8911` | Proxy base URL |
| `SERVICENOW_MCP_URL` | `http://localhost:8000` | ServiceNow MCP server URL |
| `CURL_INSECURE` | `-k` | Set to empty string to enforce TLS verification |
