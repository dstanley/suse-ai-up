# 01 - OAuth Discovery & Dynamic Client Registration

Demonstrates how an MCP client discovers the proxy's OAuth endpoints and registers itself dynamically, using RFC 9728, RFC 8414, and RFC 7591.

## What It Shows

1. Protected Resource Metadata (RFC 9728) — tells clients where to authenticate
2. Authorization Server Metadata (RFC 8414) — exposes all OAuth endpoints
3. Dynamic Client Registration (RFC 7591) — no pre-shared client credentials needed
4. 401 WWW-Authenticate challenge — standard OAuth error response

## Prerequisites

- A running proxy instance
- `curl` and `jq`

## Quick Start

```bash
# Run the demo against a running proxy
./demo.sh
```

## How It Works

An MCP client needs to discover the authorization server before it can authenticate:

1. Fetches `/.well-known/oauth-protected-resource` to find the authorization server URL and supported scopes
2. Fetches `/.well-known/oauth-authorization-server` to discover the authorization, token, registration, and revocation endpoints
3. POSTs to the registration endpoint with a client name and redirect URI to receive a `client_id`
4. Hits a protected endpoint without a token to observe the 401 challenge with a `WWW-Authenticate` header

No pre-shared credentials are needed. The client registers on the fly and is ready to start a PKCE authorization flow.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_URL` | `http://localhost:8911` | Proxy base URL |
| `REDIRECT_URI` | `http://localhost:3000/callback` | OAuth redirect URI for the registered client |
| `CURL_INSECURE` | `-k` | Set to empty string to enforce TLS verification |
