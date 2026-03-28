# 02 - PKCE Authorization Code Flow

Demonstrates the full OAuth 2.1 PKCE (S256) authorization code flow through the proxy, with delegated authentication to an upstream OIDC identity provider.

## What It Shows

1. Endpoint discovery and dynamic client registration
2. PKCE code verifier/challenge generation (S256)
3. Authorization redirect through the upstream identity provider
4. Token exchange with PKCE verification
5. Authenticated MCP request using a proxy-issued JWT
6. Refresh token rotation
7. Token revocation (RFC 7009)

## Prerequisites

- A running proxy instance with an upstream OIDC identity provider configured
- `curl`, `jq`, and `openssl`
- A browser to complete the identity provider login

## Quick Start

```bash
# Run the demo against a running proxy
./demo.sh
```

The script will print an authorization URL. Open it in a browser, authenticate with your identity provider, then paste the authorization code back into the terminal to complete the flow.

## How It Works

1. Discovers OAuth endpoints via `/.well-known/oauth-authorization-server`
2. Registers a public client dynamically (RFC 7591, `token_endpoint_auth_method: none`)
3. Generates a random `code_verifier` and computes `code_challenge = BASE64URL(SHA256(code_verifier))`
4. Builds an authorization URL with the challenge and opens it in a browser
5. The proxy stores the challenge in an encrypted session cookie, then redirects to the identity provider
6. After the user authenticates, the proxy issues an authorization code to the redirect URI
7. The client exchanges the code + `code_verifier` at the token endpoint; the proxy verifies `SHA256(verifier) == challenge`
8. The proxy returns a proxy-issued JWT containing enterprise identity claims
9. The client uses the JWT as a bearer token to call protected MCP endpoints
10. Refresh tokens are rotated on each use; tokens can be revoked via RFC 7009

The upstream identity provider token never leaves the proxy. Clients only see proxy-issued JWTs.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_URL` | `http://localhost:8911` | Proxy base URL |
| `REDIRECT_URI` | `http://localhost:3000/callback` | OAuth redirect URI for the registered client |
| `CURL_INSECURE` | `-k` | Set to empty string to enforce TLS verification |
