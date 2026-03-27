# Security Examples

End-to-end examples demonstrating the SUSE AI Universal Proxy's OAuth 2.1 authentication, downstream credential management, and tool-level authorization. Each example focuses on a single security capability and can be run independently.

## Prerequisites

- Running `suse-ai-up` proxy (or Docker Compose from the example)
- `curl` and `jq` installed
- For examples 03-05: Docker (to run the mock MCP servers)

## Examples

| # | Directory | What It Demonstrates |
|---|-----------|---------------------|
| 01 | [oauth-discovery](01-oauth-discovery/) | RFC 9728 + RFC 8414 metadata discovery, RFC 7591 dynamic client registration |
| 02 | [pkce-auth-flow](02-pkce-auth-flow/) | Full OAuth 2.1 PKCE (S256) authorization code flow with Rancher OIDC |
| 03 | [token-exchange](03-token-exchange/) | RFC 8693 token exchange — proxy exchanges Rancher ID token for Databricks token |
| 04 | [service-account](04-service-account/) | Service account impersonation — proxy authenticates as SA, impersonates user to ServiceNow |
| 05 | [unified-oauth](05-unified-oauth/) | Unified `/api/v1/mcp` endpoint with OAuth + both Databricks and ServiceNow adapters |
| 06 | [tool-policies](06-tool-policies/) | Tool-level authorization policies — deny-takes-precedence, tool filtering, call enforcement |
| 07 | [spiffe-workload-identity](07-spiffe-workload-identity/) | SPIFFE/SPIRE JWT SVID token exchange and mTLS (requires SPIRE agent) |

## Architecture

All examples follow the same pattern:

```
MCP Client (curl)
    |
    | OAuth 2.1 + Bearer Token
    v
SUSE AI Universal Proxy
    |
    | Downstream Auth (per adapter type)
    v
MCP Server (ServiceNow / Databricks mock)
```

The proxy handles all authentication concerns:
- **Inbound**: OAuth 2.1 discovery, PKCE, JWT validation, tool-level policy enforcement
- **Outbound**: Token exchange (RFC 8693), service account impersonation, SPIFFE (JWT SVID / mTLS)

## Mock MCP Servers

Examples 03-05 use the ServiceNow and Databricks mock MCP servers from `../servicenow-databricks-demo/servers/`. In mock mode, these servers return realistic demo data without requiring real credentials. The proxy still applies full downstream authentication — the mock servers simply accept any inbound auth headers.

## Quick Start

```bash
# Start with the simplest example
cd 01-oauth-discovery
./demo.sh

# For examples with MCP servers, start Docker Compose first
cd 03-token-exchange
docker compose up -d
./demo.sh
```

## Standards Compliance

These examples collectively exercise:

- RFC 9728 — Protected Resource Metadata
- RFC 8414 — Authorization Server Metadata
- RFC 7591 — Dynamic Client Registration
- RFC 8693 — Token Exchange
- RFC 7009 — Token Revocation
- OAuth 2.1 — PKCE mandatory (S256), no implicit grant
