# 07 - SPIFFE/SPIRE Workload Identity

Demonstrates how the proxy uses SPIFFE workload identity for downstream authentication via JWT SVID token exchange and X.509 SVID mTLS.

## What It Shows

1. JWT SVID mode -- SPIRE-issued JWTs used as the subject token in RFC 8693 token exchange
2. mTLS mode -- X.509 SVIDs for certificate-based mutual TLS with no bearer tokens
3. SPIRE Agent Workload API interaction (Unix domain socket)
4. Per-adapter SPIFFE configuration with graceful degradation
5. Comparison of token exchange, service account, and SPIFFE auth strategies

## Prerequisites

- A running proxy instance
- A SPIRE agent running on the node (for full execution)
- `curl` and `jq`

## Quick Start

```bash
# Start the SPIRE agent (see https://spiffe.io/docs/latest/try/getting-started/)
# Enable SPIFFE in the proxy:
export SPIRE_ENABLED=true
export SPIRE_AGENT_SOCKET_PATH=/tmp/spire-agent/public/api.sock

# Run the demo
./demo.sh
```

There is no `docker-compose.yml` for this example. The script describes the SPIFFE architecture and checks for a local SPIRE agent. Full execution requires a running SPIRE agent.

## How It Works

SPIFFE provides cryptographic workload identity without static secrets. The proxy supports two modes:

**JWT SVID Token Exchange**

1. User calls a SPIFFE-enabled adapter through the proxy
2. Proxy validates the user's OAuth token as usual
3. Instead of the user's upstream ID token, the proxy calls the SPIRE agent (`FetchJWTSVID`) to obtain a JWT signed by the SPIRE server
4. Proxy exchanges the JWT SVID at the downstream token endpoint using RFC 8693
5. Downstream service trusts the SPIRE CA and issues an access token
6. Proxy forwards the MCP request with the downstream token

**X.509 SVID mTLS**

1. Proxy calls the SPIRE agent (`GetX509SVID`) to obtain an X.509 certificate, private key, and trust bundle
2. Proxy connects to the downstream service via mutual TLS -- both sides present and verify certificates
3. No `Authorization` header needed; identity lives at the transport layer
4. SPIRE agent handles automatic certificate rotation

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_URL` | `http://localhost:8911` | Proxy base URL |
| `SPIRE_ENABLED` | `false` | Enable the SPIFFE client in the proxy |
| `SPIRE_AGENT_SOCKET_PATH` | `/tmp/spire-agent/public/api.sock` | Path to the SPIRE agent Workload API socket |
| `SPIFFE_DEFAULT_AUDIENCE` | *(none)* | Default audience for JWT SVIDs when not set per-adapter |
| `CURL_INSECURE` | `-k` | Set to empty string to enforce TLS verification |
