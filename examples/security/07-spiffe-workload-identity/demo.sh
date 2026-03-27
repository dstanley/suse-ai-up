#!/usr/bin/env bash
# 07 — SPIFFE/SPIRE Workload Identity
# Demonstrates JWT SVID token exchange and mTLS modes.
# Note: Full execution requires a running SPIRE agent.
set -euo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8911}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

step() { echo -e "\n${CYAN}=== Step $1: $2 ===${NC}\n"; }
ok()   { echo -e "${GREEN}OK${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }
info() { echo -e "${YELLOW}INFO${NC}: $1"; }

echo -e "${CYAN}SPIFFE/SPIRE Workload Identity${NC}"
echo "Proxy: ${PROXY_URL}"
echo ""

info "This example describes the SPIFFE integration architecture."
info "Full execution requires a SPIRE agent running on the node."
info "Enable with: SPIRE_ENABLED=true SPIRE_AGENT_SOCKET_PATH=/tmp/spire-agent/public/api.sock"
echo ""

# ─── Step 1: SPIFFE Overview ─────────────────────────────────────────

step 1 "What is SPIFFE/SPIRE?"

cat <<'OVERVIEW'
SPIFFE (Secure Production Identity Framework for Everyone) provides
cryptographic workload identity without secrets management.

SPIRE (SPIFFE Runtime Environment) is the reference implementation:

  SPIRE Server
    |-- Issues identity documents (SVIDs) to workloads
    |-- Manages trust bundles and attestation policies
    |
  SPIRE Agent (runs on each node)
    |-- Attests workloads via kernel metadata, k8s API, etc.
    |-- Serves SVIDs via the Workload API (Unix domain socket)
    |
  Workload (SUSE AI Universal Proxy)
    |-- Calls SPIRE Agent to get SVIDs
    |-- Uses SVIDs for authentication to downstream services
OVERVIEW

ok "Identity without static secrets"

# ─── Step 2: JWT SVID Mode ──────────────────────────────────────────

step 2 "Mode 1: JWT SVID Token Exchange"

info "In JWT SVID mode, the proxy fetches a JWT from the SPIRE agent"
info "and uses it as the subject_token in an RFC 8693 token exchange."
info "This replaces the Rancher ID token for workload-to-workload flows."
echo ""

cat <<'JSON'
{
  "name": "databricks-spiffe",
  "remoteUrl": "http://databricks-mcp:8001/mcp",
  "connectionType": "remote-http",
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
JSON

echo ""

cat <<'FLOW'
Flow:
  1. User calls databricks-spiffe__execute_sql via the unified endpoint
  2. Proxy validates the user's OAuth token (same as always)
  3. Instead of using the user's Rancher ID token, the proxy calls:
     SPIRE Agent -> FetchJWTSVID(audience="https://databricks.example.com")
  4. SPIRE returns a JWT SVID signed by the SPIRE server
  5. Proxy exchanges the JWT SVID at Databricks' token endpoint:
     POST https://accounts.cloud.databricks.com/oidc/v1/token
     grant_type=urn:ietf:params:oauth:token-type:token-exchange
     subject_token=<jwt-svid>
     subject_token_type=urn:ietf:params:oauth:token-type:jwt
  6. Databricks trusts the SPIRE CA and issues a Databricks token
  7. Proxy forwards the request with the Databricks token

Why use this over Rancher ID token exchange?
  - Workload identity is independent of user session
  - Trust is based on workload attestation, not user credentials
  - Works for service-to-service flows without a user context
  - SPIRE handles credential rotation automatically
FLOW

ok "JWT SVID replaces the Rancher ID token as the subject_token"

# ─── Step 3: mTLS Mode ──────────────────────────────────────────────

step 3 "Mode 2: X.509 SVID mTLS"

info "In mTLS mode, the proxy uses X.509 SVIDs for mutual TLS."
info "No bearer tokens needed — identity is at the transport layer."
echo ""

cat <<'JSON'
{
  "name": "internal-service",
  "remoteUrl": "https://internal-mcp.mesh.local/mcp",
  "connectionType": "remote-http",
  "authentication": {
    "required": true,
    "type": "spiffe",
    "spiffe": {
      "use_mtls": true
    }
  }
}
JSON

echo ""

cat <<'FLOW'
Flow:
  1. Proxy calls SPIRE Agent -> GetX509SVID()
  2. SPIRE returns:
     - X.509 certificate (with SPIFFE ID as SAN)
     - Private key
     - Trust bundle (CA certificates)
  3. Proxy creates a TLS client with the X.509 SVID
  4. Proxy connects to the downstream service via mTLS:
     - Client presents its SVID certificate
     - Server presents its SVID certificate
     - Both verify against the shared trust bundle
  5. No Authorization header needed — identity is the certificate

Advantages of mTLS:
  - Zero bearer tokens in transit — nothing to intercept or replay
  - Mutual authentication — both sides prove identity
  - Automatic rotation — SPIRE agent handles certificate renewal
  - Transport-layer security — cannot be bypassed by application code
  - Works with any protocol (HTTP, gRPC, TCP)
FLOW

ok "Certificate-based identity — no tokens to manage or leak"

# ─── Step 4: SPIRE Agent interaction ─────────────────────────────────

step 4 "SPIRE Agent Workload API"

info "The proxy communicates with the SPIRE agent via a Unix domain socket."
info "Default path: /tmp/spire-agent/public/api.sock"
echo ""

cat <<'API'
Proxy <-> SPIRE Agent communication:

  FetchJWTSVID(audience)
    Request:  audience = "https://databricks.example.com"
    Response: JWT signed by SPIRE server CA
              SPIFFE ID: spiffe://trust-domain/proxy

  GetX509SVID()
    Response: X.509 certificate + private key
              SAN: spiffe://trust-domain/proxy
              Trust bundle: SPIRE CA certificates
              Auto-rotated before expiry

  GetSVIDInfo()
    Response: Current SPIFFE ID, trust domain, certificate details
              Used for diagnostics and health checks
API

echo ""
info "Checking if SPIRE agent is available..."

SPIRE_SOCKET="${SPIRE_AGENT_SOCKET_PATH:-/tmp/spire-agent/public/api.sock}"
if [ -S "$SPIRE_SOCKET" ]; then
  ok "SPIRE agent socket found at ${SPIRE_SOCKET}"
else
  info "SPIRE agent not available at ${SPIRE_SOCKET}"
  info "To set up SPIRE, see: https://spiffe.io/docs/latest/try/getting-started/"
fi

# ─── Step 5: Configuration ──────────────────────────────────────────

step 5 "Proxy Configuration"

cat <<'CONFIG'
Environment variables for SPIFFE support:

  SPIRE_ENABLED=true
    Enables the SPIFFE client in the proxy.
    When false (default), SPIFFE adapters will fail gracefully.

  SPIRE_AGENT_SOCKET_PATH=/tmp/spire-agent/public/api.sock
    Path to the SPIRE agent's Workload API socket.
    In Kubernetes, this is typically mounted from the host.

  SPIFFE_DEFAULT_AUDIENCE=https://example.com
    Default audience for JWT SVIDs when not specified per-adapter.

The proxy initializes the SPIFFE client at startup:
  - If SPIRE agent is unreachable, logs a warning and continues
  - SPIFFE adapters will return errors, other auth types work normally
  - When the agent becomes available, SVIDs are fetched on demand
CONFIG

ok "SPIFFE is opt-in per adapter, graceful degradation when unavailable"

# ─── Step 6: Comparison of auth strategies ───────────────────────────

step 6 "Auth Strategy Comparison"

cat <<'TABLE'
+-------------------+------------------+------------------+------------------+
| Feature           | Token Exchange   | Service Account  | SPIFFE           |
+-------------------+------------------+------------------+------------------+
| Identity basis    | User's IdP token | Shared SA creds  | Workload cert/JWT|
| Per-user tokens   | Yes              | No (impersonate) | No (workload)    |
| Credential source | Rancher OIDC     | CSI Secret Store | SPIRE Agent      |
| Rotation          | Token expiry     | Manual           | Automatic        |
| Trust model       | IdP federation   | Shared secret    | PKI/attestation  |
| Use case          | Cross-IdP access | Legacy systems   | Zero-trust mesh  |
| Example           | Databricks       | ServiceNow       | Internal services|
+-------------------+------------------+------------------+------------------+
TABLE

ok "Choose based on downstream service capabilities and trust requirements"

# ─── Summary ─────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}=== SPIFFE Demo Complete ===${NC}"
echo ""
echo "What we demonstrated:"
echo "  1. JWT SVID mode — workload identity for token exchange"
echo "  2. mTLS mode — certificate-based transport authentication"
echo "  3. SPIRE Agent Workload API interaction"
echo "  4. Configuration and graceful degradation"
echo "  5. Comparison of all three auth strategies"
echo ""
echo "SPIFFE is best suited for:"
echo "  - Zero-trust service mesh environments"
echo "  - Internal service-to-service authentication"
echo "  - Environments where static secrets should be eliminated"
echo "  - Workload-to-workload flows without user context"
