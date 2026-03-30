# 07 - SPIFFE/SPIRE Workload Identity

Demonstrates how the proxy uses SPIFFE workload identity for downstream authentication via JWT SVID token exchange and X.509 SVID mTLS.

## What It Shows

1. JWT SVID mode -- SPIRE-issued JWTs used as the subject token in RFC 8693 token exchange
2. mTLS mode -- X.509 SVIDs for certificate-based mutual TLS with no bearer tokens
3. SPIRE Agent Workload API interaction (Unix domain socket)
4. Live cluster verification (pods, health, entries, agents, Tornjak)
5. Comparison of token exchange, service account, and SPIFFE auth strategies

## Prerequisites

- A running Kubernetes cluster (tested on RKE2)
- `helm`, `kubectl`, `curl`, and `jq`
- nginx ingress controller (for Tornjak ingress, optional)

## Quick Start

```bash
# 1. Copy and edit environment variables
cp .env.example .env
# Edit .env with your cluster name, trust domain, etc.

# 2. Install SPIRE (one-time setup)
source .env
./setup.sh

# 3. Run the demo (auto-deploys mock server, runs live token exchange)
./demo.sh
```

`setup.sh` installs SPIRE via Helm and registers the proxy workload. `demo.sh` auto-deploys the mock server into the cluster, registers a SPIFFE adapter on the proxy, and performs full end-to-end MCP tool calls routed through the proxy with workload identity authentication.

## Installing SPIRE (Manual Steps)

If you prefer to install manually instead of using `setup.sh`:

### 1. Add Helm repo

```bash
helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/
helm repo update
```

### 2. Install CRDs first (required)

The SPIFFE chart requires CRDs to be installed separately before the main chart:

```bash
kubectl create namespace spire-system
helm install spire-crds spiffe/spire-crds --namespace spire-system
```

### 3. Install SPIRE server and agent

```bash
helm install spire spiffe/spire --namespace spire-system \
  --set global.spire.clusterName=marv \
  --set global.spire.trustDomain=marv.suse-ai.com
```

**Cluster name** is an arbitrary label used to identify the cluster in multi-cluster federation.

**Trust domain** is the root of all SPIFFE IDs (e.g. `spiffe://marv.suse-ai.com/suse-ai-up`). Choose carefully -- it's permanent for the SPIRE installation and should be unique per trust boundary.

### 4. Verify pods are running

```bash
kubectl -n spire-system get pods
# Expected:
#   spire-server-0                                 2/2  Running
#   spire-agent-xxxxx                              1/1  Running  (one per node)
#   spire-spiffe-csi-driver-xxxxx                  2/2  Running
#   spire-spiffe-oidc-discovery-provider-xxxxx     2/2  Running
```

### 5. Register the proxy workload

```bash
kubectl -n spire-system exec -it spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://marv.suse-ai.com/suse-ai-up \
  -parentID spiffe://marv.suse-ai.com/agent \
  -selector k8s:namespace:suse-ai-up \
  -selector k8s:sa:suse-ai-up-proxy-sa
```

### 6. Enable SPIFFE in the proxy

```bash
helm upgrade suse-ai-up ./charts/suse-ai-up --reuse-values \
  --set spiffe.enabled=true
```

This mounts the SPIRE agent socket into the proxy pod and sets the required environment variables automatically.

## Mock Server (End-to-End Demo)

The mock server provides a complete token exchange and MCP endpoint for demonstrating the full SPIFFE flow without external dependencies. No Python packages required -- uses only the standard library.

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/token` | POST | RFC 8693 token exchange (accepts JWT SVID, returns bearer token) |
| `/mcp` | POST | Mock MCP server (tools/list, tools/call -- requires exchanged bearer token) |

### Running the Mock Server

**In-cluster (recommended)** -- `demo.sh` auto-deploys the mock server into the proxy namespace using `mock-server/k8s.yaml`. The server.py is loaded via ConfigMap, so no container image build is required.

```bash
# Manual deploy (demo.sh does this automatically):
kubectl -n suse-ai-up create configmap spiffe-mock-server --from-file=server.py=mock-server/server.py
kubectl -n suse-ai-up apply -f mock-server/k8s.yaml
```

The proxy reaches it at `http://spiffe-mock-server.suse-ai-up.svc.cluster.local:8002`.

**Local with Docker:**

```bash
docker compose up -d
```

**Local without Docker:**

```bash
python3 mock-server/server.py &
```

Note: When running locally, the proxy pod cannot reach `localhost:8002`. Use the in-cluster deployment for the full end-to-end flow through the proxy.

### Demo Flow

When the proxy and mock server are both running, `demo.sh` performs the full end-to-end round-trip through the proxy:

1. **Register adapter** -- Create a `databricks_spiffe` adapter on the proxy with `type: "spiffe"` and `tokenExchange` config pointing at the mock server
2. **Call tools via proxy** -- POST `tools/list` and `tools/call` to the proxy's unified `/api/v1/mcp` endpoint
3. **Proxy fetches SVID** -- Proxy calls SPIRE agent `FetchJWTSVID()` for workload identity
4. **Token exchange** -- Proxy exchanges the JWT SVID at the mock `/token` endpoint (RFC 8693)
5. **Forward request** -- Proxy calls mock `/mcp` with the exchanged bearer token
6. **Verify identity** -- Tool results include `authenticated_via: "spiffe_token_exchange"` and `workload_identity` fields

```
Client -> Proxy (OAuth) -> SPIRE Agent (JWT SVID) -> Token Exchange -> Mock MCP Server
```

The mock MCP server exposes three tools: `get_cluster_status`, `execute_sql`, and `get_workspace_info`.

## Tornjak Web UI (Optional)

Tornjak provides a web dashboard for managing SPIRE entries, agents, and trust domains.

### Enabling Tornjak

Both the frontend and backend must be enabled separately:

```bash
helm upgrade spire spiffe/spire --namespace spire-system --reuse-values \
  --set tornjak-frontend.enabled=true \
  --set spire-server.tornjak.enabled=true \
  --set "tornjak-frontend.apiServerURL=http://localhost:10000"
```

Or with `setup.sh`:

```bash
ENABLE_TORNJAK=true ./setup.sh
```

### Accessing Tornjak

Port-forward both the backend API and frontend in separate terminals:

```bash
# Terminal 1: Tornjak backend API
kubectl -n spire-system port-forward svc/spire-tornjak-backend 10000:10000

# Terminal 2: Tornjak frontend
kubectl -n spire-system port-forward svc/spire-tornjak-frontend 3500:3000
```

Then open `http://localhost:3500`.

### Tornjak Troubleshooting

- **"Invalid origin" error**: Newer versions of the `serve` static server reject requests where the `Host` header doesn't match. Use port-forward (above) rather than ingress to avoid this.
- **Frontend prompting for API URL**: The Tornjak backend wasn't enabled. Make sure both `tornjak-frontend.enabled=true` and `spire-server.tornjak.enabled=true` are set.
- **Port 3000 conflict**: Use a different local port for the frontend, e.g. `port-forward svc/spire-tornjak-frontend 3500:3000`.

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

### demo.sh

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_URL` | `http://localhost:8911` | Proxy base URL |
| `CURL_INSECURE` | `-k` | Set to empty string to enforce TLS verification |
| `SPIRE_NAMESPACE` | `spire-system` | Namespace where SPIRE is installed |
| `SPIRE_SERVER_POD` | `spire-server-0` | SPIRE server pod name |
| `PROXY_NAMESPACE` | `suse-ai-up` | Namespace where proxy and mock server run |
| `MOCK_SERVER_URL` | `http://localhost:8002` | Mock server URL for local testing |
| `MOCK_SERVER_CLUSTER_URL` | `http://spiffe-mock-server.<ns>.svc.cluster.local:8002` | In-cluster URL the proxy uses to reach mock server |
| `AUTH_TOKEN` | *(none)* | OAuth token from demo 02 (falls back to dev-mode `X-User-ID: admin`) |

### setup.sh

| Variable | Default | Description |
|----------|---------|-------------|
| `SPIRE_NAMESPACE` | `spire-system` | Namespace for SPIRE installation |
| `SPIRE_CLUSTER_NAME` | `marv` | Cluster name for SPIRE (arbitrary label) |
| `SPIRE_TRUST_DOMAIN` | `marv.suse-ai.com` | Trust domain for SPIFFE IDs (permanent) |
| `SPIRE_SERVER_POD` | `spire-server-0` | SPIRE server pod name |
| `PROXY_NAMESPACE` | `suse-ai-up` | Namespace where the proxy runs |
| `PROXY_SERVICE_ACCOUNT` | `suse-ai-up-proxy-sa` | Proxy service account name |
| `ENABLE_TORNJAK` | `false` | Set to `true` to install Tornjak UI |

### Set automatically by Helm when `spiffe.enabled=true`

| Variable | Default | Description |
|----------|---------|-------------|
| `SPIRE_ENABLED` | `false` | Enable the SPIFFE client in the proxy |
| `SPIRE_AGENT_SOCKET_PATH` | `/run/spire/sockets/agent.sock` | Path to the SPIRE agent Workload API socket |
| `SPIFFE_DEFAULT_AUDIENCE` | *(none)* | Default audience for JWT SVIDs when not set per-adapter |

## Proxy Helm Values

```yaml
spiffe:
  enabled: true
  agentSocketPath: "/run/spire/sockets/agent.sock"
  defaultAudience: "https://example.com"  # optional
```
