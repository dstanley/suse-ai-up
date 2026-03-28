#!/usr/bin/env bash
# 07 — SPIFFE/SPIRE Setup
# Installs SPIRE in the cluster and configures the proxy for SPIFFE workload identity.
# Run this once before running demo.sh.
set -euo pipefail

SPIRE_NAMESPACE="${SPIRE_NAMESPACE:-spire-system}"
SPIRE_CLUSTER_NAME="${SPIRE_CLUSTER_NAME:-marv}"
SPIRE_TRUST_DOMAIN="${SPIRE_TRUST_DOMAIN:-marv.suse-ai.com}"
SPIRE_SERVER_POD="${SPIRE_SERVER_POD:-spire-server-0}"
PROXY_NAMESPACE="${PROXY_NAMESPACE:-suse-ai-up}"
PROXY_SERVICE_ACCOUNT="${PROXY_SERVICE_ACCOUNT:-suse-ai-up-proxy-sa}"
ENABLE_TORNJAK="${ENABLE_TORNJAK:-false}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

step() { echo -e "\n${CYAN}=== Step $1: $2 ===${NC}\n"; }
ok()   { echo -e "${GREEN}OK${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }
info() { echo -e "${YELLOW}INFO${NC}: $1"; }

echo -e "${CYAN}SPIFFE/SPIRE Setup${NC}"
echo "Cluster:      ${SPIRE_CLUSTER_NAME}"
echo "Trust Domain: ${SPIRE_TRUST_DOMAIN}"
echo "Namespace:    ${SPIRE_NAMESPACE}"
echo "Tornjak UI:   ${ENABLE_TORNJAK}"
echo ""

# ─── Step 1: Prerequisites ────────────────────────────────────────

step 1 "Check Prerequisites"

command -v helm &>/dev/null || fail "helm is required but not found"
command -v kubectl &>/dev/null || fail "kubectl is required but not found"
command -v jq &>/dev/null || fail "jq is required but not found"

ok "helm, kubectl, and jq are available"

# ─── Step 2: Add Helm repo ────────────────────────────────────────

step 2 "Add SPIFFE Helm Repository"

helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/ 2>/dev/null || true
helm repo update

ok "SPIFFE Helm repo ready"

# ─── Step 3: Create namespace and install CRDs ────────────────────

step 3 "Install CRDs"

kubectl create namespace "${SPIRE_NAMESPACE}" 2>/dev/null || info "Namespace ${SPIRE_NAMESPACE} already exists"

if helm status spire-crds -n "${SPIRE_NAMESPACE}" &>/dev/null; then
  info "spire-crds already installed, upgrading..."
  helm upgrade spire-crds spiffe/spire-crds --namespace "${SPIRE_NAMESPACE}"
else
  helm install spire-crds spiffe/spire-crds --namespace "${SPIRE_NAMESPACE}"
fi

ok "SPIRE CRDs installed"

# ─── Step 4: Install SPIRE ────────────────────────────────────────

step 4 "Install SPIRE Server and Agent"

HELM_ARGS=(
  --namespace "${SPIRE_NAMESPACE}"
  --set "global.spire.clusterName=${SPIRE_CLUSTER_NAME}"
  --set "global.spire.trustDomain=${SPIRE_TRUST_DOMAIN}"
)

if [ "${ENABLE_TORNJAK}" = "true" ]; then
  HELM_ARGS+=(
    --set "tornjak-frontend.enabled=true"
    --set "spire-server.tornjak.enabled=true"
    --set "tornjak-frontend.apiServerURL=http://localhost:10000"
  )
  info "Tornjak UI will be enabled"
fi

if helm status spire -n "${SPIRE_NAMESPACE}" &>/dev/null; then
  info "SPIRE already installed, upgrading..."
  helm upgrade spire spiffe/spire "${HELM_ARGS[@]}"
else
  helm install spire spiffe/spire "${HELM_ARGS[@]}"
fi

ok "SPIRE installed"

# ─── Step 5: Wait for pods ────────────────────────────────────────

step 5 "Wait for SPIRE Pods"

info "Waiting for SPIRE server to be ready..."
kubectl -n "${SPIRE_NAMESPACE}" wait --for=condition=ready pod/"${SPIRE_SERVER_POD}" --timeout=120s 2>/dev/null || {
  info "Timeout waiting for SPIRE server. Current pod status:"
  kubectl -n "${SPIRE_NAMESPACE}" get pods
  fail "SPIRE server not ready"
}

info "Waiting for SPIRE agent to be ready..."
kubectl -n "${SPIRE_NAMESPACE}" wait --for=condition=ready -l app.kubernetes.io/name=agent pod --timeout=120s 2>/dev/null || {
  info "Timeout waiting for SPIRE agent"
}

echo ""
kubectl -n "${SPIRE_NAMESPACE}" get pods
echo ""
ok "SPIRE pods are running"

# ─── Step 6: Verify health ────────────────────────────────────────

step 6 "Verify SPIRE Health"

HEALTH=$(kubectl -n "${SPIRE_NAMESPACE}" exec "${SPIRE_SERVER_POD}" -c spire-server -- \
  /opt/spire/bin/spire-server healthcheck 2>/dev/null) || true

if echo "$HEALTH" | grep -qi "healthy"; then
  ok "SPIRE server is healthy"
else
  info "SPIRE server health: ${HEALTH:-unknown}"
fi

# ─── Step 7: Register proxy workload ──────────────────────────────

step 7 "Register Proxy Workload"

SPIFFE_ID="spiffe://${SPIRE_TRUST_DOMAIN}/suse-ai-up"

# Check if already registered
EXISTING=$(kubectl -n "${SPIRE_NAMESPACE}" exec "${SPIRE_SERVER_POD}" -c spire-server -- \
  /opt/spire/bin/spire-server entry show -spiffeID "${SPIFFE_ID}" 2>/dev/null) || true

if echo "$EXISTING" | grep -q "Entry ID"; then
  info "Proxy workload already registered:"
  echo "$EXISTING" | head -10
  ok "Registration exists"
else
  info "Registering proxy workload with SPIFFE ID: ${SPIFFE_ID}"
  kubectl -n "${SPIRE_NAMESPACE}" exec "${SPIRE_SERVER_POD}" -c spire-server -- \
    /opt/spire/bin/spire-server entry create \
    -spiffeID "${SPIFFE_ID}" \
    -parentID "spiffe://${SPIRE_TRUST_DOMAIN}/agent" \
    -selector "k8s:namespace:${PROXY_NAMESPACE}" \
    -selector "k8s:sa:${PROXY_SERVICE_ACCOUNT}" || fail "Failed to register workload"
  ok "Proxy workload registered"
fi

# ─── Step 8: Tornjak access ──────────────────────────────────────

if [ "${ENABLE_TORNJAK}" = "true" ]; then
  step 8 "Tornjak UI Access"

  TORNJAK_SVC=$(kubectl -n "${SPIRE_NAMESPACE}" get svc spire-tornjak-backend --no-headers 2>/dev/null) || true
  if [ -n "$TORNJAK_SVC" ]; then
    ok "Tornjak backend service is available"
  fi

  info "To access the Tornjak UI, run these in separate terminals:"
  echo ""
  echo "  # Terminal 1: Tornjak backend API"
  echo "  kubectl -n ${SPIRE_NAMESPACE} port-forward svc/spire-tornjak-backend 10000:10000"
  echo ""
  echo "  # Terminal 2: Tornjak frontend"
  echo "  kubectl -n ${SPIRE_NAMESPACE} port-forward svc/spire-tornjak-frontend 3500:3000"
  echo ""
  echo "  Then open http://localhost:3500"
fi

# ─── Summary ─────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}=== SPIRE Setup Complete ===${NC}"
echo ""
echo "What was configured:"
echo "  1. SPIFFE Helm repo added"
echo "  2. SPIRE CRDs installed"
echo "  3. SPIRE server and agent deployed"
echo "  4. Proxy workload registered (${SPIFFE_ID})"
if [ "${ENABLE_TORNJAK}" = "true" ]; then
echo "  5. Tornjak UI enabled"
fi
echo ""
echo "Next steps:"
echo "  1. Enable SPIFFE in the proxy:"
echo "     helm upgrade suse-ai-up ./charts/suse-ai-up --reuse-values --set spiffe.enabled=true"
echo ""
echo "  2. Run the demo:"
echo "     ./demo.sh"
