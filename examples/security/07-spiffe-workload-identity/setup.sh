#!/usr/bin/env bash
# 07 — SPIFFE/SPIRE Setup
# Installs SPIRE in the cluster and configures the proxy for SPIFFE workload identity.
# Run this once before running demo.sh. Idempotent — skips anything already set up.
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
skip() { echo -e "${GREEN}SKIP${NC}: $1 (already done)"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }
info() { echo -e "${YELLOW}INFO${NC}: $1"; }

echo -e "${CYAN}SPIFFE/SPIRE Setup${NC}"
echo "Cluster:      ${SPIRE_CLUSTER_NAME}"
echo "Trust Domain: ${SPIRE_TRUST_DOMAIN}"
echo "Namespace:    ${SPIRE_NAMESPACE}"
echo "Tornjak UI:   ${ENABLE_TORNJAK}"
echo ""

# ─── Step 1: Preflight Checks ───────────────────────────────────

step 1 "Preflight Checks"

# Required tools
MISSING_TOOLS=()
command -v helm &>/dev/null || MISSING_TOOLS+=("helm")
command -v kubectl &>/dev/null || MISSING_TOOLS+=("kubectl")
command -v jq &>/dev/null || MISSING_TOOLS+=("jq")

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
  fail "Missing required tools: ${MISSING_TOOLS[*]}"
fi
ok "Required tools: helm, kubectl, jq"

# Cluster connectivity
if ! kubectl cluster-info &>/dev/null; then
  fail "Cannot connect to Kubernetes cluster. Check your kubeconfig."
fi
ok "Cluster is reachable"

# Detect current state
NEEDS_NAMESPACE=false
NEEDS_CRDS=false
NEEDS_SPIRE=false
NEEDS_WAIT=false
NEEDS_REGISTRATION=false

# Check namespace
if kubectl get namespace "${SPIRE_NAMESPACE}" &>/dev/null; then
  skip "Namespace ${SPIRE_NAMESPACE} exists"
else
  NEEDS_NAMESPACE=true
  info "Namespace ${SPIRE_NAMESPACE} will be created"
fi

# Check CRDs (use kubectl — helm status may fail through Rancher API proxy)
if kubectl get crd clusterspiffeids.spire.spiffe.io &>/dev/null; then
  skip "SPIRE CRDs installed"
else
  NEEDS_CRDS=true
  info "SPIRE CRDs will be installed"
fi

# Check SPIRE (detect by looking for the server pod, not helm status)
SPIRE_SERVER_READY=$(kubectl -n "${SPIRE_NAMESPACE}" get pod "${SPIRE_SERVER_POD}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null) || true
AGENT_COUNT=$(kubectl -n "${SPIRE_NAMESPACE}" get pods -l app.kubernetes.io/name=agent --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l | tr -d ' ') || true

if [ -n "$SPIRE_SERVER_READY" ]; then
  # Server pod exists — SPIRE is installed
  SPIRE_IMAGE=$(kubectl -n "${SPIRE_NAMESPACE}" get pod "${SPIRE_SERVER_POD}" -o jsonpath='{.spec.containers[0].image}' 2>/dev/null) || true
  skip "SPIRE installed (${SPIRE_IMAGE:-unknown})"

  if [ "$SPIRE_SERVER_READY" = "True" ] && [ "$AGENT_COUNT" -gt 0 ]; then
    skip "SPIRE server ready, ${AGENT_COUNT} agent(s) running"
  else
    NEEDS_WAIT=true
    info "SPIRE installed but pods not ready — will wait"
  fi
else
  NEEDS_SPIRE=true
  info "SPIRE will be installed"
fi

# Check workload registration
SPIFFE_ID="spiffe://${SPIRE_TRUST_DOMAIN}/suse-ai-up"
if [ "$NEEDS_SPIRE" = "false" ] && [ "$NEEDS_WAIT" = "false" ]; then
  EXISTING=$(kubectl -n "${SPIRE_NAMESPACE}" exec "${SPIRE_SERVER_POD}" -c spire-server -- \
    /opt/spire/bin/spire-server entry show -spiffeID "${SPIFFE_ID}" 2>/dev/null) || true
  if echo "$EXISTING" | grep -q "Entry ID"; then
    skip "Proxy workload registered (${SPIFFE_ID})"
  else
    NEEDS_REGISTRATION=true
    info "Proxy workload will be registered"
  fi
else
  NEEDS_REGISTRATION=true
fi

# Summary
echo ""
if [ "$NEEDS_NAMESPACE" = "false" ] && [ "$NEEDS_CRDS" = "false" ] && \
   [ "$NEEDS_SPIRE" = "false" ] && [ "$NEEDS_WAIT" = "false" ] && \
   [ "$NEEDS_REGISTRATION" = "false" ]; then
  echo -e "${GREEN}Everything is already set up. Nothing to do.${NC}"
  echo ""
  echo "Next steps:"
  echo "  ./demo.sh"
  exit 0
fi

# ─── Step 2: Add Helm repo ──────────────────────────────────────

if [ "$NEEDS_CRDS" = "true" ] || [ "$NEEDS_SPIRE" = "true" ]; then
  step 2 "Add SPIFFE Helm Repository"

  helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/ 2>/dev/null || true
  helm repo update

  ok "SPIFFE Helm repo ready"
fi

# ─── Step 3: Create namespace and install CRDs ──────────────────

if [ "$NEEDS_NAMESPACE" = "true" ] || [ "$NEEDS_CRDS" = "true" ]; then
  step 3 "Install CRDs"

  if [ "$NEEDS_NAMESPACE" = "true" ]; then
    kubectl create namespace "${SPIRE_NAMESPACE}" 2>/dev/null || true
    ok "Namespace ${SPIRE_NAMESPACE} created"
  fi

  if [ "$NEEDS_CRDS" = "true" ]; then
    helm install spire-crds spiffe/spire-crds --namespace "${SPIRE_NAMESPACE}"
    ok "SPIRE CRDs installed"
  fi
fi

# ─── Step 4: Install SPIRE ──────────────────────────────────────

if [ "$NEEDS_SPIRE" = "true" ]; then
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

  helm install spire spiffe/spire "${HELM_ARGS[@]}"
  ok "SPIRE installed"
  NEEDS_WAIT=true
fi

# ─── Step 5: Wait for pods ──────────────────────────────────────

if [ "$NEEDS_WAIT" = "true" ]; then
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
fi

# ─── Step 6: Verify health ──────────────────────────────────────

step 6 "Verify SPIRE Health"

HEALTH=$(kubectl -n "${SPIRE_NAMESPACE}" exec "${SPIRE_SERVER_POD}" -c spire-server -- \
  /opt/spire/bin/spire-server healthcheck 2>/dev/null) || true

if echo "$HEALTH" | grep -qi "healthy"; then
  ok "SPIRE server is healthy"
else
  info "SPIRE server health: ${HEALTH:-unknown}"
fi

# ─── Step 7: Register proxy workload ────────────────────────────

if [ "$NEEDS_REGISTRATION" = "true" ]; then
  step 7 "Register Proxy Workload"

  # Re-check in case we just waited for pods
  EXISTING=$(kubectl -n "${SPIRE_NAMESPACE}" exec "${SPIRE_SERVER_POD}" -c spire-server -- \
    /opt/spire/bin/spire-server entry show -spiffeID "${SPIFFE_ID}" 2>/dev/null) || true

  if echo "$EXISTING" | grep -q "Entry ID"; then
    skip "Proxy workload already registered"
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
fi

# ─── Step 8: Tornjak access ────────────────────────────────────

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
echo "  - SPIRE CRDs, server, and agent in ${SPIRE_NAMESPACE}"
echo "  - Proxy workload registered as ${SPIFFE_ID}"
if [ "${ENABLE_TORNJAK}" = "true" ]; then
echo "  - Tornjak UI enabled"
fi
echo ""
echo "Next steps:"
echo "  1. Enable SPIFFE in the proxy:"
echo "     helm upgrade suse-ai-up ./charts/suse-ai-up --reuse-values --set spiffe.enabled=true"
echo ""
echo "  2. Run the demo:"
echo "     ./demo.sh"
