#!/usr/bin/env bash
# Obtain an OAuth access token from the proxy using Rancher OIDC.
# Requires a Rancher API token (from your kubeconfig or Rancher UI).
#
# Usage:
#   ./get-token.sh
#   export AUTH_TOKEN=$(./get-token.sh)
#   ./demo.sh
set -euo pipefail

PROXY_URL="${PROXY_URL:-https://suse-ai-up.192.168.5.61.nip.io}"
CURL_INSECURE="${CURL_INSECURE:--k}"

# Auto-detect Rancher token from kubeconfig if not set
if [ -z "${RANCHER_TOKEN:-}" ]; then
  # Try to extract from kubeconfig files matching *marv*
  for f in ~/.kube/*marv*.yaml ~/.kube/*marv*.yml; do
    if [ -f "$f" ]; then
      RANCHER_TOKEN=$(grep -m1 'token:' "$f" | awk '{print $2}' | tr -d '"' 2>/dev/null) || true
      if [ -n "$RANCHER_TOKEN" ]; then
        break
      fi
    fi
  done
fi

if [ -z "${RANCHER_TOKEN:-}" ]; then
  echo "ERROR: No Rancher API token found." >&2
  echo "Set RANCHER_TOKEN or ensure a *marv* kubeconfig exists in ~/.kube/" >&2
  exit 1
fi

# Step 1: Register a dynamic OAuth client
CLIENT_JSON=$(curl ${CURL_INSECURE} -s -X POST "${PROXY_URL}/oauth/register" \
  -H "Content-Type: application/json" \
  -d '{"client_name":"token-cli","redirect_uris":["http://localhost:19876/callback"]}')

CLIENT_ID=$(echo "$CLIENT_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['client_id'])")

# Step 2: Generate PKCE verifier and challenge
VERIFIER=$(python3 -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode())")
CHALLENGE=$(python3 -c "import hashlib, base64; print(base64.urlsafe_b64encode(hashlib.sha256('${VERIFIER}'.encode()).digest()).rstrip(b'=').decode())")
STATE="s$(date +%s)"

# Step 3: Hit proxy authorize — get redirect to Rancher + cookie
curl ${CURL_INSECURE} -s -D /tmp/.gt_auth_headers \
  "${PROXY_URL}/oauth/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=http://localhost:19876/callback&state=${STATE}&code_challenge=${CHALLENGE}&code_challenge_method=S256&scope=mcp:read+mcp:write" >/dev/null 2>&1

COOKIE=$(grep -i set-cookie /tmp/.gt_auth_headers | sed 's/.*oauth_params=/oauth_params=/' | sed 's/;.*//')
RANCHER_URL=$(grep -i location /tmp/.gt_auth_headers | sed 's/location: //' | tr -d '\r')

if [ -z "$RANCHER_URL" ]; then
  echo "ERROR: No redirect to Rancher from proxy authorize endpoint" >&2
  exit 1
fi

# Step 4: Authenticate with Rancher using API token
curl ${CURL_INSECURE} -s -D /tmp/.gt_rancher_headers \
  -H "Authorization: Bearer ${RANCHER_TOKEN}" \
  "$RANCHER_URL" >/dev/null 2>&1

RANCHER_CODE=$(grep -i location /tmp/.gt_rancher_headers | sed 's/.*code=//' | sed 's/&.*//' | tr -d '\r')

if [ -z "$RANCHER_CODE" ]; then
  echo "ERROR: Rancher did not return an authorization code" >&2
  echo "Check that RANCHER_TOKEN is valid" >&2
  exit 1
fi

# Step 5: Hit proxy callback with Rancher code + cookie
curl ${CURL_INSECURE} -s -D /tmp/.gt_callback_headers \
  -b "$COOKIE" \
  "${PROXY_URL}/oauth/callback?code=${RANCHER_CODE}&state=${STATE}" >/dev/null 2>&1

PROXY_CODE=$(grep -i location /tmp/.gt_callback_headers | sed 's/.*code=//' | sed 's/&.*//' | tr -d '\r')

if [ -z "$PROXY_CODE" ]; then
  echo "ERROR: Proxy callback did not return an authorization code" >&2
  cat /tmp/.gt_callback_headers >&2
  exit 1
fi

# Step 6: Exchange proxy code for access token
TOKEN_JSON=$(curl ${CURL_INSECURE} -s -X POST "${PROXY_URL}/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=${PROXY_CODE}&redirect_uri=http://localhost:19876/callback&client_id=${CLIENT_ID}&code_verifier=${VERIFIER}")

ACCESS_TOKEN=$(echo "$TOKEN_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])" 2>/dev/null) || true

if [ -z "$ACCESS_TOKEN" ]; then
  echo "ERROR: Failed to obtain access token" >&2
  echo "$TOKEN_JSON" >&2
  exit 1
fi

# Clean up temp files
rm -f /tmp/.gt_auth_headers /tmp/.gt_rancher_headers /tmp/.gt_callback_headers

# Output just the token (for use with export AUTH_TOKEN=$(./get-token.sh))
echo "$ACCESS_TOKEN"
