#!/usr/bin/env python3
"""
Mock server for SPIFFE token exchange demo.

Provides three endpoints:
  GET  /health  — health check
  POST /token   — RFC 8693 token exchange (accepts JWT SVID, returns bearer token)
  POST /mcp     — Mock MCP server (tools/list and tools/call)

The token endpoint validates that:
  1. grant_type is urn:ietf:params:oauth:grant-type:token-exchange
  2. A subject_token (JWT SVID) is provided
  3. subject_token_type is urn:ietf:params:oauth:token-type:jwt

It decodes the SVID (without signature verification — this is a mock) and issues
a bearer token that embeds the SPIFFE ID. The MCP endpoint checks for a valid
bearer token before returning tool results.
"""

import base64
import json
import os
import sys
import uuid
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

PORT = int(os.environ.get("PORT", "8002"))
TOKEN_PREFIX = "mock-databricks-"


def decode_jwt_payload(token):
    """Decode JWT payload without verification (mock only)."""
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        # base64url -> base64
        payload = payload.replace("-", "+").replace("_", "/")
        # add padding
        payload += "=" * (4 - len(payload) % 4)
        return json.loads(base64.b64decode(payload))
    except Exception:
        return None


# In-memory token store: bearer_token -> {spiffe_id, audience, issued_at, expires_at}
issued_tokens = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        sys.stderr.write(f"[mock-server] {args[0]}\n")

    def send_json(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {
                "status": "healthy",
                "service": "spiffe-demo-mock",
                "mode": "mock",
                "endpoints": {
                    "token": "/token",
                    "mcp": "/mcp",
                },
            })
        else:
            self.send_json(404, {"error": "not_found"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else ""

        if self.path == "/token":
            self.handle_token_exchange(body)
        elif self.path == "/mcp":
            self.handle_mcp(body)
        else:
            self.send_json(404, {"error": "not_found"})

    def handle_token_exchange(self, body):
        """RFC 8693 token exchange: accept JWT SVID, return bearer token."""
        params = parse_qs(body)

        grant_type = params.get("grant_type", [""])[0]
        if grant_type != "urn:ietf:params:oauth:grant-type:token-exchange":
            self.send_json(400, {
                "error": "unsupported_grant_type",
                "error_description": f"Expected token-exchange grant, got: {grant_type}",
            })
            return

        subject_token = params.get("subject_token", [""])[0]
        if not subject_token:
            self.send_json(400, {
                "error": "invalid_request",
                "error_description": "subject_token is required",
            })
            return

        token_type = params.get("subject_token_type", [""])[0]
        if token_type != "urn:ietf:params:oauth:token-type:jwt":
            self.send_json(400, {
                "error": "invalid_request",
                "error_description": f"Expected jwt token type, got: {token_type}",
            })
            return

        # Decode the JWT SVID (no signature verification — mock only)
        claims = decode_jwt_payload(subject_token)
        if not claims:
            self.send_json(400, {
                "error": "invalid_grant",
                "error_description": "Could not decode subject_token as JWT",
            })
            return

        spiffe_id = claims.get("sub", "unknown")
        audience = params.get("audience", [claims.get("aud", ["unknown"])[0] if isinstance(claims.get("aud"), list) else claims.get("aud", "unknown")])[0]

        # Issue a mock bearer token
        bearer_token = f"{TOKEN_PREFIX}{uuid.uuid4().hex[:16]}"
        now = int(time.time())
        expires_in = 3600

        issued_tokens[bearer_token] = {
            "spiffe_id": spiffe_id,
            "audience": audience,
            "issued_at": now,
            "expires_at": now + expires_in,
        }

        sys.stderr.write(f"[token-exchange] Exchanged SVID for {spiffe_id} -> {bearer_token[:30]}...\n")

        self.send_json(200, {
            "access_token": bearer_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": params.get("scope", ["sql:read"])[0],
        })

    def handle_mcp(self, body):
        """Mock MCP server with bearer token validation."""
        # Check authorization
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self.send_json(401, {
                "jsonrpc": "2.0",
                "error": {"code": -32001, "message": "Bearer token required"},
            })
            return

        token = auth[7:]
        token_info = issued_tokens.get(token)
        if not token_info:
            self.send_json(403, {
                "jsonrpc": "2.0",
                "error": {"code": -32002, "message": "Invalid or expired token"},
            })
            return

        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self.send_json(400, {
                "jsonrpc": "2.0",
                "error": {"code": -32700, "message": "Parse error"},
            })
            return

        method = request.get("method", "")
        req_id = request.get("id", 1)

        if method == "tools/list":
            self.send_json(200, {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "get_cluster_status",
                            "description": "Get the status of a Databricks cluster",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "cluster_id": {"type": "string", "description": "Cluster ID"},
                                },
                                "required": ["cluster_id"],
                            },
                        },
                        {
                            "name": "execute_sql",
                            "description": "Execute a SQL query on Databricks",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "query": {"type": "string", "description": "SQL query to execute"},
                                    "warehouse_id": {"type": "string", "description": "SQL warehouse ID"},
                                },
                                "required": ["query"],
                            },
                        },
                        {
                            "name": "get_workspace_info",
                            "description": "Get information about the Databricks workspace",
                            "inputSchema": {"type": "object", "properties": {}},
                        },
                    ],
                },
            })

        elif method == "tools/call":
            params = request.get("params", {})
            tool_name = params.get("name", "")
            args = params.get("arguments", {})

            if tool_name == "get_cluster_status":
                result = {
                    "cluster_id": args.get("cluster_id", "demo-cluster-01"),
                    "state": "RUNNING",
                    "num_workers": 4,
                    "spark_version": "13.3.x-scala2.12",
                    "authenticated_via": "spiffe_token_exchange",
                    "workload_identity": token_info["spiffe_id"],
                }
            elif tool_name == "execute_sql":
                result = {
                    "status": "SUCCEEDED",
                    "query": args.get("query", "SELECT 1"),
                    "rows_affected": 42,
                    "columns": ["id", "name", "value"],
                    "data": [
                        [1, "sensor-a", 23.5],
                        [2, "sensor-b", 18.2],
                        [3, "sensor-c", 31.7],
                    ],
                    "authenticated_via": "spiffe_token_exchange",
                    "workload_identity": token_info["spiffe_id"],
                }
            elif tool_name == "get_workspace_info":
                result = {
                    "workspace_url": "https://databricks.example.com",
                    "workspace_id": "1234567890",
                    "cloud": "azure",
                    "region": "westus2",
                    "authenticated_via": "spiffe_token_exchange",
                    "workload_identity": token_info["spiffe_id"],
                }
            else:
                self.send_json(200, {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps({"error": f"Unknown tool: {tool_name}"})}],
                        "isError": True,
                    },
                })
                return

            self.send_json(200, {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                    "isError": False,
                },
            })
        else:
            self.send_json(200, {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            })


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Mock SPIFFE token exchange + MCP server listening on :{PORT}")
    print(f"  GET  /health  — health check")
    print(f"  POST /token   — RFC 8693 token exchange")
    print(f"  POST /mcp     — MCP server (requires exchanged bearer token)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()
