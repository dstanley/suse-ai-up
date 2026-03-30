# SUSE AI Universal Proxy Authentication Guide

## Overview

This document explains how to configure and use authentication in SUSE AI Universal Proxy, supporting multiple providers including local authentication, GitHub OAuth, and Rancher OIDC.

## Quick Start

### Basic Local Authentication

```bash
# Set environment variables
export AUTH_MODE=local
export ADMIN_PASSWORD=your_secure_password

# Start the service
go run ./cmd/uniproxy
```

### GitHub OAuth Setup

```bash
export AUTH_MODE=github
export GITHUB_CLIENT_ID=your_github_app_id
export GITHUB_CLIENT_SECRET=your_github_app_secret
export GITHUB_REDIRECT_URI=http://localhost:8911/auth/github/callback
```

### Rancher OIDC Setup

```bash
export AUTH_MODE=rancher
export RANCHER_ISSUER_URL=https://your-rancher-url/oidc
export RANCHER_CLIENT_ID=your_rancher_client_id
export RANCHER_CLIENT_SECRET=your_rancher_client_secret
export RANCHER_REDIRECT_URI=http://localhost:8911/auth/rancher/callback
```

## Kubernetes/Helm Deployment

For production deployments on Kubernetes, use the provided Helm chart which handles authentication configuration securely.

### Prerequisites

- Kubernetes cluster with Helm 3.x
- Rancher (optional, for Rancher OIDC authentication)
- GitHub OAuth App (optional, for GitHub OAuth)

### Quick Start with Helm

#### Local Authentication (Default)

```bash
# Install with local authentication
helm install suse-ai-up ./charts/suse-ai-up \
  --set auth.mode=local \
  --set auth.local.defaultAdminPassword="your_secure_password"
```

#### GitHub OAuth

```bash
# Install with GitHub OAuth
helm install suse-ai-up ./charts/suse-ai-up \
  --set auth.mode=github \
  --set auth.github.clientId="your_github_app_id" \
  --set auth.github.clientSecret="your_github_app_secret" \
  --set auth.github.allowedOrgs="your-org" \
  --set auth.github.adminTeams="platform-team"
```

#### Rancher OIDC

```bash
# Install with Rancher OIDC
helm install suse-ai-up ./charts/suse-ai-up \
  --set auth.mode=rancher \
  --set auth.rancher.issuerUrl="https://rancher.example.com/oidc" \
  --set auth.rancher.clientId="rancher_client_id" \
  --set auth.rancher.clientSecret="rancher_client_secret" \
  --set auth.rancher.adminGroups="system-admins"
```

### Helm Configuration Options

#### Authentication Mode

```yaml
auth:
  mode: "local"  # local, github, rancher, dev
  devMode: false # Enable development mode (bypass auth)
```

#### Local Authentication

```yaml
auth:
  local:
    defaultAdminPassword: "secure_password"
    forcePasswordChange: true
    passwordMinLength: 8
```

#### GitHub OAuth

```yaml
auth:
  github:
    clientId: "gh_oauth_app_id"
    clientSecret: "gh_oauth_app_secret"
    redirectUri: ""  # Auto-generated if empty
    allowedOrgs: []  # List of allowed organizations
    adminTeams: []   # Teams that get admin permissions
```

#### Rancher OIDC

```yaml
auth:
  rancher:
    issuerUrl: "https://rancher.example.com/oidc"
    clientId: "rancher_client_id"
    clientSecret: "rancher_client_secret"
    redirectUri: ""  # Auto-generated if empty
    adminGroups: []  # Groups that get admin permissions
    fallbackLocal: true  # Allow local auth fallback
```

### Initial Users and Groups

The Helm chart automatically creates initial users and groups:

```yaml
initialUsers:
  enabled: true
  users:
    - id: "admin"
      name: "System Administrator"
      email: "admin@suse.ai"
      password: ""  # Uses auth.local.defaultAdminPassword
      groups: ["mcp-admins"]
      authProvider: "local"

initialGroups:
  enabled: true
  groups:
    - id: "mcp-admins"
      name: "MCP Administrators"
      description: "Full administrative access to all MCP proxy features"
      permissions: [
        "user:create", "user:read", "user:update", "user:delete",
        "group:create", "group:read", "group:update", "group:delete",
        "adapter:create", "adapter:read", "adapter:update", "adapter:delete", "adapter:assign",
        "server:create", "server:read", "server:update", "server:delete",
        "discovery:create", "discovery:read", "discovery:update", "discovery:delete",
        "registry:create", "registry:read", "registry:update", "registry:delete"
      ]
    - id: "mcp-users"
      name: "MCP Users"
      description: "Basic access to MCP servers with limited adapter operations"
      permissions: [
        "server:read", "adapter:read",
        "adapter:create", "adapter:assign"
      ]
```

### Rancher UI Integration

When deploying via Rancher UI, the questions.yml provides an organized interface with dedicated sections:

#### **SUSE AI Universal Proxy Section** (QuickStart)
1. **Installation Type**: Choose Quick Start or Advanced Configuration
2. **Basic Configuration**: Image version, external access, TLS settings
3. **RBAC Configuration**: Service account and permissions

#### **MCP Registry Section**
1. **External Registry URL**: Configure MCP server registry source
2. **Registry Fetch Timeout**: Set timeout for external registry access

#### **Users Section**
1. **Authentication Mode**: Select local, GitHub OAuth, Rancher OIDC, or dev mode
2. **Provider Configuration**: Enter OAuth credentials and settings
3. **Development Mode**: Enable/disable development authentication bypass
4. **Create Initial Users**: Enable/disable automatic user creation
5. **Admin User Configuration**: Set admin user details (ID, name, email, password, groups)

#### **Groups Section**
1. **Create Initial Groups**: Enable/disable automatic group creation
2. **Admin Group**: Configure the administrators group (full permissions predefined)
3. **User Group**: Configure the regular users group (limited permissions predefined)

### Security in Kubernetes

- **OAuth Secrets**: Client secrets stored in Kubernetes secrets, not ConfigMaps
- **RBAC**: ServiceAccount with minimal required permissions
- **Network Policies**: Restrict pod-to-pod communication
- **TLS**: Automatic TLS certificate generation
- **Pod Security**: Non-root execution with restricted capabilities

### Post-Installation

After Helm installation:

1. **Wait for Init Job**: The init job creates initial users and groups
2. **Access Service**: Use the configured ingress or service endpoint
3. **Login**: Use admin credentials to access the system
4. **Configure Users**: Add additional users via the API or UI

### Troubleshooting Kubernetes Deployments

#### Check Pod Status
```bash
kubectl get pods -l app.kubernetes.io/name=suse-ai-up
kubectl logs -l app.kubernetes.io/name=suse-ai-up
```

#### Check Init Job
```bash
kubectl get jobs -l app.kubernetes.io/name=suse-ai-up
kubectl logs job/suse-ai-up-init-users
```

#### Check Secrets
```bash
kubectl get secrets -l app.kubernetes.io/name=suse-ai-up
kubectl describe secret suse-ai-up-auth
```

#### Common Issues
- **Init Job Failures**: Check network connectivity to the service
- **OAuth Redirect Issues**: Ensure ingress/external URL is correctly configured
- **Secret Not Found**: Verify OAuth credentials were provided during installation

## Authentication Methods

### 1. Local Authentication

- Default password-based authentication
- Admin user created automatically with default password "admin"
- Requires password change on first login

### 2. GitHub OAuth

- OAuth 2.0 integration with GitHub
- Automatic user provisioning on first login
- Group mapping from GitHub organizations/teams

### 3. Rancher OIDC

- OIDC integration with Rancher
- Administrative users mapped from Rancher groups
- Seamless integration with Rancher user management

### 4. Development Mode

- Bypass authentication for development
- Set `DEV_MODE=true` environment variable
- Use X-User-ID headers directly

## Configuration Options

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `AUTH_MODE` | Authentication mode: `local`, `github`, `rancher`, `dev` | `development` | No |
| `DEV_MODE` | Enable development mode (bypass auth) | `false` | No |
| `ADMIN_PASSWORD` | Initial admin password | `admin` | No |
| `FORCE_PASSWORD_CHANGE` | Force password change on first login | `true` | No |
| `PASSWORD_MIN_LENGTH` | Minimum password length | `8` | No |

#### GitHub OAuth Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GITHUB_CLIENT_ID` | GitHub OAuth App Client ID | Yes |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth App Client Secret | Yes |
| `GITHUB_REDIRECT_URI` | OAuth callback URL | Yes |
| `GITHUB_ALLOWED_ORGS` | Comma-separated list of allowed GitHub orgs | No |
| `GITHUB_ADMIN_TEAMS` | Comma-separated list of admin teams | No |

#### Rancher OIDC Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `RANCHER_ISSUER_URL` | Rancher OIDC issuer URL | Yes |
| `RANCHER_CLIENT_ID` | Rancher OIDC Client ID | Yes |
| `RANCHER_CLIENT_SECRET` | Rancher OIDC Client Secret | Yes |
| `RANCHER_REDIRECT_URI` | OIDC callback URL | Yes |
| `RANCHER_ADMIN_GROUPS` | Comma-separated list of admin groups | No |
| `RANCHER_FALLBACK_LOCAL` | Allow local auth fallback | `true` | No |

## API Usage Examples

### Get Authentication Mode

Before authenticating, clients can discover the current authentication configuration:

```bash
curl -X GET http://localhost:8911/auth/mode
```

Response (Local Mode):
```json
{
  "mode": "local",
  "dev_mode": false,
  "local": {
    "default_admin_password": "admin",
    "force_password_change": true,
    "password_min_length": 8
  }
}
```

Response (GitHub OAuth Mode):
```json
{
  "mode": "github",
  "dev_mode": false,
  "github": {
    "client_id": "your_github_app_id",
    "redirect_uri": "https://your-app.com/auth/oauth/callback"
  }
}
```

Response (Rancher OIDC Mode):
```json
{
  "mode": "rancher",
  "dev_mode": false,
  "rancher": {
    "issuer_url": "https://rancher.example.com/oidc",
    "client_id": "your_rancher_client_id",
    "redirect_uri": "https://your-app.com/auth/oauth/callback"
  }
}
```

### Working with Groups and Members

#### List Groups with Members

```bash
curl http://localhost:8911/api/v1/groups
```

Response:
```json
[
  {
    "id": "mcp-admins",
    "name": "MCP Administrators",
    "description": "Full administrative access",
    "members": ["admin"],
    "permissions": ["user:create", "group:create"],
    "createdAt": "2026-01-15T17:49:53.928118Z",
    "updatedAt": "2026-01-15T17:49:53.928118Z"
  },
  {
    "id": "mcp-users",
    "name": "MCP Users",
    "description": "Basic access to MCP servers",
    "members": ["user1", "user2"],
    "permissions": ["server:read", "adapter:read"],
    "createdAt": "2026-01-15T17:49:53.928122Z",
    "updatedAt": "2026-01-15T17:49:53.928122Z"
  }
]
```

#### Add User to Group

```bash
curl -X POST http://localhost:8911/api/v1/groups/mcp-users/members \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d '{"userId": "newuser"}'
```

#### Remove User from Group

```bash
curl -X DELETE http://localhost:8911/api/v1/groups/mcp-users/members/newuser \
  -H "Authorization: Bearer <your_token>"
```

### Local Authentication

#### Login

```bash
curl -X POST http://localhost:8911/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "admin",
    "password": "your_password"
  }'
```

Response:
```json
{
  "token": {
    "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_at": "2024-01-15T10:00:00Z",
    "user_id": "admin"
  },
  "user": {
    "id": "admin",
    "name": "System Administrator",
    "email": "admin@suse.ai",
    "groups": ["mcp-admins"]
  }
}
```

#### Change Password

```bash
curl -X PUT http://localhost:8911/auth/password \
  -H "Authorization: Bearer <your_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "old_password",
    "new_password": "new_secure_password"
  }'
```

### GitHub OAuth

#### Initiate OAuth Flow

```bash
curl -X POST http://localhost:8911/auth/oauth/login \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "github"
  }'
```

Response:
```json
{
  "auth_url": "https://github.com/login/oauth/authorize?client_id=...&redirect_uri=..."
}
```

#### OAuth Callback

The user will be redirected to the auth URL, authenticate with GitHub, and GitHub will redirect back to `/auth/oauth/callback` with a code. The callback endpoint will exchange the code for a token and return user authentication.

```bash
curl -X POST http://localhost:8911/auth/oauth/callback \
  -H "Content-Type: application/json" \
  -d '{
    "code": "github_oauth_code",
    "state": "optional_state"
  }'
```

### Rancher OIDC

#### Initiate OIDC Flow

```bash
curl -X POST http://localhost:8911/auth/oauth/login \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "rancher"
  }'
```

#### OIDC Callback

Similar to GitHub, the user authenticates with Rancher and gets redirected back with a code.

### Using Authenticated APIs

All protected APIs require a Bearer token:

```bash
curl -X GET http://localhost:8911/api/v1/users \
  -H "Authorization: Bearer <your_token>"
```

### Per-User Adapter Tokens

The system supports **per-user adapter tokens** for secure, user-specific access to MCP adapters. When a user requests their client configuration via `api/v1/user/config`, the system generates unique tokens for each adapter the user has access to.

#### How It Works

1. **Token Generation**: Each user gets unique tokens for each adapter they can access
2. **Token Format**: `uat-{userID}-{adapterID}-{random}` (User Adapter Token)
3. **Token Storage**: Tokens are persisted in `user_adapter_tokens.json`
4. **Auto-Creation**: Tokens are created on-demand when users request their config

#### User Config Response

When calling `GET /api/v1/user/config` with `X-User-ID` header:

```bash
curl -X GET http://localhost:8911/api/v1/user/config \
  -H "X-User-ID: alefesta"
```

Response includes per-user tokens:

```json
{
  "mcpClientConfig": {
    "gemini": {
      "mcpServers": {
        "bugzilla-adapter": {
          "headers": {
            "Authorization": "Bearer uat-alefesta-bugzilla-adapter-aBc123...",
            "X-User-ID": "alefesta"
          },
          "httpUrl": "http://localhost:8911/api/v1/adapters/bugzilla-adapter/mcp"
        }
      }
    },
    "vscode": {
      "inputs": [],
      "servers": {
        "bugzilla-adapter": {
          "headers": {
            "Authorization": "Bearer uat-alefesta-bugzilla-adapter-aBc123...",
            "X-User-ID": "alefesta"
          },
          "type": "http",
          "url": "http://localhost:8911/api/v1/adapters/bugzilla-adapter/mcp"
        }
      }
    }
  }
}
```

#### Token Validation

The authentication middleware validates per-user tokens:

1. **JWT Token** (if TokenManager configured)
2. **Per-User Token** - Looks up `user_adapter_tokens.json` for valid token
3. **Adapter Static Token** - Fallback to adapter's original token (backward compatible)

#### Security Benefits

- **User Isolation**: Each user has unique tokens
- **Traceability**: Tokens include user and adapter identifiers
- **Revocation**: Can delete user tokens without affecting other users
- **Audit**: Track which user accessed which adapter

#### Managing User Adapter Tokens

**List User's Tokens** (Admin Only):
```bash
curl -X GET http://localhost:8911/api/v1/users/alefesta/tokens \
  -H "Authorization: Bearer <admin_token>"
```

**Revoke User's Token** (Admin Only):
```bash
curl -X DELETE http://localhost:8911/api/v1/users/alefesta/tokens/bugzilla-adapter \
  -H "Authorization: Bearer <admin_token>"
```

**Note**: User adapter tokens are automatically created when users request their client configuration. No manual token management is required for normal usage.

## Swagger UI with Authentication

The API includes interactive Swagger documentation that requires authentication for protected endpoints.

### Accessing Swagger UI

```bash
# Local development
open http://localhost:8911/docs/

# Kubernetes deployment
open http://your-service-url:8911/docs/
```

### Authentication Methods in Swagger

#### Method 1: JWT Token Authentication (Recommended)

1. **Login first** to obtain a JWT token:
   ```bash
   curl -X POST http://localhost:8911/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{
       "user_id": "admin",
       "password": "your_password"
     }'
   ```

2. **Authorize in Swagger UI**:
   - Click the **"Authorize"** button (lock icon) at the top of the page
   - Enter: `Bearer <your_jwt_token>` (replace with actual token)
   - Click **"Authorize"**

3. **All API calls** will now include the authentication header automatically

#### Method 2: Development Mode (No Authentication)

For development/testing, enable dev mode to bypass authentication:

```bash
# Environment variables
export AUTH_MODE=dev
export DEV_MODE=true

# Or with Helm
helm install suse-ai-up ./charts/suse-ai-up --set auth.mode=dev --set auth.devMode=true
```

In dev mode, requests from development IPs (localhost, 192.168.*, 10.*) are allowed anonymous access.

#### Method 3: X-User-ID Header (Development Only)

For quick testing, you can use the X-User-ID header:

```bash
curl -H "X-User-ID: admin" http://localhost:8911/api/v1/users
```

**Note**: This method is only available in dev mode and should not be used in production.

### Swagger UI Features

- **Interactive API Testing**: Try API endpoints directly from the browser
- **Request/Response Examples**: See actual data structures
- **Authentication Persistence**: Token remains active during your session
- **Schema Validation**: Automatic validation of request/response formats

### Troubleshooting Swagger Issues

#### CORS Errors
If you see CORS errors when accessing Swagger from different origins:
- Ensure the request origin is allowed in CORS configuration
- For Kubernetes deployments, add your IP range to allowed origins

#### Authentication Errors
- Verify your JWT token is valid and not expired
- Check that you're using the correct token format: `Bearer <token>`
- Ensure the user has appropriate permissions for the requested operation

#### Dev Mode Not Working
- Confirm `AUTH_MODE=dev` and `DEV_MODE=true` are set
- Check that your request comes from an allowed development IP range
- Verify the X-User-ID header is set correctly (if using that method)

### User Management

#### Create User (Admin Only)

```bash
curl -X POST http://localhost:8911/api/v1/users \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "newuser",
    "name": "New User",
    "email": "user@example.com",
    "groups": ["mcp-users"],
    "auth_provider": "local"
  }'
```

#### List Users (Admin Only)

```bash
curl -X GET http://localhost:8911/api/v1/users \
  -H "Authorization: Bearer <admin_token>"
```

## User Groups and Permissions

When a user authenticates via OAuth, their groups are **merged** from two sources:

1. **OIDC groups** from the identity provider (e.g., `data-engineers`, `platform-team`)
2. **Mapped local groups** based on `AIPROXY_ADMIN_GROUPS` config (e.g., `mcp-admins`)

For example, if `AIPROXY_ADMIN_GROUPS=platform-team` and a user has OIDC groups `["data-engineers", "platform-team"]`, their merged groups will be:
```
["data-engineers", "platform-team", "mcp-admins"]
```

This merged set is used for:
- **Proxy API permissions** (e.g., checking for `mcp-admins`)
- **Scope policies** (e.g., mapping `data-engineers` to backend scopes)
- **Tool authorization** (e.g., restricting tools to specific groups)

### Default Local Groups

- **`mcp-admins`**: Full administrative access to all MCP proxy features
  - **Users**: Create, read, update, delete users
  - **Groups**: Create, read, update, delete groups
  - **Adapters**: Full CRUD operations plus assignment capabilities
  - **Servers**: Create, read, update, delete MCP servers
  - **Discovery**: Full CRUD operations for service discovery
  - **Registry**: Full CRUD operations for MCP server registry

- **`mcp-users`**: Basic access to MCP servers with limited adapter operations
  - **Servers**: Read access to MCP servers
  - **Adapters**: Read access plus create and assign (POST/GET, no delete)

### Available Permissions

The system supports granular permissions for different operations:

#### User Management
- `user:create` - Create new users
- `user:read` - View user information
- `user:update` - Modify user details
- `user:delete` - Delete users

#### Group Management
- `group:create` - Create new groups
- `group:read` - View group information
- `group:update` - Modify group details
- `group:delete` - Delete groups

#### Adapter Management
- `adapter:create` - Create new adapters
- `adapter:read` - View adapter information
- `adapter:update` - Modify adapter configuration
- `adapter:delete` - Delete adapters
- `adapter:assign` - Assign adapters to groups/users

#### Server Management
- `server:create` - Register new MCP servers
- `server:read` - View server information
- `server:update` - Modify server configuration
- `server:delete` - Unregister servers

#### Discovery Management
- `discovery:create` - Create discovery configurations
- `discovery:read` - View discovery information
- `discovery:update` - Modify discovery settings
- `discovery:delete` - Delete discovery configurations

#### Registry Management
- `registry:create` - Add servers to registry
- `registry:read` - View registry information
- `registry:update` - Modify registry entries
- `registry:delete` - Remove servers from registry

### Permission Mapping

- **GitHub**: Users in configured admin teams automatically get `mcp-admins` group
- **Rancher**: Users in configured admin groups automatically get `mcp-admins` group
- **Local**: Groups assigned during user creation or via API

## Adapter Authentication and Scope Policies

The proxy supports two patterns for authenticating to backend MCP servers:

### M2M (Machine-to-Machine)

The proxy authenticates to the backend using its own credentials. The user's identity is either irrelevant or passed as metadata (e.g., via impersonation headers).

| Auth Type | Description | Use Case |
|-----------|-------------|----------|
| `bearer` | Static or dynamic bearer token | Shared API keys |
| `apikey` | API key in header/query/cookie | Simple service auth |
| `basic` | Username/password | Legacy services |
| `service_account` | Proxy's own credentials + user impersonation header | ServiceNow, Jira |
| `spiffe` (mTLS) | X.509 SVID certificate-based auth | Zero-trust internal services |

### U2M (User-to-Machine)

The user's own identity and permissions flow through to the backend. The backend enforces authorization based on who the user is.

| Auth Type | Description | Use Case |
|-----------|-------------|----------|
| `token_exchange` | RFC 8693 exchange of user's Rancher ID token for backend token | Databricks, cloud APIs |
| `spiffe` (JWT) | SPIRE JWT SVID exchanged for backend token | Workload identity |

### Scope Policies

Scope policies map user identity (groups, roles, user IDs) to backend-specific scopes per adapter. This allows different users to receive different permissions when accessing the same backend service.

**Resolution rules:**
1. All matching policies' scopes are merged (union)
2. A policy matches if the user is in any of its `groups` or `users` lists
3. Empty `groups` and `users` = default policy (matches all users)
4. If no policies match, the adapter's static `scopes` field is used as fallback
5. Policies are evaluated in `priority` order (highest first)

#### Token Exchange with Scope Policies

When the proxy exchanges a user's Rancher ID token for a backend token via RFC 8693, scope policies determine which scopes are requested from the backend token endpoint.

```json
{
  "authentication": {
    "required": true,
    "type": "token_exchange",
    "tokenExchange": {
      "token_endpoint": "https://accounts.cloud.databricks.com/oidc/v1/token",
      "audience": "https://databricks.example.com",
      "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
      "scopes": ["sql:read"],
      "scope_policies": [
        {
          "groups": ["data-engineers"],
          "scopes": ["sql:read", "sql:write", "clusters:manage"],
          "priority": 10
        },
        {
          "groups": ["analysts"],
          "scopes": ["sql:read"]
        },
        {
          "scopes": ["sql:read"],
          "priority": 0
        }
      ]
    }
  }
}
```

In this example:
- Users in `data-engineers` get `sql:read`, `sql:write`, and `clusters:manage`
- Users in `analysts` get `sql:read`
- A user in both groups gets the union: `sql:read`, `sql:write`, `clusters:manage`
- Users matching no group get the default policy: `sql:read`
- If no scope policies are defined, the static `scopes` field (`["sql:read"]`) is used for all users

#### Service Account with Scope Policies

For service account authentication, the proxy authenticates as itself but can send the user's resolved scopes to the backend via a configurable HTTP header.

```json
{
  "authentication": {
    "required": true,
    "type": "service_account",
    "serviceAccount": {
      "username": "mcp-proxy-sa",
      "password": "from-csi-secret-store",
      "impersonation_header": "X-UserToken",
      "impersonation_field": "email",
      "scope_header": "X-User-Scopes",
      "scope_policies": [
        {
          "groups": ["it-admins"],
          "scopes": ["incident:write", "cmdb:write"]
        },
        {
          "groups": ["helpdesk"],
          "scopes": ["incident:read", "incident:write"]
        },
        {
          "scopes": ["incident:read"]
        }
      ]
    }
  }
}
```

In this example:
- The proxy authenticates as `mcp-proxy-sa` (M2M credential)
- The user's email is sent via `X-UserToken` header (impersonation)
- The user's resolved scopes are sent via `X-User-Scopes` header
- Users in `it-admins` get scopes `incident:write cmdb:write`
- Users in `helpdesk` get `incident:read incident:write`
- Everyone else gets `incident:read`

#### Scope Policy Fields

| Field | Type | Description |
|-------|------|-------------|
| `groups` | `[]string` | Match users in any of these groups or roles |
| `users` | `[]string` | Match specific user IDs, usernames, or emails |
| `scopes` | `[]string` | Backend scopes to grant when matched |
| `priority` | `int` | Evaluation order (highest first, default 0) |

User groups include both OIDC groups from the identity provider and mapped local groups (like `mcp-admins`). Roles are sourced from OIDC claims.

### Scope-Aware Tool Authorization

Authorization policies can use `required_scopes` to control tool access based on a user's resolved backend scopes. This creates a two-tier authorization model:

1. **Scope resolution**: User identity (groups/roles) maps to backend scopes via scope policies
2. **Tool authorization**: Policies check the user's resolved scopes to determine tool visibility

This means the same OIDC groups that determine backend API permissions also control which MCP tools are visible and callable through the proxy.

#### Example: Restrict Dangerous Tools by Scope

```json
{
  "policy_id": "restrict-drop-table",
  "adapter_name": "databricks",
  "tool_name": "drop_table",
  "effect": "allow",
  "allowed_groups": ["data-engineers"],
  "required_scopes": ["sql:write"],
  "priority": 10
}
```

This policy only allows `drop_table` for users who are both in the `data-engineers` group AND have the `sql:write` scope resolved from the adapter's scope policies. Users without `sql:write` won't see the tool in `tools/list` and will receive a 403 if they attempt to call it directly.

#### Authorization Policy Fields

| Field | Type | Description |
|-------|------|-------------|
| `policy_id` | `string` | Unique identifier for the policy |
| `adapter_name` | `string` | Target adapter name |
| `tool_name` | `string` | Target tool name |
| `effect` | `string` | `"allow"` or `"deny"` |
| `allowed_groups` | `[]string` | Groups permitted (allow policies) |
| `allowed_users` | `[]string` | Users permitted (allow policies) |
| `denied_groups` | `[]string` | Groups denied (deny policies) |
| `denied_users` | `[]string` | Users denied (deny policies) |
| `required_scopes` | `[]string` | All listed scopes must be present in user's resolved scopes |
| `priority` | `int` | Evaluation order (higher first) |

**Evaluation rules:**
- Deny takes precedence: if any matching deny policy applies, access is denied
- `required_scopes` on allow policies: user must have ALL listed scopes for the policy to match
- If no policies match a tool, access defaults to allowed (adapter-level fallback)
- Tool filtering applies to both the unified MCP endpoint (`/mcp`) and per-adapter REST endpoints (`/adapters/{name}/tools`)

## Unified MCP Endpoint Authentication

The unified MCP endpoint (`/api/v1/mcp`) aggregates tools, resources, and prompts from all registered adapters into a single interface. It implements a comprehensive authentication and authorization flow.

### Authentication Flow

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐     ┌─────────────┐
│   Client    │────▶│  OAuth Middleware │────▶│  Unified MCP    │────▶│  Backend    │
│  (Claude,   │     │  (validates JWT,  │     │  Handler        │     │  Adapter    │
│   IDE)      │     │   extracts claims)│     │  (authorization │     │  (ServiceNow│
└─────────────┘     └──────────────────┘     │   + routing)    │     │   Databricks)
                                              └─────────────────┘     └─────────────┘
```

1. **Client Authentication**: Client sends request with `Authorization: Bearer <token>` header
2. **OAuth Middleware**: Validates the JWT token and extracts user claims (user_id, email, groups, roles)
3. **Context Injection**: `InjectOAuthContext` middleware propagates claims to the request context
4. **User Context**: Handler extracts authenticated user context including:
   - `user_id` - User identifier
   - `username` - Display name
   - `email` - User email
   - `groups` - OIDC groups (from Rancher/IdP)
   - `roles` - OIDC roles
   - `access_token` - Raw token for downstream auth
5. **Tool Authorization**: Before listing or calling tools, policies are evaluated with scope awareness
6. **Downstream Auth**: Requests to backend adapters include appropriate authentication (token exchange, service account, etc.)

### Backwards Compatibility

For development and legacy clients, the endpoint falls back to `X-User-ID` header if no OAuth context is present:

```bash
# OAuth authentication (recommended)
curl -X POST https://proxy.example.com/api/v1/mcp \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}'

# Legacy X-User-ID header (dev mode only)
curl -X POST https://proxy.example.com/api/v1/mcp \
  -H "X-User-ID: alice" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}'
```

### Tool Authorization with Scope Awareness

The unified endpoint implements two-tier authorization:

1. **Scope Resolution**: User's groups/roles are mapped to backend-specific scopes via adapter scope policies
2. **Tool Filtering**: Authorization policies filter which tools are visible based on groups AND resolved scopes

```
User Request → Resolve Scopes → Filter Tools → Return Allowed Tools
     │              │                │
     │              ▼                ▼
     │         scope_policies    tool_policies
     │         (groups → scopes) (groups + scopes → allow/deny)
     │
     └── groups: ["data-engineers"]
         roles: ["analyst"]
```

#### Example: Scope-Aware Tool Filtering

Given an adapter with scope policies:
```json
{
  "scope_policies": [
    {"groups": ["data-engineers"], "scopes": ["sql:write", "clusters:manage"]},
    {"groups": ["analysts"], "scopes": ["sql:read"]}
  ]
}
```

And a tool authorization policy:
```json
{
  "adapter_name": "databricks",
  "tool_name": "drop_table",
  "effect": "allow",
  "allowed_groups": ["data-engineers"],
  "required_scopes": ["sql:write"]
}
```

A user in the `data-engineers` group will:
1. Have scopes `["sql:write", "clusters:manage"]` resolved
2. See `drop_table` in `tools/list` (passes both group AND scope check)
3. Be able to call `drop_table` via `tools/call`

A user in the `analysts` group will:
1. Have scopes `["sql:read"]` resolved
2. NOT see `drop_table` in `tools/list` (fails scope check)
3. Receive a 403 error if they try to call it directly

### Downstream Authentication

When forwarding requests to backend adapters, the unified endpoint applies the configured authentication:

| Auth Type | Flow |
|-----------|------|
| `bearer` | Static/dynamic bearer token attached to request |
| `token_exchange` | User's Rancher ID token exchanged for backend token via RFC 8693 |
| `service_account` | Proxy credentials + user impersonation header + scope header |
| `spiffe` (mTLS) | X.509 SVID certificate for workload identity |
| `spiffe` (JWT) | JWT SVID exchanged for backend token |

#### Token Exchange Flow

```
┌────────┐    ┌───────────────┐    ┌─────────────────┐    ┌──────────┐
│ Client │───▶│ Unified MCP   │───▶│ Token Vault     │───▶│ Backend  │
│        │    │ Handler       │    │ (RFC 8693)      │    │ Token    │
└────────┘    └───────────────┘    └─────────────────┘    │ Endpoint │
                     │                     │              └──────────┘
                     │                     │
                     ▼                     ▼
              User's Rancher        Scope policies
              ID Token              resolve scopes
              (from session)        for exchange
```

1. Handler looks up user's OAuth session to get Rancher ID token
2. Scope policies resolve user-specific scopes based on groups/roles
3. Token vault exchanges ID token for backend access token with resolved scopes
4. Backend token is cached and reused until expiration

#### Service Account Flow

```
┌────────┐    ┌───────────────┐    ┌──────────────┐
│ Client │───▶│ Unified MCP   │───▶│ Backend      │
│        │    │ Handler       │    │ Adapter      │
└────────┘    └───────────────┘    └──────────────┘
                     │
                     ├─ Authorization: Basic <sa_credentials>
                     ├─ X-UserToken: alice@example.com (impersonation)
                     └─ X-User-Scopes: incident:read incident:write
```

1. Proxy authenticates with service account credentials (Basic auth)
2. User identity sent via impersonation header (configurable field: email or username)
3. Resolved scopes sent via scope header for backend authorization

## Development Mode

When `DEV_MODE=true`, authentication is bypassed and you can use X-User-ID headers:

```bash
curl -X GET http://localhost:8911/api/v1/users \
  -H "X-User-ID: admin"
```

This is useful for development and testing without setting up full authentication.

## Troubleshooting

### Common Issues

1. **403 Forbidden**: Check user permissions and group memberships
2. **Invalid Token**: Verify JWT hasn't expired, check issuer/audience
3. **OAuth Callback Errors**: Ensure redirect URIs match provider settings
4. **Rancher Group Mapping**: Confirm OIDC claims include group information

### Debug Mode

Set `LOG_LEVEL=debug` to see detailed authentication logs.

### Token Expiration

JWT tokens expire after 24 hours. Use the refresh token flow or re-authenticate.

### Password Requirements

- Minimum 8 characters (configurable)
- Admin password must be changed on first login
- Strong password recommended for production

## Security Considerations

1. **HTTPS Required**: Always use HTTPS in production
2. **Secure Secrets**: Store client secrets securely, not in environment variables
3. **Token Storage**: Store JWT tokens securely on client side
4. **Regular Rotation**: Rotate OAuth client secrets regularly
5. **Audit Logging**: Monitor authentication attempts and failures

## Migration Guide

### From No Authentication

1. Set `AUTH_MODE=local`
2. Start service (creates admin user)
3. Login as admin and change password
4. Create additional users via API

### Adding OAuth Providers

1. Configure provider settings
2. Test OAuth flow with test user
3. Update existing users if needed
4. Set as primary auth mode

### Rancher Integration

1. Configure Rancher OIDC client
2. Set admin group mappings
3. Test admin access via Rancher
4. Optionally disable local auth fallback

## API Reference

### Authentication Endpoints

- `GET /auth/mode` - Get current authentication configuration (unauthenticated)
- `POST /auth/login` - Local user login
- `POST /auth/oauth/login` - Initiate OAuth/OIDC flow
- `POST /auth/oauth/callback` - Handle OAuth/OIDC callback
- `PUT /auth/password` - Change password
- `POST /auth/logout` - Logout

### Unified MCP Endpoint

- `POST /api/v1/mcp` - Unified MCP JSON-RPC endpoint (authenticated)
  - Supports methods: `initialize`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`, `prompts/get`
  - Requires `Authorization: Bearer <token>` header (or `X-User-ID` in dev mode)
  - Returns aggregated tools/resources/prompts from all accessible adapters
  - Tool names prefixed with adapter name (e.g., `servicenow__get_incident`)
  - Resource URIs prefixed with adapter scheme (e.g., `servicenow://incident/INC0001`)

### User and Group Management Endpoints

#### Users
- `GET /api/v1/users` - List all users (unauthenticated)
- `GET /api/v1/users/{id}` - Get user details (unauthenticated)
- `POST /api/v1/users` - Create new user (authenticated)
- `PUT /api/v1/users/{id}` - Update user (authenticated)
- `DELETE /api/v1/users/{id}` - Delete user (authenticated)

#### Groups
- `GET /api/v1/groups` - List all groups with members (unauthenticated)
- `GET /api/v1/groups/{id}` - Get group details with members (unauthenticated)
- `POST /api/v1/groups` - Create new group (authenticated)
- `PUT /api/v1/groups/{id}` - Update group (authenticated)
- `DELETE /api/v1/groups/{id}` - Delete group (authenticated)

#### Group Members
- `POST /api/v1/groups/{id}/members` - Add user to group (authenticated)
- `DELETE /api/v1/groups/{id}/members/{userId}` - Remove user from group (authenticated)

**Note**: Group responses include a `members` array containing the user IDs of all users in that group.

### Error Codes

- `401 Unauthorized`: Missing or invalid authentication
- `403 Forbidden`: Insufficient permissions
- `400 Bad Request`: Invalid request parameters</content>
<parameter name="filePath">AUTHENTICATION.md