package models

import (
	"time"
)

// OAuthRegisteredClient represents a dynamically registered MCP client (RFC 7591).
type OAuthRegisteredClient struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	CreatedAt               time.Time `json:"created_at"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
}

// OAuthAuthorizationCode represents a short-lived authorization code issued during the OAuth flow.
type OAuthAuthorizationCode struct {
	Code                string                 `json:"code"`
	ClientID            string                 `json:"client_id"`
	RedirectURI         string                 `json:"redirect_uri"`
	CodeChallenge       string                 `json:"code_challenge"`
	CodeChallengeMethod string                 `json:"code_challenge_method"`
	UserID              string                 `json:"user_id"`
	UserClaims          map[string]interface{} `json:"user_claims"`
	Scopes              []string               `json:"scopes"`
	ExpiresAt           time.Time              `json:"expires_at"`
	Used                bool                   `json:"used"`
	// State preserved from the authorization request for validation
	State string `json:"state"`
	// RancherIDToken is the upstream Rancher ID token for downstream exchanges
	RancherIDToken string `json:"rancher_id_token,omitempty"`
}

// OAuthSession represents an active authenticated session with proxy-issued tokens.
type OAuthSession struct {
	SessionID             string                 `json:"session_id"`
	ClientID              string                 `json:"client_id"`
	UserID                string                 `json:"user_id"`
	UserClaims            map[string]interface{} `json:"user_claims"`
	AccessToken           string                 `json:"access_token"`
	RefreshToken          string                 `json:"refresh_token"`
	AccessTokenExpiresAt  time.Time              `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time              `json:"refresh_token_expires_at"`
	Scopes                []string               `json:"scopes"`
	CreatedAt             time.Time              `json:"created_at"`
	LastActivityAt        time.Time              `json:"last_activity_at"`
	RancherIDToken        string                 `json:"rancher_id_token,omitempty"`
}

// TokenVaultEntry represents a securely stored downstream service token.
type TokenVaultEntry struct {
	EntryID         string            `json:"entry_id"`
	UserID          string            `json:"user_id"`
	AdapterName     string            `json:"adapter_name"`
	ServiceType     string            `json:"service_type"`
	AccessToken     string            `json:"access_token"`
	RefreshToken    string            `json:"refresh_token,omitempty"`
	ExpiresAt       time.Time         `json:"expires_at"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	LastRefreshedAt time.Time         `json:"last_refreshed_at"`
}

// IsExpired returns true if the vault entry's access token has expired.
func (t *TokenVaultEntry) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// AuthorizationPolicy represents an administrator-defined rule for tool-level access control.
type AuthorizationPolicy struct {
	PolicyID     string    `json:"policy_id"`
	AdapterName  string    `json:"adapter_name"`
	ToolName     string    `json:"tool_name"`
	AllowedGroups []string `json:"allowed_groups,omitempty"`
	AllowedUsers  []string `json:"allowed_users,omitempty"`
	DeniedGroups  []string `json:"denied_groups,omitempty"`
	DeniedUsers   []string `json:"denied_users,omitempty"`
	Effect       string    `json:"effect"`
	Priority     int       `json:"priority"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// RegistrationRateLimit tracks dynamic client registration rate per source IP.
type RegistrationRateLimit struct {
	SourceIP    string    `json:"source_ip"`
	WindowStart time.Time `json:"window_start"`
	Count       int       `json:"count"`
}

// ScopePolicy maps user groups/users to backend scopes for an adapter.
// When a user matches multiple policies, their scopes are merged (union).
// If no policies match, the adapter's default Scopes field is used as fallback.
type ScopePolicy struct {
	Groups   []string `json:"groups,omitempty"`   // Match users in any of these groups
	Users    []string `json:"users,omitempty"`    // Match specific user IDs
	Scopes   []string `json:"scopes"`             // Backend scopes to grant
	Priority int      `json:"priority,omitempty"` // Higher priority evaluated first (default 0)
}

// TokenExchangeConfig holds RFC 8693 token exchange configuration for an adapter.
type TokenExchangeConfig struct {
	TokenEndpoint    string   `json:"token_endpoint"`
	Audience         string   `json:"audience"`
	Resource         string   `json:"resource,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	SubjectTokenType string   `json:"subject_token_type"`
	// UseWorkloadIdentity indicates the subject token should come from SPIRE (JWT SVID)
	// instead of the user's Rancher ID token
	UseWorkloadIdentity bool `json:"use_workload_identity,omitempty"`
	// ScopePolicies maps user identity to backend scopes. If set, scopes are resolved
	// per-user based on their groups/identity instead of using the static Scopes field.
	ScopePolicies []ScopePolicy `json:"scope_policies,omitempty"`
}

// ServiceAccountConfig holds service account impersonation configuration.
type ServiceAccountConfig struct {
	Username            string `json:"username"`
	Password            string `json:"password"`
	ImpersonationHeader string `json:"impersonation_header"`
	ImpersonationField  string `json:"impersonation_field"`
	// ScopeHeader is the HTTP header name to send resolved scopes to the backend.
	// If set, the proxy sends the user's resolved scopes via this header.
	ScopeHeader string `json:"scope_header,omitempty"`
	// ScopePolicies maps user identity to backend scopes for service account mode.
	ScopePolicies []ScopePolicy `json:"scope_policies,omitempty"`
}
