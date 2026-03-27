package service

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"suse-ai-up/pkg/auth"
	"suse-ai-up/pkg/models"
)

// MCPAuthIntegrationService handles authentication integration for MCP adapters
type MCPAuthIntegrationService struct {
	tokenManager     *auth.TokenManager
	tokenVaultService *TokenVaultService
	oauthService     *OAuthServerService
	httpClient       *http.Client
}

// NewMCPAuthIntegrationService creates a new MCP auth integration service
func NewMCPAuthIntegrationService(tokenManager *auth.TokenManager) *MCPAuthIntegrationService {
	return &MCPAuthIntegrationService{
		tokenManager: tokenManager,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

// SetTokenVaultService sets the token vault service for token exchange support.
func (mais *MCPAuthIntegrationService) SetTokenVaultService(tvs *TokenVaultService) {
	mais.tokenVaultService = tvs
}

// SetOAuthService sets the OAuth server service for session lookups.
func (mais *MCPAuthIntegrationService) SetOAuthService(svc *OAuthServerService) {
	mais.oauthService = svc
}

// GetClientToken retrieves a client token for the given adapter
func (mais *MCPAuthIntegrationService) GetClientToken(adapter models.AdapterResource) (*ClientTokenResponse, error) {
	log.Printf("MCPAuthIntegrationService: Getting client token for adapter %s", adapter.Name)

	if adapter.Authentication == nil || !adapter.Authentication.Required {
		return &ClientTokenResponse{
			Token:     "",
			Type:      "none",
			ExpiresAt: time.Time{},
			Message:   "No authentication required",
		}, nil
	}

	switch adapter.Authentication.Type {
	case "bearer":
		return mais.getBearerToken(adapter)
	case "oauth":
		return mais.getOAuthToken(adapter)
	case "basic":
		return mais.getBasicAuth(adapter)
	case "apikey":
		return mais.getAPIKey(adapter)
	case "token_exchange":
		return nil, fmt.Errorf("token_exchange requires user context; use GetUserToken instead")
	case "service_account":
		return nil, fmt.Errorf("service_account requires user context; use GetUserToken instead")
	case "spiffe":
		return nil, fmt.Errorf("spiffe auth requires user context; use GetUserToken instead")
	default:
		return nil, fmt.Errorf("unsupported authentication type: %s", adapter.Authentication.Type)
	}
}

// ClientTokenResponse represents a client token response
type ClientTokenResponse struct {
	Token     string    `json:"token"`
	Type      string    `json:"type"`
	ExpiresAt time.Time `json:"expiresAt"`
	Message   string    `json:"message,omitempty"`
}

// getBearerToken handles bearer token authentication
func (mais *MCPAuthIntegrationService) getBearerToken(adapter models.AdapterResource) (*ClientTokenResponse, error) {
	// Check for bearer token configuration
	if adapter.Authentication.BearerToken != nil && adapter.Authentication.BearerToken.Token != "" {
		return &ClientTokenResponse{
			Token:     adapter.Authentication.BearerToken.Token,
			Type:      "bearer",
			ExpiresAt: adapter.Authentication.BearerToken.ExpiresAt,
			Message:   "Using bearer token",
		}, nil
	}

	// Check for new bearer token configuration
	if adapter.Authentication.BearerToken != nil {
		if adapter.Authentication.BearerToken.Token != "" && !adapter.Authentication.BearerToken.Dynamic {
			return &ClientTokenResponse{
				Token:     adapter.Authentication.BearerToken.Token,
				Type:      "bearer",
				ExpiresAt: adapter.Authentication.BearerToken.ExpiresAt,
				Message:   "Using static bearer token",
			}, nil
		}

		// Generate dynamic token if token manager is available
		if adapter.Authentication.BearerToken.Dynamic && mais.tokenManager != nil {
			tokenInfo, err := mais.tokenManager.GenerateBearerToken(adapter.Name, adapter.RemoteUrl, 24)
			if err != nil {
				return nil, fmt.Errorf("failed to generate dynamic bearer token: %w", err)
			}

			return &ClientTokenResponse{
				Token:     tokenInfo.AccessToken,
				Type:      "bearer",
				ExpiresAt: tokenInfo.ExpiresAt,
				Message:   "Using dynamic bearer token",
			}, nil
		}
	}

	return nil, fmt.Errorf("no bearer token configuration found")
}

// getOAuthToken handles OAuth authentication
func (mais *MCPAuthIntegrationService) getOAuthToken(adapter models.AdapterResource) (*ClientTokenResponse, error) {
	if adapter.Authentication.OAuth == nil {
		return nil, fmt.Errorf("OAuth configuration not found")
	}

	oauthConfig := adapter.Authentication.OAuth

	// For now, return a placeholder message
	// In a full implementation, this would handle OAuth flows
	return &ClientTokenResponse{
		Token:     "",
		Type:      "oauth",
		ExpiresAt: time.Time{},
		Message:   fmt.Sprintf("OAuth authentication configured for client ID: %s. Please use OAuth flow to obtain token.", oauthConfig.ClientID),
	}, nil
}

// getBasicAuth handles basic authentication
func (mais *MCPAuthIntegrationService) getBasicAuth(adapter models.AdapterResource) (*ClientTokenResponse, error) {
	if adapter.Authentication.Basic == nil {
		return nil, fmt.Errorf("Basic authentication configuration not found")
	}

	basicConfig := adapter.Authentication.Basic

	// Create basic auth token (base64 encoded username:password)
	credentials := fmt.Sprintf("%s:%s", basicConfig.Username, basicConfig.Password)
	// Note: In a real implementation, you would base64 encode this
	// For security reasons, we're not exposing the actual password in the response

	return &ClientTokenResponse{
		Token:     credentials, // In practice, this would be base64 encoded
		Type:      "basic",
		ExpiresAt: time.Time{},
		Message:   "Basic authentication credentials",
	}, nil
}

// getAPIKey handles API key authentication
func (mais *MCPAuthIntegrationService) getAPIKey(adapter models.AdapterResource) (*ClientTokenResponse, error) {
	if adapter.Authentication.APIKey == nil {
		return nil, fmt.Errorf("API key configuration not found")
	}

	apiKeyConfig := adapter.Authentication.APIKey

	return &ClientTokenResponse{
		Token:     apiKeyConfig.Key,
		Type:      "apikey",
		ExpiresAt: time.Time{},
		Message:   fmt.Sprintf("API key authentication (location: %s, name: %s)", apiKeyConfig.Location, apiKeyConfig.Name),
	}, nil
}

// GetUserToken retrieves a downstream token for user-context auth types (token_exchange, service_account).
// accessToken is the user's proxy-issued access token, used to look up their session and Rancher ID token.
func (mais *MCPAuthIntegrationService) GetUserToken(adapter models.AdapterResource, userID, accessToken string) (*ClientTokenResponse, error) {
	if adapter.Authentication == nil || !adapter.Authentication.Required {
		return &ClientTokenResponse{Token: "", Type: "none", Message: "No authentication required"}, nil
	}

	switch adapter.Authentication.Type {
	case "token_exchange":
		return mais.getTokenExchangeToken(adapter, userID, accessToken)
	case "service_account":
		return mais.getServiceAccountToken(adapter, userID)
	case "spiffe":
		return mais.getSPIFFEToken(adapter, userID, accessToken)
	default:
		// Fall back to non-user-context auth
		return mais.GetClientToken(adapter)
	}
}

// getTokenExchangeToken performs RFC 8693 token exchange for the user.
func (mais *MCPAuthIntegrationService) getTokenExchangeToken(adapter models.AdapterResource, userID, accessToken string) (*ClientTokenResponse, error) {
	if mais.tokenVaultService == nil {
		return nil, fmt.Errorf("token vault service not configured")
	}
	if mais.oauthService == nil {
		return nil, fmt.Errorf("OAuth service not configured")
	}
	if adapter.Authentication.TokenExchange == nil {
		return nil, fmt.Errorf("token_exchange configuration not found for adapter %s", adapter.Name)
	}

	// Look up the user's session to get the Rancher ID token
	session, err := mais.oauthService.GetSessionByAccessToken(accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to find session for token exchange: %w", err)
	}

	if session.RancherIDToken == "" {
		return nil, fmt.Errorf("no Rancher ID token in session for token exchange")
	}

	// Exchange or retrieve cached downstream token
	entry, err := mais.tokenVaultService.GetOrExchangeToken(userID, adapter.Name, session.RancherIDToken, adapter.Authentication.TokenExchange)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed for adapter %s: %w", adapter.Name, err)
	}

	return &ClientTokenResponse{
		Token:     entry.AccessToken,
		Type:      "bearer",
		ExpiresAt: entry.ExpiresAt,
		Message:   "Using exchanged token via RFC 8693",
	}, nil
}

// getServiceAccountToken returns service account credentials with impersonation for the user.
func (mais *MCPAuthIntegrationService) getServiceAccountToken(adapter models.AdapterResource, userID string) (*ClientTokenResponse, error) {
	if adapter.Authentication.ServiceAccount == nil {
		return nil, fmt.Errorf("service_account configuration not found for adapter %s", adapter.Name)
	}

	// Service account auth uses static credentials; impersonation is applied at request time
	return &ClientTokenResponse{
		Token:   adapter.Authentication.ServiceAccount.Username,
		Type:    "service_account",
		Message: fmt.Sprintf("Service account impersonation for user %s", userID),
	}, nil
}

// getSPIFFEToken handles SPIFFE workload identity authentication.
// If the adapter has a TokenExchange config with UseWorkloadIdentity, it performs
// RFC 8693 token exchange using a JWT SVID as the subject token.
// If the adapter has UseMTLS, the mTLS transport is applied at request time instead.
func (mais *MCPAuthIntegrationService) getSPIFFEToken(adapter models.AdapterResource, userID, accessToken string) (*ClientTokenResponse, error) {
	if adapter.Authentication.SPIFFE == nil {
		return nil, fmt.Errorf("spiffe configuration not found for adapter %s", adapter.Name)
	}

	spiffeCfg := adapter.Authentication.SPIFFE

	// mTLS mode: no bearer token needed, mTLS is applied at request transport level
	if spiffeCfg.UseMTLS {
		return &ClientTokenResponse{
			Token:   "",
			Type:    "spiffe_mtls",
			Message: "Using SPIFFE X.509 SVID mTLS for downstream authentication",
		}, nil
	}

	// JWT SVID mode: use workload identity for token exchange
	if mais.tokenVaultService == nil {
		return nil, fmt.Errorf("token vault service not configured for SPIFFE token exchange")
	}

	// Build a synthetic TokenExchangeConfig for the SVID-based exchange
	if adapter.Authentication.TokenExchange == nil {
		return nil, fmt.Errorf("spiffe JWT mode requires tokenExchange configuration on adapter %s", adapter.Name)
	}

	exchangeConfig := *adapter.Authentication.TokenExchange
	exchangeConfig.UseWorkloadIdentity = true
	if spiffeCfg.TargetAudience != "" {
		exchangeConfig.Audience = spiffeCfg.TargetAudience
	}

	entry, err := mais.tokenVaultService.GetOrExchangeToken(userID, adapter.Name, "", &exchangeConfig)
	if err != nil {
		return nil, fmt.Errorf("SPIFFE token exchange failed for adapter %s: %w", adapter.Name, err)
	}

	return &ClientTokenResponse{
		Token:     entry.AccessToken,
		Type:      "bearer",
		ExpiresAt: entry.ExpiresAt,
		Message:   "Using token exchanged via SPIFFE JWT SVID (RFC 8693)",
	}, nil
}

// ApplyUserAuthToRequest applies user-context authentication to an outbound HTTP request.
func (mais *MCPAuthIntegrationService) ApplyUserAuthToRequest(req *http.Request, adapter models.AdapterResource, userID, userEmail, accessToken string) error {
	if adapter.Authentication == nil || !adapter.Authentication.Required {
		return nil
	}

	switch adapter.Authentication.Type {
	case "token_exchange":
		tokenResp, err := mais.getTokenExchangeToken(adapter, userID, accessToken)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tokenResp.Token)
		return nil

	case "service_account":
		return mais.applyServiceAccountAuth(req, adapter, userID, userEmail)

	case "spiffe":
		return mais.applySPIFFEAuth(req, adapter, userID, accessToken)

	default:
		return mais.ApplyAuthToRequest(req, adapter.Authentication)
	}
}

// applySPIFFEAuth applies SPIFFE authentication to an outbound request.
// For mTLS mode, the TLS transport must be configured separately on the HTTP client.
// For JWT SVID mode, applies the exchanged bearer token.
func (mais *MCPAuthIntegrationService) applySPIFFEAuth(req *http.Request, adapter models.AdapterResource, userID, accessToken string) error {
	tokenResp, err := mais.getSPIFFEToken(adapter, userID, accessToken)
	if err != nil {
		return err
	}
	if tokenResp.Type == "spiffe_mtls" {
		// mTLS: no Authorization header needed; TLS client cert handles auth
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+tokenResp.Token)
	return nil
}

// applyServiceAccountAuth applies service account credentials with impersonation headers.
func (mais *MCPAuthIntegrationService) applyServiceAccountAuth(req *http.Request, adapter models.AdapterResource, userID, userEmail string) error {
	sa := adapter.Authentication.ServiceAccount
	if sa == nil {
		return fmt.Errorf("service_account configuration not found")
	}

	// Set basic auth with service account credentials
	req.SetBasicAuth(sa.Username, sa.Password)

	// Set impersonation header
	impersonationValue := userEmail
	if sa.ImpersonationField == "username" {
		impersonationValue = userID
	}
	if impersonationValue != "" && sa.ImpersonationHeader != "" {
		req.Header.Set(sa.ImpersonationHeader, impersonationValue)
	}

	return nil
}

// ValidateAuthConfig validates authentication configuration
func (mais *MCPAuthIntegrationService) ValidateAuthConfig(auth *models.AdapterAuthConfig) error {
	if auth == nil {
		return nil // No auth is valid
	}

	switch auth.Type {
	case "none":
		return nil
	case "bearer":
		return mais.validateBearerConfig(auth)
	case "oauth":
		return mais.validateOAuthConfig(auth)
	case "basic":
		return mais.validateBasicConfig(auth)
	case "apikey":
		return mais.validateAPIKeyConfig(auth)
	case "token_exchange":
		return mais.validateTokenExchangeConfig(auth)
	case "service_account":
		return mais.validateServiceAccountConfig(auth)
	case "spiffe":
		return mais.validateSPIFFEConfig(auth)
	default:
		return fmt.Errorf("unsupported authentication type: %s", auth.Type)
	}
}

// validateBearerConfig validates bearer token configuration
func (mais *MCPAuthIntegrationService) validateBearerConfig(auth *models.AdapterAuthConfig) error {
	// Check bearer token configuration
	if auth.BearerToken == nil {
		return fmt.Errorf("bearer token configuration is required")
	}

	if auth.BearerToken.Token == "" && !auth.BearerToken.Dynamic {
		return fmt.Errorf("either static token or dynamic token generation must be configured")
	}

	return nil
}

// validateOAuthConfig validates OAuth configuration
func (mais *MCPAuthIntegrationService) validateOAuthConfig(auth *models.AdapterAuthConfig) error {
	if auth.OAuth == nil {
		return fmt.Errorf("OAuth configuration is required")
	}

	if auth.OAuth.ClientID == "" {
		return fmt.Errorf("OAuth client ID is required")
	}

	if auth.OAuth.AuthURL == "" {
		return fmt.Errorf("OAuth authorization URL is required")
	}

	if auth.OAuth.TokenURL == "" {
		return fmt.Errorf("OAuth token URL is required")
	}

	return nil
}

// validateBasicConfig validates basic authentication configuration
func (mais *MCPAuthIntegrationService) validateBasicConfig(auth *models.AdapterAuthConfig) error {
	if auth.Basic == nil {
		return fmt.Errorf("Basic authentication configuration is required")
	}

	if auth.Basic.Username == "" {
		return fmt.Errorf("username is required for basic authentication")
	}

	if auth.Basic.Password == "" {
		return fmt.Errorf("password is required for basic authentication")
	}

	return nil
}

// validateAPIKeyConfig validates API key configuration
func (mais *MCPAuthIntegrationService) validateAPIKeyConfig(auth *models.AdapterAuthConfig) error {
	if auth.APIKey == nil {
		return fmt.Errorf("API key configuration is required")
	}

	if auth.APIKey.Key == "" {
		return fmt.Errorf("API key is required")
	}

	if auth.APIKey.Location == "" {
		auth.APIKey.Location = "header" // Default to header
	}

	if auth.APIKey.Name == "" {
		auth.APIKey.Name = "X-API-Key" // Default header name
	}

	// Validate location
	validLocations := []string{"header", "query", "cookie"}
	valid := false
	for _, loc := range validLocations {
		if auth.APIKey.Location == loc {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid API key location: %s. Valid options: %v", auth.APIKey.Location, validLocations)
	}

	return nil
}

// ApplyAuthToRequest applies authentication to an HTTP request
func (mais *MCPAuthIntegrationService) ApplyAuthToRequest(req *http.Request, auth *models.AdapterAuthConfig) error {
	if auth == nil || !auth.Required {
		return nil // No authentication required
	}

	switch auth.Type {
	case "bearer":
		return mais.applyBearerAuth(req, auth)
	case "oauth":
		return mais.applyOAuthAuth(req, auth)
	case "basic":
		return mais.applyBasicAuth(req, auth)
	case "apikey":
		return mais.applyAPIKeyAuth(req, auth)
	default:
		return fmt.Errorf("unsupported authentication type: %s", auth.Type)
	}
}

// applyBearerAuth applies bearer authentication to request
func (mais *MCPAuthIntegrationService) applyBearerAuth(req *http.Request, auth *models.AdapterAuthConfig) error {
	var token string

	// Check bearer token configuration
	if auth.BearerToken != nil {
		if auth.BearerToken.Token != "" {
			token = auth.BearerToken.Token
		} else if auth.BearerToken.Dynamic && mais.tokenManager != nil {
			// Generate dynamic token
			tokenInfo, err := mais.tokenManager.GenerateBearerToken("", "", 24)
			if err != nil {
				return fmt.Errorf("failed to generate dynamic bearer token: %w", err)
			}
			token = tokenInfo.AccessToken
		}
	}

	if token == "" {
		return fmt.Errorf("no bearer token available")
	}

	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// applyOAuthAuth applies OAuth authentication to request
func (mais *MCPAuthIntegrationService) applyOAuthAuth(req *http.Request, auth *models.AdapterAuthConfig) error {
	// For now, this is a placeholder
	// In a full implementation, this would handle OAuth token management
	return fmt.Errorf("OAuth authentication not yet implemented for request signing")
}

// applyBasicAuth applies basic authentication to request
func (mais *MCPAuthIntegrationService) applyBasicAuth(req *http.Request, auth *models.AdapterAuthConfig) error {
	if auth.Basic == nil {
		return fmt.Errorf("basic authentication configuration not found")
	}

	req.SetBasicAuth(auth.Basic.Username, auth.Basic.Password)
	return nil
}

// applyAPIKeyAuth applies API key authentication to request
func (mais *MCPAuthIntegrationService) applyAPIKeyAuth(req *http.Request, auth *models.AdapterAuthConfig) error {
	if auth.APIKey == nil {
		return fmt.Errorf("API key configuration not found")
	}

	location := strings.ToLower(auth.APIKey.Location)
	name := auth.APIKey.Name
	key := auth.APIKey.Key

	switch location {
	case "header":
		req.Header.Set(name, key)
	case "query":
		// Add to query parameters
		if req.URL == nil {
			return fmt.Errorf("request URL is nil")
		}
		query := req.URL.Query()
		query.Set(name, key)
		req.URL.RawQuery = query.Encode()
	case "cookie":
		// Add cookie
		req.AddCookie(&http.Cookie{Name: name, Value: key})
	default:
		return fmt.Errorf("unsupported API key location: %s", location)
	}

	return nil
}

// validateTokenExchangeConfig validates token exchange configuration
func (mais *MCPAuthIntegrationService) validateTokenExchangeConfig(auth *models.AdapterAuthConfig) error {
	if auth.TokenExchange == nil {
		return fmt.Errorf("token_exchange configuration is required")
	}
	if auth.TokenExchange.TokenEndpoint == "" {
		return fmt.Errorf("token_exchange token_endpoint is required")
	}
	if auth.TokenExchange.SubjectTokenType == "" {
		return fmt.Errorf("token_exchange subject_token_type is required")
	}
	return nil
}

// validateServiceAccountConfig validates service account configuration
func (mais *MCPAuthIntegrationService) validateServiceAccountConfig(auth *models.AdapterAuthConfig) error {
	if auth.ServiceAccount == nil {
		return fmt.Errorf("service_account configuration is required")
	}
	if auth.ServiceAccount.Username == "" {
		return fmt.Errorf("service_account username is required")
	}
	if auth.ServiceAccount.Password == "" {
		return fmt.Errorf("service_account password is required")
	}
	if auth.ServiceAccount.ImpersonationHeader == "" {
		return fmt.Errorf("service_account impersonation_header is required")
	}
	return nil
}

// validateSPIFFEConfig validates SPIFFE authentication configuration
func (mais *MCPAuthIntegrationService) validateSPIFFEConfig(auth *models.AdapterAuthConfig) error {
	if auth.SPIFFE == nil {
		return fmt.Errorf("spiffe configuration is required")
	}
	// mTLS mode doesn't require additional config
	if auth.SPIFFE.UseMTLS {
		return nil
	}
	// JWT SVID mode requires a token exchange config for the downstream exchange
	if auth.TokenExchange == nil {
		return fmt.Errorf("spiffe JWT mode requires tokenExchange configuration")
	}
	if auth.TokenExchange.TokenEndpoint == "" {
		return fmt.Errorf("spiffe JWT mode requires tokenExchange.token_endpoint")
	}
	return nil
}
