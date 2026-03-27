package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// WellKnownHandler serves OAuth discovery endpoints (RFC 9728, RFC 8414).
type WellKnownHandler struct {
	issuerURL string
}

// NewWellKnownHandler creates a new handler for well-known endpoints.
func NewWellKnownHandler(issuerURL string) *WellKnownHandler {
	return &WellKnownHandler{issuerURL: issuerURL}
}

// GetProtectedResourceMetadata handles GET /.well-known/oauth-protected-resource (RFC 9728).
func (h *WellKnownHandler) GetProtectedResourceMetadata(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"resource":                 h.issuerURL,
		"authorization_servers":    []string{h.issuerURL},
		"scopes_supported":        []string{"mcp:read", "mcp:write", "mcp:admin"},
		"bearer_methods_supported": []string{"header"},
	})
}

// GetAuthorizationServerMetadata handles GET /.well-known/oauth-authorization-server (RFC 8414).
func (h *WellKnownHandler) GetAuthorizationServerMetadata(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                h.issuerURL,
		"authorization_endpoint":                h.issuerURL + "/oauth/authorize",
		"token_endpoint":                        h.issuerURL + "/oauth/token",
		"registration_endpoint":                 h.issuerURL + "/oauth/register",
		"revocation_endpoint":                   h.issuerURL + "/oauth/revoke",
		"scopes_supported":                      []string{"mcp:read", "mcp:write", "mcp:admin"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"service_documentation":                 h.issuerURL + "/docs",
	})
}
