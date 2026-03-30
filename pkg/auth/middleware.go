package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// DevelopmentAuthMiddleware is a simple middleware for development
func DevelopmentAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// In development, set a fake user
		c.Set("user", "dev")
		c.Next()
	}
}

// ExternalOAuthConfig holds external OAuth provider configuration
type ExternalOAuthConfig struct {
	Provider string
	ClientID string
	TenantID string
	JWKSURL  string
	Issuer   string
	Audience string
	Required bool
}

// OAuthMiddleware provides OAuth authentication
type OAuthMiddleware struct {
	config *ExternalOAuthConfig
}

// NewOAuthMiddleware creates a new OAuth middleware
func NewOAuthMiddleware(config *ExternalOAuthConfig) *OAuthMiddleware {
	return &OAuthMiddleware{config: config}
}

// Middleware returns the Gin middleware function
func (om *OAuthMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// For minimal version, check for Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			if om.config.Required {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization required"})
				c.Abort()
				return
			}
			// Not required, set default user
			c.Set("user", "anonymous")
			c.Next()
			return
		}

		// Basic Bearer token validation (placeholder)
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if userID, err := om.validateToken(token); err == nil {
				c.Set("user", userID)
				c.Next()
				return
			}
		}

		if om.config.Required {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Fallback to anonymous
		c.Set("user", "anonymous")
		c.Next()
	}
}

// validateToken performs basic token validation (placeholder for full JWT validation)
func (om *OAuthMiddleware) validateToken(tokenString string) (string, error) {
	// For minimal version, accept any non-empty token as valid
	// In production, this would validate JWT signature, issuer, audience, etc.
	if tokenString == "" {
		return "", fmt.Errorf("empty token")
	}

	// For minimal version, just return a user ID based on token presence
	// This is NOT secure and should be replaced with proper JWT validation
	return "authenticated-user", nil
}

// MCPOAuthMiddleware validates proxy-issued JWT bearer tokens for MCP endpoints.
// On failure, returns 401 with WWW-Authenticate header per RFC 9728.
func MCPOAuthMiddleware(tokenManager *TokenManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			issuer := tokenManager.GetIssuer()
			c.Header("WWW-Authenticate", fmt.Sprintf(
				`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, issuer))
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": "Missing bearer token. Use OAuth discovery to authenticate.",
			})
			c.Abort()
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": "Invalid authorization scheme. Use Bearer.",
			})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := tokenManager.ValidateOAuthToken(tokenString)
		if err != nil {
			issuer := tokenManager.GetIssuer()
			c.Header("WWW-Authenticate", fmt.Sprintf(
				`Bearer resource_metadata="%s/.well-known/oauth-protected-resource", error="invalid_token"`, issuer))
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": err.Error(),
			})
			c.Abort()
			return
		}

		// Set user identity in context and header for downstream handlers
		if sub, ok := claims["sub"].(string); ok {
			c.Set("user_id", sub)
			c.Request.Header.Set("X-User-ID", sub)
		}
		if username, ok := claims["username"].(string); ok {
			c.Set("username", username)
		}
		if email, ok := claims["email"].(string); ok {
			c.Set("email", email)
		}
		if groups, ok := claims["groups"].([]interface{}); ok {
			groupStrs := make([]string, 0, len(groups))
			for _, g := range groups {
				if s, ok := g.(string); ok {
					groupStrs = append(groupStrs, s)
				}
			}
			c.Set("groups", groupStrs)
		}
		if roles, ok := claims["roles"].([]interface{}); ok {
			roleStrs := make([]string, 0, len(roles))
			for _, r := range roles {
				if s, ok := r.(string); ok {
					roleStrs = append(roleStrs, s)
				}
			}
			c.Set("roles", roleStrs)
		}
		if clientID, ok := claims["client_id"].(string); ok {
			c.Set("client_id", clientID)
		}
		if scope, ok := claims["scope"].(string); ok {
			c.Set("scope", scope)
		}

		// Store the raw token for downstream token vault lookups
		c.Set("access_token", tokenString)

		c.Next()
	}
}
