package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"suse-ai-up/internal/config"
	"suse-ai-up/internal/service"
	"suse-ai-up/pkg/auth"
	"suse-ai-up/pkg/clients"
	"suse-ai-up/pkg/models"
)

// OAuthServerHandler handles all OAuth 2.1 AS endpoints.
type OAuthServerHandler struct {
	oauthService    *service.OAuthServerService
	userAuthService *auth.UserAuthService
	auditLogger     *auth.AuditLogger
	cfg             *config.Config
	policyStore     clients.AuthPolicyStore
}

// NewOAuthServerHandler creates a new OAuth server handler.
func NewOAuthServerHandler(oauthService *service.OAuthServerService, userAuthService *auth.UserAuthService, auditLogger *auth.AuditLogger, cfg *config.Config) *OAuthServerHandler {
	return &OAuthServerHandler{
		oauthService:    oauthService,
		userAuthService: userAuthService,
		auditLogger:     auditLogger,
		cfg:             cfg,
	}
}

// SetPolicyStore sets the authorization policy store for admin CRUD endpoints.
func (h *OAuthServerHandler) SetPolicyStore(store clients.AuthPolicyStore) {
	h.policyStore = store
}

// --- Dynamic Client Registration (POST /oauth/register) ---

type clientRegistrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// Register handles POST /oauth/register (RFC 7591).
func (h *OAuthServerHandler) Register(c *gin.Context) {
	var req clientRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client_metadata",
			"error_description": "Invalid request body",
		})
		return
	}

	if len(req.RedirectURIs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_redirect_uri",
			"error_description": "At least one redirect_uri is required",
		})
		return
	}

	client, err := h.oauthService.RegisterClient(
		req.ClientName,
		req.RedirectURIs,
		req.GrantTypes,
		req.ResponseTypes,
		req.TokenEndpointAuthMethod,
		c.ClientIP(),
	)
	if err != nil {
		if strings.Contains(err.Error(), "rate limit") {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":             "rate_limit_exceeded",
				"error_description": "Too many registration requests. Try again later.",
			})
			return
		}
		if strings.Contains(err.Error(), "allowlist") {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_redirect_uri",
				"error_description": err.Error(),
			})
			return
		}
		if strings.Contains(err.Error(), "max clients reached") {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":             "too_many_clients",
				"error_description": "Maximum number of registered clients reached. Try again later.",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to register client",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"client_id":                  client.ClientID,
		"client_name":               client.ClientName,
		"redirect_uris":             client.RedirectURIs,
		"grant_types":               client.GrantTypes,
		"response_types":            client.ResponseTypes,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"client_id_issued_at":       client.ClientIDIssuedAt,
	})
}

// --- Authorization Endpoint (GET /oauth/authorize) ---

// Authorize handles GET /oauth/authorize — validates parameters and redirects to Rancher OIDC.
func (h *OAuthServerHandler) Authorize(c *gin.Context) {
	responseType := c.Query("response_type")
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")
	scope := c.Query("scope")
	state := c.Query("state")

	if responseType != "code" {
		redirectWithError(c, redirectURI, "unsupported_response_type", "Only 'code' response type is supported", state)
		return
	}

	if err := h.oauthService.ValidateAuthorizationRequest(clientID, redirectURI, codeChallenge, codeChallengeMethod, scope, state); err != nil {
		redirectWithError(c, redirectURI, "invalid_request", err.Error(), state)
		return
	}

	// Generate PKCE verifier/challenge for the Rancher OIDC leg
	rancherVerifier, rancherChallenge := generatePKCE()

	// Store authorization request parameters in a temporary session cookie
	// so the callback can retrieve them after Rancher authentication
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", codeChallengeMethod)
	params.Set("scope", scope)
	params.Set("state", state)
	params.Set("rancher_pkce_verifier", rancherVerifier)

	// Store in a secure cookie for the callback to read
	secureCookie := !h.cfg.DevMode
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "oauth_params",
		Value:    params.Encode(),
		MaxAge:   600,
		Path:     "/",
		Secure:   secureCookie,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// Build Rancher OIDC authorization URL and redirect
	rancherAuthURL := h.buildRancherAuthURL(state, rancherChallenge)
	c.Redirect(http.StatusFound, rancherAuthURL)
}

// --- Token Endpoint (POST /oauth/token) ---

// Token handles POST /oauth/token — authorization code exchange and refresh token.
func (h *OAuthServerHandler) Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeExchange(c)
	case "refresh_token":
		h.handleRefreshToken(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": fmt.Sprintf("Grant type '%s' is not supported", grantType),
		})
	}
}

func (h *OAuthServerHandler) handleAuthorizationCodeExchange(c *gin.Context) {
	code := c.PostForm("code")
	clientID := c.PostForm("client_id")
	redirectURI := c.PostForm("redirect_uri")
	codeVerifier := c.PostForm("code_verifier")

	if code == "" || clientID == "" || redirectURI == "" || codeVerifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing required parameters: code, client_id, redirect_uri, code_verifier",
		})
		return
	}

	tokenResp, err := h.oauthService.ExchangeAuthorizationCode(code, clientID, redirectURI, codeVerifier)
	if err != nil {
		h.auditLogger.Log(auth.AuditEvent{
			EventType: auth.AuditEventLoginFailed,
			ClientID:  clientID,
			SourceIP:  c.ClientIP(),
			Detail:    err.Error(),
			Success:   false,
		})

		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, tokenResp)
}

func (h *OAuthServerHandler) handleRefreshToken(c *gin.Context) {
	refreshToken := c.PostForm("refresh_token")
	clientID := c.PostForm("client_id")

	if refreshToken == "" || clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing required parameters: refresh_token, client_id",
		})
		return
	}

	tokenResp, err := h.oauthService.RefreshAccessToken(refreshToken, clientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": err.Error(),
		})
		return
	}

	h.auditLogger.Log(auth.AuditEvent{
		EventType: auth.AuditEventTokenRefreshed,
		ClientID:  clientID,
		SourceIP:  c.ClientIP(),
		Success:   true,
	})

	c.JSON(http.StatusOK, tokenResp)
}

// --- Token Revocation (POST /oauth/revoke) ---

// Revoke handles POST /oauth/revoke (RFC 7009) — always returns 200.
func (h *OAuthServerHandler) Revoke(c *gin.Context) {
	token := c.PostForm("token")
	tokenTypeHint := c.PostForm("token_type_hint")
	clientID := c.PostForm("client_id")

	if token != "" {
		h.oauthService.RevokeToken(token, tokenTypeHint, clientID)
	}

	// Per RFC 7009, always return 200 even if token was already invalid
	c.JSON(http.StatusOK, gin.H{})
}

// --- OAuth Callback (GET /oauth/callback) ---

// Callback handles GET /oauth/callback — receives Rancher OIDC callback after user authenticates.
// Exchanges the Rancher authorization code for an ID token, extracts user claims,
// creates a proxy authorization code, and redirects back to the MCP client.
func (h *OAuthServerHandler) Callback(c *gin.Context) {
	rancherCode := c.Query("code")
	rancherError := c.Query("error")

	// Retrieve the original MCP client authorization params from the cookie
	oauthParams := h.getOAuthParamsFromCookie(c)
	clientRedirectURI := oauthParams.Get("redirect_uri")
	clientID := oauthParams.Get("client_id")
	codeChallenge := oauthParams.Get("code_challenge")
	codeChallengeMethod := oauthParams.Get("code_challenge_method")
	scope := oauthParams.Get("scope")
	state := oauthParams.Get("state")
	rancherPKCEVerifier := oauthParams.Get("rancher_pkce_verifier")

	if rancherError != "" {
		h.auditLogger.Log(auth.AuditEvent{
			EventType: auth.AuditEventLoginFailed,
			ClientID:  clientID,
			SourceIP:  c.ClientIP(),
			Detail:    fmt.Sprintf("rancher_error=%s", rancherError),
			Success:   false,
		})
		redirectWithError(c, clientRedirectURI, "access_denied", "Authentication failed at identity provider", state)
		return
	}

	if rancherCode == "" {
		redirectWithError(c, clientRedirectURI, "server_error", "Missing authorization code from identity provider", state)
		return
	}

	// Exchange the Rancher code for user claims and ID token
	userID, userClaims, rancherIDToken, err := h.oauthService.ExchangeRancherCode(rancherCode, rancherPKCEVerifier, h.cfg)
	if err != nil {
		h.auditLogger.Log(auth.AuditEvent{
			EventType: auth.AuditEventLoginFailed,
			ClientID:  clientID,
			SourceIP:  c.ClientIP(),
			Detail:    fmt.Sprintf("rancher_exchange_failed: %v", err),
			Success:   false,
		})
		redirectWithError(c, clientRedirectURI, "server_error", "Failed to authenticate with identity provider", state)
		return
	}

	// Provision or update the user in the local store so that permission
	// checks (CanManageGroups, ListAdapters, etc.) can resolve the user.
	// We use the Rancher sub claim directly as the user ID to match the
	// OAuth access token's sub claim.
	if h.userAuthService != nil {
		username, _ := userClaims["username"].(string)
		email, _ := userClaims["email"].(string)
		var groups []string
		if g, ok := userClaims["groups"].([]interface{}); ok {
			for _, v := range g {
				if s, ok := v.(string); ok {
					groups = append(groups, s)
				}
			}
		} else if g, ok := userClaims["groups"].([]string); ok {
			groups = g
		}
		localGroups := h.userAuthService.MapExternalGroups(models.UserAuthProviderRancher, groups)
		// Check if this user ID is in the admin users list
		for _, adminUser := range h.cfg.AdminUsers {
			if adminUser == userID {
				hasAdmin := false
				for _, g := range localGroups {
					if g == "mcp-admins" {
						hasAdmin = true
						break
					}
				}
				if !hasAdmin {
					localGroups = append(localGroups, "mcp-admins")
				}
				break
			}
		}
		if err := h.userAuthService.ProvisionExternalUser(
			c.Request.Context(),
			userID, // Use Rancher sub directly — must match OAuth token sub
			username,
			email,
			string(models.UserAuthProviderRancher),
			userID, // externalID
			groups,
			localGroups,
		); err != nil {
			fmt.Printf("Warning: failed to provision Rancher user %s: %v\n", userID, err)
		}
	}

	// Parse scopes
	var scopes []string
	if scope != "" {
		scopes = strings.Split(scope, " ")
	} else {
		scopes = []string{"mcp:read", "mcp:write"}
	}

	// Create proxy authorization code for the MCP client
	code, err := h.oauthService.CreateAuthorizationCode(
		clientID, clientRedirectURI, codeChallenge, codeChallengeMethod,
		scopes, state, userID, userClaims, rancherIDToken,
	)
	if err != nil {
		redirectWithError(c, clientRedirectURI, "server_error", "Failed to create authorization code", state)
		return
	}

	// Clear the oauth_params cookie
	secureCookie := !h.cfg.DevMode
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "oauth_params",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Secure:   secureCookie,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	h.auditLogger.Log(auth.AuditEvent{
		EventType: auth.AuditEventLogin,
		UserID:    userID,
		ClientID:  clientID,
		SourceIP:  c.ClientIP(),
		Detail:    "rancher_oidc_login",
		Success:   true,
	})

	// Redirect back to MCP client with the authorization code
	u, _ := url.Parse(clientRedirectURI)
	q := u.Query()
	q.Set("code", code)
	q.Set("state", state)
	u.RawQuery = q.Encode()

	c.Redirect(http.StatusFound, u.String())
}

// --- Authorization Policy CRUD (Admin API) ---

type createPolicyRequest struct {
	AdapterName   string   `json:"adapter_name" binding:"required"`
	ToolName      string   `json:"tool_name" binding:"required"`
	Effect        string   `json:"effect" binding:"required"`
	AllowedGroups []string `json:"allowed_groups,omitempty"`
	AllowedUsers  []string `json:"allowed_users,omitempty"`
	DeniedGroups  []string `json:"denied_groups,omitempty"`
	DeniedUsers   []string `json:"denied_users,omitempty"`
	Priority      int      `json:"priority"`
}

// ListPolicies handles GET /api/v1/auth/policies.
func (h *OAuthServerHandler) ListPolicies(c *gin.Context) {
	if h.policyStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Policy store not configured"})
		return
	}

	policies, err := h.policyStore.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list policies"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"policies": policies})
}

// CreatePolicy handles POST /api/v1/auth/policies.
func (h *OAuthServerHandler) CreatePolicy(c *gin.Context) {
	if h.policyStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Policy store not configured"})
		return
	}

	var req createPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Effect != "allow" && req.Effect != "deny" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "effect must be 'allow' or 'deny'"})
		return
	}

	now := time.Now()
	policy := models.AuthorizationPolicy{
		PolicyID:      uuid.New().String(),
		AdapterName:   req.AdapterName,
		ToolName:      req.ToolName,
		Effect:        req.Effect,
		AllowedGroups: req.AllowedGroups,
		AllowedUsers:  req.AllowedUsers,
		DeniedGroups:  req.DeniedGroups,
		DeniedUsers:   req.DeniedUsers,
		Priority:      req.Priority,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := h.policyStore.Create(policy); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create policy"})
		return
	}

	h.auditLogger.Log(auth.AuditEvent{
		EventType:   auth.AuditEventPolicyChanged,
		AdapterName: req.AdapterName,
		ToolName:    req.ToolName,
		Detail:      fmt.Sprintf("policy_created id=%s effect=%s", policy.PolicyID, req.Effect),
		Success:     true,
	})

	c.JSON(http.StatusCreated, policy)
}

// UpdatePolicy handles PUT /api/v1/auth/policies/:id.
func (h *OAuthServerHandler) UpdatePolicy(c *gin.Context) {
	if h.policyStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Policy store not configured"})
		return
	}

	policyID := c.Param("id")

	existing, err := h.policyStore.Get(policyID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	var req createPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Effect != "allow" && req.Effect != "deny" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "effect must be 'allow' or 'deny'"})
		return
	}

	existing.AdapterName = req.AdapterName
	existing.ToolName = req.ToolName
	existing.Effect = req.Effect
	existing.AllowedGroups = req.AllowedGroups
	existing.AllowedUsers = req.AllowedUsers
	existing.DeniedGroups = req.DeniedGroups
	existing.DeniedUsers = req.DeniedUsers
	existing.Priority = req.Priority
	existing.UpdatedAt = time.Now()

	if err := h.policyStore.Update(*existing); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update policy"})
		return
	}

	h.auditLogger.Log(auth.AuditEvent{
		EventType:   auth.AuditEventPolicyChanged,
		AdapterName: req.AdapterName,
		ToolName:    req.ToolName,
		Detail:      fmt.Sprintf("policy_updated id=%s effect=%s", policyID, req.Effect),
		Success:     true,
	})

	c.JSON(http.StatusOK, existing)
}

// DeletePolicy handles DELETE /api/v1/auth/policies/:id.
func (h *OAuthServerHandler) DeletePolicy(c *gin.Context) {
	if h.policyStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Policy store not configured"})
		return
	}

	policyID := c.Param("id")

	if err := h.policyStore.Delete(policyID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	h.auditLogger.Log(auth.AuditEvent{
		EventType: auth.AuditEventPolicyChanged,
		Detail:    fmt.Sprintf("policy_deleted id=%s", policyID),
		Success:   true,
	})

	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted"})
}

// --- Helpers ---

func (h *OAuthServerHandler) buildRancherAuthURL(state, codeChallenge string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", h.cfg.RancherClientID)
	params.Set("redirect_uri", h.cfg.OAuthIssuerURL+"/oauth/callback")
	params.Set("scope", "openid profile offline_access")
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")

	return fmt.Sprintf("%s/authorize?%s", h.cfg.RancherIssuerURL, params.Encode())
}

// generatePKCE creates a PKCE verifier and S256 challenge for the Rancher OIDC flow.
func generatePKCE() (verifier, challenge string) {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

func (h *OAuthServerHandler) getOAuthParamsFromCookie(c *gin.Context) url.Values {
	cookie, err := c.Cookie("oauth_params")
	if err != nil {
		return url.Values{}
	}
	params, err := url.ParseQuery(cookie)
	if err != nil {
		return url.Values{}
	}
	return params
}

func redirectWithError(c *gin.Context, redirectURI, errorCode, description, state string) {
	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             errorCode,
			"error_description": description,
		})
		return
	}

	u, err := url.Parse(redirectURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             errorCode,
			"error_description": description,
		})
		return
	}

	q := u.Query()
	q.Set("error", errorCode)
	q.Set("error_description", description)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	c.Redirect(http.StatusFound, u.String())
}
