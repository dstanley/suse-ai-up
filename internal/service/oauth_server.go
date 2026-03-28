package service

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"suse-ai-up/internal/config"
	"suse-ai-up/pkg/auth"
	"suse-ai-up/pkg/clients"
	"suse-ai-up/pkg/models"
)

// OAuthServerService implements the OAuth 2.1 Authorization Server logic.
type OAuthServerService struct {
	tokenManager  *auth.TokenManager
	clientStore   clients.OAuthClientStore
	auditLogger   *auth.AuditLogger
	cfg           *config.Config
	httpClient    *http.Client

	// In-memory authorization code store (codes are too short-lived for disk persistence)
	codes   map[string]*models.OAuthAuthorizationCode
	codesMu sync.RWMutex

	// In-memory rate limiter for client registration
	rateLimits   map[string]*models.RegistrationRateLimit
	rateLimitsMu sync.Mutex

	// OAuth session store (maps access token -> session for lookup)
	sessions   map[string]*models.OAuthSession
	sessionsMu sync.RWMutex

	// Refresh token -> session ID mapping
	refreshIndex   map[string]string
	refreshIndexMu sync.RWMutex
}

// NewOAuthServerService creates a new OAuth server service.
func NewOAuthServerService(
	tokenManager *auth.TokenManager,
	clientStore clients.OAuthClientStore,
	auditLogger *auth.AuditLogger,
	cfg *config.Config,
) *OAuthServerService {
	svc := &OAuthServerService{
		tokenManager: tokenManager,
		clientStore:  clientStore,
		auditLogger:  auditLogger,
		cfg:          cfg,
		httpClient: newHTTPClient(cfg),
		codes:        make(map[string]*models.OAuthAuthorizationCode),
		rateLimits:   make(map[string]*models.RegistrationRateLimit),
		sessions:     make(map[string]*models.OAuthSession),
		refreshIndex: make(map[string]string),
	}

	// Start background cleanup goroutines
	go svc.cleanupExpiredCodes()
	go svc.cleanupExpiredSessions()

	return svc
}

func newHTTPClient(cfg *config.Config) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.RancherTLSSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // configurable for self-signed certs
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: transport}
}

// RegisterClient handles dynamic client registration (RFC 7591).
func (s *OAuthServerService) RegisterClient(clientName string, redirectURIs []string, grantTypes, responseTypes []string, tokenEndpointAuthMethod, sourceIP string) (*models.OAuthRegisteredClient, error) {
	// Rate limiting
	if err := s.checkRegistrationRateLimit(sourceIP); err != nil {
		return nil, err
	}

	// Validate redirect URIs against allowlist
	if len(s.cfg.OAuthRedirectURIAllowlist) > 0 {
		for _, uri := range redirectURIs {
			if !s.isRedirectURIAllowed(uri) {
				return nil, fmt.Errorf("redirect URI not permitted by allowlist: %s", uri)
			}
		}
	}

	// Default grant types and response types
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}
	if tokenEndpointAuthMethod == "" {
		tokenEndpointAuthMethod = "none"
	}

	now := time.Now()
	client := models.OAuthRegisteredClient{
		ClientID:                uuid.New().String(),
		ClientName:              clientName,
		RedirectURIs:            redirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		CreatedAt:               now,
		ClientIDIssuedAt:        now.Unix(),
	}

	if err := s.clientStore.Create(client); err != nil {
		return nil, fmt.Errorf("failed to store client: %w", err)
	}

	s.auditLogger.Log(auth.AuditEvent{
		EventType: auth.AuditEventClientRegistered,
		ClientID:  client.ClientID,
		SourceIP:  sourceIP,
		Detail:    fmt.Sprintf("client_name=%s", clientName),
		Success:   true,
	})

	return &client, nil
}

// ValidateAuthorizationRequest validates the OAuth authorization request parameters.
func (s *OAuthServerService) ValidateAuthorizationRequest(clientID, redirectURI, codeChallenge, codeChallengeMethod, scope, state string) error {
	// Validate client exists
	client, err := s.clientStore.Get(clientID)
	if err != nil {
		return fmt.Errorf("invalid client_id: %w", err)
	}

	// Validate redirect URI matches registration
	if !s.isRegisteredRedirectURI(client, redirectURI) {
		return fmt.Errorf("redirect_uri does not match registered URIs")
	}

	// PKCE is mandatory (OAuth 2.1)
	if codeChallenge == "" {
		return fmt.Errorf("code_challenge is required (PKCE mandatory)")
	}
	if codeChallengeMethod != "S256" {
		return fmt.Errorf("only S256 code_challenge_method is supported")
	}

	if state == "" {
		return fmt.Errorf("state parameter is required")
	}

	return nil
}

// CreateAuthorizationCode creates an authorization code after successful user authentication.
func (s *OAuthServerService) CreateAuthorizationCode(clientID, redirectURI, codeChallenge, codeChallengeMethod string, scopes []string, state, userID string, userClaims map[string]interface{}, rancherIDToken string) (string, error) {
	code := uuid.New().String()
	lifetime := time.Duration(s.cfg.OAuthCodeLifetime) * time.Minute

	authCode := &models.OAuthAuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		UserID:              userID,
		UserClaims:          userClaims,
		Scopes:              scopes,
		ExpiresAt:           time.Now().Add(lifetime),
		Used:                false,
		State:               state,
		RancherIDToken:      rancherIDToken,
	}

	s.codesMu.Lock()
	s.codes[code] = authCode
	s.codesMu.Unlock()

	return code, nil
}

// ExchangeAuthorizationCode exchanges an authorization code for tokens.
func (s *OAuthServerService) ExchangeAuthorizationCode(code, clientID, redirectURI, codeVerifier string) (*TokenResponse, error) {
	s.codesMu.Lock()
	authCode, exists := s.codes[code]
	if !exists {
		s.codesMu.Unlock()
		return nil, fmt.Errorf("invalid authorization code")
	}
	if authCode.Used {
		s.codesMu.Unlock()
		return nil, fmt.Errorf("authorization code already used")
	}
	if time.Now().After(authCode.ExpiresAt) {
		delete(s.codes, code)
		s.codesMu.Unlock()
		return nil, fmt.Errorf("authorization code expired")
	}
	authCode.Used = true
	s.codesMu.Unlock()

	// Validate client_id matches
	if authCode.ClientID != clientID {
		return nil, fmt.Errorf("client_id mismatch")
	}

	// Validate redirect_uri matches
	if authCode.RedirectURI != redirectURI {
		return nil, fmt.Errorf("redirect_uri mismatch")
	}

	// Validate PKCE code_verifier
	if err := s.verifyPKCE(authCode.CodeChallenge, codeVerifier); err != nil {
		return nil, fmt.Errorf("PKCE verification failed: %w", err)
	}

	// Generate tokens
	return s.issueTokens(authCode.ClientID, authCode.UserID, authCode.UserClaims, authCode.Scopes, authCode.RancherIDToken)
}

// RefreshAccessToken exchanges a refresh token for new tokens.
func (s *OAuthServerService) RefreshAccessToken(refreshToken, clientID string) (*TokenResponse, error) {
	s.refreshIndexMu.RLock()
	sessionID, exists := s.refreshIndex[refreshToken]
	s.refreshIndexMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("invalid refresh token")
	}

	s.sessionsMu.RLock()
	session, exists := s.sessions[sessionID]
	s.sessionsMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	if session.ClientID != clientID {
		return nil, fmt.Errorf("client_id mismatch")
	}

	if time.Now().After(session.RefreshTokenExpiresAt) {
		return nil, fmt.Errorf("refresh token expired")
	}

	// Remove old refresh token from index
	s.refreshIndexMu.Lock()
	delete(s.refreshIndex, refreshToken)
	s.refreshIndexMu.Unlock()

	// Issue new tokens
	return s.issueTokens(session.ClientID, session.UserID, session.UserClaims, session.Scopes, session.RancherIDToken)
}

// RevokeToken revokes an access or refresh token.
func (s *OAuthServerService) RevokeToken(token, tokenTypeHint, clientID string) {
	// Try to find and remove from sessions by access token
	s.sessionsMu.Lock()
	for id, session := range s.sessions {
		if session.AccessToken == token || session.RefreshToken == token {
			if session.ClientID == clientID {
				// Remove refresh token from index
				s.refreshIndexMu.Lock()
				delete(s.refreshIndex, session.RefreshToken)
				s.refreshIndexMu.Unlock()

				delete(s.sessions, id)

				s.auditLogger.Log(auth.AuditEvent{
					EventType: auth.AuditEventTokenRevoked,
					UserID:    session.UserID,
					ClientID:  clientID,
					Detail:    fmt.Sprintf("token_type_hint=%s", tokenTypeHint),
					Success:   true,
				})
			}
			break
		}
	}
	s.sessionsMu.Unlock()
}

// GetSessionByAccessToken looks up an OAuth session by its access token.
func (s *OAuthServerService) GetSessionByAccessToken(accessToken string) (*models.OAuthSession, error) {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	for _, session := range s.sessions {
		if session.AccessToken == accessToken {
			return session, nil
		}
	}
	return nil, fmt.Errorf("session not found for token")
}

// GetSessionsByUserID returns all active sessions for a given user ID.
func (s *OAuthServerService) GetSessionsByUserID(userID string) []*models.OAuthSession {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	var result []*models.OAuthSession
	for _, session := range s.sessions {
		if session.UserID == userID {
			result = append(result, session)
		}
	}
	return result
}

// TokenResponse represents the OAuth token endpoint response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func (s *OAuthServerService) issueTokens(clientID, userID string, userClaims map[string]interface{}, scopes []string, rancherIDToken string) (*TokenResponse, error) {
	scopeStr := "mcp:read mcp:write"
	if len(scopes) > 0 {
		scopeStr = ""
		for i, scope := range scopes {
			if i > 0 {
				scopeStr += " "
			}
			scopeStr += scope
		}
	}

	// Extract claims for JWT
	claims := &auth.MCPUserClaims{
		UserID:   userID,
		Username: getClaimString(userClaims, "username"),
		Email:    getClaimString(userClaims, "email"),
		Groups:   getClaimStringSlice(userClaims, "groups"),
		Roles:    getClaimStringSlice(userClaims, "roles"),
		ClientID: clientID,
	}

	accessToken, accessExpiresAt, err := s.tokenManager.GenerateOAuthAccessToken(claims, scopeStr, s.cfg.OAuthAccessTokenLifetime)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, refreshExpiresAt, err := s.tokenManager.GenerateOAuthRefreshToken(userID, clientID, s.cfg.OAuthRefreshTokenLifetime)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Create OAuth session
	sessionID := uuid.New().String()
	now := time.Now()
	session := &models.OAuthSession{
		SessionID:             sessionID,
		ClientID:              clientID,
		UserID:                userID,
		UserClaims:            userClaims,
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshTokenExpiresAt: refreshExpiresAt,
		Scopes:                scopes,
		CreatedAt:             now,
		LastActivityAt:        now,
		RancherIDToken:        rancherIDToken,
	}

	s.sessionsMu.Lock()
	s.sessions[sessionID] = session
	s.sessionsMu.Unlock()

	s.refreshIndexMu.Lock()
	s.refreshIndex[refreshToken] = sessionID
	s.refreshIndexMu.Unlock()

	expiresIn := int(time.Until(accessExpiresAt).Seconds())

	s.auditLogger.Log(auth.AuditEvent{
		EventType: auth.AuditEventTokenIssued,
		UserID:    userID,
		ClientID:  clientID,
		Detail:    fmt.Sprintf("scope=%s expires_in=%d", scopeStr, expiresIn),
		Success:   true,
	})

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		Scope:        scopeStr,
	}, nil
}

func (s *OAuthServerService) verifyPKCE(codeChallenge, codeVerifier string) error {
	if codeVerifier == "" {
		return fmt.Errorf("code_verifier is required")
	}

	// S256: BASE64URL(SHA256(code_verifier)) == code_challenge
	hash := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])

	if computed != codeChallenge {
		return fmt.Errorf("code_verifier does not match code_challenge")
	}

	return nil
}

func (s *OAuthServerService) checkRegistrationRateLimit(sourceIP string) error {
	s.rateLimitsMu.Lock()
	defer s.rateLimitsMu.Unlock()

	now := time.Now()
	window := 1 * time.Minute
	limit := s.cfg.OAuthRegistrationRateLimit

	rl, exists := s.rateLimits[sourceIP]
	if !exists || now.Sub(rl.WindowStart) > window {
		s.rateLimits[sourceIP] = &models.RegistrationRateLimit{
			SourceIP:    sourceIP,
			WindowStart: now,
			Count:       1,
		}
		return nil
	}

	if rl.Count >= limit {
		return fmt.Errorf("rate limit exceeded: too many registration requests")
	}

	rl.Count++
	return nil
}

func (s *OAuthServerService) isRedirectURIAllowed(uri string) bool {
	for _, allowed := range s.cfg.OAuthRedirectURIAllowlist {
		if uri == allowed {
			return true
		}
	}
	return false
}

// ExchangeRancherCode exchanges a Rancher OIDC authorization code for an ID token,
// extracts user claims (sub, preferred_username, email, groups, roles), and returns them.
func (s *OAuthServerService) ExchangeRancherCode(rancherCode string, pkceVerifier string, cfg *config.Config) (string, map[string]interface{}, string, error) {
	// Build token exchange request to Rancher
	tokenURL := fmt.Sprintf("%s/token", cfg.RancherIssuerURL)
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", rancherCode)
	data.Set("client_id", cfg.RancherClientID)
	data.Set("client_secret", cfg.RancherClientSecret)
	data.Set("redirect_uri", cfg.OAuthIssuerURL+"/oauth/callback")
	if pkceVerifier != "" {
		data.Set("code_verifier", pkceVerifier)
	}

	resp, err := s.httpClient.PostForm(tokenURL, data)
	if err != nil {
		return "", nil, "", fmt.Errorf("failed to contact Rancher token endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, "", fmt.Errorf("failed to read Rancher token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", nil, "", fmt.Errorf("Rancher token exchange failed (status %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp rancherTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", nil, "", fmt.Errorf("failed to parse Rancher token response: %w", err)
	}

	if tokenResp.IDToken == "" {
		return "", nil, "", fmt.Errorf("Rancher token response missing id_token")
	}

	// Parse the ID token to extract user claims.
	// We parse without signature verification here because we just received the token
	// directly from the Rancher token endpoint over TLS (back-channel).
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenResp.IDToken, jwt.MapClaims{})
	if err != nil {
		return "", nil, "", fmt.Errorf("failed to parse Rancher ID token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", nil, "", fmt.Errorf("failed to extract claims from Rancher ID token")
	}

	// Extract user identity
	userID := ""
	if sub, ok := claims["sub"].(string); ok {
		userID = sub
	}
	if userID == "" {
		return "", nil, "", fmt.Errorf("Rancher ID token missing 'sub' claim")
	}

	// Build user claims map for downstream use
	userClaims := make(map[string]interface{})
	if username, ok := claims["preferred_username"].(string); ok {
		userClaims["username"] = username
	} else if name, ok := claims["name"].(string); ok {
		userClaims["username"] = name
	}
	if email, ok := claims["email"].(string); ok {
		userClaims["email"] = email
	}
	if groups, ok := claims["groups"]; ok {
		userClaims["groups"] = groups
	}
	if roles, ok := claims["roles"]; ok {
		userClaims["roles"] = roles
	}

	return userID, userClaims, tokenResp.IDToken, nil
}

// rancherTokenResponse represents the token endpoint response from Rancher OIDC.
type rancherTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (s *OAuthServerService) isRegisteredRedirectURI(client *models.OAuthRegisteredClient, uri string) bool {
	for _, registered := range client.RedirectURIs {
		if registered == uri {
			return true
		}
	}
	return false
}

func (s *OAuthServerService) cleanupExpiredCodes() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.codesMu.Lock()
		now := time.Now()
		for code, authCode := range s.codes {
			if now.After(authCode.ExpiresAt) {
				delete(s.codes, code)
			}
		}
		s.codesMu.Unlock()
	}
}

func (s *OAuthServerService) cleanupExpiredSessions() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.sessionsMu.Lock()
		now := time.Now()
		for id, session := range s.sessions {
			if now.After(session.RefreshTokenExpiresAt) {
				// Remove refresh token from index
				s.refreshIndexMu.Lock()
				delete(s.refreshIndex, session.RefreshToken)
				s.refreshIndexMu.Unlock()

				delete(s.sessions, id)
			}
		}
		s.sessionsMu.Unlock()
	}
}

func getClaimString(claims map[string]interface{}, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

func getClaimStringSlice(claims map[string]interface{}, key string) []string {
	if v, ok := claims[key].([]string); ok {
		return v
	}
	if v, ok := claims[key].([]interface{}); ok {
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

