package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"

	"suse-ai-up/pkg/auth"
	"suse-ai-up/pkg/clients"
	"suse-ai-up/pkg/models"
)

// TokenVaultService handles RFC 8693 token exchange, caching, and transparent refresh.
type TokenVaultService struct {
	vaultStore   clients.TokenVaultStore
	auditLogger  *auth.AuditLogger
	httpClient   *http.Client
	spiffeClient *auth.SPIFFEClient
}

// NewTokenVaultService creates a new token vault service.
func NewTokenVaultService(vaultStore clients.TokenVaultStore, auditLogger *auth.AuditLogger) *TokenVaultService {
	return &TokenVaultService{
		vaultStore:  vaultStore,
		auditLogger: auditLogger,
		httpClient:  &http.Client{Timeout: 15 * time.Second},
	}
}

// SetSPIFFEClient sets the SPIFFE client for workload identity token exchange.
func (tvs *TokenVaultService) SetSPIFFEClient(client *auth.SPIFFEClient) {
	tvs.spiffeClient = client
}

// GetOrExchangeToken retrieves a cached token or performs an RFC 8693 token exchange.
// subjectToken is the Rancher ID token from the user's session (ignored when UseWorkloadIdentity is true).
// exchangeConfig comes from the adapter's TokenExchange configuration.
func (tvs *TokenVaultService) GetOrExchangeToken(userID, adapterName, subjectToken string, exchangeConfig *models.TokenExchangeConfig) (*models.TokenVaultEntry, error) {
	// Try to get a cached, non-expired token
	entry, err := tvs.vaultStore.Get(userID, adapterName)
	if err == nil && !entry.IsExpired() {
		return entry, nil
	}

	// If workload identity is enabled, fetch a JWT SVID as the subject token
	if exchangeConfig.UseWorkloadIdentity {
		svidToken, svidErr := tvs.fetchSVIDSubjectToken(exchangeConfig.Audience)
		if svidErr != nil {
			return nil, fmt.Errorf("SPIFFE workload identity token fetch failed: %w", svidErr)
		}
		subjectToken = svidToken
	}

	// If we have a cached entry with a refresh token, try refreshing first
	if entry != nil && entry.RefreshToken != "" {
		refreshed, refreshErr := tvs.refreshDownstreamToken(entry, exchangeConfig)
		if refreshErr == nil {
			return refreshed, nil
		}
	}

	// Perform RFC 8693 token exchange
	return tvs.performTokenExchange(userID, adapterName, subjectToken, exchangeConfig)
}

// performTokenExchange executes an RFC 8693 token exchange request.
func (tvs *TokenVaultService) performTokenExchange(userID, adapterName, subjectToken string, exchangeConfig *models.TokenExchangeConfig) (*models.TokenVaultEntry, error) {
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("subject_token", subjectToken)
	data.Set("subject_token_type", exchangeConfig.SubjectTokenType)

	if exchangeConfig.Audience != "" {
		data.Set("audience", exchangeConfig.Audience)
	}
	if exchangeConfig.Resource != "" {
		data.Set("resource", exchangeConfig.Resource)
	}
	if len(exchangeConfig.Scopes) > 0 {
		scopeStr := ""
		for i, s := range exchangeConfig.Scopes {
			if i > 0 {
				scopeStr += " "
			}
			scopeStr += s
		}
		data.Set("scope", scopeStr)
	}

	resp, err := tvs.httpClient.PostForm(exchangeConfig.TokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token exchange response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		tvs.auditLogger.Log(auth.AuditEvent{
			EventType:   auth.AuditEventAccessDenied,
			UserID:      userID,
			AdapterName: adapterName,
			Detail:      fmt.Sprintf("token_exchange_failed status=%d", resp.StatusCode),
			Success:     false,
		})
		return nil, fmt.Errorf("token exchange failed (status %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenExchangeResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token exchange response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("token exchange response missing access_token")
	}

	now := time.Now()
	expiresIn := tokenResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}

	entry := models.TokenVaultEntry{
		EntryID:         uuid.New().String(),
		UserID:          userID,
		AdapterName:     adapterName,
		ServiceType:     "token_exchange",
		AccessToken:     tokenResp.AccessToken,
		RefreshToken:    tokenResp.RefreshToken,
		ExpiresAt:       now.Add(time.Duration(expiresIn) * time.Second),
		CreatedAt:       now,
		LastRefreshedAt: now,
	}

	if err := tvs.vaultStore.Set(entry); err != nil {
		return nil, fmt.Errorf("failed to store exchanged token: %w", err)
	}

	tvs.auditLogger.Log(auth.AuditEvent{
		EventType:   auth.AuditEventTokenExchanged,
		UserID:      userID,
		AdapterName: adapterName,
		Detail:      fmt.Sprintf("expires_in=%d", expiresIn),
		Success:     true,
	})

	return &entry, nil
}

// refreshDownstreamToken attempts to refresh a cached downstream token.
func (tvs *TokenVaultService) refreshDownstreamToken(entry *models.TokenVaultEntry, exchangeConfig *models.TokenExchangeConfig) (*models.TokenVaultEntry, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", entry.RefreshToken)

	resp, err := tvs.httpClient.PostForm(exchangeConfig.TokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("downstream token refresh failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downstream refresh failed (status %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenExchangeResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse refresh response: %w", err)
	}

	now := time.Now()
	expiresIn := tokenResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}

	entry.AccessToken = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		entry.RefreshToken = tokenResp.RefreshToken
	}
	entry.ExpiresAt = now.Add(time.Duration(expiresIn) * time.Second)
	entry.LastRefreshedAt = now

	if err := tvs.vaultStore.Set(*entry); err != nil {
		return nil, fmt.Errorf("failed to store refreshed token: %w", err)
	}

	tvs.auditLogger.Log(auth.AuditEvent{
		EventType:   auth.AuditEventTokenRefreshed,
		UserID:      entry.UserID,
		AdapterName: entry.AdapterName,
		Detail:      "downstream_token_refreshed",
		Success:     true,
	})

	return entry, nil
}

// RevokeEntry removes a token vault entry for a user and adapter.
func (tvs *TokenVaultService) RevokeEntry(userID, adapterName string) error {
	return tvs.vaultStore.Delete(userID, adapterName)
}

// fetchSVIDSubjectToken fetches a JWT SVID from the SPIRE agent to use as the
// subject token in an RFC 8693 token exchange.
func (tvs *TokenVaultService) fetchSVIDSubjectToken(audience string) (string, error) {
	if tvs.spiffeClient == nil {
		return "", fmt.Errorf("SPIFFE client not configured; enable SPIRE_ENABLED and ensure SPIRE agent is running")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return tvs.spiffeClient.FetchJWTSVID(ctx, audience)
}

// GetMTLSHTTPClient returns an HTTP client configured with X.509 SVID mTLS
// for direct mutual TLS authentication to downstream services.
func (tvs *TokenVaultService) GetMTLSHTTPClient(authorizedSpiffeID string) (*http.Client, error) {
	if tvs.spiffeClient == nil {
		return nil, fmt.Errorf("SPIFFE client not configured")
	}

	tlsConfig, err := tvs.spiffeClient.GetTLSConfig(authorizedSpiffeID)
	if err != nil {
		return nil, fmt.Errorf("failed to build mTLS config: %w", err)
	}

	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

// tokenExchangeResponse represents the response from an RFC 8693 token exchange.
type tokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	Scope           string `json:"scope,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
}
