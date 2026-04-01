package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"suse-ai-up/pkg/auth"
	"suse-ai-up/pkg/clients"
	"suse-ai-up/pkg/mcp"
	"suse-ai-up/pkg/models"
	"suse-ai-up/pkg/proxy"
	"suse-ai-up/pkg/session"
)

// AdapterMCPHandler handles per-adapter REST-style MCP endpoints.
// It provides tools/list, tools/call, resources/list, resources/read,
// prompts/list, and prompts/get for individual adapters.
type AdapterMCPHandler struct {
	adapterStore       clients.AdapterResourceStore
	stdioToHTTPAdapter *proxy.StdioToHTTPAdapter
	remoteHTTPPlugin   *proxy.RemoteHttpProxyPlugin
	sessionStore       session.SessionStore
	policyEngine       *auth.PolicyEngine
	httpClient         *http.Client
}

// NewAdapterMCPHandler creates a new per-adapter MCP handler with all dependencies.
func NewAdapterMCPHandler(
	adapterStore clients.AdapterResourceStore,
	stdioToHTTPAdapter *proxy.StdioToHTTPAdapter,
	remoteHTTPPlugin *proxy.RemoteHttpProxyPlugin,
	sessionStore session.SessionStore,
	policyEngine *auth.PolicyEngine,
) *AdapterMCPHandler {
	return &AdapterMCPHandler{
		adapterStore:       adapterStore,
		stdioToHTTPAdapter: stdioToHTTPAdapter,
		remoteHTTPPlugin:   remoteHTTPPlugin,
		sessionStore:       sessionStore,
		policyEngine:       policyEngine,
		httpClient:         &http.Client{Timeout: 30 * time.Second},
	}
}

// getAdapterAndAuth is a shared helper that retrieves the adapter and validates
// client authentication. Returns the adapter or writes an error response and returns nil.
func (h *AdapterMCPHandler) getAdapterAndAuth(c *gin.Context) *models.AdapterResource {
	adapterName := c.Param("name")

	adapter, err := h.adapterStore.Get(c.Request.Context(), adapterName)
	if err != nil || adapter == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Adapter not found"})
		return nil
	}

	if adapter.Authentication != nil && adapter.Authentication.Required {
		if err := validateClientAuth(c, adapter.Authentication); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required: " + err.Error()})
			return nil
		}
	}

	return adapter
}

// userContextFromGin extracts the authenticated user context from gin context
// values set by the OAuth middleware (pkg/auth/middleware.go).
func (h *AdapterMCPHandler) userContextFromGin(c *gin.Context) *auth.UserContext {
	uc := &auth.UserContext{}
	if v, ok := c.Get("user_id"); ok {
		uc.UserID, _ = v.(string)
	}
	if v, ok := c.Get("username"); ok {
		uc.Username, _ = v.(string)
	}
	if v, ok := c.Get("email"); ok {
		uc.Email, _ = v.(string)
	}
	if v, ok := c.Get("groups"); ok {
		uc.Groups, _ = v.([]string)
	}
	if v, ok := c.Get("roles"); ok {
		uc.Roles, _ = v.([]string)
	}
	return uc
}

// routeToAdapter routes a JSON-RPC request to the appropriate adapter backend
// based on connection type (stdio or HTTP).
func (h *AdapterMCPHandler) routeToAdapter(c *gin.Context, adapter *models.AdapterResource, jsonBody []byte) {
	mockContext, _ := gin.CreateTestContext(c.Writer)
	mockContext.Request = c.Request
	mockContext.Request.Method = "POST"
	mockContext.Request.Header.Set("Content-Type", "application/json")
	mockContext.Request.Body = io.NopCloser(bytes.NewReader(jsonBody))
	mockContext.Params = c.Params

	switch adapter.ConnectionType {
	case models.ConnectionTypeLocalStdio:
		if h.stdioToHTTPAdapter == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Stdio to HTTP adapter not initialized"})
			return
		}
		if err := h.stdioToHTTPAdapter.HandleRequest(mockContext, *adapter); err != nil {
			fmt.Printf("Stdio adapter error for %s: %v\n", adapter.Name, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Adapter request failed"})
		}
	case models.ConnectionTypeRemoteHttp, models.ConnectionTypeStreamableHttp, models.ConnectionTypeSSE:
		if h.remoteHTTPPlugin == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Remote HTTP plugin not initialized"})
			return
		}
		if err := h.remoteHTTPPlugin.ProxyRequest(mockContext, *adapter, h.sessionStore); err != nil {
			fmt.Printf("Remote HTTP plugin error for %s: %v\n", adapter.Name, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Adapter request failed"})
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Unsupported connection type: %s", adapter.ConnectionType)})
	}
}

// ToolsList handles GET /adapters/{name}/tools
// @Summary List MCP tools
// @Description Get the list of tools available from the MCP server
// @Tags adapters,mcp
// @Accept json
// @Produce json
// @Param name path string true "Adapter ID"
// @Success 200 {object} map[string]interface{} "MCP response with tools list"
// @Failure 404 {object} ErrorResponse "Adapter not found"
// @Failure 401 {object} ErrorResponse "Authentication required"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name}/tools [get]
func (h *AdapterMCPHandler) ToolsList(c *gin.Context) {
	adapter := h.getAdapterAndAuth(c)
	if adapter == nil {
		return
	}

	toolsListRequest := mcp.MCPMessage{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
		Params:  map[string]interface{}{},
	}

	resp, err := h.makeMCPRequestWithSession(c.Request.Context(), adapter.URL, toolsListRequest, adapter.Authentication)
	if err != nil {
		fmt.Printf("MCP request failed for %s: %v\n", adapter.Name, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MCP request failed"})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response"})
		return
	}

	if resp.StatusCode != http.StatusOK {
		c.Data(resp.StatusCode, "application/json", body)
		return
	}

	// Apply tool authorization filtering
	if h.policyEngine != nil {
		body = h.filterToolsResponse(c, adapter, body)
	}

	c.Data(http.StatusOK, "application/json", body)
}

// filterToolsResponse filters the MCP tools/list response based on authorization policies.
func (h *AdapterMCPHandler) filterToolsResponse(c *gin.Context, adapter *models.AdapterResource, body []byte) []byte {
	var mcpResp map[string]interface{}
	if err := json.Unmarshal(body, &mcpResp); err != nil {
		return body
	}

	result, ok := mcpResp["result"].(map[string]interface{})
	if !ok {
		return body
	}

	tools, ok := result["tools"].([]interface{})
	if !ok {
		return body
	}

	uc := h.userContextFromGin(c)
	scopeCtx := auth.ResolveUserScopes(uc, adapter.Authentication)

	var filtered []interface{}
	for _, t := range tools {
		toolMap, ok := t.(map[string]interface{})
		if !ok {
			filtered = append(filtered, t)
			continue
		}
		name, ok := toolMap["name"].(string)
		if !ok {
			filtered = append(filtered, t)
			continue
		}
		if allowed, _ := h.policyEngine.IsToolAllowed(adapter.Name, name, scopeCtx); allowed {
			filtered = append(filtered, t)
		}
	}

	result["tools"] = filtered
	mcpResp["result"] = result
	if filteredBody, err := json.Marshal(mcpResp); err == nil {
		return filteredBody
	}
	return body
}

// ToolCall handles POST /adapters/{name}/tools/{toolName}/call
// @Summary Call MCP tool
// @Description Execute a specific MCP tool with given arguments
// @Tags adapters,mcp
// @Accept json
// @Produce json
// @Param name path string true "Adapter ID"
// @Param toolName path string true "Tool name"
// @Param request body mcp.MCPMessage true "Tool call request with arguments"
// @Success 200 {object} map[string]interface{} "MCP response with tool result"
// @Failure 404 {object} ErrorResponse "Adapter or tool not found"
// @Failure 401 {object} ErrorResponse "Authentication required"
// @Failure 403 {object} ErrorResponse "Access denied by policy"
// @Failure 400 {object} ErrorResponse "Invalid request parameters"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name}/tools/{toolName}/call [post]
func (h *AdapterMCPHandler) ToolCall(c *gin.Context) {
	adapter := h.getAdapterAndAuth(c)
	if adapter == nil {
		return
	}

	toolName := c.Param("toolName")

	// Check tool authorization policy
	if h.policyEngine != nil {
		uc := h.userContextFromGin(c)
		scopeCtx := auth.ResolveUserScopes(uc, adapter.Authentication)
		if allowed, policyID := h.policyEngine.IsToolAllowed(adapter.Name, toolName, scopeCtx); !allowed {
			c.JSON(http.StatusForbidden, gin.H{
				"error":     fmt.Sprintf("Access denied to tool %q by policy %s", toolName, policyID),
				"policy_id": policyID,
			})
			return
		}
	}

	var requestBody map[string]interface{}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	toolCallRequest := mcp.MCPMessage{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      toolName,
			"arguments": requestBody,
		},
	}

	jsonBody, err := json.Marshal(toolCallRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	h.routeToAdapter(c, adapter, jsonBody)
}

// ResourcesList handles GET /adapters/{name}/resources
// @Summary List MCP resources
// @Description Get the list of resources available from the MCP server
// @Tags adapters,mcp
// @Accept json
// @Produce json
// @Param name path string true "Adapter ID"
// @Success 200 {object} map[string]interface{} "MCP response with resources list"
// @Failure 404 {object} ErrorResponse "Adapter not found"
// @Failure 401 {object} ErrorResponse "Authentication required"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name}/resources [get]
func (h *AdapterMCPHandler) ResourcesList(c *gin.Context) {
	adapter := h.getAdapterAndAuth(c)
	if adapter == nil {
		return
	}

	request := mcp.MCPMessage{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "resources/list",
		Params:  map[string]interface{}{},
	}

	jsonBody, err := json.Marshal(request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	h.routeToAdapter(c, adapter, jsonBody)
}

// ResourceRead handles GET /adapters/{name}/resources/*uri
// @Summary Read MCP resource
// @Description Read the contents of a specific MCP resource
// @Tags adapters,mcp
// @Accept json
// @Produce json
// @Param name path string true "Adapter ID"
// @Param uri path string true "Resource URI"
// @Success 200 {object} map[string]interface{} "MCP response with resource contents"
// @Failure 404 {object} ErrorResponse "Adapter not found"
// @Failure 401 {object} ErrorResponse "Authentication required"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name}/resources/{uri} [get]
func (h *AdapterMCPHandler) ResourceRead(c *gin.Context) {
	adapter := h.getAdapterAndAuth(c)
	if adapter == nil {
		return
	}

	resourceURI := c.Param("uri")

	request := mcp.MCPMessage{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "resources/read",
		Params: map[string]interface{}{
			"uri": resourceURI,
		},
	}

	jsonBody, err := json.Marshal(request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	h.routeToAdapter(c, adapter, jsonBody)
}

// PromptsList handles GET /adapters/{name}/prompts
// @Summary List MCP prompts
// @Description Get the list of prompts available from the MCP server
// @Tags adapters,mcp
// @Accept json
// @Produce json
// @Param name path string true "Adapter ID"
// @Success 200 {object} map[string]interface{} "MCP response with prompts list"
// @Failure 404 {object} ErrorResponse "Adapter not found"
// @Failure 401 {object} ErrorResponse "Authentication required"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name}/prompts [get]
func (h *AdapterMCPHandler) PromptsList(c *gin.Context) {
	adapter := h.getAdapterAndAuth(c)
	if adapter == nil {
		return
	}

	request := mcp.MCPMessage{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "prompts/list",
		Params:  map[string]interface{}{},
	}

	jsonBody, err := json.Marshal(request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	h.routeToAdapter(c, adapter, jsonBody)
}

// PromptGet handles GET /adapters/{name}/prompts/:promptName
// @Summary Get MCP prompt
// @Description Get a specific MCP prompt with arguments
// @Tags adapters,mcp
// @Accept json
// @Produce json
// @Param name path string true "Adapter ID"
// @Param promptName path string true "Prompt name"
// @Success 200 {object} map[string]interface{} "MCP response with prompt content"
// @Failure 404 {object} ErrorResponse "Adapter not found"
// @Failure 401 {object} ErrorResponse "Authentication required"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /api/v1/adapters/{name}/prompts/{promptName} [get]
func (h *AdapterMCPHandler) PromptGet(c *gin.Context) {
	adapter := h.getAdapterAndAuth(c)
	if adapter == nil {
		return
	}

	promptName := c.Param("promptName")

	args := make(map[string]interface{})
	for key, values := range c.Request.URL.Query() {
		if len(values) > 0 {
			args[key] = values[0]
		}
	}

	request := mcp.MCPMessage{
		JSONRPC: "2.0",
		ID:      6,
		Method:  "prompts/get",
		Params: map[string]interface{}{
			"name":      promptName,
			"arguments": args,
		},
	}

	jsonBody, err := json.Marshal(request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	h.routeToAdapter(c, adapter, jsonBody)
}

// makeMCPRequestWithSession establishes an MCP session and makes the request.
func (h *AdapterMCPHandler) makeMCPRequestWithSession(ctx context.Context, mcpURL string, request mcp.MCPMessage, authConfig *models.AdapterAuthConfig) (*http.Response, error) {
	initRequest := mcp.MCPMessage{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "suse-ai-up-rest-api",
				"version": "1.0.0",
			},
		},
	}

	initResp, err := h.makeRawMCPRequest(ctx, mcpURL, initRequest, authConfig, "")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize MCP session: %w", err)
	}
	defer initResp.Body.Close()

	initBody, err := io.ReadAll(initResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read initialize response: %w", err)
	}

	if initResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("initialize failed with status %d: %s", initResp.StatusCode, string(initBody))
	}

	// Parse initialize response (handle SSE format: "event: message\ndata: {...}")
	responseBody := string(initBody)
	var jsonData string

	if strings.Contains(responseBody, "event: message\ndata: ") {
		lines := strings.Split(responseBody, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "data: ") {
				jsonData = strings.TrimPrefix(line, "data: ")
				break
			}
		}
	} else {
		jsonData = responseBody
	}

	var initResult map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &initResult); err != nil {
		return nil, fmt.Errorf("failed to parse initialize response: %w", err)
	}

	sessionID := "rest-api-session"
	if result, ok := initResult["result"].(map[string]interface{}); ok {
		if serverInfo, ok := result["serverInfo"].(map[string]interface{}); ok {
			if name, ok := serverInfo["name"].(string); ok {
				sessionID = fmt.Sprintf("rest-api-%s", name)
			}
		}
	}

	// Send initialized notification
	initializedRequest := mcp.MCPMessage{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
		Params:  map[string]interface{}{},
	}

	initializedResp, err := h.makeRawMCPRequest(ctx, mcpURL, initializedRequest, authConfig, sessionID)
	if err == nil && initializedResp != nil {
		initializedResp.Body.Close()
	}

	return h.makeRawMCPRequest(ctx, mcpURL, request, authConfig, sessionID)
}

// makeRawMCPRequest makes an HTTP POST request to an MCP endpoint.
func (h *AdapterMCPHandler) makeRawMCPRequest(ctx context.Context, mcpURL string, request mcp.MCPMessage, authConfig *models.AdapterAuthConfig, sessionID string) (*http.Response, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", mcpURL, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	if sessionID != "" {
		req.Header.Set("mcp-session-id", sessionID)
		values := url.Values{}
		values.Set("sessionId", sessionID)
		req.URL.RawQuery = values.Encode()
	}

	if authConfig != nil && authConfig.BearerToken != nil && authConfig.BearerToken.Token != "" {
		req.Header.Set("Authorization", "Bearer "+authConfig.BearerToken.Token)
	}

	return h.httpClient.Do(req)
}

// validateClientAuth validates client authentication for adapter access.
func validateClientAuth(c *gin.Context, authConfig *models.AdapterAuthConfig) error {
	if authConfig == nil || !authConfig.Required {
		return nil
	}

	switch authConfig.Type {
	case "bearer":
		return validateBearerTokenAuth(c, authConfig)
	case "basic":
		return validateBasicCredentials(c, authConfig)
	case "apikey":
		return validateAPIKeyCredentials(c, authConfig)
	default:
		return fmt.Errorf("unsupported authentication type: %s", authConfig.Type)
	}
}

func validateBearerTokenAuth(c *gin.Context, authConfig *models.AdapterAuthConfig) error {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return fmt.Errorf("missing Authorization header")
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return fmt.Errorf("invalid Authorization header format")
	}

	token := strings.TrimPrefix(authHeader, bearerPrefix)
	var expectedToken string
	if authConfig.BearerToken != nil && authConfig.BearerToken.Token != "" {
		expectedToken = authConfig.BearerToken.Token
	}

	if token != expectedToken {
		return fmt.Errorf("invalid token")
	}
	return nil
}

func validateBasicCredentials(c *gin.Context, authConfig *models.AdapterAuthConfig) error {
	if authConfig.Basic == nil {
		return fmt.Errorf("basic authentication configuration not found")
	}

	username, password, ok := c.Request.BasicAuth()
	if !ok {
		return fmt.Errorf("missing or invalid Basic authentication header")
	}

	if username != authConfig.Basic.Username || password != authConfig.Basic.Password {
		return fmt.Errorf("invalid username or password")
	}
	return nil
}

func validateAPIKeyCredentials(c *gin.Context, authConfig *models.AdapterAuthConfig) error {
	if authConfig.APIKey == nil {
		return fmt.Errorf("API key configuration not found")
	}

	location := strings.ToLower(authConfig.APIKey.Location)
	name := authConfig.APIKey.Name
	expectedKey := authConfig.APIKey.Key

	var providedKey string
	var found bool

	switch location {
	case "header":
		providedKey = c.GetHeader(name)
		found = providedKey != ""
	case "query":
		providedKey = c.Query(name)
		found = providedKey != ""
	case "cookie":
		cookie, err := c.Cookie(name)
		if err == nil {
			providedKey = cookie
			found = true
		}
	default:
		return fmt.Errorf("unsupported API key location: %s", location)
	}

	if !found {
		return fmt.Errorf("API key not found in %s '%s'", location, name)
	}

	if providedKey != expectedKey {
		return fmt.Errorf("invalid API key")
	}
	return nil
}
