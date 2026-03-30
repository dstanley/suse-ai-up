package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"gopkg.in/yaml.v3"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	_ "suse-ai-up/docs"
	"suse-ai-up/internal/config"
	"suse-ai-up/internal/handlers"
	"suse-ai-up/internal/service"
	"suse-ai-up/pkg/auth"
	"suse-ai-up/pkg/clients"
	"suse-ai-up/pkg/logging"
	"suse-ai-up/pkg/mcp"

	// "suse-ai-up/pkg/middleware"
	"suse-ai-up/pkg/models"
	"suse-ai-up/pkg/plugins"
	"suse-ai-up/pkg/proxy"
	"suse-ai-up/pkg/scanner"
	"suse-ai-up/pkg/services"
	adaptersvc "suse-ai-up/pkg/services/adapters"
	"suse-ai-up/pkg/session"

	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

// generateID generates a random hex ID
func generateID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// parseAndUploadRegistryYAML parses YAML data and uploads MCP servers to registry
func parseAndUploadRegistryYAML(data []byte, registryManager *handlers.DefaultRegistryManager, source string) error {
	var servers []map[string]interface{}
	if err := yaml.Unmarshal(data, &servers); err != nil {
		return fmt.Errorf("could not parse registry YAML from %s: %w", source, err)
	}

	log.Printf("Loading %d MCP servers from %s", len(servers), source)

	var mcpServers []*models.MCPServer
	log.Printf("DEBUG: Processing %d servers from YAML", len(servers))
	for i, serverData := range servers {
		log.Printf("DEBUG: Server %d data: %+v", i, serverData)
		// Convert to models.MCPServer format
		server := &models.MCPServer{}

		if name, ok := serverData["name"].(string); ok {
			server.ID = name
			server.Name = name
			log.Printf("DEBUG: Server name/ID: %s", name)
		} else {
			log.Printf("Warning: Server missing name field, skipping: %+v", serverData)
			continue
		}

		if desc, ok := serverData["description"].(string); ok {
			server.Description = desc
		}

		if image, ok := serverData["image"].(string); ok {
			server.Packages = []models.Package{
				{
					Identifier: image,
					Transport: models.Transport{
						Type: "stdio",
					},
				},
			}
		}

		// Handle meta field
		if meta, ok := serverData["meta"].(map[string]interface{}); ok {
			server.Meta = meta
			log.Printf("DEBUG: Loaded meta for server %s: %+v", server.Name, meta)
		} else {
			server.Meta = make(map[string]interface{})
			log.Printf("DEBUG: No meta field found for server %s", server.Name)
		}

		// Set source to distinguish from external registries
		server.Meta["source"] = "yaml"

		// Include all additional fields from YAML in meta
		if about, ok := serverData["about"].(map[string]interface{}); ok {
			server.Meta["about"] = about
		}
		if sourceInfo, ok := serverData["source"].(map[string]interface{}); ok {
			server.Meta["source_info"] = sourceInfo
		}
		if config, ok := serverData["config"].(map[string]interface{}); ok {
			server.Meta["config"] = config
		}
		if serverType, ok := serverData["type"].(string); ok {
			server.Meta["type"] = serverType
		}

		mcpServers = append(mcpServers, server)
	}

	// Use the registry manager to upload all servers
	log.Printf("DEBUG: Uploading %d MCP servers to registry", len(mcpServers))
	if err := registryManager.UploadRegistryEntries(mcpServers); err != nil {
		return fmt.Errorf("could not upload registry entries: %w", err)
	}
	log.Printf("DEBUG: Successfully uploaded MCP servers")

	return nil
}

// loadRegistryFromURL loads MCP servers from a URL
func loadRegistryFromURL(registryManager *handlers.DefaultRegistryManager, url string, timeout time.Duration) error {
	log.Printf("Loading MCP registry from URL: %s", url)

	client := &http.Client{
		Timeout: timeout,
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch from URL %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("URL returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	return parseAndUploadRegistryYAML(data, registryManager, url)
}

// loadRegistryFromFile loads MCP servers from URL or config/mcp_registry.yaml
func loadRegistryFromFile(registryManager *handlers.DefaultRegistryManager, cfg *config.Config) {
	log.Printf("DEBUG: loadRegistryFromFile called")

	// Clear existing registry for clean startup state
	if err := registryManager.Clear(); err != nil {
		log.Printf("Warning: Failed to clear registry at startup: %v", err)
	}

	// Try to load from URL first if configured
	if cfg.MCPRegistryURL != "" {
		timeout, err := time.ParseDuration(cfg.RegistryTimeout)
		if err != nil {
			log.Printf("Warning: Invalid registry timeout %s, using 30s: %v", cfg.RegistryTimeout, err)
			timeout = 30 * time.Second
		}

		if err := loadRegistryFromURL(registryManager, cfg.MCPRegistryURL, timeout); err != nil {
			log.Printf("Warning: Failed to load registry from URL %s: %v, falling back to local file", cfg.MCPRegistryURL, err)
			// Fall through to local file loading
		} else {
			log.Printf("Successfully loaded MCP registry from URL: %s", cfg.MCPRegistryURL)
			return
		}
	}

	// Fallback to local file
	registryFile := "config/mcp_registry.yaml"
	data, err := os.ReadFile(registryFile)
	if err != nil {
		log.Printf("Warning: Could not read registry file %s: %v", registryFile, err)
		return
	}

	if err := parseAndUploadRegistryYAML(data, registryManager, registryFile); err != nil {
		log.Printf("Warning: Failed to parse and upload registry from file %s: %v", registryFile, err)
		return
	}

	log.Printf("Successfully loaded MCP registry from %s", registryFile)
}

// isVirtualMCPAdapter checks if an adapter is configured for VirtualMCP
func isVirtualMCPAdapter(data *models.AdapterData) bool {
	log.Printf("Checking adapter for VirtualMCP: %s (type: %s)", data.Name, data.ConnectionType)

	// Check if any MCP server config references a VirtualMCP package
	for serverName, serverConfig := range data.MCPClientConfig.MCPServers {
		log.Printf("Checking server config: %s", serverName)
		log.Printf("  Command: %s", serverConfig.Command)
		log.Printf("  Args: %v", serverConfig.Args)

		// Check command
		cmdLower := strings.ToLower(serverConfig.Command)
		if strings.Contains(cmdLower, "@suse") ||
			strings.Contains(cmdLower, "virtual-mcp") ||
			strings.Contains(cmdLower, "virtualmcp") ||
			strings.Contains(cmdLower, "virtual") {
			log.Printf("Detected VirtualMCP package in command: %s", serverConfig.Command)
			return true
		}

		// Check all args
		for i, arg := range serverConfig.Args {
			log.Printf("  Arg[%d]: %s", i, arg)
			argLower := strings.ToLower(arg)
			if strings.Contains(argLower, "@suse") ||
				strings.Contains(argLower, "virtual-mcp") ||
				strings.Contains(argLower, "virtualmcp") ||
				strings.Contains(argLower, "virtual") {
				log.Printf("Detected VirtualMCP package in args: %s", arg)
				return true
			}
		}

		// Check env vars
		for envKey, envValue := range serverConfig.Env {
			log.Printf("  Env[%s]: %s", envKey, envValue)
			envLower := strings.ToLower(envValue)
			if strings.Contains(envLower, "@suse") ||
				strings.Contains(envLower, "virtual-mcp") ||
				strings.Contains(envLower, "virtualmcp") ||
				strings.Contains(envLower, "virtual") {
				log.Printf("Detected VirtualMCP package in env: %s", envValue)
				return true
			}
		}
	}

	// Check adapter metadata for VirtualMCP indicators
	nameLower := strings.ToLower(data.Name)
	descLower := strings.ToLower(data.Description)
	if strings.Contains(nameLower, "virtual") ||
		strings.Contains(descLower, "virtual") ||
		strings.Contains(nameLower, "suse") ||
		strings.Contains(descLower, "suse") ||
		strings.Contains(nameLower, "mcp") ||
		strings.Contains(descLower, "mcp") {
		log.Printf("Detected VirtualMCP by name/description: %s - %s", data.Name, data.Description)
		return true
	}

	log.Printf("Adapter %s is not VirtualMCP", data.Name)
	return false
}

// reconfigureVirtualMCPAdapter reconfigures a VirtualMCP adapter to run VirtualMCP server locally via stdio
func reconfigureVirtualMCPAdapter(data *models.AdapterData) {
	log.Printf("Reconfiguring VirtualMCP adapter: %s", data.Name)
	log.Printf("Original connection type: %s", data.ConnectionType)

	// Skip reconfiguration if this is already an HTTP-based VirtualMCP adapter (from registry spawning)
	if data.ConnectionType == models.ConnectionTypeStreamableHttp {
		log.Printf("Skipping reconfiguration for HTTP-based VirtualMCP adapter: %s", data.Name)
		return
	}

	// Get API base URL from adapter configuration or default
	apiBaseUrl := data.ApiBaseUrl
	if apiBaseUrl == "" {
		apiBaseUrl = "http://localhost:8000"
	}

	// Get tools config from Tools field or default to empty
	toolsConfig := "[]"
	if len(data.Tools) > 0 {
		if toolsJSON, err := json.Marshal(data.Tools); err == nil {
			toolsConfig = string(toolsJSON)
		}
	}

	// Keep connection type as LocalStdio for stdio communication
	data.ConnectionType = models.ConnectionTypeLocalStdio

	// Modify MCPClientConfig to run VirtualMCP server locally via stdio
	log.Printf("Modifying MCPClientConfig for VirtualMCP adapter")
	data.MCPClientConfig = models.MCPClientConfig{
		MCPServers: map[string]models.MCPServerConfig{
			"virtualmcp": {
				Command: "tsx",
				Args:    []string{"templates/virtualmcp-server.ts"}, // No --transport flag = stdio mode
				Env: map[string]string{
					"SERVER_NAME":  data.Name,
					"TOOLS_CONFIG": toolsConfig, // Use tools from Tools field
					"API_BASE_URL": apiBaseUrl,  // Use configured API base URL
				},
			},
		},
	}

	// Add authentication for VirtualMCP (required for MCP protocol)
	data.Authentication = &models.AdapterAuthConfig{
		Required: true,
		Type:     "bearer",
		BearerToken: &models.BearerTokenConfig{
			Token:     "virtualmcp-token",
			Dynamic:   false,
			ExpiresAt: time.Now().Add(365 * 24 * time.Hour), // Long expiry
		},
	}

	// Update description
	data.Description = fmt.Sprintf("VirtualMCP adapter: %s", data.Description)

	log.Printf("Reconfigured VirtualMCP adapter: connectionType=%s, tools=%s, apiBaseUrl=%s",
		data.ConnectionType, toolsConfig, apiBaseUrl)
}

// initOTEL initializes OpenTelemetry tracing and metrics
func initOTEL(ctx context.Context, cfg *config.Config) error {
	log.Printf("DEBUG: initOTEL called")

	// Create OTLP trace exporter
	traceExporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(cfg.OtelEndpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return fmt.Errorf("failed to create trace exporter: %w", err)
	}

	// Create OTLP metric exporter
	metricExporter, err := otlpmetricgrpc.New(ctx,
		otlpmetricgrpc.WithEndpoint(cfg.OtelEndpoint),
		otlpmetricgrpc.WithInsecure(),
	)
	if err != nil {
		return fmt.Errorf("failed to create metric exporter: %w", err)
	}

	// Create resource
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String("suse-ai-up"),
			semconv.ServiceVersionKey.String("1.0.0"),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Create trace provider
	tracerProvider := trace.NewTracerProvider(
		trace.WithBatcher(traceExporter),
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tracerProvider)

	// Create meter provider
	meterProvider := metric.NewMeterProvider(
		metric.WithReader(metric.NewPeriodicReader(metricExporter)),
		metric.WithResource(res),
	)
	otel.SetMeterProvider(meterProvider)

	log.Println("OpenTelemetry initialized successfully")
	return nil
}

// @title SUSE AI Universal Proxy API
// @version 1.0
// @description A comprehensive, modular MCP (Model Context Protocol) proxy system
// @termsOfService http://swagger.io/terms/

// @contact.name SUSE
// @contact.url https://github.com/suse/suse-ai-up
// @contact.email info@suse.ai

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8911
// @BasePath /

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name X-API-Key

// RunUniproxy starts the SUSE AI Universal Proxy service
func RunUniproxy() {
	log.Printf("MAIN FUNCTION STARTED")
	// Load configuration
	cfg := config.LoadConfig()
	log.Printf("Config loaded: Port=%s", cfg.Port)

	// Initialize OpenTelemetry (if enabled)
	if cfg.OtelEnabled {
		ctx := context.Background()
		if err := initOTEL(ctx, cfg); err != nil {
			log.Printf("Failed to initialize OpenTelemetry: %v", err)
			// Continue without OTEL rather than failing
		}
	}

	// Initialize Gin
	if cfg.AuthMode == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	// Custom recovery middleware to handle panics properly
	r.Use(gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(string); ok {
			log.Printf("Panic recovered: %s", err)
		} else {
			log.Printf("Panic recovered: %v", recovered)
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal server error",
			"message": "An unexpected error occurred",
		})
	}))

	// Add OTEL Gin middleware (if enabled)
	if cfg.OtelEnabled {
		r.Use(otelgin.Middleware("suse-ai-up"))
	}

	// Initialize stores
	// Initialize crypto for storage encryption
	crypto, err := clients.NewStorageCrypto(cfg.StorageEncryptionKey)
	if err != nil {
		log.Printf("Warning: Failed to initialize storage encryption: %v. Data will be stored unencrypted.", err)
	} else if cfg.StorageEncryptionKey != "" {
		log.Printf("Storage encryption enabled")
	}

	// Ensure data directory exists
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		log.Fatalf("Failed to create data directory %s: %v", cfg.DataDir, err)
	}

	// Use file-based stores for persistence
	adapterStorePath := filepath.Join(cfg.DataDir, "adapters.json")
	adapterGroupAssignmentStorePath := filepath.Join(cfg.DataDir, "adapter_assignments.json")
	userStorePath := filepath.Join(cfg.DataDir, "users.json")
	groupStorePath := filepath.Join(cfg.DataDir, "groups.json")
	mcpServerStorePath := filepath.Join(cfg.DataDir, "mcp_servers.json")

	adapterStore := clients.NewFileAdapterStore(adapterStorePath, crypto)
	adapterGroupAssignmentStore := clients.NewFileAdapterGroupAssignmentStore(adapterGroupAssignmentStorePath, crypto)

	oauthIssuer := cfg.OAuthIssuerURL
	if oauthIssuer == "" {
		oauthIssuer = "mcp-gateway"
	}
	tokenManager, err := auth.NewTokenManager(oauthIssuer)
	if err != nil {
		log.Fatalf("Failed to create token manager: %v", err)
	}

	// Initialize user/group system with file storage
	userStore := clients.NewFileUserStore(userStorePath, crypto)
	groupStore := clients.NewFileGroupStore(groupStorePath, crypto)
	userGroupService := services.NewUserGroupService(userStore, groupStore)

	// Create user auth configuration
	userAuthConfig := &models.UserAuthConfig{
		Mode:        cfg.AuthMode,
		DevMode:     cfg.DevMode,
		AdminGroups: cfg.AdminGroups,
		Local: &models.LocalAuthConfig{
			DefaultAdminPassword: cfg.AdminPassword,
			ForcePasswordChange:  cfg.ForcePasswordChange,
			PasswordMinLength:    cfg.PasswordMinLength,
		},
		GitHub: &models.GitHubAuthConfig{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			RedirectURI:  cfg.GitHubRedirectURI,
			AllowedOrgs:  cfg.GitHubAllowedOrgs,
		},
		Rancher: &models.RancherAuthConfig{
			IssuerURL:     cfg.RancherIssuerURL,
			ClientID:      cfg.RancherClientID,
			ClientSecret:  cfg.RancherClientSecret,
			RedirectURI:   cfg.RancherRedirectURI,
			FallbackLocal: cfg.RancherFallbackLocal,
		},
	}

	// Initialize auth service
	userAuthService := auth.NewUserAuthService(userStore, tokenManager, userAuthConfig)

	// Initialize OAuth AS components
	auditLogger := auth.NewAuditLogger()
	oauthClientStorePath := filepath.Join(cfg.DataDir, "oauth_clients.json")
	oauthClientStore := clients.NewFileOAuthClientStore(oauthClientStorePath, crypto)
	oauthServerService := service.NewOAuthServerService(tokenManager, oauthClientStore, auditLogger, cfg)
	oauthServerHandler := handlers.NewOAuthServerHandler(oauthServerService, userAuthService, auditLogger, cfg)
	wellKnownHandler := handlers.NewWellKnownHandler(cfg.OAuthIssuerURL)

	// Authorization policy store and engine
	policyStorePath := filepath.Join(cfg.DataDir, "auth_policies.json")
	policyStore := clients.NewFileAuthPolicyStore(policyStorePath, crypto)
	oauthServerHandler.SetPolicyStore(policyStore)

	// Token vault (in-memory only — exchanged tokens don't survive restarts)
	tokenVaultStore := clients.NewInMemoryTokenVaultStore()
	tokenVaultService := service.NewTokenVaultService(tokenVaultStore, auditLogger)

	// SPIFFE/SPIRE workload identity (optional)
	if cfg.SPIREEnabled {
		spiffeClient, err := auth.NewSPIFFEClient(cfg.SPIREAgentSocketPath)
		if err != nil {
			log.Printf("Warning: SPIRE enabled but agent not available: %v", err)
		} else {
			tokenVaultService.SetSPIFFEClient(spiffeClient)
			defer spiffeClient.Close()
			log.Printf("SPIFFE/SPIRE workload identity enabled (agent: %s)", cfg.SPIREAgentSocketPath)
		}
	}

	// Create initial groups
	log.Printf("DEBUG: CreateInitialGroups: %v, Groups count: %d", cfg.CreateInitialGroups, len(cfg.InitialGroups))
	if cfg.CreateInitialGroups {
		log.Printf("DEBUG: Creating %d initial groups", len(cfg.InitialGroups))
		for _, initialGroup := range cfg.InitialGroups {
			log.Printf("Processing group: %s", initialGroup.ID)
			group := models.Group{
				ID:          initialGroup.ID,
				Name:        initialGroup.Name,
				Description: initialGroup.Description,
				Permissions: strings.Split(initialGroup.Permissions, ","),
			}
			if err := userGroupService.CreateGroup(context.Background(), group); err != nil {
				// Group might already exist, log but continue
				log.Printf("Note: Could not create initial group %s: %v", initialGroup.ID, err)
			} else {
				log.Printf("Created initial group: %s", initialGroup.ID)
			}
		}
	} else {
		log.Printf("CreateInitialGroups is disabled")
	}

	// Create initial users
	log.Printf("DEBUG: CreateInitialUsers: %v, Users count: %d", cfg.CreateInitialUsers, len(cfg.InitialUsers))
	if cfg.CreateInitialUsers {
		log.Printf("DEBUG: Creating %d initial users", len(cfg.InitialUsers))
		for _, initialUser := range cfg.InitialUsers {
			log.Printf("Processing user: %s", initialUser.ID)
			user := models.User{
				ID:           initialUser.ID,
				Name:         initialUser.Name,
				Email:        initialUser.Email,
				Groups:       strings.Split(initialUser.Groups, ","),
				AuthProvider: initialUser.AuthProvider,
			}

			password := initialUser.Password
			if password == "" && initialUser.AuthProvider == string(models.UserAuthProviderLocal) {
				password = cfg.AdminPassword
			}

			if _, err := userGroupService.GetUser(context.Background(), initialUser.ID); err != nil {
				if err := userAuthService.CreateUser(context.Background(), user, password); err != nil {
					log.Printf("Warning: Failed to create initial user %s: %v", initialUser.ID, err)
				} else {
					log.Printf("Created initial user: %s", initialUser.ID)
				}
			} else {
				log.Printf("User %s already exists", initialUser.ID)
			}
		}
	} else {
		log.Printf("CreateInitialUsers is disabled")
	}

	// Initialize MCP components
	capabilityCache := mcp.NewCapabilityCache()
	cache := mcp.NewMCPCache(nil)     // Use default config
	monitor := mcp.NewMCPMonitor(nil) // Use default config
	sessionStore := session.NewInMemorySessionStore()
	protocolHandler := mcp.NewProtocolHandler(sessionStore, capabilityCache)
	messageRouter := mcp.NewMessageRouter(protocolHandler, sessionStore, capabilityCache, cache, monitor)

	// Initialize stdio proxy plugin for local stdio adapters
	stdioProxy := proxy.NewLocalStdioProxyPlugin()
	log.Printf("stdioProxy initialized: %v", stdioProxy != nil)

	// Initialize stdio-to-HTTP adapter
	stdioToHTTPAdapter := proxy.NewStdioToHTTPAdapter(stdioProxy, messageRouter, sessionStore, protocolHandler, capabilityCache)
	log.Printf("stdioToHTTPAdapter initialized: %v", stdioToHTTPAdapter != nil)

	// Initialize remote HTTP proxy adapter
	remoteHTTPAdapter := proxy.NewRemoteHTTPProxyAdapter(sessionStore, messageRouter, protocolHandler, capabilityCache)
	log.Printf("remoteHTTPAdapter initialized: %v", remoteHTTPAdapter != nil)

	// Initialize remote HTTP proxy plugin
	remoteHTTPPlugin := proxy.NewRemoteHttpProxyPlugin()
	log.Printf("remoteHTTPPlugin initialized: %v", remoteHTTPPlugin != nil)

	// Initialize Kubernetes client and SidecarManager
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Printf("Failed to get in-cluster config, trying kubeconfig: %v", err)
		// Try to load from kubeconfig file
		kubeConfig, err = clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
		if err != nil {
			log.Printf("Failed to get Kubernetes config: %v", err)
			log.Printf("Sidecar functionality will not be available")
		}
	}

	var sidecarManager *proxy.SidecarManager
	if kubeConfig != nil {
		kubeClient, err := kubernetes.NewForConfig(kubeConfig)
		if err != nil {
			log.Printf("Failed to create Kubernetes client: %v", err)
		} else {
			sidecarManager = proxy.NewSidecarManager(kubeClient, "default")
			log.Printf("SidecarManager initialized successfully")
		}
	}

	// Initialize discovery components
	scanConfig := &models.ScanConfig{
		ScanRanges:    []string{"192.168.1.0/24"},
		Ports:         []string{"8000", "8001", "9000"},
		Timeout:       "30s",
		MaxConcurrent: 10,
		ExcludeProxy:  func() *bool { b := true; return &b }(),
	}
	networkScanner := scanner.NewNetworkScanner(scanConfig)
	discoveryStore := scanner.NewInMemoryDiscoveryStore()
	scanManager := scanner.NewScanManager(networkScanner, discoveryStore)
	discoveryHandler := handlers.NewDiscoveryHandler(scanManager, discoveryStore)
	tokenHandler := handlers.NewTokenHandler(adapterStore, tokenManager)
	// MCP auth integration — wires token exchange, service account, and SPIFFE auth
	authIntegrationService := service.NewMCPAuthIntegrationService(tokenManager)
	authIntegrationService.SetTokenVaultService(tokenVaultService)
	authIntegrationService.SetOAuthService(oauthServerService)

	// Tool-level authorization policy engine
	policyEngine := auth.NewPolicyEngine(policyStore)
	toolAuthService := service.NewToolAuthorizationService(policyEngine, auditLogger)

	adapterMCPHandler := handlers.NewAdapterMCPHandler(adapterStore, stdioToHTTPAdapter, remoteHTTPPlugin, sessionStore, policyEngine)

	mcpAuthHandler := handlers.NewMCPAuthHandler(adapterStore, authIntegrationService)

	// Initialize missing handlers
	registryStore := clients.NewFileMCPServerStore(mcpServerStorePath, crypto)
	registryManager := handlers.NewDefaultRegistryManager(registryStore)

	// Initialize AdapterService with SidecarManager
	logging.ProxyLogger.Info("Initializing AdapterService with SidecarManager")
	adapterService := adaptersvc.NewAdapterService(adapterStore, adapterGroupAssignmentStore, registryStore, sidecarManager)
	logging.ProxyLogger.Info("AdapterService created: %v", adapterService != nil)
	adapterHandler := handlers.NewAdapterHandler(adapterService, userGroupService)
	logging.ProxyLogger.Info("AdapterHandler created: %v", adapterHandler != nil)
	logging.ProxyLogger.Success("AdapterService and AdapterHandler initialized")

	// Initialize UnifiedMCPHandler for aggregated MCP endpoint
	unifiedMCPHandler := handlers.NewUnifiedMCPHandler(adapterService, userGroupService)
	unifiedMCPHandler.SetAuthIntegration(authIntegrationService)
	unifiedMCPHandler.SetToolAuthService(toolAuthService)
	logging.ProxyLogger.Info("UnifiedMCPHandler created: %v", unifiedMCPHandler != nil)

	// Adapter handlers are now used directly in Gin routes

	// Helper function to convert Gin context to standard HTTP handler
	ginToHTTPHandler := func(handler func(http.ResponseWriter, *http.Request)) gin.HandlerFunc {
		return func(c *gin.Context) {
			log.Printf("GIN HANDLER CALLED for path: %s", c.Request.URL.Path)
			handler(c.Writer, c.Request)
		}
	}

	// Load MCP registry from URL or config file
	loadRegistryFromFile(registryManager, cfg)

	// Initialize Kubernetes client for ConfigMap updates (optional)
	var k8sClient kubernetes.Interface
	if config, err := rest.InClusterConfig(); err == nil {
		k8sClient, _ = kubernetes.NewForConfig(config)
		log.Printf("Kubernetes client initialized for ConfigMap updates")
	} else {
		log.Printf("Not running in Kubernetes cluster, ConfigMap updates disabled")
	}

	registryHandler := handlers.NewRegistryHandler(registryStore, registryManager, adapterStore, userGroupService, cfg, k8sClient)

	// Initialize user/group and route assignment handlers
	userGroupHandler := handlers.NewUserGroupHandler(userGroupService, adapterService)
	authHandler := handlers.NewAuthHandler(userAuthService)
	routeAssignmentHandler := handlers.NewRouteAssignmentHandler(userGroupService, registryStore)
	logging.ProxyLogger.Info("UserGroupHandler created: %v", userGroupHandler != nil)
	logging.ProxyLogger.Info("RouteAssignmentHandler created: %v", routeAssignmentHandler != nil)

	// Initialize plugin service manager
	serviceManager := plugins.NewServiceManager(cfg, registryManager)
	pluginHandler := handlers.NewPluginHandler(serviceManager)

	// registrationHandler := handlers.NewRegistrationHandler(networkScanner, adapterStore, tokenManager, cfg)

	// Request/Response logging middleware
	// logger := middleware.NewRequestResponseLogger()
	// r.Use(logger.GinMiddleware())

	// CORS middleware
	r.Use(func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && (strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1") || strings.Contains(origin, "192.168.") || strings.Contains(origin, "10.")) {
			c.Header("Access-Control-Allow-Origin", origin)
		} else {
			c.Header("Access-Control-Allow-Origin", "*")
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, MCP-Protocol-Version, Mcp-Session-Id, X-User-Id, x-user-id")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
			"version":   "1.0.0",
		})
	})

	// Swagger UI - use relative URL for deployment compatibility
	r.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, ginSwagger.URL("/docs/doc.json")))

	// Well-known discovery endpoints (RFC 9728, RFC 8414)
	r.GET("/.well-known/oauth-protected-resource", wellKnownHandler.GetProtectedResourceMetadata)
	r.GET("/.well-known/oauth-authorization-server", wellKnownHandler.GetAuthorizationServerMetadata)

	// OAuth 2.1 Authorization Server endpoints
	oauth := r.Group("/oauth")
	{
		oauth.POST("/register", oauthServerHandler.Register)
		oauth.GET("/authorize", oauthServerHandler.Authorize)
		oauth.GET("/callback", oauthServerHandler.Callback)
		oauth.POST("/token", oauthServerHandler.Token)
		oauth.POST("/revoke", oauthServerHandler.Revoke)
	}

	// Authorization policy admin endpoints (OAuth-protected)
	authPolicies := r.Group("/api/v1/auth/policies", auth.MCPOAuthMiddleware(tokenManager))
	{
		authPolicies.GET("", oauthServerHandler.ListPolicies)
		authPolicies.POST("", oauthServerHandler.CreatePolicy)
		authPolicies.PUT("/:id", oauthServerHandler.UpdatePolicy)
		authPolicies.DELETE("/:id", oauthServerHandler.DeletePolicy)
	}

	// API v1 routes
	logging.ProxyLogger.Info("Setting up API v1 routes")
	v1 := r.Group("/api/v1")
	logging.ProxyLogger.Info("V1 group created: %v", v1 != nil)
	{
		// Discovery routes (OAuth-protected)
		discovery := v1.Group("/discovery", auth.MCPOAuthMiddleware(tokenManager))
		{
			discovery.POST("/scan", discoveryHandler.ScanForMCPServers)
			discovery.GET("/scan", discoveryHandler.ListScanJobs)
			discovery.GET("/scan/:jobId", discoveryHandler.GetScanJob)
			discovery.DELETE("/scan/:jobId", discoveryHandler.CancelScanJob)
			discovery.GET("/servers", discoveryHandler.ListDiscoveredServers)
			discovery.GET("/servers/:id", discoveryHandler.GetDeprecatedServer)
			discovery.GET("/results", discoveryHandler.GetAllScanResults)
			discovery.GET("/results/:id", discoveryHandler.GetServerFromResults)
		}

		// Adapter routes
		logging.ProxyLogger.Info("Setting up adapter routes")
		adapters := v1.Group("/adapters")
		{
			logging.ProxyLogger.Info("Adapter handler initialized: %v", adapterHandler != nil)
			// CRUD operations — protected by OAuth
			adapterAdmin := adapters.Group("", auth.MCPOAuthMiddleware(tokenManager))
			{
				adapterAdmin.GET("", ginToHTTPHandler(adapterHandler.ListAdapters))
				adapterAdmin.POST("", ginToHTTPHandler(adapterHandler.CreateAdapter))
				adapterAdmin.GET("/:name", ginToHTTPHandler(adapterHandler.GetAdapter))
				adapterAdmin.PUT("/:name", ginToHTTPHandler(adapterHandler.UpdateAdapter))
				adapterAdmin.DELETE("/:name", ginToHTTPHandler(adapterHandler.DeleteAdapter))
				adapterAdmin.POST("/:name/health", ginToHTTPHandler(adapterHandler.CheckAdapterHealth))

				// Group assignments
				adapterAdmin.POST("/:name/groups", ginToHTTPHandler(adapterHandler.AssignAdapterToGroup))
				adapterAdmin.DELETE("/:name/groups/:groupId", ginToHTTPHandler(adapterHandler.RemoveAdapterFromGroup))
				adapterAdmin.GET("/:name/groups", ginToHTTPHandler(adapterHandler.ListAdapterGroupAssignments))

				// Token management
				adapterAdmin.GET("/:name/token", tokenHandler.GetAdapterToken)
				adapterAdmin.POST("/:name/token/validate", tokenHandler.ValidateToken)
				adapterAdmin.POST("/:name/token/refresh", tokenHandler.RefreshToken)

				// Authentication
				adapterAdmin.GET("/:name/client-token", mcpAuthHandler.GetClientToken)
				adapterAdmin.POST("/:name/validate-auth", mcpAuthHandler.ValidateAuthConfig)
				adapterAdmin.POST("/:name/test-auth", mcpAuthHandler.TestAuthConnection)

				// Adapter status
				adapterAdmin.GET("/:name/status", func(c *gin.Context) {
					c.JSON(http.StatusOK, gin.H{
						"readyReplicas":     1,
						"updatedReplicas":   1,
						"availableReplicas": 1,
						"image":             "nginx:latest",
						"replicaStatus":     "Healthy",
					})
				})

				// Sync capabilities
				adapterAdmin.POST("/:name/sync", ginToHTTPHandler(adapterHandler.SyncAdapterCapabilities))
			}

			// User config (on v1 group, not adapters)
			v1.GET("/user/config", auth.MCPOAuthMiddleware(tokenManager), ginToHTTPHandler(adapterHandler.GetClientConfig))

			// MCP proxy endpoint — protected by OAuth for user identity
			adapters.Any("/:name/mcp", auth.MCPOAuthMiddleware(tokenManager), ginToHTTPHandler(adapterHandler.HandleMCPProtocol))

			// REST-style MCP endpoints — protected by OAuth for scope-aware tool filtering
			adapterMCP := adapters.Group("", auth.MCPOAuthMiddleware(tokenManager))
			{
				adapterMCP.GET("/:name/tools", adapterMCPHandler.ToolsList)
				adapterMCP.POST("/:name/tools/:toolName/call", adapterMCPHandler.ToolCall)
				adapterMCP.GET("/:name/resources", adapterMCPHandler.ResourcesList)
				adapterMCP.GET("/:name/resources/*uri", adapterMCPHandler.ResourceRead)
				adapterMCP.GET("/:name/prompts", adapterMCPHandler.PromptsList)
				adapterMCP.GET("/:name/prompts/:promptName", adapterMCPHandler.PromptGet)
			}
		}

		// Unified MCP endpoint - aggregates all adapters into a single MCP interface
		// Protected by OAuth middleware; InjectOAuthContext propagates claims to the http.Request context
		logging.ProxyLogger.Info("Setting up unified MCP endpoint")
		v1.Any("/mcp", auth.MCPOAuthMiddleware(tokenManager), handlers.InjectOAuthContext, ginToHTTPHandler(unifiedMCPHandler.HandleUnifiedMCP))

		// Registry routes (OAuth-protected)
		registry := v1.Group("/registry", auth.MCPOAuthMiddleware(tokenManager))
		{
			registry.GET("", ginToHTTPHandler(registryHandler.ListMCPServersFiltered))
			registry.POST("/upload", registryHandler.UploadRegistryEntry)
			registry.POST("/upload/bulk", registryHandler.UploadBulkRegistryEntries)
			registry.POST("/upload/local-mcp", registryHandler.UploadLocalMCP)
			registry.POST("/reload", registryHandler.ReloadRegistry)
			registry.GET("/browse", registryHandler.BrowseRegistry)

			registry.GET("/:id", registryHandler.GetMCPServer)
			registry.PUT("/:id", registryHandler.UpdateMCPServer)
			registry.DELETE("/:id", registryHandler.DeleteMCPServer)
		}

		// Plugin routes (OAuth-protected)
		plugins := v1.Group("/plugins", auth.MCPOAuthMiddleware(tokenManager))
		{
			plugins.POST("/register", pluginHandler.RegisterService)
			plugins.DELETE("/register/:serviceId", pluginHandler.UnregisterService)
			plugins.GET("/services", pluginHandler.ListServices)
			plugins.GET("/services/:serviceId", pluginHandler.GetService)
			plugins.GET("/services/type/:serviceType", pluginHandler.ListServicesByType)
			plugins.GET("/services/:serviceId/health", pluginHandler.GetServiceHealth)
		}

		// Authentication routes (login/callback are public, password/logout require auth)
		authRoutes := v1.Group("/auth")
		{
			authRoutes.POST("/login", authHandler.Login)
			authRoutes.POST("/oauth/login", authHandler.OAuthLogin)
			authRoutes.POST("/oauth/callback", authHandler.OAuthCallback)
			authRoutes.PUT("/password", auth.MCPOAuthMiddleware(tokenManager), authHandler.ChangePassword)
			authRoutes.POST("/logout", auth.MCPOAuthMiddleware(tokenManager), authHandler.Logout)
		}

		// Unauthenticated auth mode endpoint
		r.GET("/auth/mode", authHandler.GetAuthMode)

		// User/Group management routes (all OAuth-protected)
		logging.ProxyLogger.Info("Registering user/group routes")
		users := v1.Group("/users", auth.MCPOAuthMiddleware(tokenManager))
		{
			logging.ProxyLogger.Info("Users group created: %v", users != nil)
			users.GET("", ginToHTTPHandler(userGroupHandler.ListUsers))
			users.GET("/:id", ginToHTTPHandler(userGroupHandler.GetUser))
			users.POST("", ginToHTTPHandler(userGroupHandler.HandleUsers))
			users.PUT("/:id", ginToHTTPHandler(userGroupHandler.UpdateUser))
			users.DELETE("/:id", ginToHTTPHandler(userGroupHandler.DeleteUser))
		}

		groups := v1.Group("/groups", auth.MCPOAuthMiddleware(tokenManager))
		{
			groups.GET("", ginToHTTPHandler(userGroupHandler.HandleGroups))
			groups.GET("/:id", ginToHTTPHandler(userGroupHandler.GetGroup))
			groups.GET("/:id/adapters", ginToHTTPHandler(userGroupHandler.ListGroupAdapters))
			groups.POST("", ginToHTTPHandler(userGroupHandler.HandleGroups))
			groups.PUT("/:id", ginToHTTPHandler(userGroupHandler.UpdateGroup))
			groups.DELETE("/:id", ginToHTTPHandler(userGroupHandler.DeleteGroup))
			groups.POST("/:id/members", ginToHTTPHandler(userGroupHandler.AddUserToGroup))
			groups.DELETE("/:id/members/:userId", ginToHTTPHandler(userGroupHandler.RemoveUserFromGroup))
		}

		// Route assignment routes (under registry)
		registry.POST("/:id/routes", ginToHTTPHandler(routeAssignmentHandler.CreateRouteAssignment))
		registry.GET("/:id/routes", ginToHTTPHandler(routeAssignmentHandler.ListRouteAssignments))
		registry.PUT("/:id/routes/:assignmentId", ginToHTTPHandler(routeAssignmentHandler.UpdateRouteAssignment))
		registry.DELETE("/:id/routes/:assignmentId", ginToHTTPHandler(routeAssignmentHandler.DeleteRouteAssignment))

	}

	// Start health checks for plugins
	pluginCtx, pluginCancel := context.WithCancel(context.Background())
	defer pluginCancel()
	go serviceManager.StartHealthChecks(pluginCtx, 30*time.Second)

	// Start server
	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	log.Printf("DEBUG: About to start Gin HTTP server on port %s", cfg.Port)
	go func() {
		log.Printf("DEBUG: Gin server goroutine started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("ERROR: Gin server failed: %v", err)
			log.Fatalf("Failed to start server: %v", err)
		}
	}()
	log.Printf("DEBUG: Gin HTTP server created and goroutine started")

	// Log available server URLs
	serverURLs := cfg.GetServerURLs()
	log.Printf("Server starting on port %s (from config)", cfg.Port)
	log.Printf("PORT env var: %s", os.Getenv("PORT"))
	log.Printf("Service will be accessible at:")
	for _, url := range serverURLs {
		log.Printf("  %s", url)
	}
	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

// main is the entry point for the SUSE AI Universal Proxy service
func main() {
	RunUniproxy()
}
