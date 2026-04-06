package daemon

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/zero-day-ai/gibson/internal/finding"
	"github.com/zero-day-ai/gibson/internal/graphrag"
	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/graphrag/loader"
	"github.com/zero-day-ai/gibson/internal/graphrag/processor"
	"github.com/zero-day-ai/gibson/internal/graphrag/provider"
	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/llm/providers"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/memory/embedder"
	"github.com/zero-day-ai/gibson/internal/memory/vector"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/observability"
	"github.com/zero-day-ai/gibson/internal/plan"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/pkg/version"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
	"github.com/zero-day-ai/sdk/queue"
)

// Infrastructure holds the daemon's infrastructure components that are shared
// across different operations (DAG executor, finding store, LLM registry).
//
// This struct is embedded in daemonImpl to provide access to these components
// during mission execution, attack operations, and event streaming.
type Infrastructure struct {
	// planExecutor executes workflow DAGs with guardrails and approvals
	planExecutor *plan.PlanExecutor

	// findingStore persists and retrieves findings
	findingStore finding.FindingStore

	// llmRegistry manages LLM provider registration and discovery
	llmRegistry llm.LLMRegistry

	// slotManager resolves slot names to provider configurations
	slotManager llm.SlotManager

	// memoryManagerFactory creates mission-scoped memory managers
	memoryManagerFactory *MemoryManagerFactory

	// harnessFactory creates configured AgentHarness instances
	harnessFactory harness.HarnessFactoryInterface

	// runLinker manages relationships between mission runs with the same name
	runLinker mission.MissionRunLinker

	// graphRAGClient for Neo4j knowledge graph operations
	graphRAGClient *graph.Neo4jClient

	// graphRAGBridge adapts Neo4j client for harness interface (async storage)
	graphRAGBridge harness.GraphRAGBridge

	// graphRAGQueryBridge for querying the knowledge graph
	graphRAGQueryBridge harness.GraphRAGQueryBridge

	// otelStack holds the unified OTel observability stack (nil when disabled)
	otelStack *observability.OTelObservabilityStack

	// taxonomyRegistry manages core taxonomy and agent-installed extensions
	// Stored as concrete type to satisfy both TaxonomyRegistry and TaxonomyIntrospector interfaces
	taxonomyRegistry *sdkgraphrag.DefaultTaxonomyRegistry

	// discoveryProcessor processes agent output discoveries to Neo4j
	// This enables downstream agents to query discovered hosts, ports, services, etc.
	discoveryProcessor *discoveryProcessorAdapter

	// redisClient for tool execution queue management
	redisClient queue.Client
}

// newInfrastructure creates and initializes all infrastructure components.
//
// This method is called during daemon startup to wire up all the components
// that are needed for mission execution. It:
//  1. Creates the finding store backed by the database
//  2. Creates the LLM registry and registers configured providers
//  3. Creates the plan executor with the configured components
//
// Returns an error if any component fails to initialize.
func (d *daemonImpl) newInfrastructure(ctx context.Context) (*Infrastructure, error) {
	d.logger.Info(ctx, "initializing infrastructure components")

	// Create finding store with Redis (required)
	if d.stateClient == nil {
		return nil, fmt.Errorf("StateClient not initialized - cannot create finding store")
	}
	findingStore := finding.NewRedisFindingStore(d.stateClient)
	d.logger.Info(ctx, "initialized Redis finding store")

	// Create LLM registry
	llmRegistry := llm.NewLLMRegistry()

	// Register LLM providers from configuration
	if err := d.registerLLMProviders(ctx, llmRegistry); err != nil {
		return nil, fmt.Errorf("failed to register LLM providers: %w", err)
	}
	d.logger.Info(ctx, "initialized LLM registry")

	// Create slot manager with the LLM registry
	slotManager := NewDaemonSlotManager(llmRegistry, d.logger.WithComponent("slot-manager").Slog())

	// Populate provider env var hints for clear error messages on slot resolution failures
	if d.config != nil && d.config.LLM.Providers != nil {
		envVars := make(map[string]string)
		for name, providerCfg := range d.config.LLM.Providers {
			if providerCfg.APIKeyEnv != "" {
				envVars[name] = providerCfg.APIKeyEnv
			}
		}
		slotManager.SetProviderEnvVars(envVars)
	}
	d.logger.Info(ctx, "initialized slot manager")

	// Create memory manager factory with StateClient and config
	// Use memory config from daemon config, or nil to use defaults
	var memConfig *memory.MemoryConfig
	if d.config != nil {
		// Config.Memory is a struct, not a pointer, so take its address
		memConfig = &d.config.Memory
	}

	// Pass StateClient for Redis-backed memory (required)
	memoryFactory, err := NewMemoryManagerFactory(d.stateClient, memConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create memory manager factory: %w", err)
	}

	d.logger.Info(ctx, "initialized memory manager factory with Redis support")

	// Initialize TaxonomyRegistry with core taxonomy
	// This provides the canonical node/relationship types and parent relationship rules
	// Must be initialized before GraphRAG so relationship builders can use it
	coreTaxonomy := sdkgraphrag.NewSimpleTaxonomy()
	taxonomyRegistry := sdkgraphrag.NewTaxonomyRegistry(coreTaxonomy)
	d.logger.Info(ctx, "initialized taxonomy registry",
		"taxonomy_version", coreTaxonomy.Version())

	// Initialize Redis client for tool execution
	// Redis is required for distributed tool execution via work queues
	redisClient, err := d.initRedis(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Redis client (required): %w", err)
	}
	d.logger.Info(ctx, "initialized Redis client",
		"url", d.config.Redis.URL,
		"database", d.config.Redis.Database)

	// Initialize Neo4j GraphRAG - this is REQUIRED as GraphRAG is a core component
	// GraphRAG is always required - fail fast if initialization fails
	graphRAGClient, err := d.initGraphRAG(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Neo4j GraphRAG (required): %w", err)
	}
	d.logger.Info(ctx, "initialized Neo4j GraphRAG",
		"uri", d.config.GraphRAG.Neo4j.URI)

	// Create the full GraphRAG stack: Provider -> Store -> BridgeAdapter
	graphRAGBridge, graphRAGQueryBridge, err := d.initGraphRAGBridges(ctx, graphRAGClient)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GraphRAG bridges (required): %w", err)
	}
	d.logger.Info(ctx, "initialized GraphRAG bridges with full store support")

	// Create DiscoveryProcessor for processing agent output discoveries to Neo4j
	// This enables downstream agents to query discovered hosts, ports, services, etc.
	graphLoader := loader.NewGraphLoader(graphRAGClient).
		WithTaxonomyRegistry(taxonomyRegistry)
	discoveryProc := processor.NewDiscoveryProcessor(graphLoader, graphRAGClient, d.logger.Slog())
	discoveryProcessorAdapter := &discoveryProcessorAdapter{processor: discoveryProc}
	d.logger.Info(ctx, "initialized DiscoveryProcessor for automatic discovery storage")

	// Initialize OpenTelemetry observability stack (required for LLM tracing)
	// This provides unified tracing and metrics to OTLP-compatible backends
	otelStack := d.initOTelObservability(ctx)
	if otelStack == nil {
		d.logger.Warn(ctx, "OTel observability not configured - LLM tracing disabled",
			"docs", "docs/runbooks/otel-observability.md")
	}

	// Create plan executor with dependencies.
	// Executor configuration is read from config.Daemon.Executor.
	planExecutorOpts := []plan.ExecutorOption{
		plan.WithExecutorLogger(d.logger.WithComponent("plan-executor").Slog()),
	}
	if d.config != nil && d.config.Daemon.Executor.DefaultTimeout > 0 {
		planExecutorOpts = append(planExecutorOpts, plan.WithStepTimeout(d.config.Daemon.Executor.DefaultTimeout))
	}
	planExecutor := plan.NewPlanExecutor(planExecutorOpts...)
	d.logger.Info(ctx, "initialized plan executor")

	// Store infrastructure components temporarily so newHarnessFactory can access them
	infra := &Infrastructure{
		planExecutor:         planExecutor,
		findingStore:         findingStore,
		llmRegistry:          llmRegistry,
		slotManager:          slotManager,
		memoryManagerFactory: memoryFactory,
		graphRAGClient:       graphRAGClient,
		graphRAGBridge:       graphRAGBridge,
		graphRAGQueryBridge:  graphRAGQueryBridge,
		otelStack:            otelStack,
		taxonomyRegistry:     taxonomyRegistry,
		discoveryProcessor:   discoveryProcessorAdapter,
		redisClient:          redisClient,
	}
	d.infrastructure = infra

	// Create harness factory with all dependencies
	harnessFactory, err := d.newHarnessFactory(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create harness factory: %w", err)
	}
	d.logger.Info(ctx, "initialized harness factory")

	// Update infrastructure with harness factory
	infra.harnessFactory = harnessFactory

	// Create mission run linker
	runLinker := mission.NewMissionRunLinker(d.missionStore)
	infra.runLinker = runLinker
	d.logger.Info(ctx, "initialized mission run linker")

	return infra, nil
}

// registerLLMProviders registers all configured LLM providers with the registry.
//
// This method reads the LLM configuration and creates provider instances for
// each configured provider (Anthropic, OpenAI, Ollama, Google). Providers are
// registered with the LLM registry for slot-based selection during mission execution.
//
// Returns an error if any provider fails to initialize or register.
func (d *daemonImpl) registerLLMProviders(ctx context.Context, registry llm.LLMRegistry) error {
	d.logger.Debug(ctx, "registering LLM providers from configuration")

	// Check if config has provider-specific configurations
	if d.config != nil && d.config.LLM.Providers != nil && len(d.config.LLM.Providers) > 0 {
		// Register providers from configuration
		for name, providerCfg := range d.config.LLM.Providers {
			// Resolve API key from environment variable if specified
			apiKey := providerCfg.APIKey
			if providerCfg.APIKeyEnv != "" {
				if envKey := os.Getenv(providerCfg.APIKeyEnv); envKey != "" {
					apiKey = envKey
				}
			}

			// Convert config.ProviderConfig type string to llm.ProviderType
			var providerType llm.ProviderType
			switch providerCfg.Type {
			case "anthropic":
				providerType = llm.ProviderAnthropic
			case "openai":
				providerType = llm.ProviderOpenAI
			case "google":
				providerType = llm.ProviderGoogle
			default:
				providerType = llm.ProviderCustom
			}

			// Convert config.ProviderConfig to llm.ProviderConfig
			llmCfg := llm.ProviderConfig{
				Type:         providerType,
				APIKey:       apiKey,
				BaseURL:      providerCfg.BaseURL,
				DefaultModel: providerCfg.Model,
				RateLimits: llm.RateLimitConfig{
					RequestsPerMinute: providerCfg.RateLimits.RequestsPerMinute,
					TokensPerMinute:   providerCfg.RateLimits.TokensPerMinute,
				},
			}

			// Create provider using factory
			provider, err := providers.NewProvider(llmCfg)
			if err != nil {
				// Wrap auth errors with env var hint so operators know which variable to check
				translatedErr := llm.TranslateErrorWithEnvHint(name, providerCfg.APIKeyEnv, err)
				d.logger.Warn(ctx, "failed to create provider",
					"name", name,
					"type", providerCfg.Type,
					"error", translatedErr)
				continue
			}

			// Wrap with rate limiter if configured
			if llmCfg.RateLimits.IsEnabled() {
				provider = llm.NewRateLimitedProvider(provider, llmCfg.RateLimits)
				d.logger.Info(ctx, "rate limiting enabled for provider",
					"name", name,
					"requests_per_minute", llmCfg.RateLimits.RequestsPerMinute,
					"tokens_per_minute", llmCfg.RateLimits.TokensPerMinute,
				)
			}

			// Register provider
			if regErr := registry.RegisterProvider(provider); regErr != nil {
				d.logger.Warn(ctx, "failed to register provider",
					"name", name,
					"type", providerCfg.Type,
					"error", regErr)
			} else {
				d.logger.Info(ctx, "registered LLM provider",
					"name", name,
					"type", providerCfg.Type,
					"model", providerCfg.Model)
			}
		}
	} else {
		// Fallback to environment-based registration for backward compatibility
		d.logger.Debug(ctx, "no provider configuration found, using environment-based registration")

		// Try to register Anthropic provider from environment
		provider, err := providers.NewAnthropicProvider(llm.ProviderConfig{
			Type:         llm.ProviderAnthropic,
			DefaultModel: os.Getenv("ANTHROPIC_MODEL"), // Use env var, provider will use its default if empty
			// APIKey will be read from ANTHROPIC_API_KEY environment variable
		})
		if err == nil {
			if regErr := registry.RegisterProvider(provider); regErr != nil {
				d.logger.Warn(ctx, "failed to register Anthropic provider", "error", regErr)
			} else {
				d.logger.Info(ctx, "registered Anthropic provider")
			}
		} else {
			d.logger.Debug(ctx, "Anthropic provider not available", "error", err)
		}

		// Try to register OpenAI provider from environment
		openaiProvider, err := providers.NewOpenAIProvider(llm.ProviderConfig{
			Type:         llm.ProviderOpenAI,
			DefaultModel: os.Getenv("OPENAI_MODEL"), // Use env var, provider will use its default if empty
			// APIKey will be read from OPENAI_API_KEY environment variable
		})
		if err == nil {
			if regErr := registry.RegisterProvider(openaiProvider); regErr != nil {
				d.logger.Warn(ctx, "failed to register OpenAI provider", "error", regErr)
			} else {
				d.logger.Info(ctx, "registered OpenAI provider")
			}
		} else {
			d.logger.Debug(ctx, "OpenAI provider not available", "error", err)
		}

		// Try to register Google provider from environment
		googleProvider, err := providers.NewGoogleProvider(llm.ProviderConfig{
			Type:         llm.ProviderGoogle,
			DefaultModel: os.Getenv("GOOGLE_MODEL"), // Use env var, provider will use its default if empty
			// APIKey will be read from GOOGLE_API_KEY environment variable
		})
		if err == nil {
			if regErr := registry.RegisterProvider(googleProvider); regErr != nil {
				d.logger.Warn(ctx, "failed to register Google provider", "error", regErr)
			} else {
				d.logger.Info(ctx, "registered Google provider")
			}
		} else {
			d.logger.Debug(ctx, "Google provider not available", "error", err)
		}

		// Try to register Ollama provider from environment
		ollamaProvider, err := providers.NewOllamaProvider(llm.ProviderConfig{
			Type:         "ollama",
			BaseURL:      os.Getenv("OLLAMA_BASE_URL"), // Use env var, provider will use default if empty
			DefaultModel: os.Getenv("OLLAMA_MODEL"),    // Use env var, provider will use its default if empty
		})
		if err == nil {
			if regErr := registry.RegisterProvider(ollamaProvider); regErr != nil {
				d.logger.Warn(ctx, "failed to register Ollama provider", "error", regErr)
			} else {
				d.logger.Info(ctx, "registered Ollama provider")
			}
		} else {
			d.logger.Debug(ctx, "Ollama provider not available", "error", err)
		}
	}

	// Verify at least one provider is registered
	if len(registry.ListProviders()) == 0 {
		d.logger.Warn(ctx, "no LLM providers registered - missions may fail if they require LLM access")
	}

	return nil
}

// checkInfrastructureHealth checks the health of all infrastructure components.
//
// This method is called during health checks to verify that all infrastructure
// components are operational. It checks:
//  1. Database connectivity (via finding store)
//  2. LLM provider health
//  3. Registry health
//  4. Redis/StateClient health (if enabled)
//
// Returns a map of component names to health status strings.
func (d *daemonImpl) checkInfrastructureHealth(ctx context.Context, infra *Infrastructure) map[string]string {
	health := make(map[string]string)

	// Check database/finding store
	// We can test by attempting to count findings for a dummy mission
	_, err := infra.findingStore.Count(ctx, "health-check-mission-id")
	if err != nil {
		health["finding_store"] = fmt.Sprintf("unhealthy: %v", err)
	} else {
		health["finding_store"] = "healthy"
	}

	// Check LLM registry
	llmHealth := infra.llmRegistry.Health(ctx)
	if llmHealth.IsHealthy() {
		health["llm_registry"] = llmHealth.Message
	} else {
		health["llm_registry"] = fmt.Sprintf("unhealthy: %s", llmHealth.Message)
	}

	// Check component registry via registry adapter
	if d.registryAdapter != nil {
		// Try to list agents to verify registry is accessible
		_, err := d.registryAdapter.ListAgents(ctx)
		if err != nil {
			health["component_registry"] = fmt.Sprintf("unhealthy: %v", err)
		} else {
			health["component_registry"] = "healthy"
		}
	} else {
		health["component_registry"] = "not initialized"
	}

	// Check Redis StateClient health (required for Gibson operation)
	if d.stateClient != nil {
		if err := d.stateClient.Health(ctx); err != nil {
			health["redis_state_client"] = fmt.Sprintf("unhealthy: %v", err)
		} else {
			health["redis_state_client"] = "healthy"
		}
	} else {
		health["redis_state_client"] = "not initialized (critical error)"
	}

	return health
}

// initGraphRAGBridges creates the full GraphRAG stack and returns bridge interfaces.
//
// This method creates:
//  1. An embedder for vector operations (native by default, with fallback to mock)
//  2. A vector store for semantic similarity search
//  3. A GraphRAG provider using the Neo4j client
//  4. A GraphRAG store that orchestrates the provider and embedder
//  5. A bridge adapter that provides both GraphRAGBridge and GraphRAGQueryBridge interfaces
//
// Returns the bridge and query bridge, or an error if initialization fails.
func (d *daemonImpl) initGraphRAGBridges(ctx context.Context, neo4jClient *graph.Neo4jClient) (harness.GraphRAGBridge, harness.GraphRAGQueryBridge, error) {
	// Create embedder from config - fail fast if unavailable
	emb, err := embedder.CreateEmbedder(d.config.Embedder)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create embedder: %w", err)
	}
	d.logger.Info(ctx, "created embedder for GraphRAG",
		"provider", d.config.Embedder.Provider,
		"dimensions", emb.Dimensions(),
		"model", emb.Model())

	// Create vector store for semantic similarity search
	// Use dimensions from the embedder to ensure compatibility
	vectorStore := vector.NewEmbeddedVectorStore(emb.Dimensions())
	d.logger.Info(ctx, "created vector store for GraphRAG",
		"dimensions", emb.Dimensions(),
		"type", "embedded")

	// Convert daemon config.GraphRAGConfig to graphrag.GraphRAGConfig
	// Provider specifies the graph database type (neo4j, neptune, memgraph)
	// The factory maps these to the appropriate provider implementation
	// GraphRAG is a required core component - always configured
	graphRAGConfig := graphrag.GraphRAGConfig{
		Provider: "neo4j", // Graph database type (required)
		Neo4j: graphrag.Neo4jConfig{
			URI:      d.config.GraphRAG.Neo4j.URI,
			Username: d.config.GraphRAG.Neo4j.Username,
			Password: d.config.GraphRAG.Neo4j.Password,
			Database: "neo4j", // Default database
			PoolSize: d.config.GraphRAG.Neo4j.MaxConnections,
		},
		Vector: graphrag.VectorConfig{
			// Vector search is always enabled as part of GraphRAG
		},
	}
	graphRAGConfig.ApplyDefaults()

	// Create GraphRAG provider from config
	prov, err := provider.NewProvider(graphRAGConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GraphRAG provider: %w", err)
	}
	d.logger.Info(ctx, "created GraphRAG provider",
		"type", graphRAGConfig.Provider)

	// Inject vector store into the provider BEFORE initialization
	// The LocalGraphRAGProvider requires the vector store to be set before Initialize() is called
	if localProv, ok := prov.(*provider.LocalGraphRAGProvider); ok {
		localProv.SetVectorStore(vectorStore)
		d.logger.Info(ctx, "injected vector store into GraphRAG provider")
	}

	// Initialize the provider (after vector store is set)
	if err := prov.Initialize(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to initialize GraphRAG provider: %w", err)
	}

	// Create GraphRAG store with the provider and embedder
	store, err := graphrag.NewGraphRAGStoreWithProvider(graphRAGConfig, emb, prov)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GraphRAG store: %w", err)
	}
	d.logger.Info(ctx, "created GraphRAG store")

	// Create bridge adapter with the store
	adapter, err := NewGraphRAGBridgeAdapter(GraphRAGBridgeConfig{
		Neo4jClient:   neo4jClient,
		GraphRAGStore: store,
		Logger:        d.logger.WithComponent("graphrag-bridge").Slog(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GraphRAG bridge adapter: %w", err)
	}

	return adapter.Bridge(), adapter.QueryBridge(), nil
}

// initOTelObservability initializes the OpenTelemetry observability stack if enabled.
// Returns the initialized stack or nil if OTel is disabled or initialization fails.
// Errors are logged as warnings - tracing failures should not prevent daemon startup.
//
// This method follows the fail-open pattern: if OTel initialization fails, the daemon
// continues without observability rather than failing to start. This ensures that
// misconfigured or unavailable observability backends don't prevent mission execution.
func (d *daemonImpl) initOTelObservability(ctx context.Context) *observability.OTelObservabilityStack {
	// Check if OTel is enabled in configuration
	if d.config == nil || !d.config.OTelObservability.Enabled {
		d.logger.Debug(ctx, "OpenTelemetry observability disabled in configuration")
		return nil
	}

	d.logger.Info(ctx, "initializing OpenTelemetry observability stack",
		"endpoint", d.config.OTelObservability.Endpoint,
		"protocol", d.config.OTelObservability.Protocol,
		"service_name", d.config.OTelObservability.ServiceName)

	// Build OTelConfig from daemon configuration
	cfg := observability.OTelConfig{
		Enabled:           d.config.OTelObservability.Enabled,
		Endpoint:          d.config.OTelObservability.Endpoint,
		Protocol:          d.config.OTelObservability.Protocol,
		Headers:           d.config.OTelObservability.Headers,
		ServiceName:       d.config.OTelObservability.ServiceName,
		ServiceVersion:    version.Version,
		BatchSize:         d.config.OTelObservability.Batching.MaxSize,
		BatchTimeout:      d.config.OTelObservability.Batching.Timeout,
		RetryEnabled:      d.config.OTelObservability.Retry.Enabled,
		RetryInitial:      d.config.OTelObservability.Retry.InitialInterval,
		RetryMax:          d.config.OTelObservability.Retry.MaxInterval,
		RetryMaxElapsed: d.config.OTelObservability.Retry.MaxElapsedTime,
		Neo4jBrowserURL: d.config.Observability.Neo4jBrowserURL,
	}

	// Convert ContentLoggingSubConfig to observability.ContentLoggingConfig
	if d.config.OTelObservability.ContentLogging.Enabled {
		contentCfg := &observability.ContentLoggingConfig{
			Enabled:             d.config.OTelObservability.ContentLogging.Enabled,
			MaxPromptLength:     d.config.OTelObservability.ContentLogging.MaxPromptLength,
			MaxCompletionLength: d.config.OTelObservability.ContentLogging.MaxCompletionLength,
			RedactPatterns:      d.config.OTelObservability.ContentLogging.RedactPatterns,
			IncludeToolIO:       d.config.OTelObservability.ContentLogging.IncludeToolIO,
		}

		// Compile redaction patterns
		if err := contentCfg.CompilePatterns(); err != nil {
			d.logger.Warn(ctx, "failed to compile content logging patterns, using defaults",
				"error", err)
			// Use defaults if pattern compilation fails
			defaultCfg := observability.DefaultContentLoggingConfig()
			if err := defaultCfg.CompilePatterns(); err == nil {
				contentCfg = &defaultCfg
			}
		}

		cfg.ContentLogging = contentCfg
	}

	// Initialize the OTel observability stack
	stack, err := observability.InitOTelObservability(ctx, cfg)
	if err != nil {
		d.logger.Warn(ctx, "failed to initialize OpenTelemetry observability, continuing without OTel tracing",
			"error", err,
			"endpoint", cfg.Endpoint,
			"protocol", cfg.Protocol,
			"service_name", cfg.ServiceName,
			"troubleshooting", "verify OTLP collector is accessible and protocol matches collector configuration")
		// Fail open - continue without OTel observability
		return nil
	}

	d.logger.Info(ctx, "OpenTelemetry observability stack initialized successfully",
		"endpoint", cfg.Endpoint,
		"protocol", cfg.Protocol,
		"service_name", cfg.ServiceName,
		"content_logging_enabled", cfg.ContentLogging != nil && cfg.ContentLogging.Enabled)

	return stack
}

// initRedis initializes the Redis client for tool execution.
// Returns the client or an error if initialization fails.
func (d *daemonImpl) initRedis(ctx context.Context) (queue.Client, error) {
	d.logger.Info(ctx, "initializing Redis client",
		"url", d.config.Redis.URL,
		"database", d.config.Redis.Database)

	// Create Redis client with daemon configuration
	client, err := queue.NewRedisClient(queue.RedisOptions{
		URL:            d.config.Redis.URL,
		ConnectTimeout: d.config.Redis.ConnectTimeout,
		ReadTimeout:    d.config.Redis.ReadTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis client: %w", err)
	}

	d.logger.Info(ctx, "Redis client initialized successfully")
	return client, nil
}

// RedisClient returns the Redis client for tool execution.
// Returns nil if Redis is not initialized.
func (i *Infrastructure) RedisClient() queue.Client {
	return i.redisClient
}

// initStateClient creates and initializes a StateClient for Redis state stores.
// This provides unified Redis client access for mission stores, finding stores, and DAOs.
// The method ensures RediSearch indexes are created during initialization.
//
// Implements retry logic with exponential backoff (3 attempts) for resilience during startup.
//
// Returns the initialized StateClient or an error if connection/initialization fails after all retries.
func (d *daemonImpl) initStateClient(ctx context.Context) (*state.StateClient, error) {
	d.logger.Info(ctx, "initializing StateClient for Redis state stores",
		"url", d.config.Redis.URL,
		"database", d.config.Redis.Database)

	// Create StateClient config from daemon config
	cfg := &state.Config{
		URL:         d.config.Redis.URL,
		Database:    d.config.Redis.Database,
		DialTimeout: d.config.Redis.ConnectTimeout,
		ReadTimeout: d.config.Redis.ReadTimeout,
	}
	cfg.ApplyDefaults()

	// Retry configuration: 3 attempts with exponential backoff
	const maxAttempts = 3
	var client *state.StateClient
	var err error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			// Calculate exponential backoff delay: 1s, 2s, 4s
			backoffDelay := time.Duration(1<<uint(attempt-2)) * time.Second
			d.logger.Warn(ctx, "retrying StateClient initialization after backoff",
				"attempt", attempt,
				"max_attempts", maxAttempts,
				"backoff_delay", backoffDelay,
				"previous_error", err)

			// Sleep with context cancellation support
			select {
			case <-time.After(backoffDelay):
				// Continue to retry
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled during StateClient initialization retry: %w", ctx.Err())
			}
		}

		d.logger.Debug(ctx, "attempting to create StateClient",
			"attempt", attempt,
			"max_attempts", maxAttempts)

		// Create the StateClient (establishes connection and validates modules)
		client, err = state.NewStateClient(cfg)
		if err != nil {
			d.logger.Warn(ctx, "failed to create StateClient",
				"attempt", attempt,
				"max_attempts", maxAttempts,
				"error", err)

			if attempt == maxAttempts {
				return nil, fmt.Errorf("failed to create StateClient after %d attempts: %w", maxAttempts, err)
			}
			continue
		}

		// Ensure RediSearch indexes are created for all Gibson entities
		// This is idempotent - existing indexes are not recreated
		d.logger.Info(ctx, "ensuring RediSearch indexes",
			"attempt", attempt)

		if err = client.EnsureIndexes(ctx); err != nil {
			d.logger.Warn(ctx, "failed to ensure RediSearch indexes",
				"attempt", attempt,
				"max_attempts", maxAttempts,
				"error", err)

			client.Close()

			if attempt == maxAttempts {
				return nil, fmt.Errorf("failed to ensure RediSearch indexes after %d attempts: %w", maxAttempts, err)
			}
			continue
		}

		// Success!
		d.logger.Info(ctx, "StateClient initialized successfully",
			"attempt", attempt,
			"indexes_ensured", true)

		return client, nil
	}

	// Should never reach here, but handle it gracefully
	return nil, fmt.Errorf("failed to initialize StateClient after %d attempts: %w", maxAttempts, err)
}
