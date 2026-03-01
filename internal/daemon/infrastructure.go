package daemon

import (
	"context"
	"fmt"
	"os"

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
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
	"github.com/zero-day-ai/sdk/queue"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
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

	// tracerProvider for distributed tracing (Langfuse or OTLP)
	tracerProvider *sdktrace.TracerProvider

	// spanProcessors for distributed tracing (used by callback service)
	spanProcessors []sdktrace.SpanProcessor

	// graphRAGClient for Neo4j knowledge graph operations
	graphRAGClient *graph.Neo4jClient

	// graphRAGBridge adapts Neo4j client for harness interface (async storage)
	graphRAGBridge harness.GraphRAGBridge

	// graphRAGQueryBridge for querying the knowledge graph
	graphRAGQueryBridge harness.GraphRAGQueryBridge

	// missionTracer provides mission-aware Langfuse tracing (nil when disabled)
	missionTracer *observability.MissionTracer

	// taxonomyRegistry manages core taxonomy and agent-installed extensions
	taxonomyRegistry sdkgraphrag.TaxonomyRegistry

	// discoveryProcessor processes agent output discoveries to Neo4j
	// This enables downstream agents to query discovered hosts, ports, services, etc.
	discoveryProcessor *discoveryProcessorAdapter

	// activityLogger for logging activity events (daemon-level)
	activityLogger observability.ActivityLogger

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
	d.logger.Info("initializing infrastructure components")

	// Create finding store with caching and tracing
	findingStore := finding.NewDBFindingStore(
		d.db,
		finding.WithCacheSize(1000), // Cache last 1000 findings
	)
	d.logger.Info("initialized finding store")

	// Create LLM registry
	llmRegistry := llm.NewLLMRegistry()

	// Register LLM providers from configuration
	if err := d.registerLLMProviders(ctx, llmRegistry); err != nil {
		return nil, fmt.Errorf("failed to register LLM providers: %w", err)
	}
	d.logger.Info("initialized LLM registry")

	// Create slot manager with the LLM registry
	slotManager := NewDaemonSlotManager(llmRegistry, d.logger.With("component", "slot-manager"))
	d.logger.Info("initialized slot manager")

	// Create memory manager factory with database and config
	// Use memory config from daemon config, or nil to use defaults
	var memConfig *memory.MemoryConfig
	if d.config != nil {
		// Config.Memory is a struct, not a pointer, so take its address
		memConfig = &d.config.Memory
	}
	memoryFactory, err := NewMemoryManagerFactory(d.db, memConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create memory manager factory: %w", err)
	}
	d.logger.Info("initialized memory manager factory")

	// Initialize TaxonomyRegistry with core taxonomy
	// This provides the canonical node/relationship types and parent relationship rules
	// Must be initialized before GraphRAG so relationship builders can use it
	coreTaxonomy := sdkgraphrag.NewSimpleTaxonomy()
	taxonomyRegistry := sdkgraphrag.NewTaxonomyRegistry(coreTaxonomy)
	d.logger.Info("initialized taxonomy registry",
		"taxonomy_version", coreTaxonomy.Version())

	// Initialize Redis client for tool execution
	// Redis is required for distributed tool execution via work queues
	redisClient, err := d.initRedis(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Redis client (required): %w", err)
	}
	d.logger.Info("initialized Redis client",
		"url", d.config.Redis.URL,
		"database", d.config.Redis.Database)

	// Initialize Neo4j GraphRAG - this is REQUIRED as GraphRAG is a core component
	// GraphRAG is always required - fail fast if initialization fails
	graphRAGClient, err := d.initGraphRAG(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Neo4j GraphRAG (required): %w", err)
	}
	d.logger.Info("initialized Neo4j GraphRAG",
		"uri", d.config.GraphRAG.Neo4j.URI)

	// Create the full GraphRAG stack: Provider -> Store -> BridgeAdapter
	graphRAGBridge, graphRAGQueryBridge, err := d.initGraphRAGBridges(ctx, graphRAGClient)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GraphRAG bridges (required): %w", err)
	}
	d.logger.Info("initialized GraphRAG bridges with full store support")

	// Create daemon-level activity logger for infrastructure components
	// This is separate from mission-level activity loggers and always enabled
	var daemonActivityLogger observability.ActivityLogger
	if d.config != nil && d.config.ActivityLogging.Enabled {
		cfg := observability.ActivityLoggerConfig{
			Level:            observability.ParseActivityLevel(d.config.ActivityLogging.Level),
			MaxContentLength: d.config.ActivityLogging.MaxContentLength,
			BufferSize:       d.config.ActivityLogging.BufferSize,
		}
		logger, err := observability.NewActivityLogger(cfg)
		if err != nil {
			d.logger.Warn("failed to create daemon activity logger, using noop", "error", err)
			daemonActivityLogger = observability.NewNoopActivityLogger()
		} else {
			daemonActivityLogger = logger
			d.logger.Info("daemon activity logger enabled for infrastructure components",
				"level", d.config.ActivityLogging.Level)
		}
	} else {
		daemonActivityLogger = observability.NewNoopActivityLogger()
		d.logger.Debug("daemon activity logger disabled (using noop)")
	}

	// Create DiscoveryProcessor for processing agent output discoveries to Neo4j
	// This enables downstream agents to query discovered hosts, ports, services, etc.
	graphLoader := loader.NewGraphLoader(graphRAGClient)
	discoveryProc := processor.NewDiscoveryProcessor(graphLoader, graphRAGClient, d.logger, daemonActivityLogger)
	discoveryProcessorAdapter := &discoveryProcessorAdapter{processor: discoveryProc}
	d.logger.Info("initialized DiscoveryProcessor for automatic discovery storage")

	// Initialize Langfuse tracing if enabled
	// Pass Neo4j client to enable dual export (Langfuse + Neo4j graph recording)
	var tracerProvider *sdktrace.TracerProvider
	var spanProcessors []sdktrace.SpanProcessor
	if d.config != nil && d.config.Langfuse.Enabled {
		var err error
		tracerProvider, spanProcessors, err = d.initLangfuseTracing(ctx, graphRAGClient)
		if err != nil {
			d.logger.Warn("failed to initialize Langfuse tracing, continuing without tracing",
				"error", err)
		} else {
			d.logger.Info("initialized Langfuse tracing",
				"host", d.config.Langfuse.Host)
			if graphRAGClient != nil {
				d.logger.Info("Langfuse tracing configured with Neo4j graph span recording")
			}
		}
	}

	// Initialize MissionTracer for mission-aware Langfuse tracing
	// This is separate from OTEL tracing and provides mission-level observability
	missionTracer := d.initMissionTracer(ctx)

	// Create plan executor with dependencies
	// TODO: Add executor config to Config struct when implementing
	planExecutor := plan.NewPlanExecutor(
		plan.WithExecutorLogger(d.logger.With("component", "plan-executor")),
	)
	d.logger.Info("initialized plan executor")

	// Store infrastructure components temporarily so newHarnessFactory can access them
	infra := &Infrastructure{
		planExecutor:         planExecutor,
		findingStore:         findingStore,
		llmRegistry:          llmRegistry,
		slotManager:          slotManager,
		memoryManagerFactory: memoryFactory,
		tracerProvider:       tracerProvider,
		spanProcessors:       spanProcessors,
		graphRAGClient:       graphRAGClient,
		graphRAGBridge:       graphRAGBridge,
		graphRAGQueryBridge:  graphRAGQueryBridge,
		missionTracer:        missionTracer,
		taxonomyRegistry:     taxonomyRegistry,
		discoveryProcessor:   discoveryProcessorAdapter,
		activityLogger:       daemonActivityLogger,
		redisClient:          redisClient,
	}
	d.infrastructure = infra

	// Create harness factory with all dependencies
	harnessFactory, err := d.newHarnessFactory(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create harness factory: %w", err)
	}
	d.logger.Info("initialized harness factory")

	// Update infrastructure with harness factory
	infra.harnessFactory = harnessFactory

	// Create mission run linker
	runLinker := mission.NewMissionRunLinker(d.missionStore)
	infra.runLinker = runLinker
	d.logger.Info("initialized mission run linker")

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
	d.logger.Debug("registering LLM providers from configuration")

	// TODO: Expand LLMConfig structure to support provider-specific configurations.
	// Currently using environment variables for API keys.

	// Try to register Anthropic provider from environment
	provider, err := providers.NewAnthropicProvider(llm.ProviderConfig{
		Type:         llm.ProviderAnthropic,
		DefaultModel: os.Getenv("ANTHROPIC_MODEL"), // Use env var, provider will use its default if empty
		// APIKey will be read from ANTHROPIC_API_KEY environment variable
	})
	if err == nil {
		if regErr := registry.RegisterProvider(provider); regErr != nil {
			d.logger.Warn("failed to register Anthropic provider", "error", regErr)
		} else {
			d.logger.Info("registered Anthropic provider")
		}
	} else {
		d.logger.Debug("Anthropic provider not available", "error", err)
	}

	// Try to register OpenAI provider from environment
	openaiProvider, err := providers.NewOpenAIProvider(llm.ProviderConfig{
		Type:         llm.ProviderOpenAI,
		DefaultModel: os.Getenv("OPENAI_MODEL"), // Use env var, provider will use its default if empty
		// APIKey will be read from OPENAI_API_KEY environment variable
	})
	if err == nil {
		if regErr := registry.RegisterProvider(openaiProvider); regErr != nil {
			d.logger.Warn("failed to register OpenAI provider", "error", regErr)
		} else {
			d.logger.Info("registered OpenAI provider")
		}
	} else {
		d.logger.Debug("OpenAI provider not available", "error", err)
	}

	// TODO: Add Google and Ollama provider registration when config structure is expanded

	// Verify at least one provider is registered
	if len(registry.ListProviders()) == 0 {
		d.logger.Warn("no LLM providers registered - missions may fail if they require LLM access")
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
	d.logger.Info("created embedder for GraphRAG",
		"provider", d.config.Embedder.Provider,
		"dimensions", emb.Dimensions(),
		"model", emb.Model())

	// Create vector store for semantic similarity search
	// Use dimensions from the embedder to ensure compatibility
	vectorStore := vector.NewEmbeddedVectorStore(emb.Dimensions())
	d.logger.Info("created vector store for GraphRAG",
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
	d.logger.Info("created GraphRAG provider",
		"type", graphRAGConfig.Provider)

	// Inject vector store into the provider BEFORE initialization
	// The LocalGraphRAGProvider requires the vector store to be set before Initialize() is called
	if localProv, ok := prov.(*provider.LocalGraphRAGProvider); ok {
		localProv.SetVectorStore(vectorStore)
		d.logger.Info("injected vector store into GraphRAG provider")
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
	d.logger.Info("created GraphRAG store")

	// Create bridge adapter with the store
	adapter, err := NewGraphRAGBridgeAdapter(GraphRAGBridgeConfig{
		Neo4jClient:   neo4jClient,
		GraphRAGStore: store,
		Logger:        d.logger.With("component", "graphrag-bridge"),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GraphRAG bridge adapter: %w", err)
	}

	return adapter.Bridge(), adapter.QueryBridge(), nil
}

// initMissionTracer initializes the MissionTracer for Langfuse observability.
// Returns the tracer or nil if Langfuse is disabled or initialization fails.
// Errors are logged as warnings - tracing failures should not prevent daemon startup.
func (d *daemonImpl) initMissionTracer(ctx context.Context) *observability.MissionTracer {
	// Check if Langfuse is enabled in configuration
	if d.config == nil || !d.config.Langfuse.Enabled {
		d.logger.Debug("Langfuse MissionTracer disabled in configuration")
		return nil
	}

	d.logger.Info("initializing Langfuse MissionTracer",
		"host", d.config.Langfuse.Host)

	// Create LangfuseConfig for the MissionTracer
	langfuseCfg := observability.LangfuseConfig{
		PublicKey: d.config.Langfuse.PublicKey,
		SecretKey: d.config.Langfuse.SecretKey,
		Host:      d.config.Langfuse.Host,
	}

	// Create the MissionTracer
	tracer, err := observability.NewMissionTracer(langfuseCfg)
	if err != nil {
		d.logger.Warn("failed to initialize MissionTracer, continuing without mission tracing",
			"error", err)
		return nil
	}

	// Verify connectivity on startup
	if err := tracer.CheckConnectivity(ctx); err != nil {
		d.logger.Warn("Langfuse connectivity check failed - traces may not be recorded",
			"host", d.config.Langfuse.Host,
			"error", err,
		)
		// Continue anyway - fail open for observability
	} else {
		d.logger.Info("Langfuse connectivity verified",
			"host", d.config.Langfuse.Host,
		)
	}

	d.logger.Info("MissionTracer initialized successfully",
		"host", d.config.Langfuse.Host)

	return tracer
}

// initRedis initializes the Redis client for tool execution.
// Returns the client or an error if initialization fails.
func (d *daemonImpl) initRedis(ctx context.Context) (queue.Client, error) {
	d.logger.Info("initializing Redis client",
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

	d.logger.Info("Redis client initialized successfully")
	return client, nil
}

// RedisClient returns the Redis client for tool execution.
// Returns nil if Redis is not initialized.
func (i *Infrastructure) RedisClient() queue.Client {
	return i.redisClient
}
