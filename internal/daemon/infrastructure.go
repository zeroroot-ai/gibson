package daemon

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/zeroroot-ai/gibson/internal/finding"
	"github.com/zeroroot-ai/gibson/internal/graphrag"
	"github.com/zeroroot-ai/gibson/internal/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/harness"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/llm/providers"
	"github.com/zeroroot-ai/gibson/internal/llm/providers/catalogue"
	"github.com/zeroroot-ai/gibson/internal/mission"
	"github.com/zeroroot-ai/gibson/internal/observability"
	"github.com/zeroroot-ai/gibson/internal/plan"
	"github.com/zeroroot-ai/gibson/internal/queue"
	"github.com/zeroroot-ai/gibson/internal/state"
	"github.com/zeroroot-ai/gibson/pkg/version"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// Infrastructure holds the daemon's infrastructure components that are shared
// across different operations (DAG executor, finding store, LLM registry).
//
// This struct is embedded in daemonImpl to provide access to these components
// during mission execution, attack operations, and event streaming.
type Infrastructure struct {
	// planExecutor executes mission DAGs with guardrails and approvals
	planExecutor *plan.PlanExecutor

	// findingStore persists and retrieves findings
	findingStore finding.FindingStore

	// llmRegistry manages LLM provider registration and discovery
	llmRegistry llm.LLMRegistry

	// slotManager resolves slot names to provider configurations
	slotManager llm.SlotManager

	// harnessFactory creates configured AgentHarness instances
	harnessFactory harness.HarnessFactoryInterface

	// runLinker manages relationships between mission runs with the same name
	runLinker mission.MissionRunLinker

	// otelStack holds the unified OTel observability stack (nil when disabled)
	otelStack *observability.OTelObservabilityStack

	// taxonomyRegistry manages core taxonomy and agent-installed extensions
	// Stored as concrete type to satisfy both TaxonomyRegistry and TaxonomyIntrospector interfaces
	taxonomyRegistry *sdkgraphrag.DefaultTaxonomyRegistry

	// redisClient for tool execution queue management
	redisClient queue.Client

	// reasoner is the shared ontology reasoner. Populated during
	// newInfrastructure from d.reasoner so callers that hold only an
	// Infrastructure pointer can reach it.
	reasoner interface{ Descendants(string) []string }

	// semanticQuerierFactory builds a per-request SemanticQuerier for a given
	// GraphClient (typically a SessionGraphClient wrapping a pool-acquired
	// neo4j.SessionWithContext). Call it at RPC time after resolving the
	// tenant's Neo4j session.
	//
	// Example:
	//   conn, _ := pool.For(ctx, tenant)
	//   defer conn.Release()
	//   sq := infra.SemanticQuerier(graph.NewSessionGraphClient(conn.Neo4j))
	//   results, _ := sq.FindingsByControl(ctx, tenantID, controlIRI)
	semanticQuerierFactory func(client graph.GraphClient) *graphrag.SemanticQuerier
}

// SemanticQuerier constructs a per-request SemanticQuerier backed by client.
// Returns nil when no ontology reasoner is available (e.g. in tests that
// bypass newInfrastructure).
func (i *Infrastructure) SemanticQuerier(client graph.GraphClient) *graphrag.SemanticQuerier {
	if i.semanticQuerierFactory == nil {
		return nil
	}
	return i.semanticQuerierFactory(client)
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

	// Initialise the provider catalogue.  When GIBSON_PROVIDERS_CATALOGUE_PATH
	// is set the daemon loads the operator-supplied file (e.g. mounted from the
	// provider-catalogue ConfigMap) and hot-reloads it every 5 minutes so model
	// list updates are visible without a restart.  When the env var is absent the
	// embedded provider-catalogue.yaml is used (static, no polling).
	//
	// NewLoader panics on a corrupt or unreadable file — the correct
	// fail-fast behaviour: the process should not start with a bad catalogue.
	cataloguePath := os.Getenv("GIBSON_PROVIDERS_CATALOGUE_PATH")
	catalogueLoader := catalogue.NewLoader(cataloguePath)
	catalogue.SetLoader(catalogueLoader)
	catalogueLoader.Start(ctx, 5*time.Minute)
	d.logger.Info(ctx, "provider catalogue loaded",
		"path", func() string {
			if cataloguePath == "" {
				return "<embedded>"
			}
			return cataloguePath
		}())

	// Per-tenant finding store: findings are now written through the data-plane Pool
	// (conn.Findings()) at handler time. The Infrastructure no longer holds a
	// global finding store; the field is retained as nil for backward-compat
	// with code that checks infra.findingStore != nil.
	if d.stateClient == nil {
		return nil, fmt.Errorf("StateClient not initialized - cannot initialize infrastructure")
	}
	d.logger.Info(ctx, "finding store: per-tenant path via Pool (no global Redis store)")

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

	// Initialize TaxonomyRegistry with core taxonomy
	// This provides the canonical node/relationship types and parent relationship rules
	// Must be initialized before GraphRAG so relationship builders can use it
	coreTaxonomy := sdkgraphrag.NewSimpleTaxonomy()
	taxonomyRegistry := sdkgraphrag.NewTaxonomyRegistry(coreTaxonomy)
	d.logger.Info(ctx, "initialized taxonomy registry",
		"taxonomy_version", coreTaxonomy.Version())

	// Initialize the ontology reasoner: loads embedded SDK vocabulary and
	// registers Prometheus metrics. Non-fatal file errors are logged inside
	// initOntologyReasoner; the daemon proceeds with a sparse reasoner on
	// partial load.
	reasoner, err := d.initOntologyReasoner(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ontology reasoner: %w", err)
	}
	d.reasoner = reasoner

	// Initialize Redis client for tool execution
	// Redis is required for distributed tool execution via work queues
	redisClient, err := d.initRedis(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Redis client (required): %w", err)
	}
	d.logger.Info(ctx, "initialized Redis client",
		"url", d.config.Redis.URL,
		"database", d.config.Redis.Database)

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

	// Build the semantic querier factory. The factory closes over d.reasoner so
	// each per-request SemanticQuerier uses the same live reasoner singleton.
	// If reasoner is nil (not expected in production), the factory produces nil.
	var sqFactory func(graph.GraphClient) *graphrag.SemanticQuerier
	if d.reasoner != nil {
		r := d.reasoner // capture to avoid capturing *d in the closure
		sqFactory = func(client graph.GraphClient) *graphrag.SemanticQuerier {
			return graphrag.NewSemanticQuerier(client, r)
		}
	}

	// Store infrastructure components temporarily so newHarnessFactory can access them.
	// findingStore is nil: findings are persisted via per-tenant Pool at handler time.
	infra := &Infrastructure{
		planExecutor:           planExecutor,
		findingStore:           nil, // migrated to pool-backed per-tenant path
		llmRegistry:            llmRegistry,
		slotManager:            slotManager,
		otelStack:              otelStack,
		taxonomyRegistry:       taxonomyRegistry,
		redisClient:            redisClient,
		reasoner:               d.reasoner,
		semanticQuerierFactory: sqFactory,
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

	// Mission run linker: per-tenant migration complete, no global store.
	// Pass nil store — the linker is not actively called post-cutover.
	runLinker := mission.NewMissionRunLinker(nil)
	infra.runLinker = runLinker
	d.logger.Info(ctx, "initialized mission run linker (no-op store — per-tenant via pool)")

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

			// Create provider using broker-aware factory (Phase 11, Task 29).
			// d.secretsService may be nil here (broker stack not yet wired at
			// newInfrastructure time); NewProviderWithContext handles nil by
			// falling back to cfg.Extra / cfg.APIKey / env-var chain.
			provider, err := providers.NewProviderWithContext(ctx, d.secretsService, llmCfg)
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

	// Register the e2e mock LLM provider when the binary was built with
	// -tags=test_fixtures AND GIBSON_TEST_FIXTURES_ENABLED=true.
	// In production builds this is a compile-time no-op (see
	// fixture_mock_llm_register_stub.go).
	maybeRegisterMockLLMProvider(ctx, registry)

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

	// Finding store check: findings are now per-tenant via Pool; pool health is
	// checked separately via the /readyz probe. Skip here to avoid cross-tenant access.
	if infra.findingStore != nil {
		_, err := infra.findingStore.Count(ctx, "health-check-mission-id")
		if err != nil {
			health["finding_store"] = fmt.Sprintf("unhealthy: %v", err)
		} else {
			health["finding_store"] = "healthy"
		}
	} else {
		health["finding_store"] = "per-tenant (pool-backed)"
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

	// Resolve metrics-enabled with backward-compatible default (nil → true).
	// ApplyDefaults runs before this point so the pointer should always be
	// non-nil here, but guard anyway.
	metricsEnabled := true
	if d.config.OTelObservability.Metrics.Enabled != nil {
		metricsEnabled = *d.config.OTelObservability.Metrics.Enabled
	}

	// Build OTelConfig from daemon configuration
	cfg := observability.OTelConfig{
		Enabled:         d.config.OTelObservability.Enabled,
		Endpoint:        d.config.OTelObservability.Endpoint,
		Protocol:        d.config.OTelObservability.Protocol,
		Headers:         d.config.OTelObservability.Headers,
		ServiceName:     d.config.OTelObservability.ServiceName,
		ServiceVersion:  version.Version,
		BatchSize:       d.config.OTelObservability.Batching.MaxSize,
		BatchTimeout:    d.config.OTelObservability.Batching.Timeout,
		RetryEnabled:    d.config.OTelObservability.Retry.Enabled,
		RetryInitial:    d.config.OTelObservability.Retry.InitialInterval,
		RetryMax:        d.config.OTelObservability.Retry.MaxInterval,
		RetryMaxElapsed: d.config.OTelObservability.Retry.MaxElapsedTime,
		Neo4jBrowserURL: d.config.Observability.Neo4jBrowserURL,
		MetricsEnabled:  metricsEnabled,
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

	client, err := newQueueBackend(d.config.Redis.URL, d.config.Redis.ConnectTimeout, d.config.Redis.ReadTimeout)
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
