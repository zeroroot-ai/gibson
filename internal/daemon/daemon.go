package daemon

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/attack"
	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/crypto/providers"
	"github.com/zero-day-ai/gibson/internal/daemon/api"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/graphrag/loader"
	"github.com/zero-day-ai/gibson/internal/graphrag/processor"
	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/observability"
	"github.com/zero-day-ai/gibson/internal/orchestrator"
	"github.com/zero-day-ai/gibson/internal/payload"
	"github.com/zero-day-ai/gibson/internal/provisioner"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/gibson/internal/version"
	healthhttp "github.com/zero-day-ai/sdk/health/http"
	sdktypes "github.com/zero-day-ai/sdk/types"
	"go.opentelemetry.io/otel/trace"
)

// targetStore is an interface for target data access
type targetStore interface {
	Get(ctx context.Context, id types.ID) (*types.Target, error)
	GetByName(ctx context.Context, name string) (*types.Target, error)
	Create(ctx context.Context, target *types.Target) error
}

// AgentRuntimeState tracks runtime state for a single agent.
// This includes last heartbeat time and current task information.
type AgentRuntimeState struct {
	// LastHeartbeat is the last time the agent communicated with the daemon
	LastHeartbeat time.Time

	// CurrentTask is the ID of the task the agent is currently working on
	CurrentTask string

	// TaskStartTime is when the current task was assigned
	TaskStartTime time.Time
}

// daemonImpl is the concrete implementation of the Daemon interface.
//
// It manages the lifecycle of all Gibson daemon services and coordinates
// their startup, operation, and shutdown. The daemon owns:
//   - Redis-backed component registry for runtime service discovery
//   - Callback manager (harness callback server for agents)
//   - Redis daemon registration for client discovery
type daemonImpl struct {
	// config is the loaded Gibson configuration
	config *config.Config

	// logger is the structured logger for daemon operations
	logger *observability.Logger

	// compRegistry is the Redis-backed component registry for runtime service discovery
	compRegistry component.ComponentRegistry

	// registryTenant is the tenant scope used for component registry discovery
	registryTenant string

	// registryAdapter provides component discovery and listing via Redis registry
	registryAdapter component.ComponentDiscovery

	// callback manages the harness callback server
	callback *harness.CallbackManager

	// eventBus manages event distribution to subscribers
	eventBus *EventBus

	// stateClient provides unified Redis client for state stores
	// This is initialized when GIBSON_USE_REDIS_STORES=true
	stateClient *state.StateClient

	// missionStore provides access to mission persistence
	missionStore mission.MissionStore

	// missionRunStore provides access to mission run persistence
	missionRunStore mission.MissionRunStore

	// missionAuthzStore tracks the owning user per run for component authz callback resolution.
	// When nil (authz.enabled=false or no Redis), authz state tracking is skipped.
	missionAuthzStore mission.MissionAuthzStore

	// checkpointStore provides checkpoint persistence for pause/resume
	checkpointStore mission.CheckpointStore

	// missionService provides mission business logic operations
	missionService mission.MissionService

	// targetStore provides access to target persistence
	targetStore targetStore

	// infrastructure holds shared components (DAG executor, finding store, LLM registry)
	infrastructure *Infrastructure

	// missionManager manages mission lifecycle and execution
	missionManager *missionManager

	// missionsMu protects access to activeMissions map
	missionsMu sync.RWMutex

	// activeMissions tracks currently running missions by mission ID
	// The value is a context.CancelFunc that can be called to stop the mission
	activeMissions map[string]context.CancelFunc

	// agentStateMu protects access to agentState map
	agentStateMu sync.RWMutex

	// agentState tracks runtime state for each agent (last heartbeat, current task)
	// Key is agent name, value is AgentRuntimeState
	agentState map[string]*AgentRuntimeState

	// grpcServer is the gRPC server for client connections (added in Phase 3)
	grpcServer interface{}

	// grpcAddr is the address the gRPC server listens on (added in Phase 3)
	grpcAddr string

	// attackRunner executes ad-hoc attacks
	attackRunner attack.AttackRunner

	// redisDaemonInfo provides Redis-based daemon discovery and registration
	redisDaemonInfo *RedisDaemonInfo

	// healthServer provides HTTP health endpoints for Kubernetes probes
	healthServer *healthhttp.Server

	// healthState tracks shutdown state for health endpoints
	healthState *healthStateManager

	// signalHandler manages OS signal handling for graceful shutdown
	signalHandler *SignalHandler

	// checkpointer manages mission checkpointing during graceful shutdown
	checkpointer *DaemonMissionCheckpointer

	// logTailer manages component log tailing with fsnotify
	logTailer *LogTailer

	// keyProvider provides access to encryption keys from secure storage
	keyProvider crypto.KeyProvider

	// credentialStore provides credential access with encryption
	credentialStore *DaemonCredentialStore

	// credentialHandler provides CRUD operations for credentials (used by dashboard API)
	credentialHandler *api.CredentialHandler

	// llmConfigHandler provides LLM provider configuration management (used by dashboard API)
	llmConfigHandler *api.LLMConfigHandler

	// pluginAccessStore manages tenant opt-in and encrypted configuration for platform plugins.
	// Initialized alongside credentialStore when a KeyProvider is configured.
	// May be nil when no key provider is set (plugin access RPCs will return Unimplemented).
	pluginAccessStore component.PluginAccessStore

	// toolAccessStore manages tenant opt-in for tools.
	// Initialized when a standalone Redis client is available.
	toolAccessStore *component.RedisToolAccessStore

	// agentAccessStore manages tenant opt-in for agents.
	// Initialized when a standalone Redis client is available.
	agentAccessStore *component.RedisAgentAccessStore

	// quotaManager enforces per-tenant resource quotas (missions, agents, memory).
	// Initialized after stateClient is available. May be nil until then; quota
	// enforcement is a no-op while nil.
	quotaManager *component.QuotaManager

	// redisEventStream bridges the in-process EventBus to per-tenant Redis Streams.
	// It is initialised after stateClient is available. May be nil before that;
	// event publishing gracefully no-ops when nil.
	redisEventStream *RedisEventStream

	// startTime tracks when the daemon started
	startTime time.Time

	// onRegistryReady is called during startup before other services are initialized.
	// This allows CLI to set up verbose logging during startup.
	onRegistryReady func()

	// authorizer is the authorization service client.
	// Set during initAuthorizer() in Start(). Always non-nil after startup:
	// either a real fgaAuthorizer (authz.enabled=true) or a noopAuthorizer
	// (authz.enabled=false or FGA unreachable in dev mode).
	authorizer authz.Authorizer

	// envelopeSigner signs AuthzContext payloads attached to dispatched work items.
	// Created during Start() with a random per-daemon secret. Components verify
	// signatures via the GIBSON_AUTHZ_HMAC_SECRET env var (populated from this
	// signer's Secret() method via a ConfigMap or Secret at registration time).
	// May be nil when authz is disabled.
	envelopeSigner *authz.EnvelopeSigner
}

// New creates a new daemon instance with the provided configuration.
//
// This function initializes the daemon structure and prepares service managers
// but does not start any services. Call Start() to begin daemon operations.
//
// Parameters:
//   - cfg: The loaded Gibson configuration
//   - homeDir: The Gibson home directory (typically ~/.gibson)
//
// Returns:
//   - Daemon: A new daemon instance ready to be started
//   - error: Non-nil if initialization fails
//
// Example usage:
//
//	cfg, err := config.Load()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	daemon, err := New(cfg, os.Getenv("GIBSON_HOME"))
//	if err != nil {
//	    log.Fatal(err)
//	}
func New(cfg *config.Config, homeDir string) (Daemon, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if homeDir == "" {
		return nil, fmt.Errorf("home directory cannot be empty")
	}

	// Setup unified logger
	logCfg := observability.ConfigFromEnv()
	logCfg.Component = "daemon"
	logger := observability.NewLogger(logCfg)

	// Initialize callback manager
	callbackMgr := harness.NewCallbackManager(harness.CallbackConfig{
		ListenAddress:    cfg.Callback.ListenAddress,
		AdvertiseAddress: cfg.Callback.AdvertiseAddress,
		Enabled:          cfg.Callback.Enabled,
	}, logger.Slog())

	// Initialize Redis state stores (default and required)
	// StateClient will be initialized in Start() after logging is set up
	var stateClient *state.StateClient
	var missionStore mission.MissionStore
	var missionRunStore mission.MissionRunStore
	var targetStore targetStore

	// Stores will be initialized in Start() after StateClient is created
	// For now, keep them nil - they will be set up with Redis backends
	logger.Info(nil, "Redis stores will be initialized on startup",
		"note", "Gibson requires Redis for state persistence")

	// Initialize event bus
	eventBus := NewEventBus(logger.Slog(), WithEventBufferSize(100))

	// Determine gRPC address from config, environment variable, or default
	grpcAddr := cfg.Daemon.GRPCAddress
	if grpcAddr == "" {
		grpcAddr = "localhost:50002"
	}
	// Environment variable takes precedence
	if envAddr := os.Getenv("GIBSON_DAEMON_GRPC_ADDR"); envAddr != "" {
		grpcAddr = envAddr
	}

	// Initialize health state manager
	healthState := newHealthStateManager()

	return &daemonImpl{
		config:          cfg,
		logger:          logger,
		registryAdapter: nil, // Created in Start() after registry is available
		callback:        callbackMgr,
		eventBus:        eventBus,
		stateClient:     stateClient,     // Will be initialized in Start()
		missionStore:    missionStore,    // Will be initialized in Start()
		missionRunStore: missionRunStore, // Will be initialized in Start()
		targetStore:     targetStore,     // Will be initialized in Start()
		activeMissions:  make(map[string]context.CancelFunc),
		agentState:      make(map[string]*AgentRuntimeState),
		grpcServer:      nil,         // Created in Start()
		grpcAddr:        grpcAddr,    // Configurable via config file or environment variable
		attackRunner:    nil,         // Created in Start() after registry is available
		healthState:     healthState, // Health state manager for shutdown coordination
		startTime:       time.Time{}, // Set when Start() is called
	}, nil
}

// SetOnRegistryReady sets a callback that will be called during startup
// before other services are initialized. This is used by the CLI to set up
// verbose logging during startup.
func (d *daemonImpl) SetOnRegistryReady(fn func()) {
	d.onRegistryReady = fn
}

// Start begins the daemon process and all managed services.
//
// This method performs the following operations:
// 1. Check for existing daemon (prevent multiple instances)
// 2. Start registry manager
// 3. Start callback server
// 4. Write PID and daemon.json files
// 5. Block until context cancellation or shutdown signal
//
// Parameters:
//   - ctx: Context for daemon lifetime (cancellation triggers shutdown)
//
// Returns:
//   - error: Non-nil if startup fails or daemon already running
func (d *daemonImpl) Start(ctx context.Context) error {
	d.logger.Info(ctx, "starting Gibson daemon",
		"callback_enabled", d.config.Callback.Enabled,
	)

	// Record start time
	d.startTime = time.Now()

	// Create an internal context that can be cancelled by signal handler
	internalCtx, internalCancel := context.WithCancel(ctx)
	defer internalCancel()

	// Call the startup callback if set
	if d.onRegistryReady != nil {
		d.onRegistryReady()
	}

	// Initialize StateClient and Redis stores (required for Gibson)
	d.logger.Info(ctx, "initializing Redis stores")

	// Initialize StateClient with retry logic (3 attempts with exponential backoff)
	stateClient, err := d.initStateClient(ctx)
	if err != nil {
		d.stopServices(ctx)
		return fmt.Errorf("failed to initialize StateClient (required): %w", err)
	}
	d.stateClient = stateClient

	// Initialize Redis event stream bridge for tenant-scoped event persistence.
	d.redisEventStream = NewRedisEventStream(stateClient, d.logger.Slog())
	d.logger.Info(ctx, "redis event stream initialized")

	// Initialize Redis stores
	d.missionStore = mission.NewRedisMissionStore(stateClient)
	d.missionRunStore = mission.NewRedisMissionRunStore(stateClient)
	d.checkpointStore = mission.NewRedisCheckpointStore(stateClient)
	d.missionAuthzStore = mission.NewRedisMissionAuthzStore(stateClient.Client())
	d.targetStore = database.NewRedisTargetDAO(stateClient)

	d.logger.Info(ctx, "Redis stores initialized successfully",
		"mission_store", "RedisMissionStore",
		"mission_run_store", "RedisMissionRunStore",
		"checkpoint_store", "RedisCheckpointStore",
		"mission_authz_store", "RedisMissionAuthzStore",
		"target_store", "RedisTargetDAO",
	)

	// Authorization Service phase — must run AFTER State Client and BEFORE Component Registry.
	// When authz.enabled=false (default) this is a fast no-op that injects a noopAuthorizer.
	if err := d.initAuthorizer(ctx); err != nil {
		d.stopServices(ctx)
		return fmt.Errorf("failed to initialize authorization service: %w", err)
	}

	// Initialize the per-daemon HMAC signer for work envelope AuthzContexts.
	// The signer uses a randomly generated secret on every daemon start. Components
	// pick up the secret via the GIBSON_AUTHZ_HMAC_SECRET env var (populated during
	// component registration in future task). Failure is non-fatal — authz context
	// signing is degraded to dev mode (no signing) but the daemon continues.
	if signer, signerErr := authz.NewEnvelopeSigner(); signerErr != nil {
		d.logger.Warn(ctx, "failed to create envelope HMAC signer; work items will not carry signed AuthzContext",
			"error", signerErr.Error(),
		)
	} else {
		d.envelopeSigner = signer
		d.logger.Info(ctx, "initialized envelope HMAC signer for work item AuthzContext signing")
	}

	// Keycloak Organization reconciliation phase — runs AFTER Authorization Service and
	// BEFORE Component Registry. When provisioner.reconcile_on_startup=false this is
	// a fast no-op. A failure in any individual tenant is logged but does NOT abort
	// startup; only a scan-level error (Redis unreachable) is returned.
	if d.stateClient != nil {
		if redisClient, ok := d.stateClient.Client().(*goredis.Client); ok {
			d.runOrgReconciliation(ctx, redisClient)
		}
	}

	// Initialize Redis-backed component registry and registry adapter.
	// The component registry uses Redis for runtime service discovery (registrations with TTL).
	// The tenant is scoped per-daemon; use "default" as the tenant for the daemon's own discovery.
	compRegistry := component.NewRedisComponentRegistry(stateClient.Client(), 0)
	tenant := d.config.Registry.Namespace
	if tenant == "" {
		tenant = "default"
	}
	d.compRegistry = compRegistry
	d.registryTenant = tenant
	regAdapter := component.NewRegistryAdapter(compRegistry, tenant)
	d.registryAdapter = regAdapter
	d.logger.Info(ctx, "initialized Redis-backed component registry adapter", "tenant", tenant)

	// Wire callback manager to registry adapter for external agent callback support
	regAdapter.SetCallbackManager(d.callback)
	d.logger.Info(ctx, "wired callback manager to registry adapter")

	// Share proto resolver between registry adapter and callback manager for unified caching
	d.callback.SetProtoResolver(regAdapter.GetResolver())
	d.logger.Info(ctx, "shared proto resolver with callback manager")

	// Initialize log tailer for component log streaming
	d.logTailer = NewLogTailer(ctx, 10000, *d.logger)
	d.logger.Info(ctx, "initialized log tailer")

	// Initialize mission service with inline config processor support
	// Note: MissionStore implements WorkflowCreator (has CreateDefinition method)
	// and targetStore implements TargetCreator (has Create method)
	missionService := mission.NewMissionService(d.missionStore, nil, nil) // No workflow/finding stores for now
	missionService.SetTargetStore(d.targetStore)

	// Create inline config processor using the target store and mission store
	inlineProcessor := mission.NewInlineConfigProcessor(d.targetStore, d.missionStore)
	missionService.SetInlineProcessor(inlineProcessor)
	d.missionService = missionService
	d.logger.Info(ctx, "initialized mission service with inline config processor")

	// Initialize QuotaManager for per-tenant resource enforcement.
	// The TenantScopedStore wraps stateClient so that all quota counters are
	// automatically namespaced by tenant — no cross-tenant data leakage.
	if d.stateClient != nil {
		tenantStoreCfg := &state.TenantStoreConfig{
			AuthMode:      d.config.Auth.Mode,
			DefaultTenant: "default",
			RequireTenant: d.config.Auth.Mode == "saas",
		}
		tenantStore := state.NewTenantScopedStore(d.stateClient, tenantStoreCfg)
		d.quotaManager = component.NewQuotaManager(tenantStore, d.logger.Slog())
		d.logger.Info(ctx, "quota manager initialized")
	} else {
		d.logger.Warn(ctx, "quota manager not initialized - state client unavailable")
	}

	// Initialize infrastructure components (DAG executor, finding store, LLM registry, harness factory)
	// This must happen before creating the orchestrator because the orchestrator needs the harness factory
	d.logger.Info(ctx, "initializing infrastructure components")
	infra, err := d.newInfrastructure(ctx)
	if err != nil {
		d.stopServices(ctx)
		return fmt.Errorf("failed to initialize infrastructure: %w", err)
	}
	d.infrastructure = infra
	d.logger.Info(ctx, "infrastructure components initialized")

	// Configure callback service with TracerProvider for proxy span creation (from OTel stack)
	if infra.otelStack != nil && infra.otelStack.TracerProvider != nil {
		d.callback.SetTracerProvider(infra.otelStack.TracerProvider)
		d.logger.Info(ctx, "configured callback service with OTel tracer provider")
	}

	// Configure callback service with credential store for secure credential retrieval
	// Initialize KeyProvider from config if available
	if d.config.Security.KeyProvider != nil {
		d.logger.Info(ctx, "initializing key provider", "type", d.config.Security.KeyProvider.Type)
		keyProvider, err := providers.NewKeyProvider(d.config.Security.KeyProvider)
		if err != nil {
			d.logger.Warn(ctx, "failed to initialize key provider (credentials will not be available)",
				"error", err)
		} else {
			d.keyProvider = keyProvider

			// Create credential store with Redis DAO and KeyProvider
			credentialDAO := database.NewRedisCredentialDAO(d.stateClient)
			d.logger.Info(ctx, "using Redis credential DAO")

			credentialStore, err := NewDaemonCredentialStore(credentialDAO, keyProvider)
			if err != nil {
				d.logger.Warn(ctx, "failed to initialize credential store (credentials will not be available)",
					"error", err)
			} else {
				d.credentialStore = credentialStore
				d.callback.SetCredentialStore(credentialStore)
				d.logger.Info(ctx, "configured callback service with credential store")

				// Initialize plugin access store for tenant-scoped plugin opt-in management.
				// Shares the same Redis client, encryptor, key provider, and component registry
				// as the credential store so plugin configs are co-located with other daemon state.
				if redisClient, ok := d.stateClient.Client().(*goredis.Client); ok {
					d.pluginAccessStore = component.NewRedisPluginAccessStore(
						redisClient,
						crypto.NewAESGCMEncryptor(),
						keyProvider,
						d.compRegistry,
						d.logger.Slog(),
					)
					d.logger.Info(ctx, "initialized plugin access store")

					// Patch the harness factory that was built before the key provider was
					// available. The factory stores config by value so we use SetPluginAccess
					// to inject the store without rebuilding the entire factory.
					if d.infrastructure != nil && d.infrastructure.harnessFactory != nil {
						if df, ok := d.infrastructure.harnessFactory.(*harness.DefaultHarnessFactory); ok {
							df.SetPluginAccess(d.pluginAccessStore)
							d.logger.Info(ctx, "wired plugin access store into harness factory")
						}
					}

					// Initialize tool and agent access stores.
					d.toolAccessStore = component.NewRedisToolAccessStore(redisClient, d.logger.Slog())
					d.agentAccessStore = component.NewRedisAgentAccessStore(redisClient, d.logger.Slog())
					d.logger.Info(ctx, "initialized tool and agent access stores")

				} else {
					d.logger.Warn(ctx, "plugin access store unavailable: Redis client is not standalone mode")
				}

				// Initialize credential handler for dashboard API
				credentialHandler, err := api.NewCredentialHandler(credentialDAO, keyProvider)
				if err != nil {
					d.logger.Warn(ctx, "failed to initialize credential handler", "error", err)
				} else {
					d.credentialHandler = credentialHandler
					d.logger.Info(ctx, "initialized credential handler for dashboard API")

					// Initialize LLM config handler for dashboard API
					llmConfigHandler, err := api.NewLLMConfigHandler(d.stateClient, credentialHandler)
					if err != nil {
						d.logger.Warn(ctx, "failed to initialize LLM config handler", "error", err)
					} else {
						d.llmConfigHandler = llmConfigHandler
						d.logger.Info(ctx, "initialized LLM config handler for dashboard API")
					}
				}
			}
		}
	} else {
		d.logger.Info(ctx, "credential store disabled - no key provider configured (set security.key_provider in config)")
	}

	// Configure callback service with event bus for tool/LLM event publishing
	if d.eventBus != nil {
		d.callback.SetEventBus(NewEventBusAdapter(d.eventBus))
		d.logger.Info(ctx, "configured callback service with event bus")
	}

	// Configure callback service with GraphLoader for persisting DiscoveryResult to Neo4j
	if d.infrastructure.graphRAGClient != nil {
		graphLoader := loader.NewGraphLoader(d.infrastructure.graphRAGClient)
		d.callback.SetGraphLoader(graphLoader)
		d.logger.Info(ctx, "configured callback service with GraphLoader for domain node persistence")

		// Create DiscoveryProcessor for automatic discovery storage
		// Note: Discovery processor is already initialized in infrastructure and set via adapter
		// See infrastructure.go where discoveryProcessorAdapter is created
		d.logger.Info(ctx, "DiscoveryProcessor configured via infrastructure")
	}

	// Configure callback service with QueueManager for Redis-based tool execution
	if d.infrastructure.redisClient != nil {
		queueMgr := harness.NewQueueManagerWithClient(d.infrastructure.redisClient, d.logger.Slog())
		d.callback.SetQueueManager(queueMgr)
		d.logger.Info(ctx, "configured callback service with QueueManager for Redis-based tool execution")
	}

	// Configure callback service with authz store for component authorization callbacks.
	// The adapter bridges mission.MissionAuthzStore → harness.RunAuthzLookup to break
	// the import cycle (harness→mission→eval→harness).
	if d.missionAuthzStore != nil {
		d.callback.SetAuthzStore(newMissionAuthzStoreAdapter(d.missionAuthzStore))
		d.logger.Info(ctx, "configured callback service with mission authz store")
	}

	// Wire the FGA Authorizer into the callback service for component-level authz.
	// d.authorizer is always non-nil after initAuthorizer(): either real FGA or noop.
	if d.authorizer != nil {
		d.callback.SetComponentAuthorizer(d.authorizer)
		d.logger.Info(ctx, "configured callback service with FGA component authorizer")
	}

	// Wire the OTel metrics recorder into the Authorize handler so that each
	// component authz decision increments gibson_component_authz_total.
	if rec := d.GetOTelMetricsRecorder(); rec != nil {
		d.callback.SetComponentAuthzMetrics(rec)
		d.logger.Info(ctx, "configured callback service with component authz metrics recorder")
	}

	// Perform crash recovery: find any missions that were running when daemon stopped
	// and transition them to paused status before accepting new connections
	d.logger.Info(ctx, "checking for missions to recover after daemon restart")
	if err := d.recoverRunningMissions(ctx); err != nil {
		d.logger.Warn(ctx, "failed to recover running missions", "error", err)
		// Don't fail startup on recovery error - continue with normal operation
	}

	// Initialize mission checkpointer for graceful shutdown
	if d.stateClient != nil && d.stateClient.Client() != nil {
		d.checkpointer = NewDaemonMissionCheckpointer(
			d.stateClient.Client(),
			func() map[string]context.CancelFunc {
				d.missionsMu.RLock()
				defer d.missionsMu.RUnlock()
				// Return a copy to avoid holding the lock
				missions := make(map[string]context.CancelFunc)
				for k, v := range d.activeMissions {
					missions[k] = v
				}
				return missions
			},
			d.missionStore,
			d.logger,
		)
		d.logger.Info(ctx, "mission checkpointer initialized")

		// Discover checkpoints from previous shutdown
		d.discoverCheckpoints(ctx)
	} else {
		d.logger.Warn(ctx, "mission checkpointer not initialized - state client not available")
	}

	// Initialize attack runner with required dependencies
	d.logger.Info(ctx, "initializing attack runner")

	// Create mission orchestrator if GraphRAG is available
	var orch mission.MissionOrchestrator
	if d.infrastructure.graphRAGClient != nil {
		// Create GraphLoader for storing mission definitions in Neo4j
		missionGraphLoader := orchestrator.NewGraphLoader(d.infrastructure.graphRAGClient, d.logger.Slog())

		// Get tracer from OTel stack or use noop
		var tracer trace.Tracer
		if d.infrastructure.otelStack != nil && d.infrastructure.otelStack.TracerProvider != nil {
			tracer = d.infrastructure.otelStack.TracerProvider.Tracer("gibson-orchestrator")
		} else {
			tracer = trace.NewNoopTracerProvider().Tracer("orchestrator")
		}

		// Create DiscoveryProcessor for processing agent output discoveries
		graphLoader := loader.NewGraphLoader(d.infrastructure.graphRAGClient)
		discoveryProc := processor.NewDiscoveryProcessor(graphLoader, d.infrastructure.graphRAGClient, d.logger.Slog())
		discoveryProcessorAdapter := &discoveryProcessorAdapter{processor: discoveryProc}

		cfg := orchestrator.Config{
			GraphRAGClient:     d.infrastructure.graphRAGClient,
			HarnessFactory:     d.infrastructure.harnessFactory,
			Logger:             d.logger.WithComponent("orchestrator"),
			Tracer:             tracer,
			EventBus:           NewOrchestratorEventBusAdapterWithRedis(d.eventBus, d.redisEventStream, d.registryTenant),
			MaxIterations:      100,
			MaxConcurrent:      10,
			ThinkerMaxRetries:  3,
			ThinkerTemperature: 0.2,
			GraphLoader:        missionGraphLoader,
			Registry:           d.registryAdapter,         // For component discovery and validation
			DecisionLogWriter:  nil,                       // OTel adapter created per-mission in mission_manager.go
			DiscoveryProcessor: discoveryProcessorAdapter, // Process agent output discoveries to Neo4j
		}

		var err error
		orch, err = orchestrator.NewMissionAdapter(cfg)
		if err != nil {
			d.logger.Error(ctx, "failed to create orchestrator", "error", err)
			return fmt.Errorf("failed to create orchestrator: %w", err)
		}
		d.logger.Info(ctx, "Using orchestrator for attack runner")
	} else {
		d.logger.Error(ctx, "GraphRAG not available, cannot create attack runner")
		return fmt.Errorf("GraphRAG (Neo4j) is required for attack runner but not configured")
	}

	// Create payload registry with Redis store (required)
	redisStore := payload.NewRedisPayloadStore(d.stateClient)
	payloadRegistry := payload.NewPayloadRegistryWithStore(redisStore, payload.DefaultRegistryConfig())
	d.logger.Info(ctx, "using Redis payload store")

	d.attackRunner = attack.NewAttackRunner(
		orch,
		d.registryAdapter,
		payloadRegistry,
		d.missionStore,
		d.infrastructure.findingStore,
		attack.WithLogger(d.logger.Slog()),
	)
	d.logger.Info(ctx, "initialized attack runner")

	// Start callback server
	if d.config.Callback.Enabled {
		d.logger.Info(ctx, "starting callback server")
		if err := d.callback.Start(ctx); err != nil {
			d.stopServices(ctx)
			return fmt.Errorf("failed to start callback server: %w", err)
		}
	}

	// Start gRPC server
	d.logger.Info(ctx, "starting gRPC server", "address", d.grpcAddr)
	if err := d.startGRPCServer(ctx); err != nil {
		// Stop services on gRPC start failure
		d.stopServices(ctx)
		return fmt.Errorf("failed to start gRPC server: %w", err)
	}

	// Start health server
	// Health port defaults to 8080, can be overridden via config or GIBSON_HEALTH_PORT env var
	healthPort := d.config.Health.Port
	if healthPort == 0 {
		healthPort = 8080
	}
	// Override with environment variable if set
	if envPort := os.Getenv("GIBSON_HEALTH_PORT"); envPort != "" {
		if port, err := fmt.Sscanf(envPort, "%d", &healthPort); err == nil && port == 1 {
			// Successfully parsed environment variable
		}
	}

	d.logger.Info(ctx, "starting health server", "port", healthPort)
	d.healthServer = healthhttp.NewServer(&healthhttp.Config{
		Port:         healthPort,
		CheckTimeout: 10 * time.Second, // Allow more time for DNS resolution in K8s
	})

	// Register readiness checks for all dependencies
	// Redis check - use function wrapper to avoid interface type mismatch
	if d.stateClient != nil && d.stateClient.Client() != nil {
		redisClient := d.stateClient.Client()
		d.healthServer.RegisterReadinessCheck("redis", healthhttp.RedisPingFunc(func(ctx context.Context) (string, error) {
			return redisClient.Ping(ctx).Result()
		}))
		d.logger.Debug(ctx, "registered redis readiness check")
	}

	// Neo4j check - use the Health method on the graphRAG client
	if d.infrastructure != nil && d.infrastructure.graphRAGClient != nil {
		graphRAGClient := d.infrastructure.graphRAGClient
		d.healthServer.RegisterReadinessCheck("neo4j", func(ctx context.Context) sdktypes.HealthStatus {
			status := graphRAGClient.Health(ctx)
			// Convert internal types.HealthStatus to SDK types.HealthStatus
			if status.IsHealthy() {
				return sdktypes.NewHealthyStatus(status.Message)
			} else if status.IsDegraded() {
				return sdktypes.NewDegradedStatus(status.Message, nil)
			}
			return sdktypes.NewUnhealthyStatus(status.Message, nil)
		})
		d.logger.Debug(ctx, "registered neo4j readiness check")
	}

	// Register shutdown state check - this signals Kubernetes to stop routing traffic during shutdown
	d.healthServer.RegisterReadinessCheck("shutdown", d.healthState.CheckFunc())
	d.logger.Debug(ctx, "registered shutdown state readiness check")

	// Register key provider health check if available
	if d.keyProvider != nil {
		keyProvider := d.keyProvider
		d.healthServer.RegisterReadinessCheck("key_provider", func(ctx context.Context) sdktypes.HealthStatus {
			status := keyProvider.Health(ctx)
			// Convert internal types.HealthStatus to SDK types.HealthStatus
			if status.IsHealthy() {
				return sdktypes.NewHealthyStatus(status.Message)
			} else if status.IsDegraded() {
				return sdktypes.NewDegradedStatus(status.Message, nil)
			}
			return sdktypes.NewUnhealthyStatus(status.Message, nil)
		})
		d.logger.Debug(ctx, "registered key provider readiness check")
	}

	// Register FGA readiness check when authorization is enabled.
	// Uses a 10s TTL cached result to avoid hammering FGA on every scrape.
	// Returns Degraded (not Unhealthy) so Kubernetes removes the pod from
	// service endpoints without triggering a restart.
	if d.config.Authz.Enabled && d.authorizer != nil {
		a := d.authorizer
		var (
			cacheMu      sync.Mutex
			cachedAt     time.Time
			cachedResult sdktypes.HealthStatus
		)
		const fgaCacheTTL = 10 * time.Second

		d.healthServer.RegisterReadinessCheck("authz_fga", func(ctx context.Context) sdktypes.HealthStatus {
			cacheMu.Lock()
			if time.Since(cachedAt) < fgaCacheTTL && !cachedAt.IsZero() {
				result := cachedResult
				cacheMu.Unlock()
				return result
			}
			cacheMu.Unlock()

			// Probe FGA: both allowed=true and allowed=false are valid — we only
			// care that the RPC succeeds, meaning FGA is reachable.
			_, probeErr := a.Check(ctx, "user:_system", "platform_operator", "system_tenant:_system")
			var result sdktypes.HealthStatus
			if authz.IsUnavailable(probeErr) || authz.IsTimeout(probeErr) {
				result = sdktypes.NewDegradedStatus("authz: FGA unreachable: "+probeErr.Error(), nil)
			} else {
				result = sdktypes.NewHealthyStatus("authz: FGA reachable")
			}

			cacheMu.Lock()
			cachedAt = time.Now()
			cachedResult = result
			cacheMu.Unlock()

			return result
		})
		d.logger.Debug(ctx, "registered authz FGA readiness check")
	}

	// Start the health server (non-blocking)
	if err := d.healthServer.Start(); err != nil {
		// Log error but don't fail daemon startup - health endpoints are not critical
		d.logger.Warn(ctx, "failed to start health server", "error", err)
	} else {
		d.logger.Info(ctx, "health server started successfully")
	}

	// Prepare daemon info for registration
	pid := os.Getpid()
	info := &DaemonInfo{
		PID:         pid,
		StartTime:   d.startTime,
		GRPCAddress: d.grpcAddr,
		Version:     version.Version,
	}

	// Register daemon info in Redis for daemon discovery
	if d.stateClient == nil || d.stateClient.Client() == nil {
		d.stopServices(ctx)
		return fmt.Errorf("Redis state client not available - Redis required for daemon coordination")
	}

	d.redisDaemonInfo = NewRedisDaemonInfo(d.stateClient.Client(), d.logger)
	if err := d.redisDaemonInfo.Register(ctx, info); err != nil {
		d.stopServices(ctx)
		return fmt.Errorf("failed to register daemon info in Redis: %w", err)
	}

	d.logger.Info(ctx, "daemon started successfully",
		"pid", pid,
		"instance_id", d.redisDaemonInfo.InstanceID(),
		"callback_endpoint", d.callback.CallbackEndpoint(),
	)

	// Async network policy validation (warning only, never blocks startup)
	podNamespace := os.Getenv("POD_NAMESPACE")
	if podNamespace == "" {
		podNamespace = "default"
	}
	validateNetworkPolicies(d.logger, podNamespace, d.config.Auth.Mode == "saas")

	// Setup signal handler for graceful shutdown
	d.logger.Info(ctx, "setting up signal handler for graceful shutdown")
	d.signalHandler = NewSignalHandler(SignalHandlerConfig{
		ShutdownCallback: func() {
			d.logger.Info(context.Background(), "signal handler triggered shutdown")
			// Cancel the internal context to trigger shutdown
			internalCancel()
		},
		ForceExitCode: 1,
	}, d.logger)
	d.signalHandler.Start(internalCtx)

	// Block until context cancellation or shutdown signal
	d.logger.Info(ctx, "daemon running (press Ctrl+C to stop)")
	<-internalCtx.Done()
	d.logger.Info(ctx, "shutdown signal received, stopping daemon")

	// Stop signal handler to prevent further signals during shutdown
	if d.signalHandler != nil {
		d.signalHandler.Stop()
	}

	return d.Stop(context.Background())
}

// Stop gracefully shuts down the daemon and all managed services.
//
// This method performs the following operations:
// 1. Stop callback server (no new agent callbacks)
// 2. Stop registry manager (Redis cleanup)
// 3. Remove PID and daemon.json files
//
// The method is idempotent and safe to call multiple times.
//
// Parameters:
//   - ctx: Context with timeout for shutdown operations
//
// Returns:
//   - error: Non-nil if shutdown encounters errors
func (d *daemonImpl) Stop(ctx context.Context) error {
	d.logger.Info(ctx, "stopping Gibson daemon")

	// Create shutdown context with timeout if the passed context doesn't have one
	shutdownCtx := ctx
	if ctx.Err() == nil {
		// Use a reasonable timeout for graceful shutdown (10 seconds)
		var cancel context.CancelFunc
		shutdownCtx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}

	// Stop services
	d.stopServices(shutdownCtx)

	// Deregister from Redis
	if d.redisDaemonInfo != nil {
		d.logger.Info(ctx, "deregistering daemon from Redis")
		if err := d.redisDaemonInfo.Deregister(shutdownCtx); err != nil {
			d.logger.Warn(ctx, "failed to deregister from Redis", "error", err)
		}
	}

	d.logger.Info(ctx, "daemon stopped successfully")
	return nil
}

// stopServices stops all daemon services using the ShutdownCoordinator.
//
// This is a helper method used by Stop() and error cleanup paths.
// It executes shutdown phases in order through the coordinator to ensure clean shutdown.
func (d *daemonImpl) stopServices(ctx context.Context) {
	// Stop signal handler first (no new signals during shutdown)
	if d.signalHandler != nil {
		d.logger.Debug(ctx, "stopping signal handler")
		d.signalHandler.Stop()
		d.signalHandler = nil
	}

	// Stop all running missions before coordinator
	d.missionsMu.Lock()
	if len(d.activeMissions) > 0 {
		d.logger.Info(ctx, "stopping active missions", "count", len(d.activeMissions))
		for missionID, cancel := range d.activeMissions {
			d.logger.Info(ctx, "cancelling mission", "mission_id", missionID)
			cancel()
		}
		// Clear the map
		d.activeMissions = make(map[string]context.CancelFunc)
	}
	d.missionsMu.Unlock()

	// Close log tailer before coordinator
	if d.logTailer != nil {
		d.logger.Info(ctx, "closing log tailer")
		if err := d.logTailer.Close(); err != nil {
			d.logger.Warn(ctx, "error closing log tailer", "error", err)
		}
		d.logTailer = nil
	}

	// Create and execute shutdown coordinator with all phases
	coordinator := NewShutdownCoordinator(d.config.Shutdown, d.logger)

	// Register shutdown phases in execution order

	// Phase 1: Set health endpoint to unhealthy
	if d.healthState != nil {
		coordinator.RegisterPhase(NewHealthPhase(d.healthState, d.logger))
	}

	// Phase 2: Drain in-flight requests
	if d.grpcServer != nil {
		if srv, ok := d.grpcServer.(interface{ GracefulStop() }); ok {
			coordinator.RegisterPhase(NewDrainPhase(srv, d.config.Shutdown.DrainTimeout, d.logger))
		}
	}

	// Phase 3: Checkpoint running missions (already stopped above, but maintain phase)
	if d.checkpointer != nil {
		coordinator.RegisterPhase(NewCheckpointPhase(d.checkpointer, d.config.Shutdown.CheckpointTimeout, d.logger, coordinator.metrics))
	}

	// Phase 4: Notify and disconnect agents
	if d.callback != nil {
		agentNotifier := NewDaemonAgentNotifier(d.callback, d.config.Shutdown.AgentTimeout, d.logger)
		coordinator.RegisterPhase(NewAgentPhase(agentNotifier, d.config.Shutdown.AgentTimeout, d.logger, coordinator.metrics))
	}

	// Phase 5: Close all connections
	coordinator.RegisterPhase(NewConnectionPhase(
		d.infrastructure,
		d.stateClient,
		d.callback,
		d.eventBus,
		nil, // registry stopper: was etcd; now nil (Redis cleanup handled by redisDaemonInfo.Deregister)
		d.credentialStore,
		d.logger,
	))

	// Execute shutdown phases
	if err := coordinator.Shutdown(ctx); err != nil {
		d.logger.Warn(ctx, "shutdown coordinator encountered errors", "error", err)
	}

	// Stop health server separately (already drained)
	if d.healthServer != nil {
		d.logger.Info(ctx, "stopping health server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := d.healthServer.Stop(shutdownCtx); err != nil {
			d.logger.Warn(ctx, "error stopping health server", "error", err)
		}
		d.healthServer = nil
	}

	// Clear gRPC server reference (already stopped by DrainPhase)
	d.grpcServer = nil
}

// status returns the current daemon status and health information.
//
// This is the internal status method that returns the daemon.DaemonStatus type.
// For the gRPC API implementation, see Status() in grpc.go.
//
// Returns:
//   - *DaemonStatus: Complete daemon status information
//   - error: Non-nil if status check fails
func (d *daemonImpl) status() (*DaemonStatus, error) {
	// Check if daemon is running by checking Redis registration
	running := d.redisDaemonInfo != nil
	pid := os.Getpid()

	// Calculate uptime
	var uptime string
	if running && !d.startTime.IsZero() {
		duration := time.Since(d.startTime)
		uptime = formatDuration(duration)
	}

	// Query mission counts from database
	totalMissions, activeMissions := d.queryMissionCounts(context.Background())

	// Determine Redis endpoint for status reporting
	redisAddr := d.config.Redis.URL

	// Build status struct
	status := &DaemonStatus{
		Running:      running,
		PID:          pid,
		StartTime:    d.startTime,
		Uptime:       uptime,
		GRPCAddress:  d.grpcAddr,
		RegistryType: "redis",
		RegistryAddr: redisAddr,
		CallbackAddr: d.callback.CallbackEndpoint(),
		AgentCount:   d.countRegisteredAgents(context.Background()),
		MissionCount: totalMissions,
		ActiveCount:  activeMissions,
	}

	return status, nil
}

// countRegisteredAgents returns the number of agent-kind components currently
// registered in the component registry. Returns 0 on error or if the registry
// is unavailable.
func (d *daemonImpl) countRegisteredAgents(ctx context.Context) int {
	if d.compRegistry == nil {
		return 0
	}
	agents, err := d.compRegistry.DiscoverAll(ctx, d.registryTenant, "agent")
	if err != nil {
		d.logger.Warn(ctx, "failed to count registered agents", "error", err)
		return 0
	}
	return len(agents)
}

// recoverRunningMissions handles crash recovery by transitioning any missions that were
// in running status when the daemon stopped to paused status. This ensures missions can
// be resumed after an unexpected shutdown.
//
// This function is called during daemon startup, after infrastructure initialization but
// before accepting new connections. It queries for all missions with running status and
// updates them to paused, logging a warning for each recovered mission.
func (d *daemonImpl) recoverRunningMissions(ctx context.Context) error {
	// Query for all missions that are currently in running status
	activeMissions, err := d.missionStore.GetActive(ctx)
	if err != nil {
		return fmt.Errorf("failed to query active missions: %w", err)
	}

	if len(activeMissions) == 0 {
		d.logger.Info(ctx, "no running missions to recover")
		return nil
	}

	// Transition each running mission to paused status
	recoveredCount := 0
	for _, m := range activeMissions {
		// Only recover missions that are actually running (not already paused)
		if m.Status == mission.MissionStatusRunning {
			d.logger.Warn(ctx, "recovered mission - set to paused after daemon restart",
				"mission_id", m.ID.String(),
				"mission_name", m.Name,
				"status", m.Status,
			)

			// Update mission status to paused
			if err := d.missionStore.UpdateStatus(ctx, m.ID, mission.MissionStatusPaused); err != nil {
				d.logger.Error(ctx, "failed to pause recovered mission",
					"mission_id", m.ID.String(),
					"error", err,
				)
				continue
			}

			recoveredCount++
		}
	}

	if recoveredCount > 0 {
		d.logger.Info(ctx, "completed crash recovery",
			"recovered_missions", recoveredCount,
			"total_active", len(activeMissions),
		)
	}

	return nil
}

// formatDuration formats a duration into a human-readable string.
//
// Examples:
//   - 1h 30m 45s
//   - 2m 15s
//   - 45s
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// discoverCheckpoints scans Redis for mission checkpoints from a previous shutdown.
// It logs discovered checkpoints but does not automatically resume them.
// This allows operators to inspect and manually resume missions as needed.
func (d *daemonImpl) discoverCheckpoints(ctx context.Context) {
	if d.checkpointer == nil {
		d.logger.Debug(ctx, "checkpointer not available, skipping checkpoint discovery")
		return
	}

	checkpoints, err := d.checkpointer.ListCheckpoints(ctx)
	if err != nil {
		d.logger.Warn(ctx, "failed to discover checkpoints", "error", err)
		return
	}

	if len(checkpoints) == 0 {
		d.logger.Info(ctx, "no suspended missions found")
		return
	}

	d.logger.Info(ctx, "discovered suspended missions from previous shutdown",
		"count", len(checkpoints))

	// Log each checkpoint for operator visibility
	for _, missionID := range checkpoints {
		checkpoint, err := d.checkpointer.GetCheckpoint(ctx, missionID)
		if err != nil {
			d.logger.Warn(ctx, "failed to load checkpoint details",
				"mission_id", missionID,
				"error", err)
			continue
		}

		d.logger.Info(ctx, "suspended mission available for resumption",
			"mission_id", missionID,
			"checkpoint_id", checkpoint.ID,
			"created_at", checkpoint.CreatedAt,
			"label", checkpoint.Label)
	}
}

// GetSuspendedMissions returns a list of mission IDs that have checkpoints from a previous shutdown.
// These missions can be resumed using the appropriate API or CLI commands.
//
// Returns:
//   - []types.ID: List of mission IDs with available checkpoints
//   - error: Non-nil if checkpoint discovery fails
func (d *daemonImpl) GetSuspendedMissions(ctx context.Context) ([]types.ID, error) {
	if d.checkpointer == nil {
		return nil, fmt.Errorf("checkpointer not available")
	}

	return d.checkpointer.ListCheckpoints(ctx)
}

// RequestShutdown initiates graceful shutdown of the daemon.
// This is called by the gRPC Shutdown endpoint to allow remote shutdown requests.
//
// Parameters:
//   - ctx: Context with timeout for shutdown operations
//   - force: If true, skip graceful drain and shutdown immediately
//   - timeoutSeconds: Maximum time to wait for graceful shutdown
//
// Returns:
//   - error: Non-nil if shutdown fails
func (d *daemonImpl) RequestShutdown(ctx context.Context, force bool, timeoutSeconds int32) error {
	d.logger.Info(ctx, "shutdown requested",
		"force", force,
		"timeout_seconds", timeoutSeconds,
	)

	// Send SIGTERM to ourselves to trigger graceful shutdown
	// This uses the same signal handling path as Ctrl+C
	process, err := os.FindProcess(os.Getpid())
	if err != nil {
		return fmt.Errorf("failed to find own process: %w", err)
	}

	// Send SIGTERM to trigger graceful shutdown
	if err := process.Signal(os.Interrupt); err != nil {
		return fmt.Errorf("failed to send interrupt signal: %w", err)
	}

	return nil
}

// CredentialHandler returns the credential handler for dashboard API operations.
// Returns nil if the credential handler was not initialized (missing key provider).
func (d *daemonImpl) CredentialHandler() *api.CredentialHandler {
	return d.credentialHandler
}

// LLMConfigHandler returns the LLM config handler for dashboard API operations.
// Returns nil if the LLM config handler was not initialized.
func (d *daemonImpl) LLMConfigHandler() *api.LLMConfigHandler {
	return d.llmConfigHandler
}

// runOrgReconciliation builds an OrgReconciler and calls ReconcileKeycloakOrgs.
//
// This is called once during daemon startup, after the Authorization Service
// phase and before Component Registry. It is a best-effort operation: if the
// Keycloak admin client cannot be constructed (missing credentials), or if the
// scan succeeds but individual tenants fail, the daemon continues to start.
// Only a scan-level failure (Redis unreachable) causes a logged error; even
// then startup is NOT aborted because the reconciler's return is silently
// discarded here — callers log the error for operators to action.
//
// Timing is logged at INFO so operators can monitor reconcile duration over
// time.
func (d *daemonImpl) runOrgReconciliation(ctx context.Context, redisClient *goredis.Client) {
	start := time.Now()

	kcAdmin, err := provisioner.NewKeycloakAdminClient(d.config.Keycloak.Admin, d.logger.Slog())
	if err != nil {
		d.logger.Warn(ctx, "org reconciliation skipped: failed to build Keycloak admin client",
			"error", err)
		return
	}

	scanner := provisioner.NewRedisMembershipScanner(redisClient)
	reconciler := provisioner.NewOrgReconciler(
		d.config.Provisioner,
		scanner,
		kcAdmin,
		d.authorizer,
		d.logger.Slog(),
	)

	if err := reconciler.ReconcileKeycloakOrgs(ctx); err != nil {
		d.logger.Error(ctx, "org reconciliation failed",
			"error", err,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return
	}

	d.logger.Info(ctx, "org reconciliation phase complete",
		"duration_ms", time.Since(start).Milliseconds(),
	)
}
