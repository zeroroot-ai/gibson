package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/attack"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/component/build"
	"github.com/zero-day-ai/gibson/internal/component/git"
	"github.com/zero-day-ai/gibson/internal/component/resolver"
	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/crypto/providers"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/graphrag/loader"
	"github.com/zero-day-ai/gibson/internal/graphrag/processor"
	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/observability"
	"github.com/zero-day-ai/gibson/internal/orchestrator"
	"github.com/zero-day-ai/gibson/internal/payload"
	"github.com/zero-day-ai/gibson/internal/registry"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/gibson/internal/version"
	healthhttp "github.com/zero-day-ai/sdk/health/http"
	"github.com/zero-day-ai/sdk/queue"
	sdktypes "github.com/zero-day-ai/sdk/types"
	"go.opentelemetry.io/otel/trace"
)

// Type aliases to avoid exposing resolver types directly through the daemon API
type (
	dependencyTree     = resolver.DependencyTree
	validationResult   = resolver.ValidationResult
	dependencyResolver = resolver.DependencyResolver
)

// targetStore is an interface for target data access
type targetStore interface {
	Get(ctx context.Context, id types.ID) (*types.Target, error)
	GetByName(ctx context.Context, name string) (*types.Target, error)
	Create(ctx context.Context, target *types.Target) error
}

// redisToolDiscovery is an interface for Redis-based tool discovery.
// This interface allows for mock implementations in tests.
type redisToolDiscovery interface {
	// Refresh discovers tools from Redis and updates the registry
	Refresh(ctx context.Context) error
	// GetAllMetadata returns metadata for all discovered tools
	GetAllMetadata() []queue.ToolMeta
	// IsHealthy checks if a tool has healthy workers
	IsHealthy(ctx context.Context, name string) bool
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
//   - Registry manager (embedded etcd or external etcd client)
//   - Callback manager (harness callback server for agents)
//   - PID and info files for client discovery
//
// The daemon is not yet a full implementation - it will be extended in future
// phases with:
//   - gRPC API server for client commands (Phase 3, tasks 9-11)
//   - Mission manager for orchestration
//   - Event bus for TUI streaming
type daemonImpl struct {
	// config is the loaded Gibson configuration
	config *config.Config

	// logger is the structured logger for daemon operations
	logger *observability.Logger

	// registry manages service discovery (etcd)
	registry *registry.Manager

	// registryAdapter provides component discovery and listing
	registryAdapter registry.ComponentDiscovery

	// callback manages the harness callback server
	callback *harness.CallbackManager

	// eventBus manages event distribution to subscribers
	eventBus *EventBus

	// stateClient provides unified Redis client for state stores
	// This is initialized when GIBSON_USE_REDIS_STORES=true
	stateClient *state.StateClient

	// componentStore provides access to component metadata in etcd
	componentStore component.ComponentStore

	// componentInstaller handles component installation, updates, and uninstallation
	componentInstaller component.Installer

	// componentBuildExecutor executes component builds
	componentBuildExecutor build.BuildExecutor

	// componentLogWriter manages component log files
	componentLogWriter component.LogWriter

	// componentLifecycleManager manages component start/stop operations
	componentLifecycleManager component.LifecycleManager

	// missionStore provides access to mission persistence
	missionStore mission.MissionStore

	// missionRunStore provides access to mission run persistence
	missionRunStore mission.MissionRunStore

	// checkpointStore provides checkpoint persistence for pause/resume
	checkpointStore mission.CheckpointStore

	// missionInstaller handles mission installation, updates, and uninstallation
	missionInstaller mission.MissionInstaller

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

	// dependencyResolver manages mission dependency resolution and validation
	dependencyResolver dependencyResolver

	// etcdDaemonInfo provides etcd-based daemon discovery (required - no fallback)
	etcdDaemonInfo *EtcdDaemonInfo

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

	// redisToolRegistry discovers tools registered in Redis by K8s-deployed tool workers
	// This is used by ListTools() to include Redis-based tools in addition to
	// componentStore (CLI-installed) and etcd-registered tools
	redisToolRegistry redisToolDiscovery

	// startTime tracks when the daemon started
	startTime time.Time

	// onRegistryReady is called after the registry is started but before other services
	// This allows CLI to set up verbose logging after etcd is initialized
	onRegistryReady func()
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

	// Initialize registry manager
	regMgr := registry.NewManager(cfg.Registry)

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
		registry:        regMgr,
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

// SetOnRegistryReady sets a callback that will be called after the registry
// is started but before other services. This is used by the CLI to set up
// verbose logging after etcd is initialized, avoiding conflicts with etcd's
// internal logging during startup.
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
		"registry_type", d.config.Registry.Type,
		"callback_enabled", d.config.Callback.Enabled,
	)

	// Check if embedded etcd is rejected via environment variable
	// This is used in Kubernetes deployments where external etcd is required
	if os.Getenv("GIBSON_REQUIRE_EXTERNAL_ETCD") == "true" {
		if d.config.Registry.Type == "embedded" {
			return fmt.Errorf("embedded etcd not allowed: GIBSON_REQUIRE_EXTERNAL_ETCD=true requires external etcd endpoints")
		}
	}

	// Record start time
	d.startTime = time.Now()

	// Create an internal context that can be cancelled by signal handler
	internalCtx, internalCancel := context.WithCancel(ctx)
	defer internalCancel()

	// Start registry manager
	d.logger.Info(ctx, "starting registry manager")
	if err := d.registry.Start(ctx); err != nil {
		return fmt.Errorf("failed to start registry: %w", err)
	}

	// Call the registry ready callback if set (for future use)
	if d.onRegistryReady != nil {
		d.onRegistryReady()
	}
	// Initialize registry adapter now that registry is started
	regAdapter := registry.NewRegistryAdapter(d.registry.Registry())
	d.registryAdapter = regAdapter
	d.logger.Info(ctx, "initialized registry adapter")

	// Wire callback manager to registry adapter for external agent callback support
	regAdapter.SetCallbackManager(d.callback)
	d.logger.Info(ctx, "wired callback manager to registry adapter")

	// Share proto resolver between registry adapter and callback manager for unified caching
	d.callback.SetProtoResolver(regAdapter.GetResolver())
	d.logger.Info(ctx, "shared proto resolver with callback manager")

	// Initialize StateClient and Redis stores (required for Gibson)
	d.logger.Info(ctx, "initializing Redis stores")

	// Initialize StateClient with retry logic (3 attempts with exponential backoff)
	stateClient, err := d.initStateClient(ctx)
	if err != nil {
		d.stopServices(ctx)
		return fmt.Errorf("failed to initialize StateClient (required): %w", err)
	}
	d.stateClient = stateClient

	// Initialize Redis stores
	d.missionStore = mission.NewRedisMissionStore(stateClient)
	d.missionRunStore = mission.NewRedisMissionRunStore(stateClient)
	d.checkpointStore = mission.NewRedisCheckpointStore(stateClient)
	d.targetStore = database.NewRedisTargetDAO(stateClient)

	d.logger.Info(ctx, "Redis stores initialized successfully",
		"mission_store", "RedisMissionStore",
		"mission_run_store", "RedisMissionRunStore",
		"checkpoint_store", "RedisCheckpointStore",
		"target_store", "RedisTargetDAO",
	)

	// Initialize component store with etcd client from registry
	if etcdClient := d.registry.Client(); etcdClient != nil {
		d.componentStore = component.EtcdComponentStore(etcdClient, "gibson")
		d.logger.Info(ctx, "initialized component store with etcd backend")

		// Initialize component infrastructure for install/uninstall/update operations
		gitOps := git.NewDefaultGitOperations()
		buildExecutor := build.NewDefaultBuildExecutor()
		logsDir := filepath.Join(d.config.Core.HomeDir, "logs")
		logWriter, err := component.NewDefaultLogWriter(logsDir, nil)
		if err != nil {
			d.logger.Warn(ctx, "failed to create log writer, component lifecycle management may be limited", "error", err)
		} else {
			lifecycleManager := component.NewLifecycleManager(d.componentStore, logWriter)
			d.componentLifecycleManager = lifecycleManager
			d.componentInstaller = component.NewDefaultInstaller(gitOps, buildExecutor, d.componentStore, lifecycleManager)
			d.componentBuildExecutor = buildExecutor
			d.componentLogWriter = logWriter
			d.logger.Info(ctx, "initialized component installer")

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

			// Initialize mission installer with same git operations and mission store
			// Create adapters to bridge component package types to mission interfaces
			missionsDir := filepath.Join(d.config.Core.HomeDir, "missions")
			componentStoreAdapter := mission.NewComponentStoreAdapter(d.componentStore)
			componentInstallerAdapter := mission.NewComponentInstallerAdapter(d.componentInstaller)
			d.missionInstaller = mission.NewDefaultMissionInstaller(
				gitOps,
				d.missionStore,
				missionsDir,
				componentStoreAdapter,
				componentInstallerAdapter,
			)
			d.logger.Info(ctx, "initialized mission installer", "missions_dir", missionsDir)
		}
	} else {
		d.logger.Warn(ctx, "etcd client not available, component store not initialized")
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

	// Inject taxonomy registry into component installer so it can unregister extensions on agent uninstall
	if d.componentInstaller != nil && infra.taxonomyRegistry != nil {
		// Cast to *DefaultInstaller since SetTaxonomyRegistry is not on the Installer interface
		if defaultInstaller, ok := d.componentInstaller.(*component.DefaultInstaller); ok {
			adapter := component.NewTaxonomyRegistryAdapter(infra.taxonomyRegistry)
			defaultInstaller.SetTaxonomyRegistry(adapter)
			d.logger.Info(ctx, "taxonomy registry injected into component installer")
		}
	}

	// Initialize dependency resolver for mission dependency validation
	// The resolver needs component store, lifecycle manager, and a manifest loader
	if d.componentStore != nil && d.componentLifecycleManager != nil {
		d.logger.Info(ctx, "initializing dependency resolver")
		manifestLoader := newManifestLoader(d.componentStore)
		d.dependencyResolver = resolver.NewResolver(
			d.componentStore,
			d.componentLifecycleManager,
			manifestLoader,
		)
		d.logger.Info(ctx, "dependency resolver initialized")
	} else {
		d.logger.Warn(ctx, "dependency resolver not initialized - component store or lifecycle manager unavailable")
	}

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
			EventBus:           NewOrchestratorEventBusAdapter(d.eventBus),
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
			// Stop registry on callback start failure
			d.registry.Stop(ctx)
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

	// etcd check - verify registry client exists and registry is running
	// Note: We don't perform active etcd calls in the health check because
	// embedded etcd shares the same connection pool with the main application,
	// and frequent health checks can cause connection contention.
	// Instead, we trust that if the registry started successfully and is marked
	// as healthy by the registry manager, etcd is working.
	if d.registry != nil {
		registryRef := d.registry
		d.healthServer.RegisterReadinessCheck("etcd", func(ctx context.Context) sdktypes.HealthStatus {
			status := registryRef.Status()
			if status.Healthy {
				return sdktypes.NewHealthyStatus("etcd is healthy")
			}
			return sdktypes.NewUnhealthyStatus("etcd registry not healthy", nil)
		})
		d.logger.Debug(ctx, "registered etcd readiness check")
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

	// Start the health server (non-blocking)
	if err := d.healthServer.Start(); err != nil {
		// Log error but don't fail daemon startup - health endpoints are not critical
		d.logger.Warn(ctx, "failed to start health server", "error", err)
	} else {
		d.logger.Info(ctx, "health server started successfully")
	}

	// Prepare daemon info for registration
	pid := os.Getpid()
	regStatus := d.registry.Status()
	info := &DaemonInfo{
		PID:         pid,
		StartTime:   d.startTime,
		GRPCAddress: d.grpcAddr,
		Version:     version.Version,
	}

	// Register daemon info in etcd (required - no filesystem fallback)
	etcdClient := d.registry.Client()
	if etcdClient == nil {
		d.stopServices(ctx)
		return fmt.Errorf("etcd client not available - external etcd required for daemon coordination")
	}

	d.etcdDaemonInfo = NewEtcdDaemonInfo(etcdClient, d.logger)
	if err := d.etcdDaemonInfo.Register(ctx, info); err != nil {
		d.stopServices(ctx)
		return fmt.Errorf("failed to register daemon info in etcd: %w", err)
	}

	d.logger.Info(ctx, "daemon started successfully",
		"pid", pid,
		"instance_id", d.etcdDaemonInfo.InstanceID(),
		"registry_endpoint", regStatus.Endpoint,
		"callback_endpoint", d.callback.CallbackEndpoint(),
	)

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
// 2. Stop registry manager (etcd shutdown)
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

	// Deregister from etcd
	if d.etcdDaemonInfo != nil {
		d.logger.Info(ctx, "deregistering daemon from etcd")
		if err := d.etcdDaemonInfo.Deregister(shutdownCtx); err != nil {
			d.logger.Warn(ctx, "failed to deregister from etcd", "error", err)
		}
	} else {
		d.logger.Warn(ctx, "etcd daemon info not initialized, cannot deregister")
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
		d.registry,
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
	// Check if daemon is running by checking etcd registration
	running := d.etcdDaemonInfo != nil
	pid := os.Getpid()

	// Calculate uptime
	var uptime string
	if running && !d.startTime.IsZero() {
		duration := time.Since(d.startTime)
		uptime = formatDuration(duration)
	}

	// Get registry status
	regStatus := d.registry.Status()

	// Query mission counts from database
	totalMissions, activeMissions := d.queryMissionCounts(context.Background())

	// Build status struct
	status := &DaemonStatus{
		Running:      running,
		PID:          pid,
		StartTime:    d.startTime,
		Uptime:       uptime,
		GRPCAddress:  d.grpcAddr,
		RegistryType: regStatus.Type,
		RegistryAddr: regStatus.Endpoint,
		CallbackAddr: d.callback.CallbackEndpoint(),
		AgentCount:   regStatus.Services, // TODO: Break down by kind in future
		MissionCount: totalMissions,
		ActiveCount:  activeMissions,
	}

	return status, nil
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
