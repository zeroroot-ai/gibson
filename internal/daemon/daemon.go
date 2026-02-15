package daemon

import (
	"context"
	"fmt"
	"log/slog"
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
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/graphrag/loader"
	"github.com/zero-day-ai/gibson/internal/graphrag/processor"
	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/observability"
	"github.com/zero-day-ai/gibson/internal/orchestrator"
	"github.com/zero-day-ai/gibson/internal/payload"
	"github.com/zero-day-ai/gibson/internal/registry"
	"github.com/zero-day-ai/gibson/internal/types"
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
	logger *slog.Logger

	// registry manages service discovery (etcd)
	registry *registry.Manager

	// registryAdapter provides component discovery and listing
	registryAdapter registry.ComponentDiscovery

	// callback manages the harness callback server
	callback *harness.CallbackManager

	// eventBus manages event distribution to subscribers
	eventBus *EventBus

	// db is the database connection
	db *database.DB

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

	// missionInstaller handles mission installation, updates, and uninstallation
	missionInstaller mission.MissionInstaller

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

	// grpcServer is the gRPC server for client connections (added in Phase 3)
	grpcServer interface{}

	// grpcAddr is the address the gRPC server listens on (added in Phase 3)
	grpcAddr string

	// attackRunner executes ad-hoc attacks
	attackRunner attack.AttackRunner

	// dependencyResolver manages mission dependency resolution and validation
	dependencyResolver dependencyResolver

	// pidFile is the path to the PID file (~/.gibson/daemon.pid)
	pidFile string

	// infoFile is the path to the daemon info file (~/.gibson/daemon.json)
	infoFile string

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

	// Setup logger
	logger := slog.Default().With("component", "daemon")

	// Initialize registry manager
	regMgr := registry.NewManager(cfg.Registry)

	// Initialize callback manager
	callbackMgr := harness.NewCallbackManager(harness.CallbackConfig{
		ListenAddress:    cfg.Callback.ListenAddress,
		AdvertiseAddress: cfg.Callback.AdvertiseAddress,
		Enabled:          cfg.Callback.Enabled,
	}, logger)

	// Open database connection
	db, err := database.Open(cfg.Database.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Initialize mission store
	missionStore := mission.NewDBMissionStore(db)

	// Initialize mission run store
	missionRunStore := mission.NewDBMissionRunStore(db)

	// Initialize target store
	targetStore := database.NewTargetDAO(db)

	// Initialize event bus
	eventBus := NewEventBus(logger, WithEventBufferSize(100))

	// Determine gRPC address from config, environment variable, or default
	grpcAddr := cfg.Daemon.GRPCAddress
	if grpcAddr == "" {
		grpcAddr = "localhost:50002"
	}
	// Environment variable takes precedence
	if envAddr := os.Getenv("GIBSON_DAEMON_GRPC_ADDR"); envAddr != "" {
		grpcAddr = envAddr
	}

	return &daemonImpl{
		config:          cfg,
		logger:          logger,
		registry:        regMgr,
		registryAdapter: nil, // Created in Start() after registry is available
		callback:        callbackMgr,
		eventBus:        eventBus,
		db:              db,
		missionStore:    missionStore,
		missionRunStore: missionRunStore,
		targetStore:     targetStore,
		activeMissions:  make(map[string]context.CancelFunc),
		grpcServer:      nil,      // Created in Start()
		grpcAddr:        grpcAddr, // Configurable via config file or environment variable
		attackRunner:    nil,      // Created in Start() after registry is available
		pidFile:         filepath.Join(homeDir, "daemon.pid"),
		infoFile:        filepath.Join(homeDir, "daemon.json"),
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
	d.logger.Info("starting Gibson daemon",
		"registry_type", d.config.Registry.Type,
		"callback_enabled", d.config.Callback.Enabled,
	)

	// Check if daemon is already running
	running, pid, err := CheckPIDFile(d.pidFile)
	if err != nil {
		return fmt.Errorf("failed to check for existing daemon: %w", err)
	}
	if running {
		return fmt.Errorf("daemon already running (PID %d)", pid)
	}

	// Clean up stale PID file if present
	if pid > 0 && !running {
		d.logger.Warn("removing stale PID file", "stale_pid", pid)
		if err := RemovePIDFile(d.pidFile); err != nil {
			return fmt.Errorf("failed to remove stale PID file: %w", err)
		}
	}

	// Record start time
	d.startTime = time.Now()

	// Start registry manager
	d.logger.Info("starting registry manager")
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
	d.logger.Info("initialized registry adapter")

	// Wire callback manager to registry adapter for external agent callback support
	regAdapter.SetCallbackManager(d.callback)
	d.logger.Info("wired callback manager to registry adapter")

	// Initialize component store with etcd client from registry
	if etcdClient := d.registry.Client(); etcdClient != nil {
		d.componentStore = component.EtcdComponentStore(etcdClient, "gibson")
		d.logger.Info("initialized component store with etcd backend")

		// Initialize component infrastructure for install/uninstall/update operations
		gitOps := git.NewDefaultGitOperations()
		buildExecutor := build.NewDefaultBuildExecutor()
		logsDir := filepath.Join(d.config.Core.HomeDir, "logs")
		logWriter, err := component.NewDefaultLogWriter(logsDir, nil)
		if err != nil {
			d.logger.Warn("failed to create log writer, component lifecycle management may be limited", "error", err)
		} else {
			lifecycleManager := component.NewLifecycleManager(d.componentStore, logWriter)
			d.componentLifecycleManager = lifecycleManager
			d.componentInstaller = component.NewDefaultInstaller(gitOps, buildExecutor, d.componentStore, lifecycleManager)
			d.componentBuildExecutor = buildExecutor
			d.componentLogWriter = logWriter
			d.logger.Info("initialized component installer")

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
			d.logger.Info("initialized mission installer", "missions_dir", missionsDir)
		}
	} else {
		d.logger.Warn("etcd client not available, component store not initialized")
	}

	// Initialize infrastructure components (DAG executor, finding store, LLM registry, harness factory)
	// This must happen before creating the orchestrator because the orchestrator needs the harness factory
	d.logger.Info("initializing infrastructure components")
	infra, err := d.newInfrastructure(ctx)
	if err != nil {
		d.stopServices(ctx)
		return fmt.Errorf("failed to initialize infrastructure: %w", err)
	}
	d.infrastructure = infra
	d.logger.Info("infrastructure components initialized")

	// Inject taxonomy registry into component installer so it can unregister extensions on agent uninstall
	if d.componentInstaller != nil && infra.taxonomyRegistry != nil {
		// Cast to *DefaultInstaller since SetTaxonomyRegistry is not on the Installer interface
		if defaultInstaller, ok := d.componentInstaller.(*component.DefaultInstaller); ok {
			adapter := component.NewTaxonomyRegistryAdapter(infra.taxonomyRegistry)
			defaultInstaller.SetTaxonomyRegistry(adapter)
			d.logger.Info("taxonomy registry injected into component installer")
		}
	}

	// Initialize dependency resolver for mission dependency validation
	// The resolver needs component store, lifecycle manager, and a manifest loader
	if d.componentStore != nil && d.componentLifecycleManager != nil {
		d.logger.Info("initializing dependency resolver")
		manifestLoader := newManifestLoader(d.componentStore)
		d.dependencyResolver = resolver.NewResolver(
			d.componentStore,
			d.componentLifecycleManager,
			manifestLoader,
		)
		d.logger.Info("dependency resolver initialized")
	} else {
		d.logger.Warn("dependency resolver not initialized - component store or lifecycle manager unavailable")
	}

	// Configure callback service with span processors for distributed tracing
	if len(infra.spanProcessors) > 0 {
		d.callback.AddSpanProcessors(infra.spanProcessors...)
		d.logger.Info("configured callback service with span processors",
			"count", len(infra.spanProcessors))
	}

	// Configure callback service with TracerProvider for proxy span creation
	if infra.tracerProvider != nil {
		d.callback.SetTracerProvider(infra.tracerProvider)
		d.logger.Info("configured callback service with tracer provider")
	}

	// Configure callback service with credential store for secure credential retrieval
	credentialDAO := database.NewCredentialDAO(d.db)
	credentialStore, err := NewDaemonCredentialStore(credentialDAO, d.config.Core.HomeDir)
	if err != nil {
		d.logger.Warn("failed to initialize credential store (credentials will not be available)",
			"error", err)
	} else {
		d.callback.SetCredentialStore(credentialStore)
		d.logger.Info("configured callback service with credential store")
	}

	// Configure callback service with event bus for tool/LLM event publishing
	if d.eventBus != nil {
		d.callback.SetEventBus(NewEventBusAdapter(d.eventBus))
		d.logger.Info("configured callback service with event bus")
	}

	// Configure callback service with GraphLoader for persisting DiscoveryResult to Neo4j
	if d.infrastructure.graphRAGClient != nil {
		graphLoader := loader.NewGraphLoader(d.infrastructure.graphRAGClient)
		d.callback.SetGraphLoader(graphLoader)
		d.logger.Info("configured callback service with GraphLoader for domain node persistence")

		// TODO: Re-enable DiscoveryProcessor once SDK proto_converter.go compilation issues are fixed
		// Create DiscoveryProcessor for automatic discovery storage
		// discoveryProcessor := processor.NewDiscoveryProcessor(graphLoader, d.infrastructure.graphRAGClient, d.logger)
		// d.callback.SetDiscoveryProcessor(discoveryProcessor)
		// d.logger.Info("configured callback service with DiscoveryProcessor for automatic discovery storage")
	}

	// Configure callback service with QueueManager for Redis-based tool execution
	if d.infrastructure.redisClient != nil {
		queueMgr := harness.NewQueueManagerWithClient(d.infrastructure.redisClient, d.logger)
		d.callback.SetQueueManager(queueMgr)
		d.logger.Info("configured callback service with QueueManager for Redis-based tool execution")
	}

	// Perform crash recovery: find any missions that were running when daemon stopped
	// and transition them to paused status before accepting new connections
	d.logger.Info("checking for missions to recover after daemon restart")
	if err := d.recoverRunningMissions(ctx); err != nil {
		d.logger.Warn("failed to recover running missions", "error", err)
		// Don't fail startup on recovery error - continue with normal operation
	}

	// Initialize attack runner with required dependencies
	d.logger.Info("initializing attack runner")

	// Create mission orchestrator if GraphRAG is available
	var orch mission.MissionOrchestrator
	if d.infrastructure.graphRAGClient != nil {
		// Create GraphLoader for storing mission definitions in Neo4j
		missionGraphLoader := orchestrator.NewGraphLoader(d.infrastructure.graphRAGClient, d.logger)

		// Get tracer from tracer provider
		var tracer trace.Tracer
		if d.infrastructure.tracerProvider != nil {
			tracer = d.infrastructure.tracerProvider.Tracer("gibson-orchestrator")
		} else {
			tracer = trace.NewNoopTracerProvider().Tracer("orchestrator")
		}

		// Configure Langfuse observability for attack runner missions.
		//
		// IMPORTANT: DecisionLogWriterAdapter cannot be created here because it requires
		// mission-specific context (schema.Mission) at construction time. The attack runner
		// creates ephemeral missions dynamically when Run() is called, so there's no mission
		// context available at daemon startup.
		//
		// Solution: Pass missionTracer via Config so the orchestrator adapter can create
		// DecisionLogWriterAdapter per-mission in Execute(). This requires modifying
		// MissionAdapter.createOrchestrator() to check for MissionTracer and create the
		// adapter with mission context (future work - see Task 8 notes in spec).
		//
		// For now, DecisionLogWriter remains nil. Attack runner missions will have:
		// - OpenTelemetry tracing (via Tracer) ✓
		// - No Langfuse decision logging ✗ (requires MissionAdapter enhancement)
		//
		// See mission_manager.go:462-484 for the pattern that needs to be replicated
		// in orchestrator/adapter.go:createOrchestrator().
		if d.infrastructure.missionTracer != nil {
			d.logger.Debug("mission tracer available for attack runner",
				"note", "DecisionLogWriter creation deferred to per-mission context (requires MissionAdapter enhancement)")
		}

		// Create DiscoveryProcessor for processing agent output discoveries
		graphLoader := loader.NewGraphLoader(d.infrastructure.graphRAGClient)
		discoveryProc := processor.NewDiscoveryProcessor(graphLoader, d.infrastructure.graphRAGClient, d.logger)
		discoveryProcessorAdapter := &discoveryProcessorAdapter{processor: discoveryProc}

		cfg := orchestrator.Config{
			GraphRAGClient:     d.infrastructure.graphRAGClient,
			HarnessFactory:     d.infrastructure.harnessFactory,
			Logger:             d.logger.With("component", "orchestrator"),
			Tracer:             tracer,
			EventBus:           nil, // EventBus adapter incompatible, will add later
			MaxIterations:      100,
			MaxConcurrent:      10,
			ThinkerMaxRetries:  3,
			ThinkerTemperature: 0.2,
			GraphLoader:        missionGraphLoader,
			Registry:           d.registryAdapter,              // For component discovery and validation
			DecisionLogWriter:  nil,                            // Cannot create without mission context - see comment above
			MissionTracer:      d.infrastructure.missionTracer, // Pass for future per-mission adapter creation
			DiscoveryProcessor: discoveryProcessorAdapter,      // Process agent output discoveries to Neo4j
		}

		var err error
		orch, err = orchestrator.NewMissionAdapter(cfg)
		if err != nil {
			d.logger.Error("failed to create orchestrator", "error", err)
			return fmt.Errorf("failed to create orchestrator: %w", err)
		}
		d.logger.Info("Using orchestrator for attack runner")
	} else {
		d.logger.Error("GraphRAG not available, cannot create attack runner")
		return fmt.Errorf("GraphRAG (Neo4j) is required for attack runner but not configured")
	}

	payloadRegistry := payload.NewPayloadRegistryWithDefaults(d.db)

	d.attackRunner = attack.NewAttackRunner(
		orch,
		d.registryAdapter,
		payloadRegistry,
		d.missionStore,
		d.infrastructure.findingStore,
		attack.WithLogger(d.logger),
	)
	d.logger.Info("initialized attack runner")

	// Start callback server
	if d.config.Callback.Enabled {
		d.logger.Info("starting callback server")
		if err := d.callback.Start(ctx); err != nil {
			// Stop registry on callback start failure
			d.registry.Stop(ctx)
			return fmt.Errorf("failed to start callback server: %w", err)
		}
	}

	// Start gRPC server
	d.logger.Info("starting gRPC server", "address", d.grpcAddr)
	if err := d.startGRPCServer(ctx); err != nil {
		// Stop services on gRPC start failure
		d.stopServices(ctx)
		return fmt.Errorf("failed to start gRPC server: %w", err)
	}

	// Write PID file
	pid = os.Getpid()
	d.logger.Info("writing PID file", "pid", pid, "path", d.pidFile)
	if err := WritePIDFile(d.pidFile, pid); err != nil {
		// Stop services on PID file write failure
		d.stopServices(ctx)
		return fmt.Errorf("failed to write PID file: %w", err)
	}

	// Write daemon info file for client discovery
	regStatus := d.registry.Status()
	info := &DaemonInfo{
		PID:         pid,
		StartTime:   d.startTime,
		GRPCAddress: d.grpcAddr,
		Version:     "0.1.0", // TODO: Get from version package
	}
	d.logger.Info("writing daemon info file", "path", d.infoFile)
	if err := WriteDaemonInfo(d.infoFile, info); err != nil {
		// Stop services and remove PID file on info file write failure
		RemovePIDFile(d.pidFile)
		d.stopServices(ctx)
		return fmt.Errorf("failed to write daemon info file: %w", err)
	}

	d.logger.Info("daemon started successfully",
		"pid", pid,
		"registry_endpoint", regStatus.Endpoint,
		"callback_endpoint", d.callback.CallbackEndpoint(),
	)

	// Block until context cancellation or shutdown signal
	d.logger.Info("daemon running (press Ctrl+C to stop)")
	<-ctx.Done()
	d.logger.Info("shutdown signal received, stopping daemon")
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
	d.logger.Info("stopping Gibson daemon")

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

	// Clean up state files
	d.logger.Info("removing daemon state files")
	if err := RemovePIDFile(d.pidFile); err != nil {
		d.logger.Warn("failed to remove PID file", "error", err)
	}
	if err := RemoveDaemonInfo(d.infoFile); err != nil {
		d.logger.Warn("failed to remove daemon info file", "error", err)
	}

	d.logger.Info("daemon stopped successfully")
	return nil
}

// stopServices stops all daemon services.
//
// This is a helper method used by Stop() and error cleanup paths.
// It stops services in reverse order of startup to ensure clean shutdown.
func (d *daemonImpl) stopServices(ctx context.Context) {
	// Stop all running missions first
	d.missionsMu.Lock()
	if len(d.activeMissions) > 0 {
		d.logger.Info("stopping active missions", "count", len(d.activeMissions))
		for missionID, cancel := range d.activeMissions {
			d.logger.Info("cancelling mission", "mission_id", missionID)
			cancel()
		}
		// Clear the map
		d.activeMissions = make(map[string]context.CancelFunc)
	}
	d.missionsMu.Unlock()

	// Stop gRPC server (no new client connections)
	if d.grpcServer != nil {
		d.logger.Info("stopping gRPC server")
		// Type assert to *grpc.Server and call GracefulStop
		if srv, ok := d.grpcServer.(interface{ GracefulStop() }); ok {
			srv.GracefulStop()
		}
		d.grpcServer = nil
	}

	// Stop callback server (no new callbacks)
	if d.config.Callback.Enabled && d.callback.IsRunning() {
		d.logger.Info("stopping callback server")
		d.callback.Stop()
	}

	// Close event bus (no more event subscriptions)
	if d.eventBus != nil {
		d.logger.Info("closing event bus")
		if err := d.eventBus.Close(); err != nil {
			d.logger.Warn("error closing event bus", "error", err)
		}
	}

	// Shutdown tracing - flushes pending spans to Langfuse
	if d.infrastructure != nil && d.infrastructure.tracerProvider != nil {
		d.logger.Info("shutting down tracing")
		if err := observability.ShutdownTracing(ctx, d.infrastructure.tracerProvider); err != nil {
			d.logger.Warn("failed to shutdown tracing", "error", err)
		} else {
			d.logger.Debug("tracing shutdown complete")
		}
	}

	// Close Neo4j connection
	if d.infrastructure != nil && d.infrastructure.graphRAGClient != nil {
		d.logger.Info("closing Neo4j connection")
		if err := d.infrastructure.graphRAGClient.Close(ctx); err != nil {
			d.logger.Warn("failed to close Neo4j connection", "error", err)
		} else {
			d.logger.Debug("Neo4j connection closed")
		}
	}

	// Close Redis connection
	if d.infrastructure != nil && d.infrastructure.redisClient != nil {
		d.logger.Info("closing Redis connection")
		if err := d.infrastructure.redisClient.Close(); err != nil {
			d.logger.Warn("failed to close Redis connection", "error", err)
		} else {
			d.logger.Debug("Redis connection closed")
		}
	}

	// Stop registry last (agents may still be deregistering)
	d.logger.Info("stopping registry manager")
	if err := d.registry.Stop(ctx); err != nil {
		d.logger.Warn("error stopping registry", "error", err)
	}

	// Close database connection
	if d.db != nil {
		d.logger.Info("closing database connection")
		if err := d.db.Close(); err != nil {
			d.logger.Warn("error closing database", "error", err)
		}
	}
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
	// Read PID file to check if daemon is running
	running, pid, err := CheckPIDFile(d.pidFile)
	if err != nil {
		return nil, fmt.Errorf("failed to check daemon status: %w", err)
	}

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
		d.logger.Info("no running missions to recover")
		return nil
	}

	// Transition each running mission to paused status
	recoveredCount := 0
	for _, m := range activeMissions {
		// Only recover missions that are actually running (not already paused)
		if m.Status == mission.MissionStatusRunning {
			d.logger.Warn("recovered mission - set to paused after daemon restart",
				"mission_id", m.ID.String(),
				"mission_name", m.Name,
				"status", m.Status,
			)

			// Update mission status to paused
			if err := d.missionStore.UpdateStatus(ctx, m.ID, mission.MissionStatusPaused); err != nil {
				d.logger.Error("failed to pause recovered mission",
					"mission_id", m.ID.String(),
					"error", err,
				)
				continue
			}

			recoveredCount++
		}
	}

	if recoveredCount > 0 {
		d.logger.Info("completed crash recovery",
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
