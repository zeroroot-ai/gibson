package harness

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/zeroroot-ai/gibson/internal/authz"
	"github.com/zeroroot-ai/gibson/internal/component"
	"github.com/zeroroot-ai/gibson/internal/graphrag/loader"
	"github.com/zeroroot-ai/sdk/protoresolver"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// CallbackConfig contains configuration for the callback server.
// This is a simplified version that doesn't import from internal/config
// to avoid import cycles.
type CallbackConfig struct {
	// ListenAddress is the address the callback server listens on (e.g., "0.0.0.0:50001")
	ListenAddress string

	// AdvertiseAddress is the address sent to agents as the callback endpoint
	// (e.g., "gibson:50001" for Docker networking)
	// If empty, ListenAddress is used
	AdvertiseAddress string

	// Enabled controls whether the callback server is started
	Enabled bool

	// SPIFFEEnabled indicates that the callback server is wrapped with SPIFFE
	// mTLS. After spec critical-tls-no-fallbacks, this is true whenever
	// X509Source is non-nil; it remains in CallbackConfig solely so the
	// loopback bind guard at Start() can answer "is this listener
	// transport-secured" without depending on field-by-field nil checks.
	// Loopback-only dev builds set this to false and bind to 127.0.0.1.
	SPIFFEEnabled bool

	// X509Source is the SPIFFE Workload API source used to wrap the callback
	// listener in mTLS. When nil and ListenAddress is non-loopback, Start()
	// returns an error (critical-tls-no-fallbacks Requirement 1.5 — fail-closed).
	// Populated by daemon.New() / daemon.Start() from
	// daemonImpl.spiffeX509Source so the same Workload API connection serves
	// both the main and callback listeners.
	X509Source *workloadapi.X509Source

	// PeerSVIDs is the allowlist of peer SPIFFE IDs the callback listener
	// accepts. Built from GIBSON_CALLBACK_PEER_SVIDS at daemon startup
	// (parsed by initSPIFFEX509Source). MUST be non-empty when X509Source is set.
	// Spec: critical-tls-no-fallbacks Requirement 1.3.
	PeerSVIDs []spiffeid.ID
}

// CallbackManager coordinates the lifecycle of the CallbackServer and provides
// a clean API for registering harnesses and getting callback endpoints.
//
// The manager wraps the existing CallbackServer and provides:
//   - Background goroutine lifecycle management for the gRPC server
//   - Thread-safe harness registration/unregistration via CallbackHarnessRegistry
//   - Advertise address resolution for Docker/K8s environments
//   - Graceful shutdown handling
//
// For external agents (running as separate gRPC services), the manager uses
// a CallbackHarnessRegistry keyed by "missionID:agentName" to route callbacks
// to the correct harness instance.
//
// Usage:
//
//	manager := NewCallbackManager(config, logger)
//	if err := manager.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
//	defer manager.Stop()
//
//	// Register harness before external agent execution
//	key := manager.RegisterHarnessForMission(missionID, agentName, harness)
//	defer manager.UnregisterHarness(key)
//
//	// Pass callback endpoint to agent in gRPC request
//	agent.Execute(ctx, task, manager.CallbackEndpoint())
type CallbackManager struct {
	server       *CallbackServer
	registry     *CallbackHarnessRegistry
	config       CallbackConfig
	logger       *slog.Logger
	serverCtx    context.Context
	serverCancel context.CancelFunc
	serverErrCh  chan error
	startOnce    sync.Once
	stopOnce     sync.Once
	mu           sync.RWMutex
	running      bool
}

// NewCallbackManager creates a new callback manager with the given configuration.
//
// Parameters:
//   - cfg: Callback server configuration (listen/advertise addresses)
//   - logger: Structured logger for manager events
//
// Returns:
//   - *CallbackManager: A new manager instance ready to be started
//
// The manager does not start the server automatically. Call Start() to begin
// accepting connections.
func NewCallbackManager(cfg CallbackConfig, logger *slog.Logger) *CallbackManager {
	if logger == nil {
		logger = slog.Default()
	}

	// Extract port from listen address
	// Format is either ":port" or "host:port"
	port := 50001 // default
	if cfg.ListenAddress != "" {
		// Extract port from address string
		parts := strings.Split(cfg.ListenAddress, ":")
		if len(parts) >= 2 {
			if p, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
				port = p
			}
		}
	}

	// Create registry for mission-based harness lookup
	registry := NewCallbackHarnessRegistry()

	// Create server with registry for mission-based harness lookup
	server := NewCallbackServerWithRegistry(logger, port, registry)

	// Wire the SPIFFE source + peer-SVID allowlist into the server when the
	// caller (daemon.New/Start) supplied them. Without this the listener falls
	// back to plain TCP, which is forbidden by spec critical-tls-no-fallbacks
	// Requirement 1.1 for non-loopback binds. The Start() guard at line 159
	// rejects non-loopback binds without SPIFFE — this wiring is what makes
	// SPIFFEEnabled=true in production.
	if cfg.X509Source != nil {
		server.SetSPIFFE(cfg.X509Source, cfg.PeerSVIDs)
	}

	return &CallbackManager{
		server:      server,
		registry:    registry,
		config:      cfg,
		logger:      logger.With("component", "callback_manager"),
		serverErrCh: make(chan error, 1),
		running:     false,
	}
}

// Start starts the callback server in a background goroutine.
//
// This method is safe to call multiple times - subsequent calls are no-ops.
// The server will run until Stop() is called or the provided context is cancelled.
//
// Parameters:
//   - ctx: Context for server lifetime (cancellation triggers graceful shutdown)
//
// Returns:
//   - error: Non-nil if server fails to start (e.g., port already in use)
//
// The method returns immediately after starting the server goroutine. Use the
// serverErrCh to monitor for runtime errors.
//
// Example:
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	if err := manager.Start(ctx); err != nil {
//	    log.Fatalf("Failed to start callback server: %v", err)
//	}
func (m *CallbackManager) Start(ctx context.Context) error {
	var startErr error

	m.startOnce.Do(func() {
		m.mu.Lock()
		defer m.mu.Unlock()

		// Refuse to start the callback listener on a non-loopback bind without
		// SPIFFE mTLS — critical-tls-no-fallbacks Requirement 1.5 (was
		// security-hardening R1.4). After this spec, SPIFFE is the only
		// supported posture for non-loopback binds; SPIFFEEnabled is true
		// whenever NewCallbackManager received a non-nil X509Source via
		// CallbackConfig. A non-loopback bind without SPIFFE fails here,
		// fail-closed, with a message naming GIBSON_CALLBACK_PEER_SVIDS so
		// operators have an actionable next step.
		spiffeReady := m.config.SPIFFEEnabled || m.config.X509Source != nil
		if m.config.ListenAddress != "" && !spiffeReady {
			if err := rejectNonLoopbackWithoutSPIFFE(m.config.ListenAddress); err != nil {
				m.logger.Error("callback listener refused to start", "error", err)
				startErr = err
				return
			}
		}

		// Create a cancellable context for the server
		m.serverCtx, m.serverCancel = context.WithCancel(ctx)

		m.logger.Info("starting callback server",
			"listen_address", m.config.ListenAddress,
			"advertise_address", m.CallbackEndpoint(),
		)

		// Start server in background goroutine
		go func() {
			// Server.Start() is blocking, so we run it in a goroutine
			if err := m.server.Start(m.serverCtx); err != nil {
				// Only log non-cancellation errors
				if m.serverCtx.Err() == nil {
					m.logger.Error("callback server error", "error", err)
					m.serverErrCh <- err
				}
			}
		}()

		m.running = true
		m.logger.Info("callback server started", "endpoint", m.CallbackEndpoint())
	})

	return startErr
}

// Serve starts the callback server and blocks until ctx is cancelled.
// On cancellation it calls Stop() to cleanly shut down the server.
//
// Serve is the preferred lifecycle method for integration with errgroup or a
// plain goroutine. Start/Stop remain available for callers that need split
// lifecycle control.
//
// Returns nil on clean shutdown (ctx cancelled); returns a non-nil error only
// if the server itself fails during startup (e.g., port already in use).
func (m *CallbackManager) Serve(ctx context.Context) error {
	if err := m.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	m.Stop()
	return nil
}

// Stop gracefully stops the callback server.
//
// This method blocks until the server has fully shut down. It is safe to call
// multiple times - subsequent calls are no-ops.
//
// All active harness registrations are implicitly unregistered when the server
// stops. Agents attempting to make callbacks after Stop() will receive connection
// errors.
//
// Example:
//
//	defer manager.Stop()  // Ensure cleanup on exit
func (m *CallbackManager) Stop() {
	m.stopOnce.Do(func() {
		m.mu.Lock()
		defer m.mu.Unlock()

		if !m.running {
			return
		}

		m.logger.Info("stopping callback server")

		// Cancel server context to trigger graceful shutdown
		if m.serverCancel != nil {
			m.serverCancel()
		}

		// Call server's Stop() method for immediate graceful shutdown
		m.server.Stop()

		m.running = false
		m.logger.Info("callback server stopped")
	})
}

// RegisterHarnessForMission registers a harness for external agent execution
// within a mission context and returns the registration key.
//
// This method is used for external agents (running as separate gRPC services)
// that need to make harness operations through the callback server. The
// harness is registered in the CallbackHarnessRegistry keyed by
// "missionID:agentName" to support concurrent execution of the same agent
// in different missions.
//
// Parameters:
//   - missionID: Unique identifier for the mission
//   - agentName: Name of the external agent being executed
//   - harness: The harness instance that will handle callbacks
//
// Returns:
//   - string: The registration key in the format "missionID:agentName"
//
// The harness must be registered BEFORE the agent execution request is sent,
// otherwise callbacks will fail with "no harness found" errors.
//
// Always unregister the harness after agent completion to prevent memory leaks:
//
//	key := manager.RegisterHarnessForMission(missionID, agentName, harness)
//	defer manager.UnregisterHarness(key)
//	// Execute external agent...
//
// Thread-safe: Multiple goroutines can register different harnesses concurrently.
//
// Example:
//
//	key := callbackMgr.RegisterHarnessForMission("mission-123", "recon-agent", harness)
//	defer callbackMgr.UnregisterHarness(key)
//	result, err := grpcClient.Execute(ctx, task, callbackMgr.CallbackEndpoint())
func (m *CallbackManager) RegisterHarnessForMission(missionID, agentName string, harness any) string {
	// Type assert to AgentHarness - the registry.CallbackManager interface uses any to avoid
	// circular imports, but the actual harness must implement AgentHarness
	h, ok := harness.(AgentHarness)
	if !ok {
		m.logger.Error("harness does not implement AgentHarness",
			"mission_id", missionID,
			"agent_name", agentName,
		)
		return ""
	}
	key := m.registry.Register(missionID, agentName, h)
	m.logger.Debug("registered harness for mission agent",
		"mission_id", missionID,
		"agent_name", agentName,
		"registry_key", key,
	)
	return key
}

// UnregisterHarness removes a harness registration when a task completes.
//
// Parameters:
//   - taskID: The registration key returned by RegisterHarnessForMission.
//
// This method should be called in a defer block immediately after registration
// to ensure cleanup happens even if the agent execution fails:
//
//	key := manager.RegisterHarnessForMission(missionID, agentName, harness)
//	defer manager.UnregisterHarness(key)
//	result, err := agent.Execute(ctx, task, callbackEndpoint)
//
// Thread-safe: Safe to call from multiple goroutines.
func (m *CallbackManager) UnregisterHarness(taskID string) {
	m.server.UnregisterHarness(taskID)
	m.logger.Debug("unregistered harness for task", "task_id", taskID)
}

// CallbackEndpoint returns the advertised callback endpoint address.
//
// Returns:
//   - string: The address agents should connect to (e.g., "gibson:50001")
//
// The returned address is determined by the CallbackConfig:
//   - If AdvertiseAddress is set, that value is returned
//   - Otherwise, ListenAddress is returned
//
// This allows the internal bind address to differ from the externally reachable
// address, which is critical in containerized environments:
//
//	config := CallbackConfig{
//	    ListenAddress:    "0.0.0.0:50001",      // Bind to all interfaces
//	    AdvertiseAddress: "gibson:50001",       // Docker service name
//	}
//
// Agents running in Docker can resolve "gibson" via Docker's DNS, but the server
// must bind to 0.0.0.0 to accept connections from other containers.
func (m *CallbackManager) CallbackEndpoint() string {
	if m.config.AdvertiseAddress != "" {
		return m.config.AdvertiseAddress
	}
	// If ListenAddress uses 0.0.0.0 (bind all interfaces), convert to localhost
	// since 0.0.0.0 is not a routable address that agents can connect to
	addr := m.config.ListenAddress
	if strings.HasPrefix(addr, "0.0.0.0:") {
		return "localhost:" + strings.TrimPrefix(addr, "0.0.0.0:")
	}
	return addr
}

// IsRunning returns whether the callback server is currently running.
//
// Returns:
//   - bool: true if the server is running, false otherwise
//
// This method is thread-safe and can be used to check server status before
// attempting to register harnesses.
func (m *CallbackManager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// AddSpanProcessors adds span processors to the callback service.
// This allows the callback service to forward spans received from remote agents
// to the registered span processors (e.g., for Langfuse export or Neo4j recording).
//
// This method should be called after NewCallbackManager but before Start().
//
// Parameters:
//   - processors: Span processors to register with the callback service
//
// Thread-safe: Can be called from multiple goroutines.
func (m *CallbackManager) AddSpanProcessors(processors ...sdktrace.SpanProcessor) {
	if m.server != nil && m.server.service != nil {
		m.server.service.mu.Lock()
		defer m.server.service.mu.Unlock()
		m.server.service.spanProcessors = append(m.server.service.spanProcessors, processors...)
		m.logger.Debug("added span processors to callback service",
			"count", len(processors))
	}
}

// SetTracerProvider sets the TracerProvider on the callback service.
// This is required for distributed tracing to work - proxy spans received from
// remote agents are re-created as real spans using this provider.
//
// This method should be called after NewCallbackManager but before Start().
//
// Parameters:
//   - tp: TracerProvider that will be used to create spans
//
// Thread-safe: Can be called from multiple goroutines.
func (m *CallbackManager) SetTracerProvider(tp *sdktrace.TracerProvider) {
	if m.server != nil && m.server.service != nil {
		m.server.service.mu.Lock()
		defer m.server.service.mu.Unlock()
		m.server.service.tracerProvider = tp
		m.logger.Debug("set tracer provider on callback service")
	}
}

// SetCredentialStore sets the credential store on the callback service.
// This enables agents and plugins to retrieve stored credentials securely.
//
// This method should be called after NewCallbackManager but before Start().
//
// Parameters:
//   - store: CredentialStore implementation for credential retrieval
//
// Thread-safe: Can be called from multiple goroutines.
func (m *CallbackManager) SetCredentialStore(store CredentialStore) {
	if m.server != nil {
		m.server.SetCredentialStore(store)
		m.logger.Debug("set credential store on callback service")
	}
}

// SetEventBus sets the event bus on the callback service.
// This enables the callback service to publish tool and LLM events
// for consumption by the execution graph engine.
//
// This method should be called after NewCallbackManager but before Start().
//
// Parameters:
//   - eventBus: EventBusPublisher interface for publishing events
//
// Thread-safe: Can be called from multiple goroutines.
func (m *CallbackManager) SetEventBus(eventBus interface{}) {
	if m.server != nil && m.server.service != nil {
		// Type assert to the EventBusPublisher interface
		// The interface{} parameter is used to avoid circular dependencies
		type eventBusPublisher interface {
			Publish(ctx context.Context, event interface{}) error
		}

		if bus, ok := eventBus.(eventBusPublisher); ok {
			m.server.service.mu.Lock()
			defer m.server.service.mu.Unlock()
			m.server.service.eventBus = bus
			m.logger.Debug("set event bus on callback service")
		} else {
			m.logger.Warn("provided event bus does not implement EventBusPublisher interface")
		}
	}
}

// SetObservationSink sets the observation sink on the callback service, wiring
// the Observe RPC to the brain (ADR-0007). Call after NewCallbackManager, before
// Start(). Thread-safe.
func (m *CallbackManager) SetObservationSink(sink ObservationSink) {
	if m.server != nil && m.server.service != nil {
		m.server.service.mu.Lock()
		defer m.server.service.mu.Unlock()
		m.server.service.observationSink = sink
		m.logger.Debug("set observation sink on callback service")
	}
}

// SetGraphLoader sets the GraphLoader on the callback service.
// This enables tool outputs containing DiscoveryResult to be persisted
// to the Neo4j knowledge graph automatically.
//
// This method should be called after NewCallbackManager but before Start().
//
// Parameters:
//   - gl: GraphLoader instance for persisting domain nodes to Neo4j
//
// Thread-safe: Can be called from multiple goroutines.
func (m *CallbackManager) SetGraphLoader(gl *loader.GraphLoader) {
	if m.server != nil {
		m.server.SetGraphLoader(gl)
		m.logger.Debug("set graph loader on callback service")
	}
}

// SetDiscoveryProcessor sets the DiscoveryProcessor on the callback service.
// This enables automatic extraction and storage of DiscoveryResult from tool responses.
//
// This method should be called after NewCallbackManager but before Start().
//
// Parameters:
//   - processor: DiscoveryProcessor instance for processing discoveries
//
// Thread-safe: Can be called from multiple goroutines.
func (m *CallbackManager) SetDiscoveryProcessor(processor DiscoveryProcessor) {
	if m.server != nil {
		m.server.SetDiscoveryProcessor(processor)
		m.logger.Debug("set discovery processor on callback service")
	}
}

// SetQueueManager sets the QueueManager on the callback service.
// This enables Redis-based work queue operations for tool execution,
// allowing agents to queue tool invocations for distributed processing.
//
// This method should be called after NewCallbackManager but before Start().
//
// Parameters:
//   - queueMgr: QueueManager instance for Redis queue operations
//
// Thread-safe: Can be called from multiple goroutines.
func (m *CallbackManager) SetQueueManager(queueMgr *QueueManager) {
	if m.server != nil {
		m.server.SetQueueManager(queueMgr)
		m.logger.Debug("set queue manager on callback service")
	}
}

// SetProtoResolver sets the ProtoResolver on the callback service.
// This enables dynamic proto type resolution for CallToolProto requests,
// allowing the callback service to resolve proto message types at runtime.
//
// This method should be called after NewCallbackManager but before Start().
//
// Parameters:
//   - resolver: ProtoResolver instance for dynamic type resolution
//
// Thread-safe: Can be called from multiple goroutines.
func (m *CallbackManager) SetProtoResolver(resolver protoresolver.ProtoResolver) {
	if m.server != nil && m.server.service != nil {
		m.server.service.mu.Lock()
		defer m.server.service.mu.Unlock()
		m.server.service.resolver = resolver
		m.logger.Debug("set proto resolver on callback service")
	}
}

// SetAuthzStore wires the RunAuthzLookup into the callback service so that the
// Authorize RPC handler can look up per-run authz state.
// Should be called after NewCallbackManager and before Start().
func (m *CallbackManager) SetAuthzStore(store RunAuthzLookup) {
	if m.server != nil {
		m.server.SetAuthzStore(store)
		m.logger.Debug("set authz store on callback service")
	}
}

// SetComponentAuthorizer wires the FGA Authorizer into the callback service for
// component-level authorization decisions during Authorize RPC calls.
// Should be called after NewCallbackManager and before Start().
func (m *CallbackManager) SetComponentAuthorizer(a authz.Authorizer) {
	if m.server != nil {
		m.server.SetComponentAuthorizer(a)
		m.logger.Debug("set component authorizer on callback service")
	}
}

// SetComponentRegistry wires the component registry into the callback service so
// SearchTools can enumerate the tenant's connector catalog. Should be called
// after NewCallbackManager and before Start().
func (m *CallbackManager) SetComponentRegistry(reg component.ComponentRegistry) {
	if m.server != nil {
		m.server.SetComponentRegistry(reg)
		m.logger.Debug("set component registry on callback service")
	}
}

// SetComponentAuthzMetrics wires a metrics recorder into the Authorize RPC handler.
// When not set, no authz counters are emitted. Should be called before Start().
func (m *CallbackManager) SetComponentAuthzMetrics(metrics ComponentAuthzMetrics) {
	if m.server != nil {
		m.server.SetComponentAuthzMetrics(metrics)
		m.logger.Debug("set component authz metrics recorder on callback service")
	}
}

// SetMissionManager wires a MissionOperator into the callback service so agents
// can create, run, wait for, list, cancel, and retrieve results of sub-missions
// via the harness callback RPC surface.
// Should be called after NewCallbackManager and before Start().
func (m *CallbackManager) SetMissionManager(op MissionOperator) {
	if m.server != nil {
		m.server.SetMissionManager(op)
		m.logger.Debug("set mission manager on callback service")
	}
}

// SetAgentOwnerLookup wires the AgentOwnerLookup hook into the callback
// service so DelegateToAgent populates ExecutorUser on the dispatch
// context. Pass nil to disable. Spec: llm-user-attribution-governance
// Requirement 1.5.
func (m *CallbackManager) SetAgentOwnerLookup(fn AgentOwnerLookup) {
	if m.server != nil {
		m.server.SetAgentOwnerLookup(fn)
		m.logger.Debug("set agent owner lookup on callback service")
	}
}

// SetSPIFFE wires the SPIFFE Workload API source and peer-SVID allowlist into
// the underlying CallbackServer AND records the post-init state on
// CallbackConfig so the loopback-bind guard at Start() correctly identifies
// the listener as transport-secured. Must be called BEFORE Start().
//
// daemon.Start invokes this after initSPIFFEX509Source has populated
// d.spiffeX509Source and d.callbackPeerSVIDs.
//
// Spec: critical-tls-no-fallbacks Component 4.
func (m *CallbackManager) SetSPIFFE(source *workloadapi.X509Source, peerSVIDs []spiffeid.ID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.X509Source = source
	m.config.PeerSVIDs = peerSVIDs
	m.config.SPIFFEEnabled = source != nil
	if m.server != nil {
		m.server.SetSPIFFE(source, peerSVIDs)
		m.logger.Debug("wired SPIFFE source onto callback server",
			"peer_svid_count", len(peerSVIDs))
	}
}
