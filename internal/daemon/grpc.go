package daemon

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/attack"
	"github.com/zero-day-ai/gibson/internal/audit"
	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/daemon/api"
	"github.com/zero-day-ai/gibson/internal/finding"
	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
	daemonpb "github.com/zero-day-ai/sdk/api/gen/gibson/daemon/v1"

	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/provisioner"
	"github.com/zero-day-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc"
)

// startGRPCServer creates and starts the gRPC server.
//
// This method creates a gRPC server, registers the daemon service,
// and starts listening on the configured address in a goroutine.
//
// If authentication is enabled in config, auth interceptors are installed
// to enforce authentication on all gRPC endpoints.
func (d *daemonImpl) startGRPCServer(ctx context.Context) error {
	// Create listener
	listener, err := net.Listen("tcp", d.grpcAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", d.grpcAddr, err)
	}

	// Build interceptor chains. Recovery is always first (outermost).
	var unaryInterceptors []grpc.UnaryServerInterceptor
	var streamInterceptors []grpc.StreamServerInterceptor

	// 1. Panic recovery (outermost — catches panics from all inner interceptors)
	var recoveryMeter metric.Meter
	if d.infrastructure != nil && d.infrastructure.otelStack != nil &&
		d.infrastructure.otelStack.MeterProvider != nil {
		recoveryMeter = d.infrastructure.otelStack.MeterProvider.Meter("gibson.grpc.recovery")
	}
	unaryRecovery, streamRecovery, err := panicRecoveryInterceptors(d.logger.Slog(), recoveryMeter)
	if err != nil {
		return fmt.Errorf("failed to create recovery interceptors: %w", err)
	}
	unaryInterceptors = append(unaryInterceptors, unaryRecovery)
	streamInterceptors = append(streamInterceptors, streamRecovery)

	// 2. Error scrubbing (strips internal paths, YAML parse details, Go types from responses)
	var scrubMeter metric.Meter
	if d.infrastructure != nil && d.infrastructure.otelStack != nil &&
		d.infrastructure.otelStack.MeterProvider != nil {
		scrubMeter = d.infrastructure.otelStack.MeterProvider.Meter("gibson.grpc.error_scrub")
	}
	unaryScrub, streamScrub, err := errorScrubInterceptors(d.logger.Slog(), scrubMeter)
	if err != nil {
		return fmt.Errorf("failed to create error scrub interceptors: %w", err)
	}
	unaryInterceptors = append(unaryInterceptors, unaryScrub)
	streamInterceptors = append(streamInterceptors, streamScrub)

	// 3. Auth interceptors (if enabled)
	if d.config.Auth.IsAuthEnabled() {
		d.logger.Info(ctx, "authentication enabled, installing auth interceptors",
			"mode", d.config.Auth.Mode,
		)

		authenticator, err := d.createAuthenticator(ctx)
		if err != nil {
			return fmt.Errorf("failed to create authenticator: %w", err)
		}

		unaryInterceptors = append(unaryInterceptors, auth.UnaryAuthInterceptor(authenticator, &d.config.Auth, d.logger.Slog()))
		streamInterceptors = append(streamInterceptors, auth.StreamAuthInterceptor(authenticator, &d.config.Auth, d.logger.Slog()))

		d.logger.Info(ctx, "auth interceptors installed",
			"trust_localhost", d.config.Auth.TrustLocalhost,
			"oidc_issuers", len(d.config.Auth.OIDC),
		)
	} else {
		d.logger.Warn(ctx, "auth interceptors not installed - auth mode not configured")
	}

	// 4. Authorization interceptor — OpenFGA is the sole enforcement backend.
	//
	// Build FGA registry and validate it against the FGA model.
	// Called as a startup gate: typos or model drift fail the daemon early.
	fgaRegistry := auth.NewFgaRpcRegistry()
	if err := fgaRegistry.Validate(ctx, d.authorizer); err != nil {
		return fmt.Errorf("fga registry validation failed at startup: %w", err)
	}
	d.logger.Info(ctx, "fga rpc registry validated against authorization model")

	fgaInterceptor := auth.NewFgaAuthzInterceptor(
		d.authorizer,
		fgaRegistry,
		d.logger.Slog(),
		d.GetOTelMetricsRecorder(),
	)
	unaryInterceptors = append(unaryInterceptors, fgaInterceptor.Unary())
	streamInterceptors = append(streamInterceptors, fgaInterceptor.Stream())
	d.logger.Info(ctx, "fga authz interceptor installed (fga-only mode)")

	// Build server options with chained interceptors
	serverOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.ChainStreamInterceptor(streamInterceptors...),
	}

	// Create gRPC server with options
	srv := grpc.NewServer(serverOpts...)
	d.grpcServer = srv

	// Create and register daemon service.
	// Attach the quota manager so RunMission enforces per-tenant mission limits.
	daemonSvc := api.NewDaemonServer(d, d.credentialHandler, d.logger.Slog())
	if d.quotaManager != nil {
		daemonSvc.WithQuotaManager(d.quotaManager)
		d.logger.Info(ctx, "quota manager wired into DaemonServer for mission quota enforcement")
	}
	// Wire TenantService, Provisioner, and BillingStore into DaemonServer.
	// These enable tenant CRUD, provisioning, and billing RPCs respectively.
	if d.stateClient != nil {
		if redisClient, ok := d.stateClient.Client().(*goredis.Client); ok {
			auditLogger := audit.NewAuditLogger(d.stateClient, d.logger.Slog())

			tenantService := component.NewTenantService(redisClient, d.logger.Slog(), auditLogger)
			if d.quotaManager != nil {
				tenantService.WithQuotaManager(d.quotaManager)
			}
			daemonSvc.WithTenantService(tenantService)
			d.logger.Info(ctx, "tenant service wired into DaemonServer")

			// Create APIKeyAuthenticator for provisioner's key generation and
			// the CreateAPIKey/ListAPIKeys/RevokeAPIKey RPCs.
			apiKeyAuth, akErr := auth.NewAPIKeyAuthenticator(redisClient)
			if akErr != nil {
				d.logger.Warn(ctx, "failed to create API key authenticator for provisioner", "error", akErr)
			}

			// Wire the API key store so that the key management RPCs are
			// backed by Redis.  This must be done before registering the
			// gRPC server so that the RPCs are available immediately.
			if apiKeyAuth != nil {
				daemonSvc.WithAPIKeyStore(apiKeyAuth)
				d.logger.Info(ctx, "API key store wired into DaemonServer")
			}

			// Create and wire the Provisioner.
			if apiKeyAuth != nil {
				prov := provisioner.New(
					redisClient,
					&tenantCreatorAdapter{svc: tenantService},
					&apiKeyCreatorAdapter{auth: apiKeyAuth},
					nil,
					d.logger.Slog(),
				)

				daemonSvc.WithProvisioner(prov)
				d.logger.Info(ctx, "provisioner wired into DaemonServer")

				// Wire the SignupHandler — requires KeycloakAdmin and the FGA Authorizer.
				// The KeycloakAdmin is constructed from daemon config; the Authorizer is
				// always non-nil after initAuthorizer() (noopAuthorizer when disabled).
				if kcAdmin, kcErr := provisioner.NewKeycloakAdminClient(
					d.config.Keycloak.Admin,
					d.logger.Slog(),
				); kcErr != nil {
					d.logger.Warn(ctx, "SignupHandler not wired: failed to build Keycloak admin client",
						"error", kcErr)
				} else {
					signupHandler := provisioner.NewSignupHandler(kcAdmin, d.authorizer, prov, d.logger.Slog())
					daemonSvc.WithSignupHandler(signupHandler)
					d.logger.Info(ctx, "SignupHandler wired into DaemonServer")
				}
			} else {
				d.logger.Warn(ctx, "provisioner not wired: API key authenticator unavailable")
			}

			// Wire BillingStore (composed from TenantService + QuotaManager).
			daemonSvc.WithBillingStore(tenantService, d.quotaManager)
			d.logger.Info(ctx, "billing store wired into DaemonServer")

		} else {
			d.logger.Warn(ctx, "tenant provisioning not wired: Redis client is not standalone mode")
		}
	} else {
		d.logger.Warn(ctx, "tenant provisioning not wired: stateClient is nil")
	}

	daemonpb.RegisterDaemonServiceServer(srv, daemonSvc)
	api.RegisterDaemonAdminServiceServer(srv, daemonSvc)

	// Initialize and register the ComponentService on the same gRPC port.
	//
	// ComponentService is the ingress point for all Gibson components (agents,
	// tools, plugins). It handles registration, heartbeat, work dispatch, and
	// harness proxy RPCs. All three dependencies require the shared Redis client
	// from stateClient so that component data is co-located with mission state.
	//
	// The registry uses a 30-second TTL: components that stop heartbeating within
	// that window are automatically deregistered by Redis key expiry.
	//
	// Harness proxy dependencies (llmCompleter, memStore) are wired as nil until
	// task 5.4 connects those subsystems. findingSubmitter is wired here using
	// GraphRAGFindingSubmitter when infrastructure is available.
	if d.stateClient != nil {
		if redisClient, ok := d.stateClient.Client().(*goredis.Client); ok {
			compRegistry := component.NewRedisComponentRegistry(redisClient, 30*time.Second)
			compQueue := component.NewRedisWorkQueue(d.stateClient.Client())

			auditLogger := audit.NewAuditLogger(d.stateClient, d.logger.Slog())

			// Wire GraphRAGFindingSubmitter when infrastructure is available.
			// It routes findings to both Redis (tenant-scoped indexes) and Neo4j
			// (via GraphRAGBridge.StoreAsync, fire-and-forget). Falls back to nil
			// when the finding store or bridge has not been initialized, in which
			// case ComponentServiceServer logs and returns a generated finding_id.
			var findingSubmitter component.FindingSubmitter
			if d.infrastructure != nil &&
				d.infrastructure.findingStore != nil &&
				d.infrastructure.graphRAGBridge != nil {
				if redisStore, ok := d.infrastructure.findingStore.(*finding.RedisFindingStore); ok {
					findingSubmitter = component.NewGraphRAGFindingSubmitter(
						d.infrastructure.graphRAGBridge,
						redisStore,
						d.stateClient,
						d.logger.WithComponent("finding-submitter").Slog(),
					)
					d.logger.Info(ctx, "GraphRAGFindingSubmitter wired: findings routed to Redis and Neo4j")
				} else {
					d.logger.Warn(ctx, "finding store is not *finding.RedisFindingStore; finding submitter not wired")
				}
			} else {
				d.logger.Warn(ctx, "infrastructure not ready; finding submitter not wired (findings will be logged only)")
			}

			compSvc := component.NewComponentServiceServer(
				compRegistry,
				compQueue,
				d.logger.Slog(),
				nil,                 // llmCompleter: wired in task 5.4
				nil,                 // memStore:     wired in task 5.4
				findingSubmitter,    // GraphRAGFindingSubmitter or nil
				d.pluginAccessStore, // nil when no KeyProvider configured
				auditLogger,
			)

			// Wire MemoryResolver so that MemoryGet/MemorySet/MemorySearch route
			// mission-tier operations to the per-agent mission namespace.
			// RedisMemoryResolver caches MissionMemory instances in a sync.Map and
			// resolves work_id → mission_id via short-lived Redis hash keys written
			// by PollWork when work items carrying mission_id context are dispatched.
			compSvc.WithMemoryResolver(component.NewRedisMemoryResolver(d.stateClient))

			// Wire the quota manager so RegisterComponent enforces per-tenant
			// agent quotas before the agent is admitted to the registry.
			if d.quotaManager != nil {
				compSvc.WithQuotaManager(d.quotaManager)
				d.logger.Info(ctx, "quota manager wired into ComponentService for agent quota enforcement")
			}

			componentpb.RegisterComponentServiceServer(srv, compSvc)
			d.logger.Info(ctx, "ComponentService initialized",
				"registry_ttl", "30s",
				"redis_mode", "standalone",
				"memory_resolver", "redis",
			)
		} else {
			d.logger.Warn(ctx, "ComponentService unavailable: Redis client is not standalone mode; requires *redis.Client")
		}
	} else {
		d.logger.Warn(ctx, "ComponentService unavailable: stateClient is nil, Redis not configured")
	}

	// Start serving in goroutine
	go func() {
		d.logger.Info(ctx, "gRPC server listening", "address", d.grpcAddr)
		if err := srv.Serve(listener); err != nil {
			d.logger.Error(ctx, "gRPC server error", "error", err)
		}
	}()

	return nil
}

// createAuthenticator creates an authenticator based on the auth configuration.
//
// This method creates a composite authenticator that supports multiple
// authentication methods:
//   - API key authenticator for "gsk_"-prefixed tokens (enterprise/saas modes, requires Redis)
//   - OIDC validator for OIDC issuers (Okta, Azure AD, GitHub Actions, GitLab CI)
//   - K8s validator for Kubernetes ServiceAccount tokens
//   - Local validator for static tokens (development only)
//
// Token routing: "gsk_"-prefixed tokens are handled exclusively by the API key
// authenticator. All other tokens fall through the OIDC → K8s → Local chain.
func (d *daemonImpl) createAuthenticator(ctx context.Context) (auth.Authenticator, error) {
	// Attempt to create an API key authenticator for enterprise/saas modes.
	// This requires a standalone *redis.Client (not cluster/ring mode).
	// If Redis is unavailable or in cluster mode, API key auth is silently skipped.
	var apiKeyAuth *auth.APIKeyAuthenticator
	mode := d.config.Auth.Mode
	if (mode == "enterprise" || mode == "saas") && d.stateClient != nil {
		if redisClient, ok := d.stateClient.Client().(*goredis.Client); ok {
			var err error
			apiKeyAuth, err = auth.NewAPIKeyAuthenticator(redisClient)
			if err != nil {
				// Non-fatal: log and proceed without API key support
				d.logger.Warn(ctx, "failed to create API key authenticator, continuing without it",
					"error", err,
				)
			}
		} else {
			d.logger.Info(ctx, "Redis client is not standalone mode; API key authentication unavailable")
		}
	}

	// Create composite authenticator that supports multiple auth methods
	authenticator, err := auth.NewCompositeAuthenticator(&d.config.Auth, apiKeyAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticator: %w", err)
	}

	// Log what authentication methods are enabled
	var methods []string
	if apiKeyAuth != nil {
		methods = append(methods, "apikey(gsk_)")
	}
	if len(d.config.Auth.OIDC) > 0 {
		methods = append(methods, fmt.Sprintf("oidc(%d issuers)", len(d.config.Auth.OIDC)))
	}
	if d.config.Auth.Kubernetes != nil && d.config.Auth.Kubernetes.Enabled {
		methods = append(methods, "kubernetes")
	}
	if d.config.Auth.Local != nil && len(d.config.Auth.Local.Users) > 0 {
		methods = append(methods, fmt.Sprintf("local(%d users)", len(d.config.Auth.Local.Users)))
	}

	d.logger.Info(ctx, "composite authenticator created",
		"methods", methods,
		"note", "gsk_ tokens routed to API key authenticator; others: OIDC → K8s → Local")

	return authenticator, nil
}

// Implementation of api.DaemonInterface for delegation from gRPC server.
// These methods delegate to the daemon's internal services.

// updateAgentHeartbeat updates the last heartbeat time for an agent.
// This should be called whenever an agent communicates with the daemon.
//
// Integration points (to be implemented in future):
//   - During mission execution when agents send task results
//   - During attack execution when agents report findings
//   - When agents register or re-register with the registry
//   - When agents respond to health checks
func (d *daemonImpl) updateAgentHeartbeat(agentName string) {
	d.agentStateMu.Lock()
	defer d.agentStateMu.Unlock()

	state, exists := d.agentState[agentName]
	if !exists {
		state = &AgentRuntimeState{}
		d.agentState[agentName] = state
	}
	state.LastHeartbeat = time.Now()
}

// setAgentCurrentTask updates the current task for an agent.
// This should be called when a task is assigned to or completed by an agent.
//
// Integration points (to be implemented in future):
//   - In orchestrator when assigning workflow nodes to agents
//   - In attack runner when starting agent operations
//   - When tasks complete (set to empty string to clear)
func (d *daemonImpl) setAgentCurrentTask(agentName string, taskID string) {
	d.agentStateMu.Lock()
	defer d.agentStateMu.Unlock()

	state, exists := d.agentState[agentName]
	if !exists {
		state = &AgentRuntimeState{
			LastHeartbeat: time.Now(),
		}
		d.agentState[agentName] = state
	}

	// If setting a new task (non-empty), update start time
	if taskID != "" {
		state.CurrentTask = taskID
		state.TaskStartTime = time.Now()
	} else {
		// Clearing the task
		state.CurrentTask = ""
		state.TaskStartTime = time.Time{}
	}
}

// getAgentState retrieves the runtime state for an agent.
// Returns nil if no state exists for the agent.
func (d *daemonImpl) getAgentState(agentName string) *AgentRuntimeState {
	d.agentStateMu.RLock()
	defer d.agentStateMu.RUnlock()

	state, exists := d.agentState[agentName]
	if !exists {
		return nil
	}

	// Return a copy to avoid race conditions
	stateCopy := *state
	return &stateCopy
}

// Status implements the api.DaemonInterface.Status method.
// It returns the daemon status in the format expected by the gRPC API.
func (d *daemonImpl) Status() (api.DaemonStatus, error) {
	// Get the internal status
	internalStatus, err := d.status()
	if err != nil {
		return api.DaemonStatus{}, err
	}

	// Convert to API status format
	return api.DaemonStatus{
		Running:            internalStatus.Running,
		PID:                int32(internalStatus.PID),
		StartTime:          internalStatus.StartTime,
		Uptime:             internalStatus.Uptime,
		GRPCAddress:        internalStatus.GRPCAddress,
		RegistryType:       internalStatus.RegistryType,
		RegistryAddr:       internalStatus.RegistryAddr,
		CallbackAddr:       internalStatus.CallbackAddr,
		AgentCount:         int32(internalStatus.AgentCount),
		MissionCount:       int32(internalStatus.MissionCount),
		ActiveMissionCount: int32(internalStatus.ActiveCount),
	}, nil
}

// ListAgents returns all registered agents from the registry adapter.
func (d *daemonImpl) ListAgents(ctx context.Context, kind string) ([]api.AgentInfoInternal, error) {
	d.logger.Debug(ctx, "ListAgents called", "kind", kind)

	agents, err := d.registryAdapter.ListAgents(ctx)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}

	result := make([]api.AgentInfoInternal, len(agents))
	for i, a := range agents {
		endpoint := ""
		if len(a.Endpoints) > 0 {
			endpoint = a.Endpoints[0]
		}

		health := a.Health
		if health == "" {
			health = "healthy"
		}

		// Get runtime state for last seen time
		runtimeState := d.getAgentState(a.Name)
		lastSeen := time.Now()
		if runtimeState != nil && !runtimeState.LastHeartbeat.IsZero() {
			lastSeen = runtimeState.LastHeartbeat
		}

		result[i] = api.AgentInfoInternal{
			ID:           a.Name,
			Name:         a.Name,
			Kind:         "agent",
			Version:      a.Version,
			Endpoint:     endpoint,
			Capabilities: a.Capabilities,
			Health:       health,
			LastSeen:     lastSeen,
		}
	}

	d.logger.Debug(ctx, "listed agents", "count", len(result))
	return result, nil
}

// GetAgentStatus returns status for a specific agent.
func (d *daemonImpl) GetAgentStatus(ctx context.Context, agentID string) (api.AgentStatusInternal, error) {
	d.logger.Debug(ctx, "GetAgentStatus called", "agent_id", agentID)

	// Query registry for all agents
	agents, err := d.registryAdapter.ListAgents(ctx)
	if err != nil {
		d.logger.Error(ctx, "failed to query registry for agent status", "error", err, "agent_id", agentID)
		return api.AgentStatusInternal{}, fmt.Errorf("failed to query registry: %w", err)
	}

	// Find the specific agent by ID (using name as ID)
	for _, agent := range agents {
		if agent.Name == agentID {
			// Use first endpoint if available
			endpoint := ""
			if len(agent.Endpoints) > 0 {
				endpoint = agent.Endpoints[0]
			}

			// Determine health status
			health := "healthy"
			if agent.Instances == 0 {
				health = "unknown"
			}

			// Get runtime state for the agent (last heartbeat, current task)
			runtimeState := d.getAgentState(agent.Name)
			lastSeen := time.Now()
			if runtimeState != nil && !runtimeState.LastHeartbeat.IsZero() {
				lastSeen = runtimeState.LastHeartbeat
			}

			// Build agent info
			agentInfo := api.AgentInfoInternal{
				ID:           agent.Name,
				Name:         agent.Name,
				Kind:         "agent",
				Version:      agent.Version,
				Endpoint:     endpoint,
				Capabilities: agent.Capabilities,
				Health:       health,
				LastSeen:     lastSeen,
			}

			// Get current task from runtime state
			currentTask := ""
			taskStartTime := time.Time{}
			if runtimeState != nil {
				currentTask = runtimeState.CurrentTask
				taskStartTime = runtimeState.TaskStartTime
			}

			// Build agent status
			status := api.AgentStatusInternal{
				Agent:         agentInfo,
				Active:        agent.Instances > 0,
				CurrentTask:   currentTask,
				TaskStartTime: taskStartTime,
			}

			d.logger.Debug(ctx, "found agent status", "agent_id", agentID, "instances", agent.Instances)
			return status, nil
		}
	}

	// Agent not found
	d.logger.Debug(ctx, "agent not found in registry", "agent_id", agentID)
	return api.AgentStatusInternal{}, fmt.Errorf("agent not found: %s", agentID)
}

// ListTools returns all registered tools from the registry adapter.
func (d *daemonImpl) ListTools(ctx context.Context) ([]api.ToolInfoInternal, error) {
	d.logger.Debug(ctx, "ListTools called")

	tools, err := d.registryAdapter.ListTools(ctx)
	if err != nil {
		return nil, fmt.Errorf("list tools: %w", err)
	}

	result := make([]api.ToolInfoInternal, len(tools))
	for i, t := range tools {
		endpoint := ""
		if len(t.Endpoints) > 0 {
			endpoint = t.Endpoints[0]
		}

		var caps *daemonpb.Capabilities
		if t.Capabilities != nil {
			caps = &daemonpb.Capabilities{
				HasRoot:         t.Capabilities.HasRoot,
				HasSudo:         t.Capabilities.HasSudo,
				CanRawSocket:    t.Capabilities.CanRawSocket,
				Features:        t.Capabilities.Features,
				BlockedArgs:     t.Capabilities.BlockedArgs,
				ArgAlternatives: t.Capabilities.ArgAlternatives,
			}
		}

		result[i] = api.ToolInfoInternal{
			ID:           t.Name,
			Name:         t.Name,
			Version:      t.Version,
			Endpoint:     endpoint,
			Description:  t.Description,
			Health:       t.Health,
			LastSeen:     time.Now(),
			Capabilities: caps,
		}
	}

	d.logger.Debug(ctx, "listed tools", "count", len(result))
	return result, nil
}

// ListPlugins returns all registered plugins from the registry adapter.
func (d *daemonImpl) ListPlugins(ctx context.Context) ([]api.PluginInfoInternal, error) {
	d.logger.Debug(ctx, "ListPlugins called")

	plugins, err := d.registryAdapter.ListPlugins(ctx)
	if err != nil {
		return nil, fmt.Errorf("list plugins: %w", err)
	}

	result := make([]api.PluginInfoInternal, len(plugins))
	for i, p := range plugins {
		endpoint := ""
		if len(p.Endpoints) > 0 {
			endpoint = p.Endpoints[0]
		}

		health := p.Health
		if health == "" {
			if p.Instances > 0 {
				health = "healthy"
			} else {
				health = "unknown"
			}
		}

		result[i] = api.PluginInfoInternal{
			ID:          p.Name,
			Name:        p.Name,
			Version:     p.Version,
			Endpoint:    endpoint,
			Description: p.Description,
			Health:      health,
			LastSeen:    time.Now(),
		}
	}

	d.logger.Debug(ctx, "listed plugins", "count", len(result))
	return result, nil
}

// QueryPlugin executes a method on a plugin via the registry adapter.
func (d *daemonImpl) QueryPlugin(ctx context.Context, name, method string, params map[string]any) (any, error) {
	d.logger.Debug(ctx, "QueryPlugin called", "plugin", name, "method", method)

	// Discover and connect to plugin via registry adapter
	pluginClient, err := d.registryAdapter.DiscoverPlugin(ctx, name)
	if err != nil {
		d.logger.Error(ctx, "failed to discover plugin", "plugin", name, "error", err)
		return nil, fmt.Errorf("failed to discover plugin %s: %w", name, err)
	}

	// Execute query via gRPC
	result, err := pluginClient.Query(ctx, method, params)
	if err != nil {
		d.logger.Error(ctx, "plugin query failed", "plugin", name, "method", method, "error", err)
		return nil, fmt.Errorf("plugin query failed: %w", err)
	}

	d.logger.Debug(ctx, "plugin query completed", "plugin", name, "method", method)
	return result, nil
}

// RunMission starts a mission and returns an event channel.
func (d *daemonImpl) RunMission(ctx context.Context, workflowPath string, missionID string, variables map[string]string, memoryContinuity string) (<-chan api.MissionEventData, error) {
	return d.RunMissionWithManager(ctx, workflowPath, missionID, variables, memoryContinuity)
}

// StopMission stops a running mission.
func (d *daemonImpl) StopMission(ctx context.Context, missionID string, force bool) error {
	d.logger.Info(ctx, "StopMission called", "mission_id", missionID, "force", force)

	// Validate mission ID
	if missionID == "" {
		return fmt.Errorf("mission ID cannot be empty")
	}

	// Lock the missions map to check if mission is running
	d.missionsMu.Lock()
	cancelFunc, exists := d.activeMissions[missionID]
	if !exists {
		d.missionsMu.Unlock()
		// Mission is not running in memory - check if it exists in the store
		missionObj, err := d.missionStore.Get(ctx, types.ID(missionID))
		if err != nil {
			// Mission not found in store either
			d.logger.Warn(ctx, "mission not found", "mission_id", missionID)
			return fmt.Errorf("mission not found: %s", missionID)
		}

		// If mission is paused (orphaned), mark it as failed to unblock future runs
		// This preserves memory for inheritance while allowing new runs to proceed
		if missionObj.Status == mission.MissionStatusPaused {
			d.logger.Info(ctx, "marking orphaned paused mission as failed", "mission_id", missionID)
			missionObj.Status = mission.MissionStatusFailed
			missionObj.CompletedAt = mission.NewUnixTimePtrNow()
			if missionObj.Metadata == nil {
				missionObj.Metadata = make(map[string]any)
			}
			missionObj.Metadata["failure_reason"] = "Orphaned paused mission - failed to resume"

			if err := d.missionStore.Update(ctx, missionObj); err != nil {
				d.logger.Error(ctx, "failed to update orphaned mission status", "error", err, "mission_id", missionID)
				return fmt.Errorf("failed to mark orphaned mission as failed: %w", err)
			}

			// Emit event for the status change
			d.publishEvent(ctx, api.EventData{
				EventType: "mission_failed",
				Timestamp: time.Now(),
				Source:    "daemon",
				MissionEvent: &api.MissionEventData{
					EventType: "mission_failed",
					Timestamp: time.Now(),
					MissionID: missionID,
					Message:   "Orphaned paused mission marked as failed",
				},
			})

			d.logger.Info(ctx, "orphaned paused mission marked as failed", "mission_id", missionID)
			return nil
		}

		// Mission exists but is not running and not paused (already terminal)
		d.logger.Info(ctx, "mission is not currently running", "mission_id", missionID)
		return fmt.Errorf("mission is not currently running: %s", missionID)
	}

	// Remove from active missions immediately to prevent duplicate stop requests
	delete(d.activeMissions, missionID)
	d.missionsMu.Unlock()

	// Cancel the mission context to trigger graceful shutdown
	d.logger.Info(ctx, "cancelling mission execution", "mission_id", missionID, "force", force)
	cancelFunc()

	// Update mission status in the store
	missionObj, err := d.missionStore.Get(ctx, types.ID(missionID))
	if err != nil {
		d.logger.Error(ctx, "failed to get mission for status update", "error", err, "mission_id", missionID)
		// Continue anyway - the cancellation was successful
	} else {
		// Update mission status to cancelled
		missionObj.Status = mission.MissionStatusCancelled
		completedAt := time.Now()
		missionObj.CompletedAt = mission.NewUnixTimePtr(&completedAt)
		if missionObj.Metrics != nil {
			missionObj.Metrics.Duration = completedAt.Sub(missionObj.Metrics.StartedAt)
		}

		if err := d.missionStore.Update(ctx, missionObj); err != nil {
			d.logger.Error(ctx, "failed to update mission status", "error", err, "mission_id", missionID)
		}
	}

	// Emit mission stopped event to all transports.
	d.publishEvent(ctx, api.EventData{
		EventType: "mission_stopped",
		Timestamp: time.Now(),
		Source:    "daemon",
		MissionEvent: &api.MissionEventData{
			EventType: "mission_stopped",
			Timestamp: time.Now(),
			MissionID: missionID,
			Message:   fmt.Sprintf("Mission %s stopped (force=%t)", missionID, force),
		},
	})

	d.logger.Info(ctx, "mission stopped successfully", "mission_id", missionID)
	return nil
}

// ListMissions returns mission list.

// RunAttack executes an attack and returns an event channel.
func (d *daemonImpl) RunAttack(ctx context.Context, req api.AttackRequest) (<-chan api.AttackEventData, error) {
	d.logger.Info(ctx, "RunAttack called",
		"target", req.Target,
		"attack_type", req.AttackType,
		"agent_id", req.AgentID)

	// Validate request
	if err := d.validateAttackRequest(req); err != nil {
		d.logger.Error(ctx, "invalid attack request", "error", err)
		return nil, fmt.Errorf("invalid attack request: %w", err)
	}

	// Check if attack runner is available
	if d.attackRunner == nil {
		d.logger.Error(ctx, "attack runner not initialized")
		return nil, fmt.Errorf("attack execution not available: runner not initialized")
	}

	// Convert API request to attack options
	attackOpts, err := d.buildAttackOptions(req)
	if err != nil {
		d.logger.Error(ctx, "failed to build attack options", "error", err)
		return nil, fmt.Errorf("failed to build attack options: %w", err)
	}

	// Create event channel for streaming attack progress
	eventChan := make(chan api.AttackEventData, 100)

	// Execute attack in goroutine
	go func() {
		defer close(eventChan)

		// Generate unique attack ID
		attackID := types.NewID().String()

		// Send attack started event with resolved target URL
		eventChan <- api.AttackEventData{
			EventType: "attack.started",
			Timestamp: time.Now(),
			AttackID:  attackID,
			Message:   fmt.Sprintf("Starting attack on %s with agent %s", attackOpts.TargetURL, req.AgentID),
		}

		d.logger.Info(ctx, "executing attack",
			"attack_id", attackID,
			"target_url", attackOpts.TargetURL,
			"target_name", attackOpts.TargetName,
			"agent", attackOpts.AgentName)

		// Execute attack through runner
		result, err := d.attackRunner.Run(ctx, attackOpts)
		if err != nil {
			d.logger.Error(ctx, "attack execution failed", "error", err, "attack_id", attackID)
			eventChan <- api.AttackEventData{
				EventType: "attack.failed",
				Timestamp: time.Now(),
				AttackID:  attackID,
				Message:   "Attack execution failed",
				Error:     err.Error(),
			}
			return
		}

		// Send progress events for findings
		for _, f := range result.Findings {
			eventChan <- api.AttackEventData{
				EventType: "attack.finding",
				Timestamp: time.Now(),
				AttackID:  attackID,
				Message:   fmt.Sprintf("Found %s severity finding: %s", f.Severity, f.Title),
				Finding: &api.FindingData{
					ID:          f.ID.String(),
					Title:       f.Title,
					Severity:    string(f.Severity),
					Category:    f.Category,
					Description: f.Description,
					Technique:   "", // Not available in EnhancedFinding
					Evidence:    formatEvidence(f.Evidence),
					Timestamp:   f.CreatedAt,
				},
			}
		}

		// Send attack completed event with typed OperationResult
		now := time.Now()
		startTime := now.Add(-result.Duration)

		// Create typed operation result
		operationResult := &daemonpb.OperationResult{
			Status:        string(result.Status),
			DurationMs:    result.Duration.Milliseconds(),
			StartedAt:     startTime.UnixMilli(),
			CompletedAt:   now.UnixMilli(),
			TurnsUsed:     int32(result.TurnsUsed),
			TokensUsed:    result.TokensUsed,
			FindingsCount: int32(len(result.Findings)),
		}

		// Populate severity counts from FindingsBySeverity map
		if count, ok := result.FindingsBySeverity["critical"]; ok {
			operationResult.CriticalCount = int32(count)
		}
		if count, ok := result.FindingsBySeverity["high"]; ok {
			operationResult.HighCount = int32(count)
		}
		if count, ok := result.FindingsBySeverity["medium"]; ok {
			operationResult.MediumCount = int32(count)
		}
		if count, ok := result.FindingsBySeverity["low"]; ok {
			operationResult.LowCount = int32(count)
		}

		// Add error information if present
		if result.Error != nil {
			operationResult.ErrorMessage = result.Error.Error()
		}

		eventChan <- api.AttackEventData{
			EventType: "attack.completed",
			Timestamp: now,
			AttackID:  attackID,
			Message:   fmt.Sprintf("Attack completed: %d findings discovered", len(result.Findings)),
			Data:      "", // Empty - using typed Result now
			Result:    operationResult,
		}

		d.logger.Info(ctx, "attack completed",
			"attack_id", attackID,
			"status", result.Status,
			"findings", len(result.Findings),
			"duration", result.Duration)
	}()

	return eventChan, nil
}

// validateAttackRequest validates the attack request parameters.
func (d *daemonImpl) validateAttackRequest(req api.AttackRequest) error {
	// Require either target or target_name
	if req.Target == "" && req.TargetName == "" {
		return fmt.Errorf("either target or target_name is required")
	}

	// Don't allow both to be set (user should choose one approach)
	if req.Target != "" && req.TargetName != "" {
		return fmt.Errorf("cannot specify both target and target_name")
	}

	if req.AgentID == "" {
		return fmt.Errorf("agent ID is required")
	}

	return nil
}

// buildAttackOptions converts API AttackRequest to internal AttackOptions.
func (d *daemonImpl) buildAttackOptions(req api.AttackRequest) (*attack.AttackOptions, error) {
	opts := attack.NewAttackOptions()

	// Target resolution: stored targets only (security guardrail)
	if req.TargetName == "" {
		return nil, fmt.Errorf("target name is required: use 'gibson target add' to create a target, then reference it with --target <name>")
	}

	// Look up target from database by name
	target, err := d.targetStore.GetByName(context.Background(), req.TargetName)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup target '%s': %w", req.TargetName, err)
	}

	// Extract URL from connection JSON (optional for some target types like 'network')
	targetURL := target.GetURL()

	// Set target options from stored target
	opts.TargetID = target.ID
	opts.TargetName = target.Name
	opts.TargetURL = targetURL // May be empty for non-URL-based targets (e.g., network)
	opts.TargetType = types.TargetType(target.Type)

	// Set credential if target has one configured
	if target.CredentialID != nil {
		opts.Credential = target.CredentialID.String()
	}

	opts.AgentName = req.AgentID

	// Apply payload filter if specified
	if req.PayloadFilter != "" {
		opts.PayloadCategory = req.PayloadFilter
	}

	// Apply additional options from the options map
	if req.Options != nil {
		if maxTurns, ok := req.Options["max_turns"]; ok {
			var turns int
			fmt.Sscanf(maxTurns, "%d", &turns)
			opts.MaxTurns = turns
		}

		if timeout, ok := req.Options["timeout"]; ok {
			var duration time.Duration
			duration, err := time.ParseDuration(timeout)
			if err == nil {
				opts.Timeout = duration
			}
		}

		if verbose, ok := req.Options["verbose"]; ok && verbose == "true" {
			opts.Verbose = true
		}

		if dryRun, ok := req.Options["dry_run"]; ok && dryRun == "true" {
			opts.DryRun = true
		}
	}

	return opts, nil
}

// Subscribe establishes an event stream.
//
// When redisEventStream is available it uses Redis Streams (XREAD BLOCK) as
// the transport, which allows events to survive daemon restarts and be shared
// across multiple daemon pods. The tenant is extracted from the request context
// via auth.TenantFromContext; "default" is used when no tenant is present.
//
// When redisEventStream is nil (e.g., during unit tests that use a lightweight
// daemon without Redis) the implementation falls back to the in-process
// EventBus for full backwards compatibility.
func (d *daemonImpl) Subscribe(ctx context.Context, eventTypes []string, missionID string) (<-chan api.EventData, error) {
	d.logger.Info(ctx, "Subscribe called", "event_types", eventTypes, "mission_id", missionID)

	// Use Redis Streams when available: this is the production path.
	if d.redisEventStream != nil {
		tenant := auth.TenantFromContext(ctx)
		if tenant == "" {
			tenant = "default"
		}

		redisChan, err := d.redisEventStream.SubscribeStream(ctx, tenant, eventTypes, missionID)
		if err != nil {
			// Log and fall through to EventBus fallback.
			d.logger.Warn(ctx, "redis stream subscribe failed, falling back to eventbus",
				"error", err)
		} else {
			d.logger.Info(ctx, "subscription established via redis streams",
				"tenant", tenant, "mission_id", missionID)
			return redisChan, nil
		}
	}

	// Fallback: in-process EventBus (no Redis, unit-test scenario).
	eventChan, cleanup := d.eventBus.Subscribe(ctx, eventTypes, missionID)

	go func() {
		<-ctx.Done()
		cleanup()
		d.logger.Info(ctx, "eventbus subscription cleanup completed", "mission_id", missionID)
	}()

	return eventChan, nil
}

// publishEvent writes an event to both the in-process EventBus and, when
// redisEventStream is available, the tenant-scoped Redis Stream.
//
// It extracts the tenant from the context (auth.TenantFromContext) and falls
// back to "default" when none is present.  Errors from either transport are
// logged as warnings but do not propagate — event publishing is best-effort.
func (d *daemonImpl) publishEvent(ctx context.Context, event api.EventData) {
	// In-process EventBus (always present; used by in-process subscribers and tests).
	if d.eventBus != nil {
		if err := d.eventBus.Publish(ctx, event); err != nil {
			d.logger.Warn(ctx, "failed to publish to eventbus", "error", err, "event_type", event.EventType)
		}
	}

	// Redis Streams (optional; available after stateClient is initialized).
	if d.redisEventStream != nil {
		tenant := auth.TenantFromContext(ctx)
		if tenant == "" {
			tenant = "default"
		}
		if err := d.redisEventStream.PublishEvent(ctx, tenant, event); err != nil {
			d.logger.Warn(ctx, "failed to publish to redis stream", "error", err, "event_type", event.EventType)
		}
	}
}

// formatEvidence converts a slice of Evidence to a string representation.
func formatEvidence(evidence []agent.Evidence) string {
	if len(evidence) == 0 {
		return ""
	}
	var parts []string
	for _, e := range evidence {
		parts = append(parts, fmt.Sprintf("[%s] %s", e.Type, e.Description))
	}
	return strings.Join(parts, "; ")
}

// StartComponent is not supported; component lifecycle management has been removed.
func (d *daemonImpl) StartComponent(ctx context.Context, kind string, name string) (api.StartComponentResult, error) {
	d.logger.Warn(ctx, "StartComponent called but component store has been removed", "kind", kind, "name", name)
	return api.StartComponentResult{}, fmt.Errorf("component lifecycle management is not available")
}

// StopComponent is not supported; component lifecycle management has been removed.
func (d *daemonImpl) StopComponent(ctx context.Context, kind string, name string, force bool) (api.StopComponentResult, error) {
	d.logger.Warn(ctx, "StopComponent called but component store has been removed", "kind", kind, "name", name)
	return api.StopComponentResult{}, fmt.Errorf("component lifecycle management is not available")
}

// PauseMission pauses a running mission at the next clean checkpoint boundary.
func (d *daemonImpl) PauseMission(ctx context.Context, missionID string, force bool) error {
	d.logger.Info(ctx, "PauseMission called", "mission_id", missionID, "force", force)

	// Validate mission ID
	if missionID == "" {
		return fmt.Errorf("mission ID cannot be empty")
	}

	// Initialize mission manager if not already done
	if err := d.ensureMissionManager(); err != nil {
		d.logger.Error(ctx, "failed to initialize mission manager", "error", err)
		return fmt.Errorf("failed to initialize mission manager: %w", err)
	}

	// Call mission manager's pause method
	if err := d.missionManager.Pause(ctx, missionID, force); err != nil {
		d.logger.Error(ctx, "failed to pause mission", "error", err, "mission_id", missionID)
		return fmt.Errorf("failed to pause mission: %w", err)
	}

	d.logger.Info(ctx, "mission paused successfully", "mission_id", missionID)
	return nil
}

// ResumeMission resumes a paused mission from its last checkpoint.
func (d *daemonImpl) ResumeMission(ctx context.Context, missionID string) (<-chan api.MissionEventData, error) {
	d.logger.Info(ctx, "ResumeMission called", "mission_id", missionID)

	// Validate mission ID
	if missionID == "" {
		return nil, fmt.Errorf("mission ID cannot be empty")
	}

	// Initialize mission manager if not already done
	if err := d.ensureMissionManager(); err != nil {
		d.logger.Error(ctx, "failed to initialize mission manager", "error", err)
		return nil, fmt.Errorf("failed to initialize mission manager: %w", err)
	}

	// Call mission manager's resume method
	eventChan, err := d.missionManager.Resume(ctx, missionID)
	if err != nil {
		d.logger.Error(ctx, "failed to resume mission", "error", err, "mission_id", missionID)
		return nil, fmt.Errorf("failed to resume mission: %w", err)
	}

	d.logger.Info(ctx, "mission resume started", "mission_id", missionID)
	return eventChan, nil
}

// GetMissionHistory returns all runs for a mission name.
func (d *daemonImpl) GetMissionHistory(ctx context.Context, name string, limit int, offset int) ([]api.MissionRunData, int, error) {
	d.logger.Debug(ctx, "GetMissionHistory called", "name", name, "limit", limit, "offset", offset)

	// Validate name
	if name == "" {
		return nil, 0, fmt.Errorf("mission name cannot be empty")
	}

	// Check if run store is available
	if d.missionRunStore == nil {
		d.logger.Warn(ctx, "mission run store not initialized")
		return []api.MissionRunData{}, 0, nil
	}

	// Get the mission by name to find its ID
	m, err := d.missionStore.GetByName(ctx, name)
	if err != nil {
		if mission.IsNotFoundError(err) {
			d.logger.Debug(ctx, "mission not found", "name", name)
			return []api.MissionRunData{}, 0, nil
		}
		d.logger.Error(ctx, "failed to get mission", "error", err, "name", name)
		return nil, 0, fmt.Errorf("failed to get mission: %w", err)
	}

	// Get all runs for this mission
	missionRuns, err := d.missionRunStore.ListByMission(ctx, m.ID)
	if err != nil {
		d.logger.Error(ctx, "failed to list mission runs", "error", err, "mission_id", m.ID)
		return nil, 0, fmt.Errorf("failed to list mission runs: %w", err)
	}

	// Apply pagination
	total := len(missionRuns)
	if offset >= total {
		return []api.MissionRunData{}, total, nil
	}

	end := offset + limit
	if end > total {
		end = total
	}
	if limit == 0 {
		end = total
	}

	pagedRuns := missionRuns[offset:end]

	// Extract trace ID from mission metadata (written at mission start)
	traceID := ""
	if m.Metadata != nil {
		if v, ok := m.Metadata["trace_id"].(string); ok {
			traceID = v
		}
	}

	// Convert to API format
	runs := make([]api.MissionRunData, len(pagedRuns))
	for i, r := range pagedRuns {
		completedAt := int64(0)
		if r.CompletedAt != nil {
			completedAt = r.CompletedAt.Unix()
		}

		startedAt := int64(0)
		if r.StartedAt != nil {
			startedAt = r.StartedAt.Unix()
		}

		runs[i] = api.MissionRunData{
			RunID:         r.ID.String(),
			MissionID:     r.MissionID.String(),
			RunNumber:     r.RunNumber,
			Status:        string(r.Status),
			Progress:      r.Progress,
			CreatedAt:     r.CreatedAt.Unix(),
			StartedAt:     startedAt,
			CompletedAt:   completedAt,
			FindingsCount: r.FindingsCount,
			Error:         r.Error,
			TraceID:       traceID,
		}
	}

	d.logger.Debug(ctx, "mission history retrieved", "name", name, "count", len(runs), "total", total)
	return runs, total, nil
}

// GetMissionCheckpoints returns all checkpoints for a mission.
func (d *daemonImpl) GetMissionCheckpoints(ctx context.Context, missionID string) ([]api.CheckpointData, error) {
	d.logger.Debug(ctx, "GetMissionCheckpoints called", "mission_id", missionID)

	// Validate mission ID
	if missionID == "" {
		return nil, fmt.Errorf("mission ID cannot be empty")
	}

	// Get the mission from the store
	m, err := d.missionStore.Get(ctx, types.ID(missionID))
	if err != nil {
		d.logger.Error(ctx, "failed to get mission", "error", err, "mission_id", missionID)
		return nil, fmt.Errorf("failed to get mission: %w", err)
	}

	// Check if mission has a checkpoint
	if m.Checkpoint == nil {
		d.logger.Debug(ctx, "no checkpoints found for mission", "mission_id", missionID)
		return []api.CheckpointData{}, nil
	}

	// Convert checkpoint to CheckpointData
	// Calculate total nodes from metrics if available
	totalNodes := 0
	findingsCount := 0
	if m.Metrics != nil {
		totalNodes = m.Metrics.TotalNodes
		findingsCount = m.Metrics.TotalFindings
	}

	checkpoint := api.CheckpointData{
		CheckpointID:   m.Checkpoint.ID.String(),
		CreatedAt:      m.Checkpoint.CheckpointedAt.Unix(),
		CompletedNodes: len(m.Checkpoint.CompletedNodes),
		TotalNodes:     totalNodes,
		FindingsCount:  findingsCount,
		Version:        m.Checkpoint.Version,
	}

	d.logger.Debug(ctx, "mission checkpoints retrieved", "mission_id", missionID, "count", 1)
	return []api.CheckpointData{checkpoint}, nil
}

// InstallComponent is not supported; component installation has been removed.
func (d *daemonImpl) InstallComponent(ctx context.Context, kind string, url string, branch string, tag string, force bool, skipBuild bool, verbose bool) (api.InstallComponentResult, error) {
	d.logger.Warn(ctx, "InstallComponent called but component installer has been removed", "kind", kind, "url", url)
	return api.InstallComponentResult{}, fmt.Errorf("component installation is not available")
}

// InstallAllComponent is not supported; component installation has been removed.
func (d *daemonImpl) InstallAllComponent(ctx context.Context, kind string, url string, branch string, tag string, force bool, skipBuild bool, verbose bool) (api.InstallAllComponentResult, error) {
	d.logger.Warn(ctx, "InstallAllComponent called but component installer has been removed", "kind", kind, "url", url)
	return api.InstallAllComponentResult{}, fmt.Errorf("component installation is not available")
}

// UninstallComponent is not supported; component installation has been removed.
func (d *daemonImpl) UninstallComponent(ctx context.Context, kind string, name string, force bool) error {
	d.logger.Warn(ctx, "UninstallComponent called but component installer has been removed", "kind", kind, "name", name)
	return fmt.Errorf("component installation is not available")
}

// UpdateComponent is not supported; component installation has been removed.
func (d *daemonImpl) UpdateComponent(ctx context.Context, kind string, name string, restart bool, skipBuild bool, verbose bool) (api.UpdateComponentResult, error) {
	d.logger.Warn(ctx, "UpdateComponent called but component installer has been removed", "kind", kind, "name", name)
	return api.UpdateComponentResult{}, fmt.Errorf("component installation is not available")
}

// BuildComponent is not supported; component store has been removed.
func (d *daemonImpl) BuildComponent(ctx context.Context, kind string, name string) (api.BuildComponentResult, error) {
	d.logger.Warn(ctx, "BuildComponent called but component store has been removed", "kind", kind, "name", name)
	return api.BuildComponentResult{}, fmt.Errorf("component build is not available")
}

// ShowComponent is not supported; component store has been removed.
func (d *daemonImpl) ShowComponent(ctx context.Context, kind string, name string) (api.ComponentInfoInternal, error) {
	d.logger.Warn(ctx, "ShowComponent called but component store has been removed", "kind", kind, "name", name)
	return api.ComponentInfoInternal{}, fmt.Errorf("component store is not available")
}

// GetComponentLogs streams log entries for a component using the log tailer.
func (d *daemonImpl) GetComponentLogs(ctx context.Context, kind string, name string, follow bool, lines int) (<-chan api.LogEntryData, error) {
	d.logger.Debug(ctx, "GetComponentLogs called", "kind", kind, "name", name, "follow", follow, "lines", lines)

	// Construct log file path: ~/.gibson/logs/<component-name>.log
	logDir := filepath.Join(d.config.Core.HomeDir, "logs")
	logFilePath := filepath.Join(logDir, fmt.Sprintf("%s.log", name))

	// Check if log file exists
	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		d.logger.Warn(ctx, "log file does not exist", "path", logFilePath)
		return nil, fmt.Errorf("log file not found for component '%s'", name)
	}

	// Use LogTailer if available, otherwise fall back to simple implementation
	if d.logTailer != nil {
		return d.getComponentLogsWithTailer(ctx, name, logFilePath, follow, lines)
	}

	// Fallback: simple file reading (for backward compatibility)
	return d.getComponentLogsSimple(ctx, name, logFilePath, follow, lines)
}

// getComponentLogsWithTailer uses the LogTailer for efficient log streaming with fsnotify.
func (d *daemonImpl) getComponentLogsWithTailer(ctx context.Context, componentName string, logFilePath string, follow bool, lines int) (<-chan api.LogEntryData, error) {
	// Start watching this component if not already watching
	if !d.logTailer.IsWatching(componentName) {
		if err := d.logTailer.StartWatching(componentName, logFilePath); err != nil {
			d.logger.Error(ctx, "failed to start watching component logs", "error", err, "component", componentName)
			return nil, fmt.Errorf("failed to start watching logs: %w", err)
		}
	}

	// Create subscription options
	opts := SubscribeOptions{
		ComponentIDs: []string{componentName},
		Follow:       follow,
		TailLines:    lines,
	}

	// Subscribe to log entries
	sub, err := d.logTailer.Subscribe(ctx, opts)
	if err != nil {
		d.logger.Error(ctx, "failed to subscribe to component logs", "error", err, "component", componentName)
		return nil, fmt.Errorf("failed to subscribe to logs: %w", err)
	}

	// Create output channel
	logChan := make(chan api.LogEntryData, 100)

	// Start goroutine to convert LogEntry to api.LogEntryData
	go func() {
		defer close(logChan)
		defer d.logTailer.Unsubscribe(sub)

		for {
			select {
			case <-ctx.Done():
				return
			case entry, ok := <-sub.Output:
				if !ok {
					// Subscription closed
					return
				}

				// Convert LogEntry to api.LogEntryData
				logChan <- api.LogEntryData{
					Timestamp: entry.Timestamp.Unix(),
					Level:     entry.Level,
					Message:   entry.Message,
				}
			}
		}
	}()

	return logChan, nil
}

// getComponentLogsSimple provides a simple fallback implementation without LogTailer.
func (d *daemonImpl) getComponentLogsSimple(ctx context.Context, componentName string, logFilePath string, follow bool, lines int) (<-chan api.LogEntryData, error) {
	// Create channel for streaming logs
	logChan := make(chan api.LogEntryData, 100)

	// Start goroutine to read and stream logs
	go func() {
		defer close(logChan)

		// Open log file
		file, err := os.Open(logFilePath)
		if err != nil {
			d.logger.Error(ctx, "failed to open log file", "error", err, "path", logFilePath)
			return
		}
		defer file.Close()

		// Read all lines
		scanner := bufio.NewScanner(file)
		var logLines []string
		for scanner.Scan() {
			logLines = append(logLines, scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			d.logger.Error(ctx, "error reading log file", "error", err, "path", logFilePath)
			return
		}

		// Determine which lines to send based on lines parameter
		startIdx := 0
		if lines > 0 && len(logLines) > lines {
			startIdx = len(logLines) - lines
		}

		// Send initial lines
		for i := startIdx; i < len(logLines); i++ {
			select {
			case <-ctx.Done():
				return
			case logChan <- api.LogEntryData{
				Timestamp: time.Now().Unix(),
				Level:     "info",
				Message:   logLines[i],
			}:
			}
		}

		// If follow mode not requested, we're done
		if !follow {
			return
		}

		// Simple polling for follow mode
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		lastSize, _ := file.Seek(0, io.SeekCurrent)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Check if file has grown
				fileInfo, err := os.Stat(logFilePath)
				if err != nil {
					d.logger.Error(ctx, "error checking log file", "error", err)
					return
				}

				currentSize := fileInfo.Size()
				if currentSize > lastSize {
					// Read new content
					file.Seek(lastSize, 0)
					scanner := bufio.NewScanner(file)
					for scanner.Scan() {
						select {
						case <-ctx.Done():
							return
						case logChan <- api.LogEntryData{
							Timestamp: time.Now().Unix(),
							Level:     "info",
							Message:   scanner.Text(),
						}:
						}
					}
					lastSize = currentSize
				}
			}
		}
	}()

	return logChan, nil
}

// InstallMission installs a mission from a git repository.
func (d *daemonImpl) InstallMission(ctx context.Context, url string, branch string, tag string, force bool, yes bool, timeoutMs int64) (api.InstallMissionResult, error) {
	d.logger.Warn(ctx, "InstallMission called but mission installer has been removed", "url", url)
	return api.InstallMissionResult{}, fmt.Errorf("mission installation is not available")
}

// UninstallMission is not supported; mission installer has been removed.
func (d *daemonImpl) UninstallMission(ctx context.Context, name string, force bool) error {
	d.logger.Warn(ctx, "UninstallMission called but mission installer has been removed", "name", name)
	return fmt.Errorf("mission installation is not available")
}

// ListMissionDefinitions returns all installed mission definitions.
func (d *daemonImpl) ListMissionDefinitions(ctx context.Context, limit int, offset int) ([]api.MissionDefinitionData, int, error) {
	d.logger.Debug(ctx, "ListMissionDefinitions called", "limit", limit, "offset", offset)

	if d.missionStore == nil {
		d.logger.Warn(ctx, "mission store not available, returning empty list")
		return []api.MissionDefinitionData{}, 0, nil
	}

	defs, err := d.missionStore.ListDefinitions(ctx)
	if err != nil {
		d.logger.Error(ctx, "failed to list mission definitions", "error", err)
		return nil, 0, fmt.Errorf("failed to list mission definitions: %w", err)
	}

	total := len(defs)

	// Apply offset and limit for pagination
	if offset > total {
		offset = total
	}
	defs = defs[offset:]
	if limit > 0 && len(defs) > limit {
		defs = defs[:limit]
	}

	result := make([]api.MissionDefinitionData, 0, len(defs))
	for _, def := range defs {
		nodeCount := len(def.Nodes)
		result = append(result, api.MissionDefinitionData{
			Name:        def.Name,
			Version:     def.Version,
			Description: def.Description,
			Source:      def.Source,
			InstalledAt: def.InstalledAt,
			NodeCount:   nodeCount,
		})
	}

	d.logger.Debug(ctx, "listed mission definitions", "count", len(result), "total", total)
	return result, total, nil
}

// UpdateMission is not supported; mission installer has been removed.
func (d *daemonImpl) UpdateMission(ctx context.Context, name string, timeoutMs int64) (api.UpdateMissionResult, error) {
	d.logger.Warn(ctx, "UpdateMission called but mission installer has been removed", "name", name)
	return api.UpdateMissionResult{}, fmt.Errorf("mission installation is not available")
}

// ResolveMissionDependencies is not supported; dependency resolver has been removed.
func (d *daemonImpl) ResolveMissionDependencies(ctx context.Context, missionPath string) (api.DependencyTreeData, error) {
	d.logger.Warn(ctx, "ResolveMissionDependencies called but dependency resolver has been removed", "mission_path", missionPath)
	return api.DependencyTreeData{}, fmt.Errorf("dependency resolver is not available")
}

// ValidateMissionDependencies is not supported; dependency resolver has been removed.
func (d *daemonImpl) ValidateMissionDependencies(ctx context.Context, missionPath string) (api.ValidationResultData, error) {
	d.logger.Warn(ctx, "ValidateMissionDependencies called but dependency resolver has been removed", "mission_path", missionPath)
	return api.ValidationResultData{}, fmt.Errorf("dependency resolver is not available")
}

// EnsureMissionDependencies is not supported; dependency resolver has been removed.
func (d *daemonImpl) EnsureMissionDependencies(ctx context.Context, missionPath string) error {
	d.logger.Warn(ctx, "EnsureMissionDependencies called but dependency resolver has been removed", "mission_path", missionPath)
	return fmt.Errorf("dependency resolver is not available")
}

// CreateMission creates a new mission with target and workflow configuration.
// Supports both referenced and inline target/workflow configurations.
func (d *daemonImpl) CreateMission(ctx context.Context, req api.CreateMissionData) (api.CreateMissionResultData, error) {
	d.logger.Info(ctx, "CreateMission called",
		"name", req.Name,
		"has_target_id", req.TargetID != "",
		"has_inline_target", req.InlineTarget != nil,
		"has_workflow_id", req.WorkflowID != "",
		"has_inline_workflow", req.InlineWorkflow != nil,
	)

	// Build MissionConfig from API request
	missionConfig := &mission.MissionConfig{
		Name:        req.Name,
		Description: req.Description,
	}

	// Handle target configuration
	if req.TargetID != "" {
		missionConfig.Target.Reference = req.TargetID
	} else if req.InlineTarget != nil {
		// Convert API inline target to mission inline target config
		seeds := make([]*mission.TargetSeedConfig, len(req.InlineTarget.Seeds))
		for i, s := range req.InlineTarget.Seeds {
			seeds[i] = &mission.TargetSeedConfig{
				Value: s.Value,
				Type:  s.Type,
				Scope: s.Scope,
			}
		}
		missionConfig.Target.Inline = &mission.InlineTargetConfig{
			Seeds:    seeds,
			Profile:  req.InlineTarget.Profile,
			Depth:    req.InlineTarget.Depth,
			Excluded: req.InlineTarget.Excluded,
			Metadata: req.InlineTarget.Metadata,
		}
	} else {
		d.logger.Error(ctx, "no target configuration provided")
		return api.CreateMissionResultData{}, fmt.Errorf("target configuration is required (target_id or inline_target)")
	}

	// Handle workflow configuration
	if req.WorkflowID != "" {
		missionConfig.Workflow.Reference = req.WorkflowID
	} else if req.InlineWorkflow != nil {
		// Convert API inline workflow to mission inline workflow config
		nodes := make([]*mission.WorkflowNodeConfig, len(req.InlineWorkflow.Nodes))
		for i, n := range req.InlineWorkflow.Nodes {
			// Convert map[string]any to map[string]string for config
			var config map[string]string
			if n.Config != nil {
				config = make(map[string]string, len(n.Config))
				for k, v := range n.Config {
					if str, ok := v.(string); ok {
						config[k] = str
					} else {
						config[k] = fmt.Sprintf("%v", v)
					}
				}
			}
			nodes[i] = &mission.WorkflowNodeConfig{
				ID:        n.ID,
				Type:      n.Type,
				Name:      n.Name,
				DependsOn: n.DependsOn,
				Config:    config,
			}
		}
		edges := make([]*mission.WorkflowEdgeConfig, len(req.InlineWorkflow.Edges))
		for i, e := range req.InlineWorkflow.Edges {
			edges[i] = &mission.WorkflowEdgeConfig{
				From:      e.From,
				To:        e.To,
				Condition: e.Condition,
			}
		}
		missionConfig.Workflow.Inline = &mission.InlineWorkflowConfig{
			Name:     req.InlineWorkflow.Name,
			Nodes:    nodes,
			Edges:    edges,
			Metadata: req.InlineWorkflow.Metadata,
		}
	} else {
		d.logger.Error(ctx, "no workflow configuration provided")
		return api.CreateMissionResultData{}, fmt.Errorf("workflow configuration is required (workflow_id or inline_workflow)")
	}

	// Initialize mission service if needed
	if d.missionService == nil {
		d.logger.Error(ctx, "mission service not available")
		return api.CreateMissionResultData{}, fmt.Errorf("mission service not initialized")
	}

	// Create mission using the service
	m, err := d.missionService.CreateFromConfig(ctx, missionConfig)
	if err != nil {
		d.logger.Error(ctx, "failed to create mission", "error", err, "name", req.Name)
		return api.CreateMissionResultData{}, fmt.Errorf("failed to create mission: %w", err)
	}

	d.logger.Info(ctx, "mission created successfully",
		"mission_id", m.ID.String(),
		"target_id", m.TargetID.String(),
		"workflow_id", m.WorkflowID.String(),
	)

	return api.CreateMissionResultData{
		MissionID:   m.ID.String(),
		TargetID:    m.TargetID.String(),
		WorkflowID:  m.WorkflowID.String(),
		Name:        m.Name,
		Description: m.Description,
		Status:      string(m.Status),
		CreatedAt:   m.CreatedAt.Time,
	}, nil
}

// tenantCreatorAdapter wraps *component.TenantService to satisfy the
// provisioner.TenantCreator interface, which returns (interface{}, error)
// rather than (*component.TenantRecord, error).
type tenantCreatorAdapter struct {
	svc *component.TenantService
}

func (a *tenantCreatorAdapter) CreateTenant(ctx context.Context, tenantID, displayName string, config map[string]string) (interface{}, error) {
	return a.svc.CreateTenant(ctx, tenantID, displayName, config)
}

func (a *tenantCreatorAdapter) GetTenant(ctx context.Context, tenantID string) (interface{}, error) {
	return a.svc.GetTenant(ctx, tenantID)
}

func (a *tenantCreatorAdapter) UpdateTenant(ctx context.Context, tenantID string, updates map[string]string) (interface{}, error) {
	return a.svc.UpdateTenant(ctx, tenantID, updates)
}

// apiKeyCreatorAdapter wraps *auth.APIKeyAuthenticator to satisfy the
// provisioner.APIKeyCreator interface, which returns (rawKey, interface{}, error)
// rather than (rawKey, *auth.APIKeyRecord, error).
type apiKeyCreatorAdapter struct {
	auth *auth.APIKeyAuthenticator
}

func (a *apiKeyCreatorAdapter) CreateKey(ctx context.Context, tenantID string, allowedKinds, allowedNames []string, capabilities []string, name, createdBy string) (string, interface{}, error) {
	return a.auth.CreateKey(ctx, tenantID, allowedKinds, allowedNames, capabilities, name, createdBy)
}
