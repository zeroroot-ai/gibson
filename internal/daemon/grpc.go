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
	componentpb "github.com/zero-day-ai/gibson/api/gen/componentpb"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/attack"
	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/component/build"
	"github.com/zero-day-ai/gibson/internal/daemon/api"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/types"
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

	// Build server options with optional auth interceptors
	serverOpts := []grpc.ServerOption{}

	// Add auth interceptors if authentication is enabled
	if d.config.Auth.Enabled {
		d.logger.Info(ctx, "authentication enabled, installing auth interceptors")

		// Create authenticator from config
		authenticator, err := d.createAuthenticator(ctx)
		if err != nil {
			return fmt.Errorf("failed to create authenticator: %w", err)
		}

		// Create auth interceptors
		unaryAuthInterceptor := auth.UnaryAuthInterceptor(authenticator, &d.config.Auth, d.logger.Slog())
		streamAuthInterceptor := auth.StreamAuthInterceptor(authenticator, &d.config.Auth, d.logger.Slog())

		// Add interceptors to server options
		// Auth interceptors should run before other interceptors (like tracing)
		serverOpts = append(serverOpts,
			grpc.UnaryInterceptor(unaryAuthInterceptor),
			grpc.StreamInterceptor(streamAuthInterceptor),
		)

		d.logger.Info(ctx, "auth interceptors installed",
			"trust_localhost", d.config.Auth.TrustLocalhost,
			"oidc_issuers", len(d.config.Auth.OIDC),
		)
	} else {
		d.logger.Info(ctx, "authentication disabled")
	}

	// Create gRPC server with options
	srv := grpc.NewServer(serverOpts...)
	d.grpcServer = srv

	// Create and register daemon service
	daemonSvc := api.NewDaemonServer(d, d.credentialHandler, d.logger.Slog())
	api.RegisterDaemonServiceServer(srv, daemonSvc)

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
	// Harness proxy dependencies (llmCompleter, memStore, findingSubmitter) are
	// wired as nil until tasks 5.4-5.5 connect those subsystems.
	if d.stateClient != nil {
		if redisClient, ok := d.stateClient.Client().(*goredis.Client); ok {
			compRegistry := component.NewRedisComponentRegistry(redisClient, 30*time.Second)
			compQueue := component.NewRedisWorkQueue(d.stateClient.Client())
			compSvc := component.NewComponentServiceServer(
				compRegistry,
				compQueue,
				d.logger.Slog(),
				nil, // llmCompleter: wired in task 5.4
				nil, // memStore:     wired in task 5.4
				nil, // findingSubmitter: wired in task 5.5
			)
			componentpb.RegisterComponentServiceServer(srv, compSvc)
			d.logger.Info(ctx, "ComponentService initialized",
				"registry_ttl", "30s",
				"redis_mode", "standalone",
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

// ListAgents returns all agents from both the component store and the registry.
// This includes agents installed via CLI and agents running in Kubernetes/containers
// that registered directly with the registry.
func (d *daemonImpl) ListAgents(ctx context.Context, kind string) ([]api.AgentInfoInternal, error) {
	d.logger.Debug(ctx, "ListAgents called", "kind", kind)

	// Track agents by name to avoid duplicates
	agentMap := make(map[string]api.AgentInfoInternal)

	// Query component store for installed agents (if available)
	if d.componentStore != nil {
		agents, err := d.componentStore.List(ctx, component.ComponentKindAgent)
		if err != nil {
			d.logger.Warn(ctx, "failed to list agents from component store", "error", err)
			// Continue - we can still list agents from registry
		} else {
			for _, agent := range agents {
				agentMap[agent.Name] = api.AgentInfoInternal{
					ID:       agent.Name,
					Name:     agent.Name,
					Kind:     "agent",
					Version:  agent.Version,
					Health:   "unknown", // Will be updated to "healthy" if running
					LastSeen: agent.UpdatedAt,
				}
			}
		}
	}

	// Query registry for running agents
	if d.registryAdapter != nil {
		running, err := d.registryAdapter.ListAgents(ctx)
		if err != nil {
			d.logger.Warn(ctx, "failed to list agents from registry", "error", err)
		} else {
			for _, r := range running {
				endpoint := ""
				if len(r.Endpoints) > 0 {
					endpoint = r.Endpoints[0]
				}

				// Get runtime state for last seen time
				runtimeState := d.getAgentState(r.Name)
				lastSeen := time.Now()
				if runtimeState != nil && !runtimeState.LastHeartbeat.IsZero() {
					lastSeen = runtimeState.LastHeartbeat
				}

				if existing, ok := agentMap[r.Name]; ok {
					// Update existing agent with running info
					// Use health from registry (aggregated across instances)
					existing.Health = r.Health
					if existing.Health == "" {
						existing.Health = "healthy" // Default for running agents
					}
					existing.Endpoint = endpoint
					existing.LastSeen = lastSeen
					if r.Version != "" {
						existing.Version = r.Version
					}
					agentMap[r.Name] = existing
				} else {
					// Add agent that's only in registry (e.g., K8s deployed agent)
					health := r.Health
					if health == "" {
						health = "healthy" // Default for running agents
					}
					agentMap[r.Name] = api.AgentInfoInternal{
						ID:           r.Name,
						Name:         r.Name,
						Kind:         "agent",
						Version:      r.Version,
						Endpoint:     endpoint,
						Capabilities: r.Capabilities,
						Health:       health,
						LastSeen:     lastSeen,
					}
				}
			}
		}
	}

	// Convert map to slice
	result := make([]api.AgentInfoInternal, 0, len(agentMap))
	for _, agent := range agentMap {
		result = append(result, agent)
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

// ListTools returns all installed tools from the component store.
func (d *daemonImpl) ListTools(ctx context.Context) ([]api.ToolInfoInternal, error) {
	d.logger.Debug(ctx, "ListTools called")

	if d.componentStore == nil {
		return nil, fmt.Errorf("component store not available")
	}

	// Query component store for installed tools
	tools, err := d.componentStore.List(ctx, component.ComponentKindTool)
	if err != nil {
		d.logger.Error(ctx, "failed to list tools from component store", "error", err)
		return nil, fmt.Errorf("failed to list tools: %w", err)
	}

	// Query registry to check which tools are running
	runningTools := make(map[string]bool)
	runningEndpoints := make(map[string]string)
	runningHealth := make(map[string]string)
	toolCapabilities := make(map[string]*api.Capabilities)
	if d.registryAdapter != nil {
		running, err := d.registryAdapter.ListTools(ctx)
		if err == nil {
			for _, r := range running {
				runningTools[r.Name] = true
				if len(r.Endpoints) > 0 {
					runningEndpoints[r.Name] = r.Endpoints[0]
				}
				// Capture health from registry (aggregated across instances)
				runningHealth[r.Name] = r.Health
				// Capture capabilities if available
				if r.Capabilities != nil {
					toolCapabilities[r.Name] = &api.Capabilities{
						HasRoot:         r.Capabilities.HasRoot,
						HasSudo:         r.Capabilities.HasSudo,
						CanRawSocket:    r.Capabilities.CanRawSocket,
						Features:        r.Capabilities.Features,
						BlockedArgs:     r.Capabilities.BlockedArgs,
						ArgAlternatives: r.Capabilities.ArgAlternatives,
					}
				}
			}
		}
	}

	// Query Redis tool registry for K8s-deployed tools
	// These tools register via SADD to tools:available in Redis
	redisTools := make(map[string]bool)
	redisToolMeta := make(map[string]struct {
		Version     string
		Description string
		Health      string
	})
	if d.redisToolRegistry != nil {
		if err := d.redisToolRegistry.Refresh(ctx); err != nil {
			d.logger.Warn(ctx, "failed to refresh Redis tool registry", "error", err)
		} else {
			for _, meta := range d.redisToolRegistry.GetAllMetadata() {
				redisTools[meta.Name] = true
				health := "unknown"
				if d.redisToolRegistry.IsHealthy(ctx, meta.Name) {
					health = "healthy"
				}
				redisToolMeta[meta.Name] = struct {
					Version     string
					Description string
					Health      string
				}{
					Version:     meta.Version,
					Description: meta.Description,
					Health:      health,
				}
			}
			d.logger.Debug(ctx, "discovered Redis tools", "count", len(redisTools))
		}
	}

	// Build result set, starting with component store tools
	seenTools := make(map[string]bool)
	var result []api.ToolInfoInternal

	// Add component store tools (CLI-installed)
	for _, tool := range tools {
		seenTools[tool.Name] = true

		// Determine health status based on whether tool is running
		health := "unknown"
		endpoint := ""
		if runningTools[tool.Name] {
			// Use health from registry (aggregated across instances)
			health = runningHealth[tool.Name]
			if health == "" {
				health = "healthy" // Default for running tools
			}
			endpoint = runningEndpoints[tool.Name]
		}

		// Extract description from manifest if available
		description := ""
		if tool.Manifest != nil {
			description = tool.Manifest.Description
		}

		result = append(result, api.ToolInfoInternal{
			ID:           tool.Name,
			Name:         tool.Name,
			Version:      tool.Version,
			Endpoint:     endpoint,
			Description:  description,
			Health:       health,
			LastSeen:     tool.UpdatedAt,
			Capabilities: toolCapabilities[tool.Name],
		})
	}

	// Add Redis tools that aren't already in the result (K8s-deployed)
	for name, meta := range redisToolMeta {
		if seenTools[name] {
			// Tool already exists from component store, skip
			continue
		}
		seenTools[name] = true

		result = append(result, api.ToolInfoInternal{
			ID:          name,
			Name:        name,
			Version:     meta.Version,
			Endpoint:    "", // Redis tools don't have direct endpoints (queue-based)
			Description: meta.Description,
			Health:      meta.Health,
			LastSeen:    time.Now(), // No persistent timestamp for Redis tools
		})
	}

	d.logger.Debug(ctx, "listed tools", "total", len(result), "component_store", len(tools), "redis", len(redisTools))
	return result, nil
}

// ListPlugins returns all plugins from both the component store and the registry.
// This includes plugins installed via CLI and plugins running in Kubernetes/containers
// that registered directly with the registry.
func (d *daemonImpl) ListPlugins(ctx context.Context) ([]api.PluginInfoInternal, error) {
	d.logger.Debug(ctx, "ListPlugins called")

	// Track plugins by name to avoid duplicates
	pluginMap := make(map[string]api.PluginInfoInternal)

	// Query component store for installed plugins (if available)
	if d.componentStore != nil {
		plugins, err := d.componentStore.List(ctx, component.ComponentKindPlugin)
		if err != nil {
			d.logger.Warn(ctx, "failed to list plugins from component store", "error", err)
			// Continue - we can still list plugins from registry
		} else {
			for _, p := range plugins {
				description := ""
				if p.Manifest != nil {
					description = p.Manifest.Description
				}
				pluginMap[p.Name] = api.PluginInfoInternal{
					ID:          p.Name,
					Name:        p.Name,
					Version:     p.Version,
					Description: description,
					Health:      "unknown",
					LastSeen:    p.UpdatedAt,
				}
			}
		}
	}

	// Query registry for running plugins
	if d.registryAdapter != nil {
		running, err := d.registryAdapter.ListPlugins(ctx)
		if err != nil {
			d.logger.Warn(ctx, "failed to list plugins from registry", "error", err)
		} else {
			for _, r := range running {
				endpoint := ""
				if len(r.Endpoints) > 0 {
					endpoint = r.Endpoints[0]
				}

				// Determine health: use registry value, default based on instance count
				health := r.Health
				if health == "" {
					if r.Instances > 0 {
						health = "healthy"
					} else {
						health = "unknown"
					}
				}

				if existing, ok := pluginMap[r.Name]; ok {
					// Update existing plugin with running info
					existing.Health = health
					existing.Endpoint = endpoint
					if r.Version != "" {
						existing.Version = r.Version
					}
					if r.Description != "" && existing.Description == "" {
						existing.Description = r.Description
					}
					pluginMap[r.Name] = existing
				} else {
					// Add plugin that's only in registry (e.g., K8s deployed plugin)
					pluginMap[r.Name] = api.PluginInfoInternal{
						ID:          r.Name,
						Name:        r.Name,
						Version:     r.Version,
						Endpoint:    endpoint,
						Description: r.Description,
						Health:      health,
						LastSeen:    time.Now(),
					}
				}
			}
		}
	}

	// Convert map to slice
	result := make([]api.PluginInfoInternal, 0, len(pluginMap))
	for _, p := range pluginMap {
		result = append(result, p)
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
			if d.eventBus != nil {
				event := api.EventData{
					EventType: "mission_failed",
					Timestamp: time.Now(),
					Source:    "daemon",
					MissionEvent: &api.MissionEventData{
						EventType: "mission_failed",
						Timestamp: time.Now(),
						MissionID: missionID,
						Message:   "Orphaned paused mission marked as failed",
					},
				}
				if err := d.eventBus.Publish(ctx, event); err != nil {
					d.logger.Warn(ctx, "failed to publish mission failed event", "error", err)
				}
			}

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

	// Emit mission stopped event if event bus is available
	if d.eventBus != nil {
		event := api.EventData{
			EventType: "mission_stopped",
			Timestamp: time.Now(),
			Source:    "daemon",
			MissionEvent: &api.MissionEventData{
				EventType: "mission_stopped",
				Timestamp: time.Now(),
				MissionID: missionID,
				Message:   fmt.Sprintf("Mission %s stopped (force=%t)", missionID, force),
			},
		}
		if err := d.eventBus.Publish(ctx, event); err != nil {
			d.logger.Warn(ctx, "failed to publish mission stopped event", "error", err)
		}
	}

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
		operationResult := &api.OperationResult{
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
func (d *daemonImpl) Subscribe(ctx context.Context, eventTypes []string, missionID string) (<-chan api.EventData, error) {
	d.logger.Info(ctx, "Subscribe called", "event_types", eventTypes, "mission_id", missionID)

	// Subscribe to events from the event bus
	eventChan, cleanup := d.eventBus.Subscribe(ctx, eventTypes, missionID)

	// Start a goroutine to handle cleanup when context is cancelled
	go func() {
		<-ctx.Done()
		cleanup()
		d.logger.Info(ctx, "subscription cleanup completed", "mission_id", missionID)
	}()

	return eventChan, nil
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

// StartComponent starts a component by kind and name.
func (d *daemonImpl) StartComponent(ctx context.Context, kind string, name string) (api.StartComponentResult, error) {
	d.logger.Info(ctx, "StartComponent called", "kind", kind, "name", name)

	// Validate kind
	var componentKind component.ComponentKind
	switch kind {
	case "agent":
		componentKind = component.ComponentKindAgent
	case "tool":
		componentKind = component.ComponentKindTool
	case "plugin":
		componentKind = component.ComponentKindPlugin
	default:
		return api.StartComponentResult{}, fmt.Errorf("invalid component kind: %s", kind)
	}

	// Get component from store
	if d.componentStore == nil {
		d.logger.Error(ctx, "component store not available")
		return api.StartComponentResult{}, fmt.Errorf("component store not available")
	}
	comp, err := d.componentStore.GetByName(ctx, componentKind, name)
	if err != nil {
		d.logger.Error(ctx, "failed to get component from store", "error", err, "kind", kind, "name", name)
		return api.StartComponentResult{}, fmt.Errorf("failed to get component: %w", err)
	}
	if comp == nil {
		d.logger.Warn(ctx, "component not found in store", "kind", kind, "name", name)
		return api.StartComponentResult{}, fmt.Errorf("component '%s' not found", name)
	}

	// Get component registry
	if d.compRegistry == nil {
		d.logger.Error(ctx, "component registry not available")
		return api.StartComponentResult{}, fmt.Errorf("component registry not started")
	}
	reg := d.compRegistry
	tenant := d.registryTenant

	// Check if already running by querying registry
	instances, err := reg.Discover(ctx, tenant, string(componentKind), name)
	if err != nil {
		d.logger.Error(ctx, "failed to query registry", "error", err, "kind", kind, "name", name)
		return api.StartComponentResult{}, fmt.Errorf("failed to query registry: %w", err)
	}
	if len(instances) > 0 {
		d.logger.Warn(ctx, "component already running", "kind", kind, "name", name, "instances", len(instances))
		return api.StartComponentResult{}, fmt.Errorf("component '%s' is already running (%d instance(s) found in registry)", name, len(instances))
	}

	// Use Redis URL as the registry endpoint components advertise themselves to
	registryEndpoint := d.config.Redis.URL
	if registryEndpoint == "" {
		registryEndpoint = "redis://localhost:6379"
	}

	// Get home directory from config
	homeDir := d.config.Core.HomeDir

	// Get plugin-specific config if this is a plugin
	var pluginConfig map[string]string
	if kind == "plugin" && d.config.Plugins != nil {
		pluginConfig = d.config.Plugins[name]
	}

	// Start component process
	port, pid, logPath, err := startComponentProcess(ctx, comp, reg, tenant, registryEndpoint, homeDir, pluginConfig)
	if err != nil {
		d.logger.Error(ctx, "failed to start component process", "error", err, "kind", kind, "name", name)
		return api.StartComponentResult{}, fmt.Errorf("failed to start component: %w", err)
	}

	d.logger.Info(ctx, "component started successfully", "kind", kind, "name", name, "pid", pid, "port", port)

	return api.StartComponentResult{
		PID:     pid,
		Port:    port,
		LogPath: logPath,
	}, nil
}

// StopComponent stops a component by kind and name.
func (d *daemonImpl) StopComponent(ctx context.Context, kind string, name string, force bool) (api.StopComponentResult, error) {
	d.logger.Info(ctx, "StopComponent called", "kind", kind, "name", name, "force", force)

	// Validate kind
	var componentKind component.ComponentKind
	switch kind {
	case "agent":
		componentKind = component.ComponentKindAgent
	case "tool":
		componentKind = component.ComponentKindTool
	case "plugin":
		componentKind = component.ComponentKindPlugin
	default:
		return api.StopComponentResult{}, fmt.Errorf("invalid component kind: %s", kind)
	}

	// Get component from store
	if d.componentStore == nil {
		d.logger.Error(ctx, "component store not available")
		return api.StopComponentResult{}, fmt.Errorf("component store not available")
	}
	comp, err := d.componentStore.GetByName(ctx, componentKind, name)
	if err != nil {
		d.logger.Error(ctx, "failed to get component from store", "error", err, "kind", kind, "name", name)
		return api.StopComponentResult{}, fmt.Errorf("failed to get component: %w", err)
	}
	if comp == nil {
		d.logger.Warn(ctx, "component not found in store", "kind", kind, "name", name)
		return api.StopComponentResult{}, fmt.Errorf("component '%s' not found", name)
	}

	// Get component registry
	if d.compRegistry == nil {
		d.logger.Error(ctx, "component registry not available")
		return api.StopComponentResult{}, fmt.Errorf("component registry not started")
	}
	reg := d.compRegistry
	tenant := d.registryTenant

	// Query registry for running instances
	instances, err := reg.Discover(ctx, tenant, string(componentKind), name)
	if err != nil {
		d.logger.Error(ctx, "failed to query registry", "error", err, "kind", kind, "name", name)
		return api.StopComponentResult{}, fmt.Errorf("failed to query registry: %w", err)
	}
	if len(instances) == 0 {
		d.logger.Warn(ctx, "component not running", "kind", kind, "name", name)
		return api.StopComponentResult{}, fmt.Errorf("component '%s' is not running (no instances found in registry)", name)
	}

	// Stop all instances
	var lastErr error
	stoppedCount := 0
	for _, instance := range instances {
		if err := stopComponentProcess(ctx, instance, reg, tenant, force); err != nil {
			d.logger.Warn(ctx, "failed to stop instance", "error", err, "instance_id", instance.InstanceID)
			lastErr = err
		} else {
			stoppedCount++
		}
	}

	if stoppedCount == 0 && lastErr != nil {
		d.logger.Error(ctx, "failed to stop any instances", "error", lastErr, "kind", kind, "name", name)
		return api.StopComponentResult{}, fmt.Errorf("failed to stop any instances: %w", lastErr)
	}

	d.logger.Info(ctx, "component stopped successfully", "kind", kind, "name", name, "stopped", stoppedCount, "total", len(instances))

	return api.StopComponentResult{
		StoppedCount: stoppedCount,
		TotalCount:   len(instances),
	}, nil
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

// InstallComponent installs a component from a git repository.
func (d *daemonImpl) InstallComponent(ctx context.Context, kind string, url string, branch string, tag string, force bool, skipBuild bool, verbose bool) (api.InstallComponentResult, error) {
	d.logger.Info(ctx, "InstallComponent called", "kind", kind, "url", url, "force", force)

	// Validate kind
	var componentKind component.ComponentKind
	switch kind {
	case "agent":
		componentKind = component.ComponentKindAgent
	case "tool":
		componentKind = component.ComponentKindTool
	case "plugin":
		componentKind = component.ComponentKindPlugin
	default:
		return api.InstallComponentResult{}, fmt.Errorf("invalid component kind: %s", kind)
	}

	// Check if installer is available
	if d.componentInstaller == nil {
		d.logger.Error(ctx, "component installer not available")
		return api.InstallComponentResult{}, fmt.Errorf("component installer not available")
	}

	// Build install options
	opts := component.InstallOptions{
		Branch:    branch,
		Tag:       tag,
		Force:     force,
		SkipBuild: skipBuild,
		Verbose:   verbose,
	}

	// Execute installation
	result, err := d.componentInstaller.Install(ctx, url, componentKind, opts)
	if err != nil {
		d.logger.Error(ctx, "failed to install component", "error", err, "kind", kind, "url", url)
		return api.InstallComponentResult{}, fmt.Errorf("failed to install component: %w", err)
	}

	d.logger.Info(ctx, "component installed successfully", "kind", kind, "name", result.Component.Name, "version", result.Component.Version)

	return api.InstallComponentResult{
		Name:        result.Component.Name,
		Version:     result.Component.Version,
		RepoPath:    result.Component.RepoPath,
		BinPath:     result.Component.BinPath,
		BuildOutput: result.BuildOutput,
		DurationMs:  result.Duration.Milliseconds(),
	}, nil
}

// InstallAllComponent installs all components from a mono-repo.
func (d *daemonImpl) InstallAllComponent(ctx context.Context, kind string, url string, branch string, tag string, force bool, skipBuild bool, verbose bool) (api.InstallAllComponentResult, error) {
	d.logger.Info(ctx, "InstallAllComponent called", "kind", kind, "url", url, "force", force)

	// Validate kind
	var componentKind component.ComponentKind
	switch kind {
	case "agent":
		componentKind = component.ComponentKindAgent
	case "tool":
		componentKind = component.ComponentKindTool
	case "plugin":
		componentKind = component.ComponentKindPlugin
	default:
		return api.InstallAllComponentResult{}, fmt.Errorf("invalid component kind: %s", kind)
	}

	// Check if installer is available
	if d.componentInstaller == nil {
		d.logger.Error(ctx, "component installer not available")
		return api.InstallAllComponentResult{}, fmt.Errorf("component installer not available")
	}

	// Build install options
	opts := component.InstallOptions{
		Branch:    branch,
		Tag:       tag,
		Force:     force,
		SkipBuild: skipBuild,
		Verbose:   verbose,
	}

	// Execute bulk installation
	start := time.Now()
	result, err := d.componentInstaller.InstallAll(ctx, url, componentKind, opts)
	if err != nil {
		d.logger.Error(ctx, "failed to install all components", "error", err, "kind", kind, "url", url)
		return api.InstallAllComponentResult{}, fmt.Errorf("failed to install components: %w", err)
	}

	duration := time.Since(start)
	d.logger.Info(ctx, "install all completed",
		"kind", kind,
		"found", result.ComponentsFound,
		"successful", len(result.Successful),
		"skipped", len(result.Skipped),
		"failed", len(result.Failed),
		"duration", duration,
	)

	// Convert to API result
	apiSuccessful := make([]api.InstallAllResultItem, len(result.Successful))
	for i, item := range result.Successful {
		apiSuccessful[i] = api.InstallAllResultItem{
			Name:    item.Component.Name,
			Version: item.Component.Version,
			Path:    item.Component.RepoPath,
		}
	}

	apiSkipped := make([]api.InstallAllResultItem, len(result.Skipped))
	for i, item := range result.Skipped {
		apiSkipped[i] = api.InstallAllResultItem{
			Name:    item.Name,
			Version: "", // Skipped components don't have version info
			Path:    item.Path,
		}
	}

	apiFailed := make([]api.InstallAllFailedItem, len(result.Failed))
	for i, item := range result.Failed {
		apiFailed[i] = api.InstallAllFailedItem{
			Name:  item.Name,
			Path:  item.Path,
			Error: item.Error.Error(),
		}
	}

	// Determine overall success
	success := len(result.Failed) == 0 && result.ComponentsFound > 0

	// Build message
	message := fmt.Sprintf("Found %d components: %d successful, %d skipped, %d failed",
		result.ComponentsFound, len(result.Successful), len(result.Skipped), len(result.Failed))

	return api.InstallAllComponentResult{
		Success:         success,
		ComponentsFound: result.ComponentsFound,
		SuccessfulCount: len(result.Successful),
		SkippedCount:    len(result.Skipped),
		FailedCount:     len(result.Failed),
		Successful:      apiSuccessful,
		Skipped:         apiSkipped,
		Failed:          apiFailed,
		DurationMs:      duration.Milliseconds(),
		Message:         message,
	}, nil
}

// UninstallComponent uninstalls a component by kind and name.
func (d *daemonImpl) UninstallComponent(ctx context.Context, kind string, name string, force bool) error {
	d.logger.Info(ctx, "UninstallComponent called", "kind", kind, "name", name, "force", force)

	// Validate kind
	var componentKind component.ComponentKind
	switch kind {
	case "agent":
		componentKind = component.ComponentKindAgent
	case "tool":
		componentKind = component.ComponentKindTool
	case "plugin":
		componentKind = component.ComponentKindPlugin
	default:
		return fmt.Errorf("invalid component kind: %s", kind)
	}

	// Check if component is running (unless force is set)
	if !force && d.componentStore != nil {
		comp, err := d.componentStore.GetByName(ctx, componentKind, name)
		if err != nil {
			d.logger.Error(ctx, "failed to get component", "error", err, "kind", kind, "name", name)
			return fmt.Errorf("failed to get component: %w", err)
		}
		if comp == nil {
			d.logger.Warn(ctx, "component not found", "kind", kind, "name", name)
			return fmt.Errorf("component '%s' not found", name)
		}

		// Check if running
		if comp.IsRunning() {
			d.logger.Warn(ctx, "component is running", "kind", kind, "name", name)
			return fmt.Errorf("component '%s' is running. Stop it first or use --force", name)
		}
	}

	// Check if installer is available
	if d.componentInstaller == nil {
		d.logger.Error(ctx, "component installer not available")
		return fmt.Errorf("component installer not available")
	}

	// Execute uninstallation
	_, err := d.componentInstaller.Uninstall(ctx, componentKind, name)
	if err != nil {
		d.logger.Error(ctx, "failed to uninstall component", "error", err, "kind", kind, "name", name)
		return fmt.Errorf("failed to uninstall component: %w", err)
	}

	d.logger.Info(ctx, "component uninstalled successfully", "kind", kind, "name", name)
	return nil
}

// UpdateComponent updates a component to the latest version.
func (d *daemonImpl) UpdateComponent(ctx context.Context, kind string, name string, restart bool, skipBuild bool, verbose bool) (api.UpdateComponentResult, error) {
	d.logger.Info(ctx, "UpdateComponent called", "kind", kind, "name", name, "restart", restart)

	// Validate kind
	var componentKind component.ComponentKind
	switch kind {
	case "agent":
		componentKind = component.ComponentKindAgent
	case "tool":
		componentKind = component.ComponentKindTool
	case "plugin":
		componentKind = component.ComponentKindPlugin
	default:
		return api.UpdateComponentResult{}, fmt.Errorf("invalid component kind: %s", kind)
	}

	// Check if installer is available
	if d.componentInstaller == nil {
		d.logger.Error(ctx, "component installer not available")
		return api.UpdateComponentResult{}, fmt.Errorf("component installer not available")
	}

	// Build update options
	opts := component.UpdateOptions{
		Restart:   restart,
		SkipBuild: skipBuild,
		Verbose:   verbose,
	}

	// Execute update
	result, err := d.componentInstaller.Update(ctx, componentKind, name, opts)
	if err != nil {
		d.logger.Error(ctx, "failed to update component", "error", err, "kind", kind, "name", name)
		return api.UpdateComponentResult{}, fmt.Errorf("failed to update component: %w", err)
	}

	// TODO: Handle restart if requested and component was running
	// This requires the lifecycle manager to be integrated

	d.logger.Info(ctx, "component updated successfully", "kind", kind, "name", name, "updated", result.Updated)

	return api.UpdateComponentResult{
		Updated:     result.Updated,
		OldVersion:  result.OldVersion,
		NewVersion:  result.NewVersion,
		BuildOutput: result.BuildOutput,
		DurationMs:  result.Duration.Milliseconds(),
	}, nil
}

// BuildComponent rebuilds a component from source.
func (d *daemonImpl) BuildComponent(ctx context.Context, kind string, name string) (api.BuildComponentResult, error) {
	d.logger.Info(ctx, "BuildComponent called", "kind", kind, "name", name)

	// Validate kind
	var componentKind component.ComponentKind
	switch kind {
	case "agent":
		componentKind = component.ComponentKindAgent
	case "tool":
		componentKind = component.ComponentKindTool
	case "plugin":
		componentKind = component.ComponentKindPlugin
	default:
		return api.BuildComponentResult{}, fmt.Errorf("invalid component kind: %s", kind)
	}

	// Get component from store
	if d.componentStore == nil {
		d.logger.Error(ctx, "component store not available")
		return api.BuildComponentResult{}, fmt.Errorf("component store not available")
	}

	comp, err := d.componentStore.GetByName(ctx, componentKind, name)
	if err != nil {
		d.logger.Error(ctx, "failed to get component", "error", err, "kind", kind, "name", name)
		return api.BuildComponentResult{}, fmt.Errorf("failed to get component: %w", err)
	}
	if comp == nil {
		d.logger.Warn(ctx, "component not found", "kind", kind, "name", name)
		return api.BuildComponentResult{}, fmt.Errorf("component '%s' not found", name)
	}

	// Check if build executor is available
	if d.componentBuildExecutor == nil {
		d.logger.Error(ctx, "build executor not available")
		return api.BuildComponentResult{}, fmt.Errorf("build executor not available")
	}

	// Prepare build configuration from manifest
	if comp.Manifest == nil || comp.Manifest.Build == nil {
		d.logger.Warn(ctx, "component has no build configuration", "kind", kind, "name", name)
		return api.BuildComponentResult{}, fmt.Errorf("component '%s' has no build configuration", name)
	}

	buildCfg := comp.Manifest.Build

	// Parse build command string into command and args
	command := "make"
	args := []string{"build"}
	if buildCfg.Command != "" {
		parts := strings.Fields(buildCfg.Command)
		if len(parts) > 0 {
			command = parts[0]
			if len(parts) > 1 {
				args = parts[1:]
			} else {
				args = []string{}
			}
		}
	}

	// Determine working directory
	workDir := comp.RepoPath
	if buildCfg.WorkDir != "" {
		workDir = filepath.Join(comp.RepoPath, buildCfg.WorkDir)
	}

	// Import the build package types
	buildConfig := build.BuildConfig{
		WorkDir:    workDir,
		Command:    command,
		Args:       args,
		OutputPath: "",
		Env:        buildCfg.GetEnv(),
		Verbose:    true,
	}

	// Execute build with timeout
	buildCtx, cancel := context.WithTimeout(ctx, component.DefaultBuildTimeout)
	defer cancel()

	startTime := time.Now()
	buildResult, err := d.componentBuildExecutor.Build(buildCtx, buildConfig, comp.Name, comp.Version, "dev")
	duration := time.Since(startTime)

	if err != nil {
		d.logger.Error(ctx, "build failed", "error", err, "kind", kind, "name", name, "duration_ms", duration.Milliseconds())
		errorMsg := fmt.Sprintf("build failed: %v", err)
		if buildResult != nil {
			return api.BuildComponentResult{
				Success:    false,
				Stdout:     buildResult.Stdout,
				Stderr:     buildResult.Stderr,
				DurationMs: duration.Milliseconds(),
			}, nil // Return nil error since we're reporting the error in the result
		}
		return api.BuildComponentResult{
			Success:    false,
			Stdout:     "",
			Stderr:     errorMsg,
			DurationMs: duration.Milliseconds(),
		}, nil
	}

	d.logger.Info(ctx, "component built successfully", "kind", kind, "name", name, "duration_ms", duration.Milliseconds())

	return api.BuildComponentResult{
		Success:    true,
		Stdout:     buildResult.Stdout,
		Stderr:     buildResult.Stderr,
		DurationMs: duration.Milliseconds(),
	}, nil
}

// ShowComponent returns detailed information about a component.
func (d *daemonImpl) ShowComponent(ctx context.Context, kind string, name string) (api.ComponentInfoInternal, error) {
	d.logger.Debug(ctx, "ShowComponent called", "kind", kind, "name", name)

	// Validate kind
	var componentKind component.ComponentKind
	switch kind {
	case "agent":
		componentKind = component.ComponentKindAgent
	case "tool":
		componentKind = component.ComponentKindTool
	case "plugin":
		componentKind = component.ComponentKindPlugin
	default:
		return api.ComponentInfoInternal{}, fmt.Errorf("invalid component kind: %s", kind)
	}

	// Get component from store
	if d.componentStore == nil {
		d.logger.Error(ctx, "component store not available")
		return api.ComponentInfoInternal{}, fmt.Errorf("component store not available")
	}

	comp, err := d.componentStore.GetByName(ctx, componentKind, name)
	if err != nil {
		d.logger.Error(ctx, "failed to get component", "error", err, "kind", kind, "name", name)
		return api.ComponentInfoInternal{}, fmt.Errorf("failed to get component: %w", err)
	}
	if comp == nil {
		d.logger.Warn(ctx, "component not found", "kind", kind, "name", name)
		return api.ComponentInfoInternal{}, fmt.Errorf("component '%s' not found", name)
	}

	d.logger.Debug(ctx, "component details retrieved", "kind", kind, "name", name, "version", comp.Version)

	// Convert to API format
	return api.ComponentInfoInternal{
		Name:      comp.Name,
		Version:   comp.Version,
		Kind:      kind,
		Status:    comp.Status.String(),
		Source:    comp.Source.String(),
		RepoPath:  comp.RepoPath,
		BinPath:   comp.BinPath,
		Port:      comp.Port,
		PID:       comp.PID,
		CreatedAt: comp.CreatedAt,
		UpdatedAt: comp.UpdatedAt,
	}, nil
}

// GetComponentLogs streams log entries for a component using fsnotify-based log tailer.
func (d *daemonImpl) GetComponentLogs(ctx context.Context, kind string, name string, follow bool, lines int) (<-chan api.LogEntryData, error) {
	d.logger.Debug(ctx, "GetComponentLogs called", "kind", kind, "name", name, "follow", follow, "lines", lines)

	// Validate kind
	var componentKind component.ComponentKind
	switch kind {
	case "agent":
		componentKind = component.ComponentKindAgent
	case "tool":
		componentKind = component.ComponentKindTool
	case "plugin":
		componentKind = component.ComponentKindPlugin
	default:
		return nil, fmt.Errorf("invalid component kind: %s", kind)
	}

	// Get component from store to verify it exists
	if d.componentStore == nil {
		d.logger.Error(ctx, "component store not available")
		return nil, fmt.Errorf("component store not available")
	}

	comp, err := d.componentStore.GetByName(ctx, componentKind, name)
	if err != nil {
		d.logger.Error(ctx, "failed to get component", "error", err, "kind", kind, "name", name)
		return nil, fmt.Errorf("failed to get component: %w", err)
	}
	if comp == nil {
		d.logger.Warn(ctx, "component not found", "kind", kind, "name", name)
		return nil, fmt.Errorf("component '%s' not found", name)
	}

	// Construct log file path
	// Logs are written to ~/.gibson/logs/<component-name>.log
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
	d.logger.Info(ctx, "InstallMission called", "url", url, "force", force)

	// Check if mission installer is available
	if d.missionInstaller == nil {
		d.logger.Error(ctx, "mission installer not available")
		return api.InstallMissionResult{}, fmt.Errorf("mission installer not available")
	}

	// Build install options
	opts := mission.InstallOptions{
		Branch:  branch,
		Tag:     tag,
		Force:   force,
		Yes:     yes,
		Timeout: 0, // Will be set from timeoutMs below
	}

	// Set timeout if specified
	if timeoutMs > 0 {
		opts.Timeout = time.Duration(timeoutMs) * time.Millisecond
	}

	// Execute installation
	result, err := d.missionInstaller.Install(ctx, url, opts)
	if err != nil {
		d.logger.Error(ctx, "failed to install mission", "error", err, "url", url)
		return api.InstallMissionResult{}, fmt.Errorf("failed to install mission: %w", err)
	}

	d.logger.Info(ctx, "mission installed successfully", "name", result.Name, "version", result.Version)

	// Convert dependencies to API format
	apiDeps := make([]api.InstalledDependencyData, len(result.Dependencies))
	for i, dep := range result.Dependencies {
		apiDeps[i] = api.InstalledDependencyData{
			Type:             dep.Type,
			Name:             dep.Name,
			AlreadyInstalled: dep.AlreadyInstalled,
		}
	}

	return api.InstallMissionResult{
		Name:         result.Name,
		Version:      result.Version,
		Path:         result.Path,
		Dependencies: apiDeps,
		DurationMs:   result.Duration.Milliseconds(),
	}, nil
}

// UninstallMission removes an installed mission.
func (d *daemonImpl) UninstallMission(ctx context.Context, name string, force bool) error {
	d.logger.Info(ctx, "UninstallMission called", "name", name, "force", force)

	// Check if mission installer is available
	if d.missionInstaller == nil {
		d.logger.Error(ctx, "mission installer not available")
		return fmt.Errorf("mission installer not available")
	}

	// Build uninstall options
	opts := mission.UninstallOptions{
		Force: force,
	}

	// Execute uninstallation
	err := d.missionInstaller.Uninstall(ctx, name, opts)
	if err != nil {
		d.logger.Error(ctx, "failed to uninstall mission", "error", err, "name", name)
		return fmt.Errorf("failed to uninstall mission: %w", err)
	}

	d.logger.Info(ctx, "mission uninstalled successfully", "name", name)
	return nil
}

// ListMissionDefinitions returns all installed mission definitions.
func (d *daemonImpl) ListMissionDefinitions(ctx context.Context, limit int, offset int) ([]api.MissionDefinitionData, int, error) {
	d.logger.Debug(ctx, "ListMissionDefinitions called", "limit", limit, "offset", offset)

	// For now, return empty list as the MissionStore doesn't have ListDefinitions yet
	// This will be implemented in task 3.1/3.2 when the store is extended
	// TODO: Implement once MissionStore has ListDefinitions method

	d.logger.Debug(ctx, "listed mission definitions", "count", 0, "total", 0)
	return []api.MissionDefinitionData{}, 0, nil
}

// UpdateMission updates an installed mission to the latest version.
func (d *daemonImpl) UpdateMission(ctx context.Context, name string, timeoutMs int64) (api.UpdateMissionResult, error) {
	d.logger.Info(ctx, "UpdateMission called", "name", name)

	// Check if mission installer is available
	if d.missionInstaller == nil {
		d.logger.Error(ctx, "mission installer not available")
		return api.UpdateMissionResult{}, fmt.Errorf("mission installer not available")
	}

	// Build update options
	opts := mission.UpdateOptions{
		Timeout: 0, // Will be set from timeoutMs below
	}

	// Set timeout if specified
	if timeoutMs > 0 {
		opts.Timeout = time.Duration(timeoutMs) * time.Millisecond
	}

	// Execute update
	result, err := d.missionInstaller.Update(ctx, name, opts)
	if err != nil {
		d.logger.Error(ctx, "failed to update mission", "error", err, "name", name)
		return api.UpdateMissionResult{}, fmt.Errorf("failed to update mission: %w", err)
	}

	d.logger.Info(ctx, "mission updated successfully", "name", name, "updated", result.Updated)

	return api.UpdateMissionResult{
		Updated:    result.Updated,
		OldVersion: result.OldVersion,
		NewVersion: result.NewVersion,
		DurationMs: result.Duration.Milliseconds(),
	}, nil
}

// ResolveMissionDependencies resolves and returns the dependency tree for a mission workflow.
func (d *daemonImpl) ResolveMissionDependencies(ctx context.Context, missionPath string) (api.DependencyTreeData, error) {
	d.logger.Debug(ctx, "ResolveMissionDependencies called", "mission_path", missionPath)

	// Check if dependency resolver is available
	if d.dependencyResolver == nil {
		d.logger.Error(ctx, "dependency resolver not available")
		return api.DependencyTreeData{}, fmt.Errorf("dependency resolver not initialized")
	}

	// Resolve dependencies from workflow file
	tree, err := d.dependencyResolver.ResolveFromWorkflow(ctx, missionPath)
	if err != nil {
		d.logger.Error(ctx, "failed to resolve mission dependencies", "error", err, "mission_path", missionPath)
		return api.DependencyTreeData{}, fmt.Errorf("failed to resolve dependencies: %w", err)
	}

	// Convert DependencyTree to API format
	nodes := make([]api.DependencyNodeData, 0, len(tree.Nodes))
	for _, node := range tree.Nodes {
		nodes = append(nodes, api.DependencyNodeData{
			Kind:          node.Kind.String(),
			Name:          node.Name,
			Version:       node.Version,
			Source:        string(node.Source),
			SourceRef:     node.SourceRef,
			Installed:     node.Installed,
			Running:       node.Running,
			Healthy:       node.Healthy,
			ActualVersion: node.ActualVersion,
		})
	}

	result := api.DependencyTreeData{
		MissionRef:  tree.MissionRef,
		ResolvedAt:  tree.ResolvedAt,
		TotalNodes:  len(tree.Nodes),
		AgentCount:  len(tree.Agents),
		ToolCount:   len(tree.Tools),
		PluginCount: len(tree.Plugins),
		Nodes:       nodes,
	}

	d.logger.Debug(ctx, "mission dependencies resolved",
		"mission_path", missionPath,
		"total_nodes", result.TotalNodes,
		"agents", result.AgentCount,
		"tools", result.ToolCount,
		"plugins", result.PluginCount,
	)

	return result, nil
}

// ValidateMissionDependencies validates the state of all dependencies for a mission workflow.
func (d *daemonImpl) ValidateMissionDependencies(ctx context.Context, missionPath string) (api.ValidationResultData, error) {
	d.logger.Debug(ctx, "ValidateMissionDependencies called", "mission_path", missionPath)

	// Check if dependency resolver is available
	if d.dependencyResolver == nil {
		d.logger.Error(ctx, "dependency resolver not available")
		return api.ValidationResultData{}, fmt.Errorf("dependency resolver not initialized")
	}

	// First resolve the dependency tree
	tree, err := d.dependencyResolver.ResolveFromWorkflow(ctx, missionPath)
	if err != nil {
		d.logger.Error(ctx, "failed to resolve mission dependencies", "error", err, "mission_path", missionPath)
		return api.ValidationResultData{}, fmt.Errorf("failed to resolve dependencies: %w", err)
	}

	// Validate the state of all components in the tree
	validationResult, err := d.dependencyResolver.ValidateState(ctx, tree)
	if err != nil {
		d.logger.Error(ctx, "failed to validate mission dependencies", "error", err, "mission_path", missionPath)
		return api.ValidationResultData{}, fmt.Errorf("failed to validate dependencies: %w", err)
	}

	// Convert ValidationResult to API format
	notInstalled := make([]api.DependencyNodeData, len(validationResult.NotInstalled))
	for i, node := range validationResult.NotInstalled {
		notInstalled[i] = api.DependencyNodeData{
			Kind:          node.Kind.String(),
			Name:          node.Name,
			Version:       node.Version,
			Source:        string(node.Source),
			SourceRef:     node.SourceRef,
			Installed:     node.Installed,
			Running:       node.Running,
			Healthy:       node.Healthy,
			ActualVersion: node.ActualVersion,
		}
	}

	notRunning := make([]api.DependencyNodeData, len(validationResult.NotRunning))
	for i, node := range validationResult.NotRunning {
		notRunning[i] = api.DependencyNodeData{
			Kind:          node.Kind.String(),
			Name:          node.Name,
			Version:       node.Version,
			Source:        string(node.Source),
			SourceRef:     node.SourceRef,
			Installed:     node.Installed,
			Running:       node.Running,
			Healthy:       node.Healthy,
			ActualVersion: node.ActualVersion,
		}
	}

	unhealthy := make([]api.DependencyNodeData, len(validationResult.Unhealthy))
	for i, node := range validationResult.Unhealthy {
		unhealthy[i] = api.DependencyNodeData{
			Kind:          node.Kind.String(),
			Name:          node.Name,
			Version:       node.Version,
			Source:        string(node.Source),
			SourceRef:     node.SourceRef,
			Installed:     node.Installed,
			Running:       node.Running,
			Healthy:       node.Healthy,
			ActualVersion: node.ActualVersion,
		}
	}

	versionMismatch := make([]api.VersionMismatchData, len(validationResult.VersionMismatch))
	for i, mismatch := range validationResult.VersionMismatch {
		versionMismatch[i] = api.VersionMismatchData{
			ComponentKind:   mismatch.Node.Kind.String(),
			ComponentName:   mismatch.Node.Name,
			RequiredVersion: mismatch.RequiredVersion,
			ActualVersion:   mismatch.ActualVersion,
		}
	}

	result := api.ValidationResultData{
		Valid:                validationResult.Valid,
		Summary:              validationResult.Summary,
		TotalComponents:      validationResult.TotalComponents,
		InstalledCount:       validationResult.InstalledCount,
		RunningCount:         validationResult.RunningCount,
		HealthyCount:         validationResult.HealthyCount,
		NotInstalledCount:    len(validationResult.NotInstalled),
		NotRunningCount:      len(validationResult.NotRunning),
		UnhealthyCount:       len(validationResult.Unhealthy),
		VersionMismatchCount: len(validationResult.VersionMismatch),
		ValidatedAt:          validationResult.ValidatedAt,
		DurationMs:           validationResult.Duration.Milliseconds(),
		NotInstalled:         notInstalled,
		NotRunning:           notRunning,
		Unhealthy:            unhealthy,
		VersionMismatch:      versionMismatch,
	}

	d.logger.Debug(ctx, "mission dependencies validated",
		"mission_path", missionPath,
		"valid", result.Valid,
		"total", result.TotalComponents,
		"installed", result.InstalledCount,
		"running", result.RunningCount,
		"healthy", result.HealthyCount,
	)

	return result, nil
}

// EnsureMissionDependencies ensures all dependencies for a mission workflow are running.
func (d *daemonImpl) EnsureMissionDependencies(ctx context.Context, missionPath string) error {
	d.logger.Info(ctx, "EnsureMissionDependencies called", "mission_path", missionPath)

	// Check if dependency resolver is available
	if d.dependencyResolver == nil {
		d.logger.Error(ctx, "dependency resolver not available")
		return fmt.Errorf("dependency resolver not initialized")
	}

	// First resolve the dependency tree
	tree, err := d.dependencyResolver.ResolveFromWorkflow(ctx, missionPath)
	if err != nil {
		d.logger.Error(ctx, "failed to resolve mission dependencies", "error", err, "mission_path", missionPath)
		return fmt.Errorf("failed to resolve dependencies: %w", err)
	}

	// Ensure all components are running
	err = d.dependencyResolver.EnsureRunning(ctx, tree)
	if err != nil {
		d.logger.Error(ctx, "failed to ensure mission dependencies are running", "error", err, "mission_path", missionPath)
		return fmt.Errorf("failed to start dependencies: %w", err)
	}

	d.logger.Info(ctx, "mission dependencies are running", "mission_path", missionPath, "total_nodes", len(tree.Nodes))

	return nil
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
