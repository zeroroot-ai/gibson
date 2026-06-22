// Package component provides unified component discovery and delegation for Gibson.
//
// This file implements RegistryAdapter, which bridges the component registry with
// agent, tool, and plugin discovery using gRPC connection pooling and load balancing.
package component

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/tool"
	"github.com/zeroroot-ai/gibson/internal/infra/contextkeys"
	"github.com/zeroroot-ai/sdk/auth"
	"github.com/zeroroot-ai/sdk/protoresolver"
	"github.com/zeroroot-ai/sdk/types"
)

// CallbackManager provides callback server functionality for agent harness operations.
// External gRPC agents can connect back to the callback server to access LLM, tools,
// memory, and other harness operations.
//
// This interface is implemented by harness.CallbackManager.
// Note: The harness parameter uses any to avoid circular imports between component and harness.
// The actual implementation expects harness.AgentHarness.
type CallbackManager interface {
	// RegisterHarnessForMission registers a harness for external agent execution within
	// a mission context and returns the registration key.
	RegisterHarnessForMission(missionID, agentName string, harness any) string

	// UnregisterHarness removes a harness registration after task or mission completion.
	UnregisterHarness(key string)

	// CallbackEndpoint returns the advertised callback endpoint address.
	CallbackEndpoint() string
}

// ComponentDiscovery provides a unified interface for discovering and connecting to
// agents and tools registered in the component registry.
//
// This interface abstracts away the complexity of:
//   - Querying the registry for component instances
//   - Load-balancing across multiple instances
//   - Managing gRPC connection pooling
//   - Wrapping gRPC clients with Gibson's component interfaces
//
// Plugin dispatch is intentionally NOT exposed here. The pre-release in-process
// Plugin shape (Initialize/Query/Shutdown/Methods/Health) was deleted by the
// plugin-runtime spec; the production dispatch lives on
// PluginInvokeService (component/plugin_dispatch.go) which is a separate
// service registered on the daemon's gRPC surface and called via the harness's
// QueryPlugin path. ListPlugins is retained for inventory/UI consumers; it
// returns metadata only and never returns an in-process Plugin object.
//
// Thread-safe: All methods can be called concurrently.
type ComponentDiscovery interface {
	// DiscoverAgent finds an agent by name and returns a gRPC client implementing agent.Agent.
	DiscoverAgent(ctx context.Context, name string) (agent.Agent, error)

	// DiscoverTool finds a tool by name and returns a gRPC client implementing tool.Tool.
	DiscoverTool(ctx context.Context, name string) (tool.Tool, error)

	// ListAgents returns information about all registered agents.
	ListAgents(ctx context.Context) ([]AgentInfo, error)

	// ListTools returns information about all registered tools.
	ListTools(ctx context.Context) ([]ToolInfo, error)

	// ListPlugins returns information about all registered plugins.
	ListPlugins(ctx context.Context) ([]PluginInfo, error)

	// DelegateToAgent executes a task on a remote agent via gRPC.
	DelegateToAgent(ctx context.Context, name string, task agent.Task, harness agent.AgentHarness) (agent.Result, error)
}

// AgentInfo provides metadata about a registered agent.
type AgentInfo struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	Description    string   `json:"description"`
	Instances      int      `json:"instances"`
	Endpoints      []string `json:"endpoints"`
	Capabilities   []string `json:"capabilities"`
	TargetTypes    []string `json:"target_types"`
	TechniqueTypes []string `json:"technique_types"`
	Health         string   `json:"health"`
}

// ToolInfo provides metadata about a registered tool.
type ToolInfo struct {
	Name         string              `json:"name"`
	Version      string              `json:"version"`
	Description  string              `json:"description"`
	Instances    int                 `json:"instances"`
	Endpoints    []string            `json:"endpoints"`
	Capabilities *types.Capabilities `json:"capabilities,omitempty"`
	Health       string              `json:"health"`
}

// PluginInfo provides metadata about a registered plugin.
type PluginInfo struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Instances   int      `json:"instances"`
	Endpoints   []string `json:"endpoints"`
	Health      string   `json:"health"`
	// Methods is the list of declared method names for the plugin,
	// derived from the component registry metadata set at registration time.
	Methods []string `json:"methods,omitempty"`
}

// RegistryAdapter implements ComponentDiscovery using the Redis-backed ComponentRegistry
// and gRPC connection pooling.
//
// It coordinates between:
//   - ComponentRegistry: Redis-backed component discovery
//   - LoadBalancer: Instance selection strategies
//   - GRPCPool: Connection management and reuse
//
// Thread-safe: All methods can be called concurrently.
type RegistryAdapter struct {
	// registry provides component discovery via Redis
	registry ComponentRegistry

	// tenant is the tenant scope for discovery queries
	tenant string

	// loadBalancer selects instances when multiple are available
	loadBalancer *LoadBalancer

	// pool manages gRPC connections with automatic health checking
	pool *GRPCPool

	// callbackManager provides callback server for external agents (optional)
	callbackManager CallbackManager

	// authConfig provides authentication configuration for callback connections (optional)
	authConfig *AuthConfig

	// resolver provides proto type resolution for dynamically typed tool responses
	resolver protoresolver.ProtoResolver
}

// NewRegistryAdapter creates a new adapter wrapping a ComponentRegistry.
//
// The adapter uses round-robin load balancing by default. Discovery is scoped
// to the provided tenant — pass an empty string to skip tenant scoping (will
// use "_system" namespace only).
//
// The caller is responsible for managing the registry lifecycle.
func NewRegistryAdapter(reg ComponentRegistry, tenant string) *RegistryAdapter {
	return &RegistryAdapter{
		registry:     reg,
		tenant:       tenant,
		loadBalancer: NewLoadBalancer(reg, StrategyRoundRobin),
		pool:         NewGRPCPool(),
		resolver:     protoresolver.NewDefaultProtoResolver(protoresolver.DefaultConfig()),
	}
}

// NewRegistryAdapterWithPool creates a new adapter with a custom GRPCPool.
func NewRegistryAdapterWithPool(reg ComponentRegistry, tenant string, pool *GRPCPool) *RegistryAdapter {
	return &RegistryAdapter{
		registry:     reg,
		tenant:       tenant,
		loadBalancer: NewLoadBalancer(reg, StrategyRoundRobin),
		pool:         pool,
		resolver:     protoresolver.NewDefaultProtoResolver(protoresolver.DefaultConfig()),
	}
}

// SetCallbackManager configures the callback manager for this adapter.
func (a *RegistryAdapter) SetCallbackManager(cm CallbackManager) {
	a.callbackManager = cm
}

// SetAuthConfig configures authentication for callback connections.
func (a *RegistryAdapter) SetAuthConfig(cfg *AuthConfig) {
	a.authConfig = cfg
}

// SetResolver configures a custom ProtoResolver for this adapter.
func (a *RegistryAdapter) SetResolver(r protoresolver.ProtoResolver) {
	a.resolver = r
}

// GetResolver returns the ProtoResolver used by this adapter.
func (a *RegistryAdapter) GetResolver() protoresolver.ProtoResolver {
	return a.resolver
}

// resolveTenant returns the tenant for a registry query. It checks the request
// context first (set by the identity interceptor for authenticated RPCs), falling
// back to the adapter's configured default tenant for unauthenticated or
// dev-mode paths. The _system sentinel returned by TenantFromContext when no
// real tenant is present is treated as "not set".
func (a *RegistryAdapter) resolveTenant(ctx context.Context) string {
	if tenant := auth.TenantStringFromContext(ctx); tenant != "" && tenant != auth.SystemTenantString {
		return tenant
	}
	return a.tenant
}

// DiscoverAgent discovers and connects to an agent by name.
func (a *RegistryAdapter) DiscoverAgent(ctx context.Context, name string) (agent.Agent, error) {
	tenant := a.resolveTenant(ctx)
	instances, err := a.registry.Discover(ctx, tenant, "agent", name)
	if err != nil {
		return nil, &RegistryUnavailableError{Cause: err}
	}

	if len(instances) == 0 {
		available, _ := a.getAvailableAgentNames(ctx)
		return nil, &AgentNotFoundError{Name: name, Available: available}
	}

	selected, err := a.loadBalancer.Select(ctx, tenant, "agent", name)
	if err != nil {
		return nil, fmt.Errorf("failed to select agent instance: %w", err)
	}

	endpoint := selected.Metadata["grpc_endpoint"]
	if endpoint == "" {
		return nil, fmt.Errorf("agent %s has no grpc_endpoint in metadata", name)
	}

	conn, err := a.pool.Get(ctx, endpoint)
	if err != nil {
		_ = a.pool.Remove(endpoint)
		return nil, fmt.Errorf("failed to connect to agent %s at %s: %w", name, endpoint, err)
	}

	return NewGRPCAgentClient(conn, *selected), nil
}

// DiscoverTool discovers and connects to a tool by name.
func (a *RegistryAdapter) DiscoverTool(ctx context.Context, name string) (tool.Tool, error) {
	tenant := a.resolveTenant(ctx)
	instances, err := a.registry.Discover(ctx, tenant, "tool", name)
	if err != nil {
		return nil, &RegistryUnavailableError{Cause: err}
	}

	if len(instances) == 0 {
		available, _ := a.getAvailableToolNames(ctx)
		return nil, &ToolNotFoundError{Name: name, Available: available}
	}

	selected, err := a.loadBalancer.Select(ctx, tenant, "tool", name)
	if err != nil {
		return nil, fmt.Errorf("failed to select tool instance: %w", err)
	}

	endpoint := selected.Metadata["grpc_endpoint"]
	if endpoint == "" {
		return nil, fmt.Errorf("tool %s has no grpc_endpoint in metadata", name)
	}

	conn, err := a.pool.Get(ctx, endpoint)
	if err != nil {
		_ = a.pool.Remove(endpoint)
		return nil, fmt.Errorf("failed to connect to tool %s at %s: %w", name, endpoint, err)
	}

	return NewGRPCToolClient(conn, *selected, a.resolver), nil
}

// ListAgents returns information about all registered agents.
func (a *RegistryAdapter) ListAgents(ctx context.Context) ([]AgentInfo, error) {
	tenant := a.resolveTenant(ctx)
	instances, err := a.registry.DiscoverAll(ctx, tenant, "agent")
	if err != nil {
		return nil, &RegistryUnavailableError{Cause: err}
	}

	type agentHealthTracker struct {
		info           *AgentInfo
		healthyCount   int
		unhealthyCount int
	}

	agentMap := make(map[string]*agentHealthTracker)
	for _, inst := range instances {
		health := GetHealthStatus(inst)
		endpoint := inst.Metadata["grpc_endpoint"]

		if tracker, exists := agentMap[inst.Name]; exists {
			tracker.info.Instances++
			if endpoint != "" {
				tracker.info.Endpoints = append(tracker.info.Endpoints, endpoint)
			}
			if health == HealthStatusHealthy {
				tracker.healthyCount++
			} else {
				tracker.unhealthyCount++
			}
		} else {
			healthyCount, unhealthyCount := 0, 0
			if health == HealthStatusHealthy {
				healthyCount = 1
			} else {
				unhealthyCount = 1
			}
			endpoints := []string{}
			if endpoint != "" {
				endpoints = []string{endpoint}
			}
			agentMap[inst.Name] = &agentHealthTracker{
				info: &AgentInfo{
					Name:           inst.Name,
					Version:        inst.Version,
					Description:    inst.Metadata["description"],
					Instances:      1,
					Endpoints:      endpoints,
					Capabilities:   parseCommaSeparated(inst.Metadata["capabilities"]),
					TargetTypes:    parseCommaSeparated(inst.Metadata["target_types"]),
					TechniqueTypes: parseCommaSeparated(inst.Metadata["technique_types"]),
				},
				healthyCount:   healthyCount,
				unhealthyCount: unhealthyCount,
			}
		}
	}

	result := make([]AgentInfo, 0, len(agentMap))
	for _, tracker := range agentMap {
		tracker.info.Health = aggregateHealth(tracker.healthyCount, tracker.unhealthyCount)
		result = append(result, *tracker.info)
	}
	return result, nil
}

// ListTools returns information about all registered tools.
func (a *RegistryAdapter) ListTools(ctx context.Context) ([]ToolInfo, error) {
	tenant := a.resolveTenant(ctx)
	instances, err := a.registry.DiscoverAll(ctx, tenant, "tool")
	if err != nil {
		return nil, &RegistryUnavailableError{Cause: err}
	}

	type toolHealthTracker struct {
		info           *ToolInfo
		healthyCount   int
		unhealthyCount int
	}

	toolMap := make(map[string]*toolHealthTracker)
	for _, inst := range instances {
		health := GetHealthStatus(inst)
		endpoint := inst.Metadata["grpc_endpoint"]

		if tracker, exists := toolMap[inst.Name]; exists {
			tracker.info.Instances++
			if endpoint != "" {
				tracker.info.Endpoints = append(tracker.info.Endpoints, endpoint)
			}
			if health == HealthStatusHealthy {
				tracker.healthyCount++
			} else {
				tracker.unhealthyCount++
			}
		} else {
			var caps *types.Capabilities
			if capsJSON, ok := inst.Metadata["capabilities"]; ok && capsJSON != "" {
				caps = parseCapabilitiesJSON(capsJSON)
			}
			healthyCount, unhealthyCount := 0, 0
			if health == HealthStatusHealthy {
				healthyCount = 1
			} else {
				unhealthyCount = 1
			}
			endpoints := []string{}
			if endpoint != "" {
				endpoints = []string{endpoint}
			}
			toolMap[inst.Name] = &toolHealthTracker{
				info: &ToolInfo{
					Name:         inst.Name,
					Version:      inst.Version,
					Description:  inst.Metadata["description"],
					Instances:    1,
					Endpoints:    endpoints,
					Capabilities: caps,
				},
				healthyCount:   healthyCount,
				unhealthyCount: unhealthyCount,
			}
		}
	}

	result := make([]ToolInfo, 0, len(toolMap))
	for _, tracker := range toolMap {
		tracker.info.Health = aggregateHealth(tracker.healthyCount, tracker.unhealthyCount)
		result = append(result, *tracker.info)
	}
	return result, nil
}

// ListPlugins returns information about all registered plugins.
func (a *RegistryAdapter) ListPlugins(ctx context.Context) ([]PluginInfo, error) {
	tenant := a.resolveTenant(ctx)
	instances, err := a.registry.DiscoverAll(ctx, tenant, "plugin")
	if err != nil {
		return nil, &RegistryUnavailableError{Cause: err}
	}

	type pluginHealthTracker struct {
		info           *PluginInfo
		healthyCount   int
		unhealthyCount int
	}

	pluginMap := make(map[string]*pluginHealthTracker)
	for _, inst := range instances {
		health := GetHealthStatus(inst)
		endpoint := inst.Metadata["grpc_endpoint"]

		if tracker, exists := pluginMap[inst.Name]; exists {
			tracker.info.Instances++
			if endpoint != "" {
				tracker.info.Endpoints = append(tracker.info.Endpoints, endpoint)
			}
			if health == HealthStatusHealthy {
				tracker.healthyCount++
			} else {
				tracker.unhealthyCount++
			}
		} else {
			healthyCount, unhealthyCount := 0, 0
			if health == HealthStatusHealthy {
				healthyCount = 1
			} else {
				unhealthyCount = 1
			}
			endpoints := []string{}
			if endpoint != "" {
				endpoints = []string{endpoint}
			}
			pluginMap[inst.Name] = &pluginHealthTracker{
				info: &PluginInfo{
					Name:        inst.Name,
					Version:     inst.Version,
					Description: inst.Metadata["description"],
					Instances:   1,
					Endpoints:   endpoints,
					Methods:     extractMethodNames(inst.Metadata),
				},
				healthyCount:   healthyCount,
				unhealthyCount: unhealthyCount,
			}
		}
	}

	result := make([]PluginInfo, 0, len(pluginMap))
	for _, tracker := range pluginMap {
		tracker.info.Health = aggregateHealth(tracker.healthyCount, tracker.unhealthyCount)
		result = append(result, *tracker.info)
	}
	return result, nil
}

// DelegateToAgent discovers an agent and executes a task on it.
func (a *RegistryAdapter) DelegateToAgent(ctx context.Context, name string, task agent.Task, harness agent.AgentHarness) (agent.Result, error) {
	agentClient, err := a.DiscoverAgent(ctx, name)
	if err != nil {
		return agent.Result{}, err
	}

	grpcAgent, isGRPCAgent := agentClient.(*GRPCAgentClient)

	if isGRPCAgent && a.callbackManager != nil {
		var missionID, agentName string
		var mission, target any

		harnessVal := reflect.ValueOf(harness)

		missionMethod := harnessVal.MethodByName("Mission")
		if missionMethod.IsValid() {
			results := missionMethod.Call(nil)
			if len(results) > 0 {
				mission = results[0].Interface()
			}
		}

		targetMethod := harnessVal.MethodByName("Target")
		if targetMethod.IsValid() {
			results := targetMethod.Call(nil)
			if len(results) > 0 {
				target = results[0].Interface()
			}
		}

		var missionRunID, agentRunID string
		var runNumber int32
		if mission != nil {
			missionVal := reflect.ValueOf(mission)
			if idField := missionVal.FieldByName("ID"); idField.IsValid() {
				if stringMethod := idField.MethodByName("String"); stringMethod.IsValid() {
					if results := stringMethod.Call(nil); len(results) > 0 {
						missionID = results[0].String()
					}
				}
			}
			if f := missionVal.FieldByName("CurrentAgent"); f.IsValid() {
				agentName = f.String()
			}
			if f := missionVal.FieldByName("MissionRunID"); f.IsValid() {
				missionRunID = f.String()
			}
			if f := missionVal.FieldByName("AgentRunID"); f.IsValid() {
				agentRunID = f.String()
			}
			if f := missionVal.FieldByName("RunNumber"); f.IsValid() && f.CanInt() {
				runNumber = int32(f.Int())
			}
		}

		if agentRunID == "" {
			agentRunID = contextkeys.GetAgentRunID(ctx)
		}

		var registrationKey string
		slog.Info("harness registration context",
			"mission_id", missionID,
			"agent_name", agentName,
			"task_id", task.ID.String(),
			"mission_run_id", missionRunID,
			"agent_run_id", agentRunID,
		)

		if missionID != "" && agentName != "" {
			registrationKey = a.callbackManager.RegisterHarnessForMission(missionID, agentName, harness)
		} else {
			registrationKey = a.callbackManager.RegisterHarnessForMission("", task.ID.String(), harness)
		}

		defer a.callbackManager.UnregisterHarness(registrationKey)

		var token string
		if a.authConfig != nil {
			var err error
			token, err = a.authConfig.GetToken()
			if err != nil {
				return agent.Result{}, fmt.Errorf("failed to get auth token: %w", err)
			}
		}

		callbackInfo := &CallbackInfo{
			Endpoint:     a.callbackManager.CallbackEndpoint(),
			Token:        token,
			Mission:      mission,
			Target:       target,
			MissionRunID: missionRunID,
			AgentRunID:   agentRunID,
			RunNumber:    runNumber,
		}

		result, err := grpcAgent.ExecuteWithCallback(ctx, task, callbackInfo)
		if err != nil {
			return agent.Result{}, fmt.Errorf("agent execution failed: %w", err)
		}
		return result, nil
	}

	result, err := agentClient.Execute(ctx, task, harness)
	if err != nil {
		return agent.Result{}, fmt.Errorf("agent execution failed: %w", err)
	}
	return result, nil
}

// Close releases resources held by the adapter.
func (a *RegistryAdapter) Close() error {
	if a.pool != nil {
		return a.pool.Close()
	}
	return nil
}

func (a *RegistryAdapter) getAvailableAgentNames(ctx context.Context) ([]string, error) {
	tenant := a.resolveTenant(ctx)
	instances, err := a.registry.DiscoverAll(ctx, tenant, "agent")
	if err != nil {
		return []string{}, err
	}
	nameSet := make(map[string]struct{})
	for _, inst := range instances {
		nameSet[inst.Name] = struct{}{}
	}
	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	return names, nil
}

func (a *RegistryAdapter) getAvailableToolNames(ctx context.Context) ([]string, error) {
	tenant := a.resolveTenant(ctx)
	instances, err := a.registry.DiscoverAll(ctx, tenant, "tool")
	if err != nil {
		return []string{}, err
	}
	nameSet := make(map[string]struct{})
	for _, inst := range instances {
		nameSet[inst.Name] = struct{}{}
	}
	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	return names, nil
}

func (a *RegistryAdapter) getAvailablePluginNames(ctx context.Context) ([]string, error) {
	tenant := a.resolveTenant(ctx)
	instances, err := a.registry.DiscoverAll(ctx, tenant, "plugin")
	if err != nil {
		return []string{}, err
	}
	nameSet := make(map[string]struct{})
	for _, inst := range instances {
		nameSet[inst.Name] = struct{}{}
	}
	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	return names, nil
}

// AgentNotFoundError is returned when an agent is requested but no instances are registered.
type AgentNotFoundError struct {
	Name      string
	Available []string
}

func (e *AgentNotFoundError) Error() string {
	if len(e.Available) == 0 {
		return fmt.Sprintf("agent '%s' not found (no agents registered)", e.Name)
	}
	return fmt.Sprintf("agent '%s' not found (available: %s)", e.Name, strings.Join(e.Available, ", "))
}

// ToolNotFoundError is returned when a tool is requested but no instances are registered.
type ToolNotFoundError struct {
	Name      string
	Available []string
}

func (e *ToolNotFoundError) Error() string {
	if len(e.Available) == 0 {
		return fmt.Sprintf("tool '%s' not found (no tools registered)", e.Name)
	}
	return fmt.Sprintf("tool '%s' not found (available: %s)", e.Name, strings.Join(e.Available, ", "))
}

// PluginNotFoundError is returned when a plugin is requested but no instances are registered.
type PluginNotFoundError struct {
	Name      string
	Available []string
}

func (e *PluginNotFoundError) Error() string {
	if len(e.Available) == 0 {
		return fmt.Sprintf("plugin '%s' not found (no plugins registered)", e.Name)
	}
	return fmt.Sprintf("plugin '%s' not found (available: %s)", e.Name, strings.Join(e.Available, ", "))
}

// RegistryUnavailableError is returned when the registry cannot be reached or returns an error.
type RegistryUnavailableError struct {
	Cause error
}

func (e *RegistryUnavailableError) Error() string {
	return fmt.Sprintf("registry unavailable: %v", e.Cause)
}

func (e *RegistryUnavailableError) Unwrap() error {
	return e.Cause
}

// NoHealthyInstancesError is returned when instances exist but all are unhealthy.
type NoHealthyInstancesError struct {
	Name  string
	Total int
}

func (e *NoHealthyInstancesError) Error() string {
	return fmt.Sprintf("no healthy instances of '%s' available (%d total instances)", e.Name, e.Total)
}

// parseCapabilitiesJSON deserializes a JSON-encoded Capabilities struct from metadata.
func parseCapabilitiesJSON(capsJSON string) *types.Capabilities {
	if capsJSON == "" {
		return nil
	}
	var caps types.Capabilities
	if err := json.Unmarshal([]byte(capsJSON), &caps); err != nil {
		slog.Warn("failed to parse tool capabilities JSON", "error", err, "json", capsJSON)
		return nil
	}
	return &caps
}
