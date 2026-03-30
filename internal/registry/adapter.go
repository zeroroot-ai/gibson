package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/contextkeys"
	"github.com/zero-day-ai/gibson/internal/plugin"
	"github.com/zero-day-ai/gibson/internal/tool"
	"github.com/zero-day-ai/sdk/protoresolver"
	sdkregistry "github.com/zero-day-ai/sdk/registry"
	"github.com/zero-day-ai/sdk/types"
)

// CallbackManager provides callback server functionality for agent harness operations.
// External gRPC agents can connect back to the callback server to access LLM, tools,
// memory, and other harness operations.
//
// This interface is implemented by harness.CallbackManager.
// Note: The harness parameter uses any to avoid circular imports between registry and harness.
// The actual implementation expects harness.AgentHarness.
type CallbackManager interface {
	// RegisterHarness registers a harness for a task and returns the callback endpoint.
	// The taskID is used to route callback requests to the correct harness instance.
	// The harness must implement harness.AgentHarness from internal/harness package.
	// DEPRECATED: Use RegisterHarnessForMission for new code.
	RegisterHarness(taskID string, harness any) string

	// RegisterHarnessForMission registers a harness for external agent execution within
	// a mission context and returns the registration key.
	// The harness is registered in the CallbackHarnessRegistry keyed by "missionID:agentName".
	// The harness must implement harness.AgentHarness from internal/harness package.
	RegisterHarnessForMission(missionID, agentName string, harness any) string

	// UnregisterHarness removes a harness registration after task or mission completion.
	// Works with both task-based and mission-based registration keys.
	UnregisterHarness(key string)

	// CallbackEndpoint returns the advertised callback endpoint address.
	CallbackEndpoint() string
}

// ComponentDiscovery provides a unified interface for discovering and connecting to
// agents, tools, and plugins registered in the etcd registry.
//
// This interface abstracts away the complexity of:
//   - Querying the registry for service instances
//   - Load-balancing across multiple instances
//   - Managing gRPC connection pooling
//   - Wrapping gRPC clients with Gibson's component interfaces
//
// Example usage:
//
//	reg, _ := NewExternalRegistry(cfg)
//	adapter := NewRegistryAdapter(reg)
//
//	// Discover and connect to an agent
//	davinci, err := adapter.DiscoverAgent(ctx, "davinci")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Execute a task on the agent
//	result, err := davinci.Execute(ctx, task, harness)
//
// Thread-safe: All methods can be called concurrently.
type ComponentDiscovery interface {
	// DiscoverAgent finds an agent by name and returns a gRPC client implementing agent.Agent.
	//
	// This method:
	//  1. Queries the registry for all instances of the agent
	//  2. Load-balances to select an instance
	//  3. Gets or creates a gRPC connection from the pool
	//  4. Returns a GRPCAgentClient wrapping the connection
	//
	// If no instances are registered, returns AgentNotFoundError with a list of
	// available agents to help with debugging.
	//
	// Example:
	//   agent, err := cd.DiscoverAgent(ctx, "k8skiller")
	//   if err != nil {
	//       var notFound *AgentNotFoundError
	//       if errors.As(err, &notFound) {
	//           fmt.Printf("Available agents: %v\n", notFound.Available)
	//       }
	//       return err
	//   }
	DiscoverAgent(ctx context.Context, name string) (agent.Agent, error)

	// DiscoverTool finds a tool by name and returns a gRPC client implementing tool.Tool.
	//
	// This method follows the same pattern as DiscoverAgent but for tools.
	// It queries the registry, selects an instance via load balancing, and returns
	// a GRPCToolClient wrapping the connection.
	DiscoverTool(ctx context.Context, name string) (tool.Tool, error)

	// DiscoverPlugin finds a plugin by name and returns a gRPC client implementing plugin.Plugin.
	//
	// This method follows the same pattern as DiscoverAgent but for plugins.
	// It queries the registry, selects an instance via load balancing, and returns
	// a GRPCPluginClient wrapping the connection.
	DiscoverPlugin(ctx context.Context, name string) (plugin.Plugin, error)

	// ListAgents returns information about all registered agents.
	//
	// This aggregates instances by agent name and includes:
	//   - Name, version, description
	//   - Number of instances running
	//   - Endpoints for all instances
	//   - Capabilities, target types, technique types
	//
	// Useful for status displays, dashboards, and agent selection UIs.
	ListAgents(ctx context.Context) ([]AgentInfo, error)

	// ListTools returns information about all registered tools.
	//
	// This aggregates instances by tool name and includes:
	//   - Name, version, description
	//   - Number of instances running
	//   - Endpoints for all instances
	//
	// Useful for status displays and tool selection UIs.
	ListTools(ctx context.Context) ([]ToolInfo, error)

	// ListPlugins returns information about all registered plugins.
	//
	// This aggregates instances by plugin name and includes:
	//   - Name, version, description
	//   - Number of instances running
	//   - Endpoints for all instances
	//
	// Useful for status displays and plugin selection UIs.
	ListPlugins(ctx context.Context) ([]PluginInfo, error)

	// DelegateToAgent executes a task on a remote agent via gRPC.
	//
	// This is a convenience method that combines DiscoverAgent and Execute in a single call.
	// It discovers the agent, establishes a connection, executes the task, and returns the result.
	//
	// The harness parameter provides the runtime environment for the remote agent.
	// Note: Currently the harness is not fully propagated over gRPC (future enhancement).
	//
	// Example:
	//   result, err := cd.DelegateToAgent(ctx, "davinci", task, harness)
	DelegateToAgent(ctx context.Context, name string, task agent.Task, harness agent.AgentHarness) (agent.Result, error)
}

// AgentInfo provides metadata about a registered agent.
//
// Multiple instances of the same agent are aggregated into a single AgentInfo
// entry with multiple endpoints.
type AgentInfo struct {
	// Name is the agent's unique identifier (e.g., "davinci", "k8skiller")
	Name string `json:"name"`

	// Version is the semantic version of the agent (e.g., "1.2.3")
	// If instances have different versions, this is the most recent
	Version string `json:"version"`

	// Description explains what the agent does
	Description string `json:"description"`

	// Instances is the number of running instances
	Instances int `json:"instances"`

	// Endpoints lists all instance endpoints (e.g., ["localhost:50051", "localhost:50052"])
	Endpoints []string `json:"endpoints"`

	// Capabilities lists the security testing capabilities (e.g., ["prompt_injection", "jailbreak"])
	Capabilities []string `json:"capabilities"`

	// TargetTypes lists supported target types (e.g., ["llm_chat", "llm_api"])
	TargetTypes []string `json:"target_types"`

	// TechniqueTypes lists attack techniques employed (e.g., ["prompt_injection", "model_extraction"])
	TechniqueTypes []string `json:"technique_types"`

	// Health is the aggregated health status of the agent instances.
	// Values: "healthy", "degraded", "unhealthy"
	// "healthy" if all instances are healthy
	// "degraded" if some instances are unhealthy
	// "unhealthy" if all instances are unhealthy
	Health string `json:"health"`
}

// ToolInfo provides metadata about a registered tool.
type ToolInfo struct {
	// Name is the tool's unique identifier (e.g., "nmap", "sqlmap")
	Name string `json:"name"`

	// Version is the semantic version of the tool
	Version string `json:"version"`

	// Description explains what the tool does
	Description string `json:"description"`

	// Instances is the number of running instances
	Instances int `json:"instances"`

	// Endpoints lists all instance endpoints
	Endpoints []string `json:"endpoints"`

	// Capabilities describes runtime privileges and features available to the tool.
	// Nil if the tool does not implement CapabilityProvider or has no specific requirements.
	Capabilities *types.Capabilities `json:"capabilities,omitempty"`

	// Health is the aggregated health status of the tool instances.
	// Values: "healthy", "degraded", "unhealthy"
	Health string `json:"health"`
}

// PluginInfo provides metadata about a registered plugin.
type PluginInfo struct {
	// Name is the plugin's unique identifier
	Name string `json:"name"`

	// Version is the semantic version of the plugin
	Version string `json:"version"`

	// Description explains what the plugin does
	Description string `json:"description"`

	// Instances is the number of running instances
	Instances int `json:"instances"`

	// Endpoints lists all instance endpoints
	Endpoints []string `json:"endpoints"`

	// Health is the aggregated health status of the plugin instances.
	// Values: "healthy", "degraded", "unhealthy"
	Health string `json:"health"`
}

// RegistryAdapter implements ComponentDiscovery using etcd registry and gRPC connection pooling.
//
// This is the primary implementation that bridges Gibson's registry infrastructure
// with component discovery. It coordinates between:
//   - Registry: Service discovery and instance listing
//   - LoadBalancer: Instance selection strategies
//   - GRPCPool: Connection management and reuse
//
// Example usage:
//
//	reg, _ := NewExternalRegistry(cfg)
//	adapter := NewRegistryAdapter(reg)
//	defer adapter.Close()
//
//	// Discover and use components
//	agent, _ := adapter.DiscoverAgent(ctx, "davinci")
//	tools, _ := adapter.ListTools(ctx)
//
// Thread-safe: All methods can be called concurrently.
type RegistryAdapter struct {
	// registry provides service discovery via etcd
	registry sdkregistry.Registry

	// loadBalancer selects instances when multiple are available
	loadBalancer *LoadBalancer

	// pool manages gRPC connections with automatic health checking
	pool *GRPCPool

	// callbackManager provides callback server for external agents (optional)
	// When set, enables external gRPC agents to access harness operations
	callbackManager CallbackManager

	// authConfig provides authentication configuration for callback connections (optional)
	// When set, tokens are included in callback info for external agents
	authConfig *AuthConfig

	// resolver provides proto type resolution for dynamically typed tool responses
	resolver protoresolver.ProtoResolver
}

// NewRegistryAdapter creates a new adapter wrapping an etcd registry.
//
// The adapter uses round-robin load balancing by default. This can be changed
// by accessing adapter.loadBalancer.SetStrategy().
//
// The adapter creates a new GRPCPool with default settings (insecure credentials).
// For custom connection options (TLS, keepalive, etc.), create a pool separately
// and use the WithPool option (when available).
//
// A DefaultProtoResolver is created for resolving proto message types during
// tool execution. This enables proper typing of tool responses even when types
// are not in the global proto registry.
//
// The caller is responsible for closing the registry when done. The adapter
// will close the connection pool when Close() is called.
//
// Parameters:
//   - reg: An active registry connection (embedded or external)
//
// Returns a RegistryAdapter ready for component discovery.
func NewRegistryAdapter(reg sdkregistry.Registry) *RegistryAdapter {
	return &RegistryAdapter{
		registry:     reg,
		loadBalancer: NewLoadBalancer(reg, StrategyRoundRobin),
		pool:         NewGRPCPool(),
		resolver:     protoresolver.NewDefaultProtoResolver(protoresolver.DefaultConfig()),
	}
}

// NewRegistryAdapterWithPool creates a new adapter with a custom GRPCPool.
// This is useful for testing when you need to inject a mock or test pool.
//
// A DefaultProtoResolver is created for resolving proto message types during
// tool execution. This enables proper typing of tool responses even when types
// are not in the global proto registry.
//
// Parameters:
//   - reg: An active registry connection
//   - pool: A custom GRPCPool (or compatible implementation)
//
// Returns a RegistryAdapter ready for component discovery.
func NewRegistryAdapterWithPool(reg sdkregistry.Registry, pool *GRPCPool) *RegistryAdapter {
	return &RegistryAdapter{
		registry:     reg,
		loadBalancer: NewLoadBalancer(reg, StrategyRoundRobin),
		pool:         pool,
		resolver:     protoresolver.NewDefaultProtoResolver(protoresolver.DefaultConfig()),
	}
}

// SetCallbackManager configures the callback manager for this adapter.
// When set, external gRPC agents will receive callback endpoint information
// and can access harness operations (LLM, tools, memory, etc.) via callbacks.
//
// This should be called during Gibson initialization after the callback server
// is started and before any agent execution occurs.
//
// Parameters:
//   - cm: The callback manager providing harness callback functionality
func (a *RegistryAdapter) SetCallbackManager(cm CallbackManager) {
	a.callbackManager = cm
}

// SetAuthConfig configures authentication for callback connections.
// When set, tokens from the auth config are included in callback info
// for external agents to authenticate their callback requests.
//
// This should be called during Gibson initialization if authentication
// is required for callback connections.
//
// Parameters:
//   - cfg: The authentication configuration
func (a *RegistryAdapter) SetAuthConfig(cfg *AuthConfig) {
	a.authConfig = cfg
}

// SetResolver configures a custom ProtoResolver for this adapter.
// This is primarily useful for testing when you need to inject a mock resolver.
//
// In normal operation, the default resolver created by NewRegistryAdapter
// should be sufficient.
//
// Parameters:
//   - r: The ProtoResolver to use for type resolution
func (a *RegistryAdapter) SetResolver(r protoresolver.ProtoResolver) {
	a.resolver = r
}

// GetResolver returns the ProtoResolver used by this adapter.
// This allows sharing the resolver with other components (e.g., CallbackManager)
// to maintain a unified cache of FileDescriptorSets.
//
// Returns:
//   - protoresolver.ProtoResolver: The resolver instance used by this adapter
func (a *RegistryAdapter) GetResolver() protoresolver.ProtoResolver {
	return a.resolver
}

// DiscoverAgent discovers and connects to an agent by name.
//
// This method:
//  1. Queries registry for agent instances: registry.Discover(ctx, "agent", name)
//  2. Returns AgentNotFoundError if no instances exist
//  3. Load-balances to select an instance
//  4. Gets/creates gRPC connection from pool
//  5. Returns GRPCAgentClient wrapping the connection
//
// If the registry is unavailable, returns RegistryUnavailableError.
// If instances exist but all are unhealthy, returns NoHealthyInstancesError.
//
// The returned agent.Agent interface can be used exactly like a local agent:
//
//	agent, err := adapter.DiscoverAgent(ctx, "k8skiller")
//	if err != nil {
//	    return err
//	}
//
//	result, err := agent.Execute(ctx, task, harness)
func (a *RegistryAdapter) DiscoverAgent(ctx context.Context, name string) (agent.Agent, error) {
	// Query registry for instances
	instances, err := a.registry.Discover(ctx, "agent", name)
	if err != nil {
		return nil, &RegistryUnavailableError{Cause: err}
	}

	if len(instances) == 0 {
		// No instances found - provide helpful error with available agents
		available, err := a.getAvailableAgentNames(ctx)
		if err != nil {
			// Failed to list available agents, return simpler error
			return nil, &AgentNotFoundError{
				Name:      name,
				Available: []string{},
			}
		}
		return nil, &AgentNotFoundError{
			Name:      name,
			Available: available,
		}
	}

	// Load balance to select an instance
	selected, err := a.loadBalancer.Select(ctx, "agent", name)
	if err != nil {
		return nil, fmt.Errorf("failed to select agent instance: %w", err)
	}

	// Get or create gRPC connection
	conn, err := a.pool.Get(ctx, selected.Endpoint)
	if err != nil {
		// Connection failed - this instance may be unhealthy
		// Try to remove it from the pool and return error
		_ = a.pool.Remove(selected.Endpoint)
		return nil, fmt.Errorf("failed to connect to agent %s at %s: %w", name, selected.Endpoint, err)
	}

	// Create and return GRPCAgentClient
	client := NewGRPCAgentClient(conn, *selected)
	return client, nil
}

// DiscoverTool discovers and connects to a tool by name.
//
// This method:
//  1. Queries registry for tool instances: registry.Discover(ctx, "tool", name)
//  2. Returns ToolNotFoundError if no instances exist
//  3. Load-balances to select an instance
//  4. Gets/creates gRPC connection from pool
//  5. Returns GRPCToolClient wrapping the connection
//
// If the registry is unavailable, returns RegistryUnavailableError.
// If instances exist but all are unhealthy, returns NoHealthyInstancesError.
//
// The returned tool.Tool interface can be used exactly like a local tool:
//
//	tool, err := adapter.DiscoverTool(ctx, "nmap")
//	if err != nil {
//	    return err
//	}
//
//	result, err := tool.Execute(ctx, input)
func (a *RegistryAdapter) DiscoverTool(ctx context.Context, name string) (tool.Tool, error) {
	// Query registry for instances
	instances, err := a.registry.Discover(ctx, "tool", name)
	if err != nil {
		return nil, &RegistryUnavailableError{Cause: err}
	}

	if len(instances) == 0 {
		// No instances found - provide helpful error with available tools
		available, err := a.getAvailableToolNames(ctx)
		if err != nil {
			// Failed to list available tools, return simpler error
			return nil, &ToolNotFoundError{
				Name:      name,
				Available: []string{},
			}
		}
		return nil, &ToolNotFoundError{
			Name:      name,
			Available: available,
		}
	}

	// Load balance to select an instance
	selected, err := a.loadBalancer.Select(ctx, "tool", name)
	if err != nil {
		return nil, fmt.Errorf("failed to select tool instance: %w", err)
	}

	// Get or create gRPC connection
	conn, err := a.pool.Get(ctx, selected.Endpoint)
	if err != nil {
		// Connection failed - this instance may be unhealthy
		// Try to remove it from the pool and return error
		_ = a.pool.Remove(selected.Endpoint)
		return nil, fmt.Errorf("failed to connect to tool %s at %s: %w", name, selected.Endpoint, err)
	}

	// Create and return GRPCToolClient
	client := NewGRPCToolClient(conn, *selected, a.resolver)
	return client, nil
}

// DiscoverPlugin discovers and connects to a plugin by name.
//
// This method:
//  1. Queries registry for plugin instances: registry.Discover(ctx, "plugin", name)
//  2. Returns PluginNotFoundError if no instances exist
//  3. Load-balances to select an instance
//  4. Gets/creates gRPC connection from pool
//  5. Returns GRPCPluginClient wrapping the connection
//
// If the registry is unavailable, returns RegistryUnavailableError.
// If instances exist but all are unhealthy, returns NoHealthyInstancesError.
//
// The returned plugin.Plugin interface can be used exactly like a local plugin:
//
//	plugin, err := adapter.DiscoverPlugin(ctx, "mitre-lookup")
//	if err != nil {
//	    return err
//	}
//
//	result, err := plugin.Query(ctx, "search", params)
func (a *RegistryAdapter) DiscoverPlugin(ctx context.Context, name string) (plugin.Plugin, error) {
	// Query registry for instances
	instances, err := a.registry.Discover(ctx, "plugin", name)
	if err != nil {
		return nil, &RegistryUnavailableError{Cause: err}
	}

	if len(instances) == 0 {
		// No instances found - provide helpful error with available plugins
		available, err := a.getAvailablePluginNames(ctx)
		if err != nil {
			// Failed to list available plugins, return simpler error
			return nil, &PluginNotFoundError{
				Name:      name,
				Available: []string{},
			}
		}
		return nil, &PluginNotFoundError{
			Name:      name,
			Available: available,
		}
	}

	// Load balance to select an instance
	selected, err := a.loadBalancer.Select(ctx, "plugin", name)
	if err != nil {
		return nil, fmt.Errorf("failed to select plugin instance: %w", err)
	}

	// Get or create gRPC connection
	conn, err := a.pool.Get(ctx, selected.Endpoint)
	if err != nil {
		// Connection failed - this instance may be unhealthy
		// Try to remove it from the pool and return error
		_ = a.pool.Remove(selected.Endpoint)
		return nil, fmt.Errorf("failed to connect to plugin %s at %s: %w", name, selected.Endpoint, err)
	}

	// Create and return GRPCPluginClient
	client := NewGRPCPluginClient(conn, *selected)
	return client, nil
}

// ListAgents returns information about all registered agents.
//
// This method:
//  1. Calls registry.DiscoverAll(ctx, "agent") to get all agent instances
//  2. Aggregates instances by name
//  3. Extracts metadata (capabilities, target types, etc.) from ServiceInfo
//  4. Returns a deduplicated list of AgentInfo
//
// The returned list is useful for:
//   - Status displays showing available agents
//   - Dashboards monitoring agent health
//   - Agent selection UIs
//
// Example output:
//
//	[
//	  {
//	    "name": "davinci",
//	    "version": "1.0.0",
//	    "instances": 2,
//	    "endpoints": ["localhost:50051", "localhost:50052"],
//	    "capabilities": ["jailbreak", "prompt_injection"]
//	  }
//	]
func (a *RegistryAdapter) ListAgents(ctx context.Context) ([]AgentInfo, error) {
	// Query registry for all agent instances
	instances, err := a.registry.DiscoverAll(ctx, "agent")
	if err != nil {
		return nil, &RegistryUnavailableError{Cause: err}
	}

	// Track health per agent for aggregation
	type agentHealthTracker struct {
		info           *AgentInfo
		healthyCount   int
		unhealthyCount int
	}

	// Aggregate by name
	agentMap := make(map[string]*agentHealthTracker)
	for _, inst := range instances {
		health := GetHealthStatus(inst)

		if tracker, exists := agentMap[inst.Name]; exists {
			// Add to existing entry
			tracker.info.Instances++
			tracker.info.Endpoints = append(tracker.info.Endpoints, inst.Endpoint)
			// Track health counts
			if health == HealthStatusHealthy {
				tracker.healthyCount++
			} else {
				tracker.unhealthyCount++
			}
		} else {
			// Create new entry
			healthyCount := 0
			unhealthyCount := 0
			if health == HealthStatusHealthy {
				healthyCount = 1
			} else {
				unhealthyCount = 1
			}

			agentMap[inst.Name] = &agentHealthTracker{
				info: &AgentInfo{
					Name:           inst.Name,
					Version:        inst.Version,
					Description:    inst.Metadata["description"],
					Instances:      1,
					Endpoints:      []string{inst.Endpoint},
					Capabilities:   parseCommaSeparated(inst.Metadata["capabilities"]),
					TargetTypes:    parseCommaSeparated(inst.Metadata["target_types"]),
					TechniqueTypes: parseCommaSeparated(inst.Metadata["technique_types"]),
				},
				healthyCount:   healthyCount,
				unhealthyCount: unhealthyCount,
			}
		}
	}

	// Convert map to slice and compute aggregated health
	result := make([]AgentInfo, 0, len(agentMap))
	for _, tracker := range agentMap {
		// Determine aggregated health status
		tracker.info.Health = aggregateHealth(tracker.healthyCount, tracker.unhealthyCount)
		result = append(result, *tracker.info)
	}

	return result, nil
}

// ListTools returns information about all registered tools.
//
// This method follows the same aggregation pattern as ListAgents.
func (a *RegistryAdapter) ListTools(ctx context.Context) ([]ToolInfo, error) {
	// Query registry for all tool instances
	instances, err := a.registry.DiscoverAll(ctx, "tool")
	if err != nil {
		return nil, &RegistryUnavailableError{Cause: err}
	}

	// Track health per tool for aggregation
	type toolHealthTracker struct {
		info           *ToolInfo
		healthyCount   int
		unhealthyCount int
	}

	// Aggregate by name
	toolMap := make(map[string]*toolHealthTracker)
	for _, inst := range instances {
		health := GetHealthStatus(inst)

		if tracker, exists := toolMap[inst.Name]; exists {
			// Add to existing entry
			tracker.info.Instances++
			tracker.info.Endpoints = append(tracker.info.Endpoints, inst.Endpoint)
			// Track health counts
			if health == HealthStatusHealthy {
				tracker.healthyCount++
			} else {
				tracker.unhealthyCount++
			}
		} else {
			// Parse capabilities from metadata if present
			var caps *types.Capabilities
			if capsJSON, ok := inst.Metadata["capabilities"]; ok && capsJSON != "" {
				caps = parseCapabilitiesJSON(capsJSON)
			}

			healthyCount := 0
			unhealthyCount := 0
			if health == HealthStatusHealthy {
				healthyCount = 1
			} else {
				unhealthyCount = 1
			}

			// Create new entry
			toolMap[inst.Name] = &toolHealthTracker{
				info: &ToolInfo{
					Name:         inst.Name,
					Version:      inst.Version,
					Description:  inst.Metadata["description"],
					Instances:    1,
					Endpoints:    []string{inst.Endpoint},
					Capabilities: caps,
				},
				healthyCount:   healthyCount,
				unhealthyCount: unhealthyCount,
			}
		}
	}

	// Convert map to slice and compute aggregated health
	result := make([]ToolInfo, 0, len(toolMap))
	for _, tracker := range toolMap {
		// Determine aggregated health status
		tracker.info.Health = aggregateHealth(tracker.healthyCount, tracker.unhealthyCount)
		result = append(result, *tracker.info)
	}

	return result, nil
}

// ListPlugins returns information about all registered plugins.
//
// This method follows the same aggregation pattern as ListAgents.
func (a *RegistryAdapter) ListPlugins(ctx context.Context) ([]PluginInfo, error) {
	// Query registry for all plugin instances
	instances, err := a.registry.DiscoverAll(ctx, "plugin")
	if err != nil {
		return nil, &RegistryUnavailableError{Cause: err}
	}

	// Track health per plugin for aggregation
	type pluginHealthTracker struct {
		info           *PluginInfo
		healthyCount   int
		unhealthyCount int
	}

	// Aggregate by name
	pluginMap := make(map[string]*pluginHealthTracker)
	for _, inst := range instances {
		health := GetHealthStatus(inst)

		if tracker, exists := pluginMap[inst.Name]; exists {
			// Add to existing entry
			tracker.info.Instances++
			tracker.info.Endpoints = append(tracker.info.Endpoints, inst.Endpoint)
			// Track health counts
			if health == HealthStatusHealthy {
				tracker.healthyCount++
			} else {
				tracker.unhealthyCount++
			}
		} else {
			healthyCount := 0
			unhealthyCount := 0
			if health == HealthStatusHealthy {
				healthyCount = 1
			} else {
				unhealthyCount = 1
			}

			// Create new entry
			pluginMap[inst.Name] = &pluginHealthTracker{
				info: &PluginInfo{
					Name:        inst.Name,
					Version:     inst.Version,
					Description: inst.Metadata["description"],
					Instances:   1,
					Endpoints:   []string{inst.Endpoint},
				},
				healthyCount:   healthyCount,
				unhealthyCount: unhealthyCount,
			}
		}
	}

	// Convert map to slice and compute aggregated health
	result := make([]PluginInfo, 0, len(pluginMap))
	for _, tracker := range pluginMap {
		// Determine aggregated health status
		tracker.info.Health = aggregateHealth(tracker.healthyCount, tracker.unhealthyCount)
		result = append(result, *tracker.info)
	}

	return result, nil
}

// DelegateToAgent discovers an agent and executes a task on it.
//
// This is a convenience method that combines DiscoverAgent and Execute.
// It's useful for one-off task delegation without keeping a reference to the agent.
//
// If a CallbackManager is configured, this method will:
//  1. Register the harness with the callback server before execution
//  2. Pass callback endpoint to the agent via ExecuteWithCallback
//  3. Unregister the harness after execution (even if execution fails)
//
// This enables external gRPC agents to access harness operations (LLM, tools,
// memory, findings) by connecting back to Gibson Core's callback server.
//
// Example:
//
//	result, err := adapter.DelegateToAgent(ctx, "davinci", task, harness)
//	if err != nil {
//	    log.Printf("Delegation failed: %v", err)
//	    return err
//	}
//
//	log.Printf("Task result: %s", result.Status)
func (a *RegistryAdapter) DelegateToAgent(ctx context.Context, name string, task agent.Task, harness agent.AgentHarness) (agent.Result, error) {
	// Discover the agent
	agentClient, err := a.DiscoverAgent(ctx, name)
	if err != nil {
		return agent.Result{}, err
	}

	// Check if this is a gRPC agent and if callback is enabled
	grpcAgent, isGRPCAgent := agentClient.(*GRPCAgentClient)

	if isGRPCAgent && a.callbackManager != nil {
		// Extract mission context and target from the harness via reflection
		// We use reflection because harness.MissionContext and harness.TargetInfo have specific
		// return types that don't match a simple `any` interface, and we can't import
		// the harness package here due to circular dependency issues.
		var missionID, agentName string
		var mission, target any

		// Use reflection to call Mission() and Target() methods on the harness
		harnessVal := reflect.ValueOf(harness)

		// Call Mission() method
		missionMethod := harnessVal.MethodByName("Mission")
		if missionMethod.IsValid() {
			results := missionMethod.Call(nil)
			if len(results) > 0 {
				mission = results[0].Interface()
			}
		}

		// Call Target() method
		targetMethod := harnessVal.MethodByName("Target")
		if targetMethod.IsValid() {
			results := targetMethod.Call(nil)
			if len(results) > 0 {
				target = results[0].Interface()
			}
		}

		// Extract mission context fields via reflection
		var missionRunID, agentRunID string
		var runNumber int32
		if mission != nil {
			missionVal := reflect.ValueOf(mission)
			// Get ID field and call String() on it
			idField := missionVal.FieldByName("ID")
			if idField.IsValid() {
				stringMethod := idField.MethodByName("String")
				if stringMethod.IsValid() {
					results := stringMethod.Call(nil)
					if len(results) > 0 {
						missionID = results[0].String()
					}
				}
			}
			// Get CurrentAgent field
			currentAgentField := missionVal.FieldByName("CurrentAgent")
			if currentAgentField.IsValid() {
				agentName = currentAgentField.String()
			}
			// Get MissionRunID field (for mission-scoped storage)
			missionRunIDField := missionVal.FieldByName("MissionRunID")
			if missionRunIDField.IsValid() {
				missionRunID = missionRunIDField.String()
			}
			// Get AgentRunID field (for provenance tracking)
			agentRunIDField := missionVal.FieldByName("AgentRunID")
			if agentRunIDField.IsValid() {
				agentRunID = agentRunIDField.String()
			}
			// Get RunNumber field (for historical queries)
			runNumberField := missionVal.FieldByName("RunNumber")
			if runNumberField.IsValid() && runNumberField.CanInt() {
				runNumber = int32(runNumberField.Int())
			}
		}

		// Fall back to context for AgentRunID if not set on mission struct
		// The orchestrator injects this via harness.ContextWithAgentRunID before delegation
		if agentRunID == "" {
			agentRunID = contextkeys.GetAgentRunID(ctx)
		}

		// Use mission-based registration if we have both mission ID and agent name
		var registrationKey string
		slog.Info("harness registration context",
			"mission_id", missionID,
			"agent_name", agentName,
			"task_id", task.ID.String(),
			"mission_run_id", missionRunID,
			"agent_run_id", agentRunID,
		)
		if missionID != "" && agentName != "" && a.callbackManager != nil {
			// Check if callback manager supports mission-based registration
			type missionRegistrar interface {
				RegisterHarnessForMission(missionID, agentName string, harness any) string
			}

			if mr, ok := a.callbackManager.(missionRegistrar); ok {
				// Use new mission-based registration
				registrationKey = mr.RegisterHarnessForMission(missionID, agentName, harness)
			} else {
				// Fall back to task-based registration
				taskID := task.ID.String()
				registrationKey = a.callbackManager.RegisterHarness(taskID, harness)
			}
		} else {
			// Fall back to legacy task-based registration
			taskID := task.ID.String()
			registrationKey = a.callbackManager.RegisterHarness(taskID, harness)
		}

		// Ensure unregistration happens even on failure
		defer a.callbackManager.UnregisterHarness(registrationKey)

		// Get authentication token if configured
		var token string
		if a.authConfig != nil {
			var err error
			token, err = a.authConfig.GetToken()
			if err != nil {
				return agent.Result{}, fmt.Errorf("failed to get auth token: %w", err)
			}
		}

		// Create callback info with endpoint and context
		callbackInfo := &CallbackInfo{
			Endpoint:     a.callbackManager.CallbackEndpoint(),
			Token:        token,
			Mission:      mission,
			Target:       target,
			MissionRunID: missionRunID,
			AgentRunID:   agentRunID,
			RunNumber:    runNumber,
		}

		// Execute with callback support
		result, err := grpcAgent.ExecuteWithCallback(ctx, task, callbackInfo)
		if err != nil {
			return agent.Result{}, fmt.Errorf("agent execution failed: %w", err)
		}

		return result, nil
	}

	// Fall back to standard execution for local agents or when callback is disabled
	result, err := agentClient.Execute(ctx, task, harness)
	if err != nil {
		return agent.Result{}, fmt.Errorf("agent execution failed: %w", err)
	}

	return result, nil
}

// Close releases resources held by the adapter.
//
// This closes the gRPC connection pool, terminating all active connections.
// The registry is NOT closed - the caller is responsible for that.
//
// After Close() is called, the adapter should not be used.
//
// Returns an error if the pool fails to close (typically safe to ignore).
func (a *RegistryAdapter) Close() error {
	if a.pool != nil {
		return a.pool.Close()
	}
	return nil
}

// getAvailableAgentNames returns a list of all registered agent names.
//
// This is used to provide helpful error messages when an agent is not found.
// Returns an empty slice if the registry query fails.
func (a *RegistryAdapter) getAvailableAgentNames(ctx context.Context) ([]string, error) {
	instances, err := a.registry.DiscoverAll(ctx, "agent")
	if err != nil {
		return []string{}, err
	}

	// Deduplicate by name
	nameSet := make(map[string]struct{})
	for _, inst := range instances {
		nameSet[inst.Name] = struct{}{}
	}

	// Convert to sorted slice
	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}

	return names, nil
}

// getAvailablePluginNames returns a list of all registered plugin names.
//
// This is used to provide helpful error messages when a plugin is not found.
// Returns an empty slice if the registry query fails.
func (a *RegistryAdapter) getAvailablePluginNames(ctx context.Context) ([]string, error) {
	instances, err := a.registry.DiscoverAll(ctx, "plugin")
	if err != nil {
		return []string{}, err
	}

	// Deduplicate by name
	nameSet := make(map[string]struct{})
	for _, inst := range instances {
		nameSet[inst.Name] = struct{}{}
	}

	// Convert to sorted slice
	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}

	return names, nil
}

// getAvailableToolNames returns a list of all registered tool names.
//
// This is used to provide helpful error messages when a tool is not found.
// Returns an empty slice if the registry query fails.
func (a *RegistryAdapter) getAvailableToolNames(ctx context.Context) ([]string, error) {
	instances, err := a.registry.DiscoverAll(ctx, "tool")
	if err != nil {
		return []string{}, err
	}

	// Deduplicate by name
	nameSet := make(map[string]struct{})
	for _, inst := range instances {
		nameSet[inst.Name] = struct{}{}
	}

	// Convert to sorted slice
	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}

	return names, nil
}

// parseCommaSeparated is defined in grpc_agent_client.go
// and is reused here to parse metadata fields

// AgentNotFoundError is returned when an agent is requested but no instances are registered.
//
// This error includes a list of available agents to help with debugging and
// provides a clear error message.
//
// Example usage:
//
//	agent, err := adapter.DiscoverAgent(ctx, "nonexistent")
//	if err != nil {
//	    var notFound *AgentNotFoundError
//	    if errors.As(err, &notFound) {
//	        fmt.Printf("Agent '%s' not found\n", notFound.Name)
//	        fmt.Printf("Available agents: %v\n", notFound.Available)
//	    }
//	    return err
//	}
type AgentNotFoundError struct {
	// Name is the requested agent name
	Name string

	// Available is a list of registered agent names
	Available []string
}

// Error implements the error interface.
func (e *AgentNotFoundError) Error() string {
	if len(e.Available) == 0 {
		return fmt.Sprintf("agent '%s' not found (no agents registered)", e.Name)
	}
	return fmt.Sprintf("agent '%s' not found (available: %s)", e.Name, strings.Join(e.Available, ", "))
}

// ToolNotFoundError is returned when a tool is requested but no instances are registered.
//
// This error includes a list of available tools to help with debugging and
// provides a clear error message.
//
// Example usage:
//
//	tool, err := adapter.DiscoverTool(ctx, "nonexistent")
//	if err != nil {
//	    var notFound *ToolNotFoundError
//	    if errors.As(err, &notFound) {
//	        fmt.Printf("Tool '%s' not found\n", notFound.Name)
//	        fmt.Printf("Available tools: %v\n", notFound.Available)
//	    }
//	    return err
//	}
type ToolNotFoundError struct {
	// Name is the requested tool name
	Name string

	// Available is a list of registered tool names
	Available []string
}

// Error implements the error interface.
func (e *ToolNotFoundError) Error() string {
	if len(e.Available) == 0 {
		return fmt.Sprintf("tool '%s' not found (no tools registered)", e.Name)
	}
	return fmt.Sprintf("tool '%s' not found (available: %s)", e.Name, strings.Join(e.Available, ", "))
}

// RegistryUnavailableError is returned when the registry cannot be reached or returns an error.
//
// This error wraps the underlying cause for debugging.
//
// Example usage:
//
//	agents, err := adapter.ListAgents(ctx)
//	if err != nil {
//	    var unavailable *RegistryUnavailableError
//	    if errors.As(err, &unavailable) {
//	        log.Printf("Registry down: %v", unavailable.Cause)
//	    }
//	}
type RegistryUnavailableError struct {
	// Cause is the underlying error from the registry
	Cause error
}

// Error implements the error interface.
func (e *RegistryUnavailableError) Error() string {
	return fmt.Sprintf("registry unavailable: %v", e.Cause)
}

// Unwrap enables errors.Unwrap to access the underlying error.
func (e *RegistryUnavailableError) Unwrap() error {
	return e.Cause
}

// PluginNotFoundError is returned when a plugin is requested but no instances are registered.
//
// This error includes a list of available plugins to help with debugging and
// provides a clear error message.
//
// Example usage:
//
//	plugin, err := adapter.DiscoverPlugin(ctx, "nonexistent")
//	if err != nil {
//	    var notFound *PluginNotFoundError
//	    if errors.As(err, &notFound) {
//	        fmt.Printf("Plugin '%s' not found\n", notFound.Name)
//	        fmt.Printf("Available plugins: %v\n", notFound.Available)
//	    }
//	    return err
//	}
type PluginNotFoundError struct {
	// Name is the requested plugin name
	Name string

	// Available is a list of registered plugin names
	Available []string
}

// Error implements the error interface.
func (e *PluginNotFoundError) Error() string {
	if len(e.Available) == 0 {
		return fmt.Sprintf("plugin '%s' not found (no plugins registered)", e.Name)
	}
	return fmt.Sprintf("plugin '%s' not found (available: %s)", e.Name, strings.Join(e.Available, ", "))
}

// NoHealthyInstancesError is returned when instances exist but all are unhealthy.
//
// This indicates a service is registered but all instances are failing health checks
// or connection attempts.
//
// Example usage:
//
//	agent, err := adapter.DiscoverAgent(ctx, "davinci")
//	if err != nil {
//	    var noHealthy *NoHealthyInstancesError
//	    if errors.As(err, &noHealthy) {
//	        log.Printf("All %d instances of %s are unhealthy", noHealthy.Total, noHealthy.Name)
//	    }
//	}
type NoHealthyInstancesError struct {
	// Name is the service name
	Name string

	// Total is the number of registered instances (all unhealthy)
	Total int
}

// Error implements the error interface.
func (e *NoHealthyInstancesError) Error() string {
	return fmt.Sprintf("no healthy instances of '%s' available (%d total instances)", e.Name, e.Total)
}

// parseCapabilitiesJSON deserializes a JSON-encoded Capabilities struct from metadata.
//
// Returns nil if the JSON is empty, invalid, or cannot be parsed. This ensures
// graceful handling of tools that don't provide capabilities.
//
// Example input: {"has_root":true,"can_raw_socket":false,"features":{"stealth_scan":false}}
func parseCapabilitiesJSON(capsJSON string) *types.Capabilities {
	if capsJSON == "" {
		return nil
	}

	var caps types.Capabilities
	if err := json.Unmarshal([]byte(capsJSON), &caps); err != nil {
		// Log the error but return nil to allow graceful degradation
		slog.Warn("failed to parse tool capabilities JSON", "error", err, "json", capsJSON)
		return nil
	}

	return &caps
}
