// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package component provides unified component discovery and delegation for Gibson.
//
// This file implements RegistryAdapter, which reads agent, tool and plugin
// entries from the component registry. Work reaches a component through the
// work queue. The daemon dials no component (gibson#813).
package component

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

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
	// DescribeTool returns the registry entry of a tool by name: its version
	// and the metadata it registered (description, tags, message types,
	// capabilities). It dials nothing.
	DescribeTool(ctx context.Context, name string) (ComponentInfo, error)

	// ListAgents returns information about all registered agents.
	ListAgents(ctx context.Context) ([]AgentInfo, error)

	// ListTools returns information about all registered tools.
	ListTools(ctx context.Context) ([]ToolInfo, error)

	// ListPlugins returns information about all registered plugins.
	ListPlugins(ctx context.Context) ([]PluginInfo, error)
}

// AgentInfo provides metadata about a registered agent.
type AgentInfo struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	Description    string   `json:"description"`
	Instances      int      `json:"instances"`
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
	Capabilities *types.Capabilities `json:"capabilities,omitempty"`
	Health       string              `json:"health"`
}

// PluginInfo provides metadata about a registered plugin.
type PluginInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Instances   int    `json:"instances"`
	Health      string `json:"health"`
	// Methods is the list of declared method names for the plugin,
	// derived from the component registry metadata set at registration time.
	Methods []string `json:"methods,omitempty"`
}

// RegistryAdapter implements ComponentDiscovery on the Redis-backed
// ComponentRegistry.
//
// Thread-safe: All methods can be called concurrently.
type RegistryAdapter struct {
	// registry provides component discovery via Redis
	registry ComponentRegistry

	// resolver provides proto type resolution for dynamically typed tool responses
	resolver protoresolver.ProtoResolver
}

// NewRegistryAdapter creates a new adapter wrapping a ComponentRegistry.
//
// The adapter carries no default tenant: every discovery query takes its tenant from the caller's context and
// is refused without one, so a single adapter serves every tenant without any
// of them being able to see another's components. The configured-default it
// used to hold was the mechanism by which they could.
//
// The caller is responsible for managing the registry lifecycle.
func NewRegistryAdapter(reg ComponentRegistry) *RegistryAdapter {
	return &RegistryAdapter{
		registry: reg,
		resolver: protoresolver.NewDefaultProtoResolver(protoresolver.DefaultConfig()),
	}
}

// SetCallbackManager configures the callback manager for this adapter.
func (a *RegistryAdapter) SetCallbackManager(cm CallbackManager) {
}

// SetAuthConfig configures authentication for callback connections.
func (a *RegistryAdapter) SetAuthConfig(cfg *AuthConfig) {
}

// SetResolver configures a custom ProtoResolver for this adapter.
func (a *RegistryAdapter) SetResolver(r protoresolver.ProtoResolver) {
	a.resolver = r
}

// GetResolver returns the ProtoResolver used by this adapter.
func (a *RegistryAdapter) GetResolver() protoresolver.ProtoResolver {
	return a.resolver
}

// ErrNoTenantInContext reports a registry query whose context names no tenant.
//
// It used to fall back to the adapter's configured tenant — in the daemon, the
// literal string "default". That is not a tenant, it is a shared namespace that
// every caller without an identity landed in together: components enrolled by
// one tenant were discoverable by any caller that arrived without one, and the
// query looked successful either way. Nothing in the return value distinguished
// "this tenant has these components" from "somebody's components are in the
// shared bucket".
//
// A registry query with no tenant is now refused. Discovery is a per-tenant
// operation and there is no answer to it that is not somebody's data; a caller
// that cannot say whose data it wants must not receive any.
var ErrNoTenantInContext = errors.New(
	"component: registry query has no tenant in context; discovery is per-tenant and will not fall back to a shared namespace")

// resolveTenant returns the tenant for a registry query, taken from the request
// context (set by the identity interceptor for authenticated RPCs, or bound
// explicitly by a background caller that knows whose work it is running).
//
// The _system sentinel returned by TenantFromContext when no real tenant is
// present counts as absent: it is the marker for "no identity resolved", not a
// tenant whose components anyone should see.
func (a *RegistryAdapter) resolveTenant(ctx context.Context) (string, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" || tenant == auth.SystemTenantString {
		return "", ErrNoTenantInContext
	}
	return tenant, nil
}

// DescribeTool returns the registry entry of a tool by name. When more than
// one instance is registered, the entry of the first is returned: each
// instance of one tool registers the same metadata.
func (a *RegistryAdapter) DescribeTool(ctx context.Context, name string) (ComponentInfo, error) {
	tenant, err := a.resolveTenant(ctx)
	if err != nil {
		return ComponentInfo{}, err
	}
	instances, err := a.registry.Discover(ctx, tenant, "tool", name)
	if err != nil {
		return ComponentInfo{}, &RegistryUnavailableError{Cause: err}
	}
	if len(instances) == 0 {
		available, _ := a.getAvailableToolNames(ctx)
		return ComponentInfo{}, &ToolNotFoundError{Name: name, Available: available}
	}
	return instances[0], nil
}

// ListAgents returns information about all registered agents.
func (a *RegistryAdapter) ListAgents(ctx context.Context) ([]AgentInfo, error) {
	tenant, err := a.resolveTenant(ctx)
	if err != nil {
		return nil, err
	}
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

		if tracker, exists := agentMap[inst.Name]; exists {
			tracker.info.Instances++
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
			agentMap[inst.Name] = &agentHealthTracker{
				info: &AgentInfo{
					Name:           inst.Name,
					Version:        inst.Version,
					Description:    inst.Metadata["description"],
					Instances:      1,
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
	tenant, err := a.resolveTenant(ctx)
	if err != nil {
		return nil, err
	}
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

		if tracker, exists := toolMap[inst.Name]; exists {
			tracker.info.Instances++
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
			toolMap[inst.Name] = &toolHealthTracker{
				info: &ToolInfo{
					Name:         inst.Name,
					Version:      inst.Version,
					Description:  inst.Metadata["description"],
					Instances:    1,
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
	tenant, err := a.resolveTenant(ctx)
	if err != nil {
		return nil, err
	}
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

		if tracker, exists := pluginMap[inst.Name]; exists {
			tracker.info.Instances++
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
			pluginMap[inst.Name] = &pluginHealthTracker{
				info: &PluginInfo{
					Name:        inst.Name,
					Version:     inst.Version,
					Description: inst.Metadata["description"],
					Instances:   1,
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

func (a *RegistryAdapter) getAvailableToolNames(ctx context.Context) ([]string, error) {
	tenant, err := a.resolveTenant(ctx)
	if err != nil {
		return nil, err
	}
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

// ToolCapabilities returns the capabilities a tool declared in its registry
// metadata, or nil when it declared none.
func ToolCapabilities(info ComponentInfo) *types.Capabilities {
	return parseCapabilitiesJSON(info.Metadata["capabilities"])
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
