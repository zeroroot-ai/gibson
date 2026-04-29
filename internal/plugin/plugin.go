// Package plugin is the daemon-side plugin registry stub.
//
// The pre-release daemon plugin registry (DefaultPluginRegistry, Plugin interface
// with Initialize/Query/Shutdown/Health/Methods, ExternalPluginClient) has been
// deleted by the plugin-runtime spec (Spec 2, Phase 1-3).
//
// The production plugin runtime is being rebuilt in the same spec:
//   - Phase 5: daemon-side plugin registry inside core/gibson/internal/component/
//     (plugin_registry.go, plugin_dispatch.go) extending ComponentService
//   - Phase 6: PluginInvokeService proto (invoke.proto)
//   - Phase 7: daemon startup wiring
//
// The minimal type stubs below retain only what the daemon's harness, prompt,
// agent, and orchestrator packages need to compile across Phase 1-7. They will
// be replaced or inlined once Phase 7 lands.
//
// TODO(plugin-runtime Phase 7): delete this stub package; migrate remaining
// callers (harness/config.go PluginRegistry field, harness/implementation.go
// QueryPlugin, orchestrator, agent/delegation.go) to the component-service-
// backed plugin dispatch.
package plugin

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/events"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/sdk/schema"
)

// PluginStatus represents plugin lifecycle status.
//
// TODO(plugin-runtime Phase 7): remove; status is tracked in the
// ComponentService plugin registry's Redis TTL model.
type PluginStatus string

const (
	PluginStatusUninitialized PluginStatus = "uninitialized"
	PluginStatusInitializing  PluginStatus = "initializing"
	PluginStatusRunning       PluginStatus = "running"
	PluginStatusStopping      PluginStatus = "stopping"
	PluginStatusStopped       PluginStatus = "stopped"
	PluginStatusError         PluginStatus = "error"
)

func (s PluginStatus) String() string { return string(s) }

// PluginConfig holds plugin initialization configuration.
//
// TODO(plugin-runtime Phase 7): replace with manifest-driven config.
type PluginConfig struct {
	Name     string         `json:"name"`
	Settings map[string]any `json:"settings"`
}

// MethodDescriptor describes a plugin method.
//
// TODO(plugin-runtime Phase 7): replace with the method contract type derived
// from the plugin's declared manifest and proto file descriptor set.
type MethodDescriptor struct {
	Name         string      `json:"name"`
	Description  string      `json:"description"`
	InputSchema  schema.JSON `json:"input_schema"`
	OutputSchema schema.JSON `json:"output_schema"`
}

// PluginDescriptor contains plugin metadata.
//
// TODO(plugin-runtime Phase 7): replace with the InstallInfo type from the
// component-service plugin registry.
type PluginDescriptor struct {
	Name       string             `json:"name"`
	Version    string             `json:"version"`
	Methods    []MethodDescriptor `json:"methods"`
	IsExternal bool               `json:"is_external"`
	Status     PluginStatus       `json:"status"`
}

// Plugin is the interface for daemon-internal plugin operations.
//
// TODO(plugin-runtime Phase 7): delete this interface; the new plugin runtime
// dispatches via ComponentService PollWork/SubmitResult — plugins are external
// processes, not in-process Go implementations.
type Plugin interface {
	Name() string
	Version() string
	Description() string
	Methods() []MethodDescriptor
	Query(ctx context.Context, method string, params map[string]any) (any, error)
	Initialize(ctx context.Context, config map[string]any) error
	Shutdown(ctx context.Context) error
	Health(ctx context.Context) types.HealthStatus
}

// PluginRegistry manages plugin lifecycle.
//
// TODO(plugin-runtime Phase 7): delete this interface; replace callers with the
// component-service-backed plugin dispatch (ComponentService.DiscoverPlugin →
// PluginInvokeService).
type PluginRegistry interface {
	Register(plugin Plugin, cfg PluginConfig) error
	RegisterExternal(name string, client ExternalPluginClient, cfg PluginConfig) error
	Unregister(name string) error
	Get(name string) (Plugin, error)
	List() []PluginDescriptor
	Methods(pluginName string) ([]MethodDescriptor, error)
	Query(ctx context.Context, pluginName, method string, params map[string]any) (any, error)
	Shutdown(ctx context.Context) error
	Health(ctx context.Context) types.HealthStatus
}

// ExternalPluginClient interface for gRPC plugin clients.
//
// TODO(plugin-runtime Phase 7): delete.
type ExternalPluginClient interface {
	Plugin
}

// noopPluginRegistry is a no-op implementation of PluginRegistry that always
// returns "not available" errors. It is used after the pre-release registry
// code was deleted and before the production registry (Phase 7) lands.
type noopPluginRegistry struct{}

func (r *noopPluginRegistry) Register(_ Plugin, _ PluginConfig) error {
	return fmt.Errorf("plugin registry: removed by plugin-runtime spec Phase 3; use plugin.Serve in Phase 8")
}
func (r *noopPluginRegistry) RegisterExternal(_ string, _ ExternalPluginClient, _ PluginConfig) error {
	return fmt.Errorf("plugin registry: removed by plugin-runtime spec Phase 3; use plugin.Serve in Phase 8")
}
func (r *noopPluginRegistry) Unregister(_ string) error { return nil }
func (r *noopPluginRegistry) Get(name string) (Plugin, error) {
	return nil, fmt.Errorf("plugin %q: registry unavailable (plugin-runtime spec Phase 3; replacement in Phase 7)", name)
}
func (r *noopPluginRegistry) List() []PluginDescriptor { return nil }
func (r *noopPluginRegistry) Methods(_ string) ([]MethodDescriptor, error) {
	return nil, fmt.Errorf("plugin registry unavailable (plugin-runtime spec Phase 3)")
}
func (r *noopPluginRegistry) Query(_ context.Context, pluginName, _ string, _ map[string]any) (any, error) {
	return nil, fmt.Errorf("plugin %q: registry unavailable (plugin-runtime spec Phase 3; replacement in Phase 7)", pluginName)
}
func (r *noopPluginRegistry) Shutdown(_ context.Context) error { return nil }
func (r *noopPluginRegistry) Health(_ context.Context) types.HealthStatus {
	return types.Degraded("plugin registry unavailable: plugin-runtime spec Phase 3 in progress")
}

// NewPluginRegistry returns a no-op registry stub.
//
// TODO(plugin-runtime Phase 7): replace with the component-service-backed
// registry that tracks plugin installs via Redis + Postgres.
func NewPluginRegistry(_ events.EventBus) PluginRegistry {
	return &noopPluginRegistry{}
}
