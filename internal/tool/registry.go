package tool

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// ToolRegistry manages tool registration, discovery, and health monitoring.
// It provides a centralized registry for both internal (native Go) and external (gRPC) tools,
// with built-in metrics tracking. Tools are executed via their ExecuteProto method after retrieval.
type ToolRegistry interface {
	// RegisterInternal registers a native Go tool implementation
	RegisterInternal(tool Tool) error

	// RegisterExternal registers an external gRPC tool client
	RegisterExternal(name string, client ExternalToolClient) error

	// Unregister removes a tool from the registry by name
	Unregister(name string) error

	// Get retrieves a tool by name, returning an error if not found
	Get(name string) (Tool, error)

	// List returns descriptors for all registered tools
	List() []ToolDescriptor

	// ListByTag returns descriptors for tools matching the given tag
	ListByTag(tag string) []ToolDescriptor

	// Health returns the overall health status of the registry
	Health(ctx context.Context) types.HealthStatus

	// ToolHealth returns the health status of a specific tool
	ToolHealth(ctx context.Context, name string) types.HealthStatus

	// Metrics returns execution metrics for a specific tool
	Metrics(name string) (ToolMetrics, error)
}

// ExternalToolClient interface for gRPC tool clients.
// This will be implemented in grpc_client.go after proto code generation.
type ExternalToolClient interface {
	Tool
}

// DefaultToolRegistry implements ToolRegistry with thread-safe operations.
type DefaultToolRegistry struct {
	mu       sync.RWMutex
	internal map[string]Tool
	external map[string]ExternalToolClient
	metrics  map[string]*ToolMetrics
}

// NewToolRegistry creates a new DefaultToolRegistry instance
func NewToolRegistry() *DefaultToolRegistry {
	return &DefaultToolRegistry{
		internal: make(map[string]Tool),
		external: make(map[string]ExternalToolClient),
		metrics:  make(map[string]*ToolMetrics),
	}
}

// RegisterInternal registers a native Go tool implementation.
// Returns ErrToolAlreadyExists if a tool with the same name is already registered.
func (r *DefaultToolRegistry) RegisterInternal(tool Tool) error {
	if tool == nil {
		return types.NewError(ErrToolInvalidInput, "tool cannot be nil")
	}

	name := tool.Name()
	if name == "" {
		return types.NewError(ErrToolInvalidInput, "tool name cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if tool already exists in either registry
	if _, exists := r.internal[name]; exists {
		return types.NewError(ErrToolAlreadyExists, fmt.Sprintf("internal tool %q already registered", name))
	}
	if _, exists := r.external[name]; exists {
		return types.NewError(ErrToolAlreadyExists, fmt.Sprintf("external tool %q already registered", name))
	}

	r.internal[name] = tool
	r.metrics[name] = NewToolMetrics()

	return nil
}

// RegisterExternal registers an external gRPC tool client.
// Returns ErrToolAlreadyExists if a tool with the same name is already registered.
func (r *DefaultToolRegistry) RegisterExternal(name string, client ExternalToolClient) error {
	if client == nil {
		return types.NewError(ErrToolInvalidInput, "client cannot be nil")
	}

	if name == "" {
		return types.NewError(ErrToolInvalidInput, "tool name cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if tool already exists in either registry
	if _, exists := r.internal[name]; exists {
		return types.NewError(ErrToolAlreadyExists, fmt.Sprintf("internal tool %q already registered", name))
	}
	if _, exists := r.external[name]; exists {
		return types.NewError(ErrToolAlreadyExists, fmt.Sprintf("external tool %q already registered", name))
	}

	r.external[name] = client
	r.metrics[name] = NewToolMetrics()

	return nil
}

// Unregister removes a tool from the registry by name.
// Returns ErrToolNotFound if the tool doesn't exist.
func (r *DefaultToolRegistry) Unregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check both registries
	_, internalExists := r.internal[name]
	_, externalExists := r.external[name]

	if !internalExists && !externalExists {
		return types.NewError(ErrToolNotFound, fmt.Sprintf("tool %q not found", name))
	}

	delete(r.internal, name)
	delete(r.external, name)
	delete(r.metrics, name)

	return nil
}

// Get retrieves a tool by name from either internal or external registry.
// Returns ErrToolNotFound if the tool doesn't exist.
func (r *DefaultToolRegistry) Get(name string) (Tool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Check internal first
	if tool, exists := r.internal[name]; exists {
		return tool, nil
	}

	// Check external
	if client, exists := r.external[name]; exists {
		return client, nil
	}

	return nil, types.NewError(ErrToolNotFound, fmt.Sprintf("tool %q not found", name))
}

// List returns descriptors for all registered tools.
func (r *DefaultToolRegistry) List() []ToolDescriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()

	descriptors := make([]ToolDescriptor, 0, len(r.internal)+len(r.external))

	// Add internal tools
	for _, tool := range r.internal {
		descriptors = append(descriptors, NewToolDescriptor(tool))
	}

	// Add external tools
	for _, client := range r.external {
		descriptors = append(descriptors, NewExternalToolDescriptor(client))
	}

	return descriptors
}

// ListByTag returns descriptors for tools matching the given tag.
func (r *DefaultToolRegistry) ListByTag(tag string) []ToolDescriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var descriptors []ToolDescriptor

	// Check internal tools
	for _, tool := range r.internal {
		if containsTag(tool.Tags(), tag) {
			descriptors = append(descriptors, NewToolDescriptor(tool))
		}
	}

	// Check external tools
	for _, client := range r.external {
		if containsTag(client.Tags(), tag) {
			descriptors = append(descriptors, NewExternalToolDescriptor(client))
		}
	}

	return descriptors
}

// Health returns the overall health status of the registry.
// The registry is healthy if all tools are healthy, degraded if some are unhealthy,
// and unhealthy if all tools are unhealthy or the registry is empty.
func (r *DefaultToolRegistry) Health(ctx context.Context) types.HealthStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.internal) == 0 && len(r.external) == 0 {
		return types.Unhealthy("no tools registered")
	}

	healthyCount := 0
	unhealthyCount := 0
	totalTools := len(r.internal) + len(r.external)

	// Check internal tools
	for _, tool := range r.internal {
		status := tool.Health(ctx)
		if status.IsHealthy() {
			healthyCount++
		} else {
			unhealthyCount++
		}
	}

	// Check external tools
	for _, client := range r.external {
		status := client.Health(ctx)
		if status.IsHealthy() {
			healthyCount++
		} else {
			unhealthyCount++
		}
	}

	// Determine overall health
	if unhealthyCount == 0 {
		return types.Healthy(fmt.Sprintf("all %d tools healthy", totalTools))
	} else if healthyCount == 0 {
		return types.Unhealthy(fmt.Sprintf("all %d tools unhealthy", totalTools))
	} else {
		return types.Degraded(fmt.Sprintf("%d/%d tools healthy", healthyCount, totalTools))
	}
}

// ToolHealth returns the health status of a specific tool.
// Returns an unhealthy status if the tool is not found.
func (r *DefaultToolRegistry) ToolHealth(ctx context.Context, name string) types.HealthStatus {
	tool, err := r.Get(name)
	if err != nil {
		return types.Unhealthy(fmt.Sprintf("tool %q not found", name))
	}

	return tool.Health(ctx)
}

// Metrics returns execution metrics for a specific tool.
// Returns ErrToolNotFound if the tool doesn't exist.
func (r *DefaultToolRegistry) Metrics(name string) (ToolMetrics, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	metrics, exists := r.metrics[name]
	if !exists {
		return ToolMetrics{}, types.NewError(ErrToolNotFound, fmt.Sprintf("tool %q not found", name))
	}

	// Return a copy to prevent external modification
	return *metrics, nil
}

// mapExecutor is a private interface for tools that support map-based execution.
// This is used by DefaultToolRegistry.Execute for legacy compatibility.
type mapExecutor interface {
	Execute(ctx context.Context, input map[string]any) (map[string]any, error)
}

// Execute runs a registered tool by name with map-based input and output.
// The tool must implement the mapExecutor interface (i.e. have an Execute method
// with signature Execute(ctx, map[string]any) (map[string]any, error)).
// Metrics are recorded for each execution.
func (r *DefaultToolRegistry) Execute(ctx context.Context, name string, input map[string]any) (map[string]any, error) {
	t, err := r.Get(name)
	if err != nil {
		return nil, err
	}

	executor, ok := t.(mapExecutor)
	if !ok {
		return nil, types.NewError(ErrToolInvalidInput, fmt.Sprintf("tool %q does not support map-based execution", name))
	}

	start := time.Now()
	output, execErr := executor.Execute(ctx, input)
	duration := time.Since(start)

	r.mu.Lock()
	if m, exists := r.metrics[name]; exists {
		if execErr != nil {
			m.RecordFailure(duration)
		} else {
			m.RecordSuccess(duration)
		}
	}
	r.mu.Unlock()

	return output, execErr
}

// containsTag checks if a tag exists in a slice of tags
func containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}
