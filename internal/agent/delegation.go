package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/plugin"
	"github.com/zero-day-ai/gibson/internal/tool"
)

// AgentDelegator provides the capability to delegate tasks to other agents.
// This interface is used by DelegationHarness to avoid import cycles.
type AgentDelegator interface {
	// DelegateToAgent executes a task on a named agent
	DelegateToAgent(ctx context.Context, name string, task Task, harness AgentHarness) (Result, error)
}

// DelegationHarness implements AgentHarness for delegated agent execution.
// This is used internally when executing delegated tasks.
type DelegationHarness struct {
	delegator  AgentDelegator
	logger     Logger
	toolExec   ToolExecutor
	pluginExec PluginExecutor
}

// Logger interface for structured logging
type Logger interface {
	Log(level, message string, fields map[string]any)
}

// ToolExecutor interface for executing tools
type ToolExecutor interface {
	ExecuteTool(ctx context.Context, name string, input map[string]any) (map[string]any, error)
}

// PluginExecutor interface for querying plugins
type PluginExecutor interface {
	QueryPlugin(ctx context.Context, plugin, method string, params map[string]any) (any, error)
}

// NewDelegationHarness creates a new delegation harness with registry-based executors
func NewDelegationHarness(delegator AgentDelegator, discovery ComponentDiscovery) *DelegationHarness {
	return &DelegationHarness{
		delegator:  delegator,
		logger:     &defaultLogger{},
		toolExec:   &registryToolExecutor{discovery: discovery},
		pluginExec: &registryPluginExecutor{discovery: discovery},
	}
}

// WithLogger sets the logger for this harness
func (h *DelegationHarness) WithLogger(logger Logger) *DelegationHarness {
	h.logger = logger
	return h
}

// WithToolExecutor sets the tool executor for this harness
func (h *DelegationHarness) WithToolExecutor(exec ToolExecutor) *DelegationHarness {
	h.toolExec = exec
	return h
}

// WithPluginExecutor sets the plugin executor for this harness
func (h *DelegationHarness) WithPluginExecutor(exec PluginExecutor) *DelegationHarness {
	h.pluginExec = exec
	return h
}

// ExecuteTool executes a tool and returns its output
func (h *DelegationHarness) ExecuteTool(ctx context.Context, name string, input map[string]any) (map[string]any, error) {
	h.Log("debug", "executing tool", map[string]any{
		"tool": name,
	})

	result, err := h.toolExec.ExecuteTool(ctx, name, input)
	if err != nil {
		h.Log("error", "tool execution failed", map[string]any{
			"tool":  name,
			"error": err.Error(),
		})
		return nil, err
	}

	return result, nil
}

// QueryPlugin queries a plugin for data or executes a plugin method
func (h *DelegationHarness) QueryPlugin(ctx context.Context, plugin, method string, params map[string]any) (any, error) {
	h.Log("debug", "querying plugin", map[string]any{
		"plugin": plugin,
		"method": method,
	})

	result, err := h.pluginExec.QueryPlugin(ctx, plugin, method, params)
	if err != nil {
		h.Log("error", "plugin query failed", map[string]any{
			"plugin": plugin,
			"method": method,
			"error":  err.Error(),
		})
		return nil, err
	}

	return result, nil
}

// DelegateToAgent delegates a task to another agent
func (h *DelegationHarness) DelegateToAgent(ctx context.Context, agentName string, task Task) (Result, error) {
	h.Log("info", "delegating to agent", map[string]any{
		"agent":     agentName,
		"task":      task.ID.String(),
		"task_name": task.Name,
	})

	startTime := time.Now()
	result, err := h.delegator.DelegateToAgent(ctx, agentName, task, h)
	duration := time.Since(startTime)

	if err != nil {
		h.Log("error", "agent delegation failed", map[string]any{
			"agent":    agentName,
			"task":     task.ID.String(),
			"error":    err.Error(),
			"duration": duration.String(),
		})
		return Result{}, err
	}

	h.Log("info", "agent delegation completed", map[string]any{
		"agent":    agentName,
		"task":     task.ID.String(),
		"status":   result.Status,
		"duration": duration.String(),
		"findings": len(result.Findings),
	})

	return result, nil
}

// Log writes a structured log message
func (h *DelegationHarness) Log(level, message string, fields map[string]any) {
	if h.logger != nil {
		h.logger.Log(level, message, fields)
	}
}

// defaultLogger is a simple console logger
type defaultLogger struct{}

func (l *defaultLogger) Log(level, message string, fields map[string]any) {
	// Simple console output for now
	// Full logging implementation will be added in Stage 4
	fmt.Printf("[%s] %s %v\n", level, message, fields)
}

// ComponentDiscovery provides tool and plugin discovery via registry
type ComponentDiscovery interface {
	DiscoverTool(ctx context.Context, name string) (tool.Tool, error)
	DiscoverPlugin(ctx context.Context, name string) (plugin.Plugin, error)
}

// registryToolExecutor implements ToolExecutor using registry-based discovery
type registryToolExecutor struct {
	discovery ComponentDiscovery
}

func (e *registryToolExecutor) ExecuteTool(ctx context.Context, name string, input map[string]any) (map[string]any, error) {
	// Discover the tool from registry
	t, err := e.discovery.DiscoverTool(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to discover tool %s: %w", name, err)
	}

	// Tools use proto-based execution, but for delegation harness compatibility
	// we need to convert map[string]any to proto and back.
	// For now, we return an error indicating this conversion is not yet implemented.
	// Full implementation would require:
	// 1. Get InputMessageType from tool
	// 2. Create proto message instance
	// 3. Convert map to proto (using protojson or similar)
	// 4. Call ExecuteProto
	// 5. Convert proto output back to map
	return nil, fmt.Errorf("tool %s discovered but proto-to-map conversion not yet implemented", t.Name())
}

// registryPluginExecutor implements PluginExecutor using registry-based discovery
type registryPluginExecutor struct {
	discovery ComponentDiscovery
}

func (e *registryPluginExecutor) QueryPlugin(ctx context.Context, pluginName, method string, params map[string]any) (any, error) {
	// Discover the plugin from registry
	p, err := e.discovery.DiscoverPlugin(ctx, pluginName)
	if err != nil {
		return nil, fmt.Errorf("failed to discover plugin %s: %w", pluginName, err)
	}

	// Forward the query to the discovered plugin
	result, err := p.Query(ctx, method, params)
	if err != nil {
		return nil, fmt.Errorf("plugin %s query failed: %w", pluginName, err)
	}

	return result, nil
}
