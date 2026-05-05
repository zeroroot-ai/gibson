package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

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

// ComponentDiscovery provides tool discovery via registry.
//
// Note: plugin discovery via this interface was removed when the in-process
// Plugin shape (Initialize/Query/Shutdown/Methods/Health) was deleted by the
// plugin-runtime spec. Plugin invocation now goes through the daemon's
// PluginInvokeService (component-service-backed, gRPC), reached via
// AgentHarness.QueryPlugin on the live harness — not through the
// DelegationHarness. The DelegationHarness's QueryPlugin returns an error.
type ComponentDiscovery interface {
	DiscoverTool(ctx context.Context, name string) (tool.Tool, error)
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

	// Convert map[string]any input to the tool's proto input message type.
	// Steps:
	//  1. Look up the input message descriptor by its fully-qualified name.
	//  2. Create a new instance of the input message.
	//  3. Marshal the input map to JSON, then unmarshal into the proto message.
	//  4. Call ExecuteProto with the hydrated proto message.
	//  5. Marshal the proto output to JSON, then decode into map[string]any.

	inputTypeName := t.InputMessageType()
	if inputTypeName == "" {
		return nil, fmt.Errorf("tool %s has no InputMessageType", t.Name())
	}

	// Step 1: look up message type descriptor.
	msgType, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(inputTypeName))
	if err != nil {
		return nil, fmt.Errorf("unknown proto type %s for tool %s: %w", inputTypeName, t.Name(), err)
	}

	// Step 2: create a new proto message instance.
	protoMsg := msgType.New().Interface()

	// Step 3: marshal input map to JSON, then populate the proto message.
	jsonBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("tool %s: failed to marshal input to JSON: %w", t.Name(), err)
	}
	if err := protojson.Unmarshal(jsonBytes, protoMsg); err != nil {
		return nil, fmt.Errorf("tool %s: failed to unmarshal input into proto %s: %w", t.Name(), inputTypeName, err)
	}

	// Step 4: execute the tool.
	outputProto, err := t.ExecuteProto(ctx, protoMsg)
	if err != nil {
		return nil, fmt.Errorf("tool %s execution failed: %w", t.Name(), err)
	}

	// Step 5: marshal proto output to JSON, then decode into map[string]any.
	outputJSON, err := protojson.Marshal(outputProto)
	if err != nil {
		return nil, fmt.Errorf("tool %s: failed to marshal output proto to JSON: %w", t.Name(), err)
	}
	var result map[string]any
	if err := json.Unmarshal(outputJSON, &result); err != nil {
		return nil, fmt.Errorf("tool %s: failed to decode output JSON to map: %w", t.Name(), err)
	}
	return result, nil
}

// registryPluginExecutor is the DelegationHarness's plugin executor.
//
// The pre-release in-process Plugin.Query path was deleted by the plugin-runtime
// spec; the new dispatch goes through PluginInvokeService on the live harness.
// The DelegationHarness has no direct hook into that dispatcher — its
// QueryPlugin returns a clear error directing callers to the live harness.
type registryPluginExecutor struct {
	discovery ComponentDiscovery
}

func (e *registryPluginExecutor) QueryPlugin(_ context.Context, pluginName, method string, _ map[string]any) (any, error) {
	return nil, fmt.Errorf("plugin %s.%s: DelegationHarness has no plugin dispatch path; in-process Plugin.Query was removed by the plugin-runtime spec — invoke plugins via AgentHarness.QueryPlugin (PluginInvokeService) on the live harness instead", pluginName, method)
}
