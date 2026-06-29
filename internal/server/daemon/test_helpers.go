package daemon

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/tool"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// mockComponentDiscovery is a mock implementation of component.ComponentDiscovery for testing.
type mockComponentDiscovery struct {
	agents          []component.AgentInfo
	tools           []component.ToolInfo
	plugins         []component.PluginInfo
	listAgentsFunc  func(ctx context.Context) ([]component.AgentInfo, error)
	listToolsFunc   func(ctx context.Context) ([]component.ToolInfo, error)
	listPluginsFunc func(ctx context.Context) ([]component.PluginInfo, error)
}

func (m *mockComponentDiscovery) ListAgents(ctx context.Context) ([]component.AgentInfo, error) {
	if m.listAgentsFunc != nil {
		return m.listAgentsFunc(ctx)
	}
	if m.agents != nil {
		return m.agents, nil
	}
	return []component.AgentInfo{}, nil
}

func (m *mockComponentDiscovery) ListTools(ctx context.Context) ([]component.ToolInfo, error) {
	if m.listToolsFunc != nil {
		return m.listToolsFunc(ctx)
	}
	if m.tools != nil {
		return m.tools, nil
	}
	return []component.ToolInfo{}, nil
}

func (m *mockComponentDiscovery) ListPlugins(ctx context.Context) ([]component.PluginInfo, error) {
	if m.listPluginsFunc != nil {
		return m.listPluginsFunc(ctx)
	}
	if m.plugins != nil {
		return m.plugins, nil
	}
	return []component.PluginInfo{}, nil
}

// Stub implementations for other ComponentDiscovery interface methods
func (m *mockComponentDiscovery) DiscoverAgent(ctx context.Context, name string) (agent.Agent, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockComponentDiscovery) DiscoverTool(ctx context.Context, name string) (tool.Tool, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

// DiscoverPlugin was removed from component.ComponentDiscovery in plugin-runtime
// Spec 2 Phase 7; plugin invocation now goes through PluginInvokeService.

func (m *mockComponentDiscovery) DelegateToAgent(ctx context.Context, name string, task agent.Task, harness agent.AgentHarness) (agent.Result, error) {
	return agent.Result{}, fmt.Errorf("not implemented in mock")
}
