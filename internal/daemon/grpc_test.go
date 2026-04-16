package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/daemon/api"
	"github.com/zero-day-ai/gibson/internal/observability"
)

// Stub implementations for other interface methods (not tested in this task)

// TestListAgents_Success tests ListAgents with mock registry adapter.
func TestListAgents_Success(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{
				{
					Name:         "test-agent-1",
					Version:      "1.0.0",
					Endpoints:    []string{"localhost:50100"},
					Capabilities: []string{"llm", "web"},
					Instances:    1,
				},
				{
					Name:         "test-agent-2",
					Version:      "2.0.0",
					Endpoints:    []string{"localhost:50101", "localhost:50102"},
					Capabilities: []string{"cli"},
					Instances:    2,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	agents, err := daemon.ListAgents(ctx, "")

	require.NoError(t, err)
	assert.Len(t, agents, 2)

	// Verify first agent
	assert.Equal(t, "test-agent-1", agents[0].Name)
	assert.Equal(t, "test-agent-1", agents[0].ID)
	assert.Equal(t, "1.0.0", agents[0].Version)
	assert.Equal(t, "localhost:50100", agents[0].Endpoint)
	assert.Equal(t, []string{"llm", "web"}, agents[0].Capabilities)
	assert.Equal(t, "healthy", agents[0].Health)

	// Verify second agent
	assert.Equal(t, "test-agent-2", agents[1].Name)
	assert.Equal(t, "2.0.0", agents[1].Version)
	assert.Equal(t, "localhost:50101", agents[1].Endpoint) // First endpoint used
	assert.Equal(t, "healthy", agents[1].Health)
}

// TestListAgents_EmptyResults tests ListAgents with no agents registered.
func TestListAgents_EmptyResults(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	agents, err := daemon.ListAgents(ctx, "")

	require.NoError(t, err)
	assert.Empty(t, agents)
}

// TestListAgents_NoInstances tests ListAgents with agents that have no instances.
func TestListAgents_NoInstances(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{
				{
					Name:      "offline-agent",
					Version:   "1.0.0",
					Endpoints: []string{"localhost:50100"},
					Instances: 0, // No instances running
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	agents, err := daemon.ListAgents(ctx, "")

	require.NoError(t, err)
	assert.Len(t, agents, 1)
	assert.Equal(t, "healthy", agents[0].Health) // Registry agents default to healthy
}

// TestListAgents_RegistryError tests ListAgents graceful degradation when registry fails.
func TestListAgents_RegistryError(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return nil, fmt.Errorf("registry connection failed")
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	agents, err := daemon.ListAgents(ctx, "")

	// Registry error is gracefully degraded - returns empty results, not error
	require.NoError(t, err)
	assert.Empty(t, agents)
}

// TestGetAgentStatus_Success tests GetAgentStatus with existing agent.
func TestGetAgentStatus_Success(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{
				{
					Name:         "target-agent",
					Version:      "1.5.0",
					Endpoints:    []string{"localhost:50200"},
					Capabilities: []string{"recon"},
					Instances:    3,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	status, err := daemon.GetAgentStatus(ctx, "target-agent")

	require.NoError(t, err)
	assert.Equal(t, "target-agent", status.Agent.Name)
	assert.Equal(t, "1.5.0", status.Agent.Version)
	assert.Equal(t, "localhost:50200", status.Agent.Endpoint)
	assert.Equal(t, "healthy", status.Agent.Health)
	assert.True(t, status.Active) // Active because instances > 0
	assert.Empty(t, status.CurrentTask)
}

// TestGetAgentStatus_NotFound tests GetAgentStatus with non-existent agent.
func TestGetAgentStatus_NotFound(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{
				{
					Name:    "other-agent",
					Version: "1.0.0",
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	status, err := daemon.GetAgentStatus(ctx, "nonexistent-agent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "agent not found")
	assert.Contains(t, err.Error(), "nonexistent-agent")
	assert.Equal(t, api.AgentStatusInternal{}, status)
}

// TestGetAgentStatus_RegistryError tests GetAgentStatus error propagation.
func TestGetAgentStatus_RegistryError(t *testing.T) {
	expectedErr := fmt.Errorf("etcd timeout")
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return nil, expectedErr
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	status, err := daemon.GetAgentStatus(ctx, "any-agent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to query registry")
	assert.Equal(t, api.AgentStatusInternal{}, status)
}

// TestListTools_Success tests ListTools with tools in component store and running in registry.
func TestListTools_Success(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]component.ToolInfo, error) {
			return []component.ToolInfo{
				{
					Name:      "nmap",
					Version:   "7.92",
					Endpoints: []string{"localhost:50300"},
					Instances: 1,
				},
				{
					Name:      "sqlmap",
					Version:   "1.5",
					Endpoints: []string{"localhost:50301"},
					Instances: 1,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	tools, err := daemon.ListTools(ctx)

	require.NoError(t, err)
	assert.Len(t, tools, 2)

	// Verify tools (order may vary)
	toolMap := make(map[string]api.ToolInfoInternal)
	for _, tool := range tools {
		toolMap[tool.Name] = tool
	}

	nmap := toolMap["nmap"]
	assert.Equal(t, "nmap", nmap.ID)
	assert.Equal(t, "7.92", nmap.Version)
	assert.Equal(t, "Network scanner", nmap.Description)
	assert.Equal(t, "localhost:50300", nmap.Endpoint)
	assert.Equal(t, "healthy", nmap.Health)

	sqlmap := toolMap["sqlmap"]
	assert.Equal(t, "sqlmap", sqlmap.Name)
	assert.Equal(t, "SQL injection tool", sqlmap.Description)
}

// TestListTools_EmptyResults tests ListTools with no tools registered.
func TestListTools_EmptyResults(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]component.ToolInfo, error) {
			return []component.ToolInfo{}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	tools, err := daemon.ListTools(ctx)

	require.NoError(t, err)
	assert.Empty(t, tools)
}

// TestListTools_RegistryError tests ListTools graceful degradation when registry fails.
func TestListTools_RegistryError(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]component.ToolInfo, error) {
			return nil, fmt.Errorf("registry unavailable")
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	tools, err := daemon.ListTools(ctx)

	// Registry error is propagated
	require.Error(t, err)
	assert.Empty(t, tools)
}

// TestListPlugins_Success tests ListPlugins with mock registry adapter.
func TestListPlugins_Success(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listPluginsFunc: func(ctx context.Context) ([]component.PluginInfo, error) {
			return []component.PluginInfo{
				{
					Name:        "mitre-lookup",
					Version:     "1.0.0",
					Description: "MITRE ATT&CK lookup plugin",
					Endpoints:   []string{"localhost:50400"},
					Instances:   1,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	plugins, err := daemon.ListPlugins(ctx)

	require.NoError(t, err)
	assert.Len(t, plugins, 1)

	// Verify plugin
	assert.Equal(t, "mitre-lookup", plugins[0].Name)
	assert.Equal(t, "mitre-lookup", plugins[0].ID)
	assert.Equal(t, "1.0.0", plugins[0].Version)
	assert.Equal(t, "MITRE ATT&CK lookup plugin", plugins[0].Description)
	assert.Equal(t, "localhost:50400", plugins[0].Endpoint)
	assert.Equal(t, "healthy", plugins[0].Health)
}

// TestListPlugins_EmptyResults tests ListPlugins with no plugins registered.
func TestListPlugins_EmptyResults(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listPluginsFunc: func(ctx context.Context) ([]component.PluginInfo, error) {
			return []component.PluginInfo{}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	plugins, err := daemon.ListPlugins(ctx)

	require.NoError(t, err)
	assert.Empty(t, plugins)
}

// TestListPlugins_RegistryError tests ListPlugins graceful degradation when registry fails.
func TestListPlugins_RegistryError(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listPluginsFunc: func(ctx context.Context) ([]component.PluginInfo, error) {
			return nil, fmt.Errorf("plugin registry error")
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	plugins, err := daemon.ListPlugins(ctx)

	// Registry error is gracefully degraded - returns empty results, not error
	require.NoError(t, err)
	assert.Empty(t, plugins)
}

// TestListAgents_NoEndpoints tests handling of agents with no endpoints.
func TestListAgents_NoEndpoints(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{
				{
					Name:      "no-endpoint-agent",
					Version:   "1.0.0",
					Endpoints: []string{}, // Empty endpoints
					Instances: 1,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	agents, err := daemon.ListAgents(ctx, "")

	require.NoError(t, err)
	assert.Len(t, agents, 1)
	assert.Empty(t, agents[0].Endpoint)          // Should be empty string when no endpoints
	assert.Equal(t, "healthy", agents[0].Health) // Still healthy if instances > 0
}

// TestListTools_NoEndpoints tests handling of tools with no endpoints.
func TestListTools_NoEndpoints(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]component.ToolInfo, error) {
			return []component.ToolInfo{
				{
					Name:      "no-endpoint-tool",
					Version:   "1.0.0",
					Endpoints: nil, // Nil endpoints
					Instances: 1,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	tools, err := daemon.ListTools(ctx)

	require.NoError(t, err)
	assert.Len(t, tools, 1)
	assert.Empty(t, tools[0].Endpoint) // Should be empty string when no endpoints
}

// TestGetAgentStatus_NoEndpoints tests GetAgentStatus with agent that has no endpoints.
func TestGetAgentStatus_NoEndpoints(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{
				{
					Name:      "target-agent",
					Version:   "1.0.0",
					Endpoints: []string{}, // No endpoints
					Instances: 1,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	status, err := daemon.GetAgentStatus(ctx, "target-agent")

	require.NoError(t, err)
	assert.Empty(t, status.Agent.Endpoint)
	assert.True(t, status.Active)
}

// TestListAgents_WithKindFilter tests ListAgents with kind parameter (even though not yet used).
func TestListAgents_WithKindFilter(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{
				{
					Name:      "test-agent",
					Version:   "1.0.0",
					Instances: 1,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	agents, err := daemon.ListAgents(ctx, "security") // Kind parameter passed but not yet used

	require.NoError(t, err)
	assert.Len(t, agents, 1)
	assert.Equal(t, "agent", agents[0].Kind) // Default kind
}

// TestHealthStatus_BasedOnInstances tests that health status is correctly determined by instance count.
func TestHealthStatus_BasedOnInstances(t *testing.T) {
	tests := []struct {
		name                 string
		instances            int
		expectedStatusHealth string // GetAgentStatus checks instances
		expectedActive       bool
	}{
		{
			name:                 "healthy with instances",
			instances:            5,
			expectedStatusHealth: "healthy",
			expectedActive:       true,
		},
		{
			name:                 "unknown with no instances",
			instances:            0,
			expectedStatusHealth: "unknown",
			expectedActive:       false,
		},
		{
			name:                 "healthy with one instance",
			instances:            1,
			expectedStatusHealth: "healthy",
			expectedActive:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRegistry := &mockComponentDiscovery{
				listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
					return []component.AgentInfo{
						{
							Name:      "test-agent",
							Version:   "1.0.0",
							Instances: tt.instances,
						},
					}, nil
				},
			}

			daemon := &daemonImpl{
				registryAdapter: mockRegistry,
				logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
			}

			ctx := context.Background()

			// Test via GetAgentStatus (uses instance-aware health check)
			status, err := daemon.GetAgentStatus(ctx, "test-agent")
			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatusHealth, status.Agent.Health)
			assert.Equal(t, tt.expectedActive, status.Active)
		})
	}
}

// TestListTools_HealthStatus tests tool health status based on instances.
func TestListTools_HealthStatus(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]component.ToolInfo, error) {
			return []component.ToolInfo{
				{
					Name:      "healthy-tool",
					Instances: 2,
				},
				{
					Name:      "offline-tool",
					Instances: 0,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	tools, err := daemon.ListTools(ctx)

	require.NoError(t, err)
	assert.Len(t, tools, 2)

	toolMap := make(map[string]api.ToolInfoInternal)
	for _, tool := range tools {
		toolMap[tool.Name] = tool
	}
	assert.Equal(t, "healthy", toolMap["healthy-tool"].Health)
	assert.Equal(t, "healthy", toolMap["offline-tool"].Health) // ListTools defaults all registry entries to healthy
}

// TestListPlugins_HealthStatus tests plugin health status based on instances.
func TestListPlugins_HealthStatus(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listPluginsFunc: func(ctx context.Context) ([]component.PluginInfo, error) {
			return []component.PluginInfo{
				{
					Name:      "active-plugin",
					Instances: 1,
				},
				{
					Name:      "inactive-plugin",
					Instances: 0,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	plugins, err := daemon.ListPlugins(ctx)

	require.NoError(t, err)
	assert.Len(t, plugins, 2)
	assert.Equal(t, "healthy", plugins[0].Health)
	assert.Equal(t, "unknown", plugins[1].Health)
}

// TestLastSeenTime tests that LastSeen is populated (currently uses time.Now()).
func TestLastSeenTime(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]component.AgentInfo, error) {
			return []component.AgentInfo{
				{
					Name:      "test-agent",
					Version:   "1.0.0",
					Instances: 1,
				},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	beforeTime := time.Now().Add(-1 * time.Second)

	agents, err := daemon.ListAgents(ctx, "")
	require.NoError(t, err)

	afterTime := time.Now().Add(1 * time.Second)

	assert.Len(t, agents, 1)
	assert.True(t, agents[0].LastSeen.After(beforeTime))
	assert.True(t, agents[0].LastSeen.Before(afterTime))
}
