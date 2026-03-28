package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/attack"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/component/build"
	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/daemon/api"
	"github.com/zero-day-ai/gibson/internal/finding"
	"github.com/zero-day-ai/gibson/internal/observability"
	"github.com/zero-day-ai/gibson/internal/registry"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/sdk/queue"
	sdkregistry "github.com/zero-day-ai/sdk/registry"
)

// Stub implementations for other interface methods (not tested in this task)

// TestListAgents_Success tests ListAgents with mock registry adapter.
func TestListAgents_Success(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]registry.AgentInfo, error) {
			return []registry.AgentInfo{
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
		listAgentsFunc: func(ctx context.Context) ([]registry.AgentInfo, error) {
			return []registry.AgentInfo{}, nil
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
		listAgentsFunc: func(ctx context.Context) ([]registry.AgentInfo, error) {
			return []registry.AgentInfo{
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
	assert.Equal(t, "unknown", agents[0].Health) // Should be unknown when no instances
}

// TestListAgents_RegistryError tests ListAgents error propagation from registry.
func TestListAgents_RegistryError(t *testing.T) {
	expectedErr := fmt.Errorf("registry connection failed")
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]registry.AgentInfo, error) {
			return nil, expectedErr
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	agents, err := daemon.ListAgents(ctx, "")

	assert.Error(t, err)
	assert.Nil(t, agents)
	assert.Contains(t, err.Error(), "failed to list agents")
}

// TestGetAgentStatus_Success tests GetAgentStatus with existing agent.
func TestGetAgentStatus_Success(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]registry.AgentInfo, error) {
			return []registry.AgentInfo{
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
		listAgentsFunc: func(ctx context.Context) ([]registry.AgentInfo, error) {
			return []registry.AgentInfo{
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
		listAgentsFunc: func(ctx context.Context) ([]registry.AgentInfo, error) {
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

// TestListTools_Success tests ListTools with mock registry adapter.
func TestListTools_Success(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]registry.ToolInfo, error) {
			return []registry.ToolInfo{
				{
					Name:        "nmap",
					Version:     "7.92",
					Description: "Network scanner",
					Endpoints:   []string{"localhost:50300"},
					Instances:   1,
				},
				{
					Name:        "sqlmap",
					Version:     "1.5",
					Description: "SQL injection tool",
					Endpoints:   []string{"localhost:50301"},
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
	tools, err := daemon.ListTools(ctx)

	require.NoError(t, err)
	assert.Len(t, tools, 2)

	// Verify first tool
	assert.Equal(t, "nmap", tools[0].Name)
	assert.Equal(t, "nmap", tools[0].ID)
	assert.Equal(t, "7.92", tools[0].Version)
	assert.Equal(t, "Network scanner", tools[0].Description)
	assert.Equal(t, "localhost:50300", tools[0].Endpoint)
	assert.Equal(t, "healthy", tools[0].Health)

	// Verify second tool
	assert.Equal(t, "sqlmap", tools[1].Name)
	assert.Equal(t, "SQL injection tool", tools[1].Description)
}

// TestListTools_EmptyResults tests ListTools with no tools registered.
func TestListTools_EmptyResults(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]registry.ToolInfo, error) {
			return []registry.ToolInfo{}, nil
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

// TestListTools_RegistryError tests ListTools error propagation from registry.
func TestListTools_RegistryError(t *testing.T) {
	expectedErr := fmt.Errorf("registry unavailable")
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]registry.ToolInfo, error) {
			return nil, expectedErr
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	tools, err := daemon.ListTools(ctx)

	assert.Error(t, err)
	assert.Nil(t, tools)
	assert.Contains(t, err.Error(), "failed to list tools")
}

// TestListPlugins_Success tests ListPlugins with mock registry adapter.
func TestListPlugins_Success(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listPluginsFunc: func(ctx context.Context) ([]registry.PluginInfo, error) {
			return []registry.PluginInfo{
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
		listPluginsFunc: func(ctx context.Context) ([]registry.PluginInfo, error) {
			return []registry.PluginInfo{}, nil
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

// TestListPlugins_RegistryError tests ListPlugins error propagation from registry.
func TestListPlugins_RegistryError(t *testing.T) {
	expectedErr := fmt.Errorf("plugin registry error")
	mockRegistry := &mockComponentDiscovery{
		listPluginsFunc: func(ctx context.Context) ([]registry.PluginInfo, error) {
			return nil, expectedErr
		},
	}

	daemon := &daemonImpl{
		registryAdapter: mockRegistry,
		logger:          observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	plugins, err := daemon.ListPlugins(ctx)

	assert.Error(t, err)
	assert.Nil(t, plugins)
	assert.Contains(t, err.Error(), "failed to list plugins")
}

// TestListAgents_NoEndpoints tests handling of agents with no endpoints.
func TestListAgents_NoEndpoints(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]registry.AgentInfo, error) {
			return []registry.AgentInfo{
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
		listToolsFunc: func(ctx context.Context) ([]registry.ToolInfo, error) {
			return []registry.ToolInfo{
				{
					Name:        "no-endpoint-tool",
					Version:     "1.0.0",
					Description: "Test tool",
					Endpoints:   nil, // Nil endpoints
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
	tools, err := daemon.ListTools(ctx)

	require.NoError(t, err)
	assert.Len(t, tools, 1)
	assert.Empty(t, tools[0].Endpoint) // Should be empty string when no endpoints
}

// TestGetAgentStatus_NoEndpoints tests GetAgentStatus with agent that has no endpoints.
func TestGetAgentStatus_NoEndpoints(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listAgentsFunc: func(ctx context.Context) ([]registry.AgentInfo, error) {
			return []registry.AgentInfo{
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
		listAgentsFunc: func(ctx context.Context) ([]registry.AgentInfo, error) {
			return []registry.AgentInfo{
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
		name           string
		instances      int
		expectedHealth string
		expectedActive bool
	}{
		{
			name:           "healthy with instances",
			instances:      5,
			expectedHealth: "healthy",
			expectedActive: true,
		},
		{
			name:           "unknown with no instances",
			instances:      0,
			expectedHealth: "unknown",
			expectedActive: false,
		},
		{
			name:           "healthy with one instance",
			instances:      1,
			expectedHealth: "healthy",
			expectedActive: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRegistry := &mockComponentDiscovery{
				listAgentsFunc: func(ctx context.Context) ([]registry.AgentInfo, error) {
					return []registry.AgentInfo{
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

			// Test via ListAgents
			agents, err := daemon.ListAgents(ctx, "")
			require.NoError(t, err)
			assert.Len(t, agents, 1)
			assert.Equal(t, tt.expectedHealth, agents[0].Health)

			// Test via GetAgentStatus
			status, err := daemon.GetAgentStatus(ctx, "test-agent")
			require.NoError(t, err)
			assert.Equal(t, tt.expectedHealth, status.Agent.Health)
			assert.Equal(t, tt.expectedActive, status.Active)
		})
	}
}

// TestListTools_HealthStatus tests tool health status based on instances.
func TestListTools_HealthStatus(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]registry.ToolInfo, error) {
			return []registry.ToolInfo{
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
	assert.Equal(t, "healthy", tools[0].Health)
	assert.Equal(t, "unknown", tools[1].Health)
}

// TestListPlugins_HealthStatus tests plugin health status based on instances.
func TestListPlugins_HealthStatus(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listPluginsFunc: func(ctx context.Context) ([]registry.PluginInfo, error) {
			return []registry.PluginInfo{
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
		listAgentsFunc: func(ctx context.Context) ([]registry.AgentInfo, error) {
			return []registry.AgentInfo{
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

// mockAttackRunner is a mock implementation of attack.AttackRunner for testing
type mockAttackRunner struct {
	runFunc func(ctx context.Context, opts *attack.AttackOptions) (*attack.AttackResult, error)
}

func (m *mockAttackRunner) Run(ctx context.Context, opts *attack.AttackOptions) (*attack.AttackResult, error) {
	if m.runFunc != nil {
		return m.runFunc(ctx, opts)
	}
	return attack.NewAttackResult(), nil
}

// TestRunAttack_Success tests successful attack execution with findings
func TestRunAttack_Success(t *testing.T) {
	// Create mock attack runner that returns findings
	mockRunner := &mockAttackRunner{
		runFunc: func(ctx context.Context, opts *attack.AttackOptions) (*attack.AttackResult, error) {
			result := attack.NewAttackResult()
			result.Status = attack.AttackStatusFindings
			result.Duration = 5 * time.Second

			// Add a test finding
			testFinding := finding.EnhancedFinding{
				Finding: agent.Finding{
					ID:          types.NewID(),
					Title:       "Test Vulnerability",
					Description: "Test vulnerability description",
					Severity:    agent.SeverityHigh,
					Category:    "injection",
					CreatedAt:   time.Now(),
				},
			}
			result.AddFindings([]finding.EnhancedFinding{testFinding})

			return result, nil
		},
	}

	daemon := &daemonImpl{
		attackRunner: mockRunner,
		logger:       observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	req := api.AttackRequest{
		Target:     "https://example.com/api",
		AgentID:    "test-agent",
		AttackType: "injection",
	}

	ctx := context.Background()
	eventChan, err := daemon.RunAttack(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, eventChan)

	// Collect events
	var events []api.AttackEventData
	for event := range eventChan {
		events = append(events, event)
	}

	// Verify events
	require.GreaterOrEqual(t, len(events), 3) // started, finding, completed

	// Check attack started event
	assert.Equal(t, "attack.started", events[0].EventType)
	assert.Contains(t, events[0].Message, "Starting attack")

	// Check finding discovered event
	var foundFindingEvent bool
	for _, event := range events {
		if event.EventType == "attack.finding" {
			foundFindingEvent = true
			assert.NotNil(t, event.Finding)
			assert.Equal(t, "Test Vulnerability", event.Finding.Title)
			assert.Equal(t, "high", event.Finding.Severity)
			break
		}
	}
	assert.True(t, foundFindingEvent, "expected attack.finding event")

	// Check attack completed event
	lastEvent := events[len(events)-1]
	assert.Equal(t, "attack.completed", lastEvent.EventType)
	assert.Contains(t, lastEvent.Message, "completed")
	assert.NotNil(t, lastEvent.Result, "expected Result field in attack.completed event")
	assert.Equal(t, "findings", lastEvent.Result.Status)      // AttackStatusFindings
	assert.Equal(t, int64(5000), lastEvent.Result.DurationMs) // 5 seconds
	assert.Equal(t, int32(1), lastEvent.Result.FindingsCount)
}

// TestRunAttack_ValidationError tests attack request validation
func TestRunAttack_ValidationError(t *testing.T) {
	daemon := &daemonImpl{
		attackRunner: &mockAttackRunner{},
		logger:       observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	tests := []struct {
		name    string
		req     api.AttackRequest
		wantErr string
	}{
		{
			name: "missing target",
			req: api.AttackRequest{
				AgentID: "test-agent",
			},
			wantErr: "either target or target_name is required",
		},
		{
			name: "missing agent ID",
			req: api.AttackRequest{
				Target: "https://example.com",
			},
			wantErr: "agent ID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			eventChan, err := daemon.RunAttack(ctx, tt.req)

			assert.Error(t, err)
			assert.Nil(t, eventChan)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestRunAttack_RunnerNotInitialized tests behavior when attack runner is not initialized
func TestRunAttack_RunnerNotInitialized(t *testing.T) {
	daemon := &daemonImpl{
		attackRunner: nil, // No runner initialized
		logger:       observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	req := api.AttackRequest{
		Target:  "https://example.com/api",
		AgentID: "test-agent",
	}

	ctx := context.Background()
	eventChan, err := daemon.RunAttack(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, eventChan)
	assert.Contains(t, err.Error(), "runner not initialized")
}

// TestRunAttack_ExecutionError tests attack execution error handling
func TestRunAttack_ExecutionError(t *testing.T) {
	// Create mock attack runner that returns an error
	mockRunner := &mockAttackRunner{
		runFunc: func(ctx context.Context, opts *attack.AttackOptions) (*attack.AttackResult, error) {
			return nil, fmt.Errorf("target unreachable")
		},
	}

	daemon := &daemonImpl{
		attackRunner: mockRunner,
		logger:       observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	req := api.AttackRequest{
		Target:  "https://example.com/api",
		AgentID: "test-agent",
	}

	ctx := context.Background()
	eventChan, err := daemon.RunAttack(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, eventChan)

	// Collect events
	var events []api.AttackEventData
	for event := range eventChan {
		events = append(events, event)
	}

	// Verify error event
	require.GreaterOrEqual(t, len(events), 2) // started, error

	// Check attack started event
	assert.Equal(t, "attack.started", events[0].EventType)

	// Check error event
	assert.Equal(t, "attack.failed", events[len(events)-1].EventType)
	assert.Contains(t, events[len(events)-1].Error, "target unreachable")
}

// TestRunAttack_OptionsMapping tests conversion from API request to attack options
func TestRunAttack_OptionsMapping(t *testing.T) {
	var capturedOpts *attack.AttackOptions

	mockRunner := &mockAttackRunner{
		runFunc: func(ctx context.Context, opts *attack.AttackOptions) (*attack.AttackResult, error) {
			capturedOpts = opts
			return attack.NewAttackResult(), nil
		},
	}

	daemon := &daemonImpl{
		attackRunner: mockRunner,
		logger:       observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	req := api.AttackRequest{
		Target:        "https://example.com/api",
		AgentID:       "test-agent",
		AttackType:    "injection",
		PayloadFilter: "sql",
		Options: map[string]string{
			"max_turns": "10",
			"timeout":   "5m",
			"verbose":   "true",
		},
	}

	ctx := context.Background()
	eventChan, err := daemon.RunAttack(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, eventChan)

	// Drain the channel
	for range eventChan {
	}

	// Verify options were mapped correctly
	require.NotNil(t, capturedOpts)
	assert.Equal(t, "https://example.com/api", capturedOpts.TargetURL)
	assert.Equal(t, "test-agent", capturedOpts.AgentName)
	assert.Equal(t, "sql", capturedOpts.PayloadCategory)
	assert.Equal(t, 10, capturedOpts.MaxTurns)
	assert.Equal(t, 5*time.Minute, capturedOpts.Timeout)
	assert.True(t, capturedOpts.Verbose)
}

// TestRunAttack_NoFindings tests attack execution with no findings
func TestRunAttack_NoFindings(t *testing.T) {
	mockRunner := &mockAttackRunner{
		runFunc: func(ctx context.Context, opts *attack.AttackOptions) (*attack.AttackResult, error) {
			result := attack.NewAttackResult()
			result.Status = attack.AttackStatusSuccess
			result.Duration = 3 * time.Second
			return result, nil
		},
	}

	daemon := &daemonImpl{
		attackRunner: mockRunner,
		logger:       observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	req := api.AttackRequest{
		Target:  "https://example.com/api",
		AgentID: "test-agent",
	}

	ctx := context.Background()
	eventChan, err := daemon.RunAttack(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, eventChan)

	// Collect events
	var events []api.AttackEventData
	for event := range eventChan {
		events = append(events, event)
	}

	// Verify events - should have started and completed, no finding events
	require.Equal(t, 2, len(events))
	assert.Equal(t, "attack.started", events[0].EventType)
	assert.Equal(t, "attack.completed", events[1].EventType)
	assert.Contains(t, events[1].Message, "0 findings")
}

// TestValidateAttackRequest tests the attack request validation logic
func TestValidateAttackRequest(t *testing.T) {
	daemon := &daemonImpl{
		logger: observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	tests := []struct {
		name    string
		req     api.AttackRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: api.AttackRequest{
				Target:  "https://example.com",
				AgentID: "test-agent",
			},
			wantErr: false,
		},
		{
			name: "missing target",
			req: api.AttackRequest{
				AgentID: "test-agent",
			},
			wantErr: true,
		},
		{
			name: "missing agent ID",
			req: api.AttackRequest{
				Target: "https://example.com",
			},
			wantErr: true,
		},
		{
			name:    "empty request",
			req:     api.AttackRequest{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := daemon.validateAttackRequest(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestBuildAttackOptions tests conversion from API request to internal attack options
func TestBuildAttackOptions(t *testing.T) {
	daemon := &daemonImpl{
		logger: observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	tests := []struct {
		name  string
		req   api.AttackRequest
		check func(t *testing.T, opts *attack.AttackOptions)
	}{
		{
			name: "basic request",
			req: api.AttackRequest{
				Target:  "https://example.com",
				AgentID: "test-agent",
			},
			check: func(t *testing.T, opts *attack.AttackOptions) {
				assert.Equal(t, "https://example.com", opts.TargetURL)
				assert.Equal(t, "test-agent", opts.AgentName)
			},
		},
		{
			name: "with attack type",
			req: api.AttackRequest{
				Target:     "https://example.com",
				AgentID:    "test-agent",
				AttackType: "sql-injection",
			},
			check: func(t *testing.T, opts *attack.AttackOptions) {
				assert.Equal(t, "test-agent", opts.AgentName)
			},
		},
		{
			name: "with payload filter",
			req: api.AttackRequest{
				Target:        "https://example.com",
				AgentID:       "test-agent",
				PayloadFilter: "xss",
			},
			check: func(t *testing.T, opts *attack.AttackOptions) {
				assert.Equal(t, "xss", opts.PayloadCategory)
			},
		},
		{
			name: "with options",
			req: api.AttackRequest{
				Target:  "https://example.com",
				AgentID: "test-agent",
				Options: map[string]string{
					"max_turns": "15",
					"timeout":   "10m",
					"verbose":   "true",
					"dry_run":   "true",
				},
			},
			check: func(t *testing.T, opts *attack.AttackOptions) {
				assert.Equal(t, 15, opts.MaxTurns)
				assert.Equal(t, 10*time.Minute, opts.Timeout)
				assert.True(t, opts.Verbose)
				assert.True(t, opts.DryRun)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := daemon.buildAttackOptions(tt.req)
			require.NoError(t, err)
			require.NotNil(t, opts)
			tt.check(t, opts)
		})
	}
}

// mockTargetDAO is a mock implementation of TargetDAO for testing
type mockTargetDAO struct {
	getByNameFunc func(ctx context.Context, name string) (*types.Target, error)
	getFunc       func(ctx context.Context, id types.ID) (*types.Target, error)
	createFunc    func(ctx context.Context, target *types.Target) error
}

func (m *mockTargetDAO) GetByName(ctx context.Context, name string) (*types.Target, error) {
	if m.getByNameFunc != nil {
		return m.getByNameFunc(ctx, name)
	}
	return nil, fmt.Errorf("target not found")
}

func (m *mockTargetDAO) Get(ctx context.Context, id types.ID) (*types.Target, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, id)
	}
	return nil, fmt.Errorf("target not found")
}

func (m *mockTargetDAO) Create(ctx context.Context, target *types.Target) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, target)
	}
	return nil
}

// TestValidateAttackRequest_TargetName tests validation with target_name field
func TestValidateAttackRequest_TargetName(t *testing.T) {
	daemon := &daemonImpl{
		logger: observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	tests := []struct {
		name    string
		req     api.AttackRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request with target_name",
			req: api.AttackRequest{
				TargetName: "demo-target",
				AgentID:    "test-agent",
			},
			wantErr: false,
		},
		{
			name: "valid request with inline target",
			req: api.AttackRequest{
				Target:  "https://example.com",
				AgentID: "test-agent",
			},
			wantErr: false,
		},
		{
			name: "both target and target_name specified",
			req: api.AttackRequest{
				Target:     "https://example.com",
				TargetName: "demo-target",
				AgentID:    "test-agent",
			},
			wantErr: true,
			errMsg:  "cannot specify both",
		},
		{
			name: "neither target nor target_name specified",
			req: api.AttackRequest{
				AgentID: "test-agent",
			},
			wantErr: true,
			errMsg:  "either target or target_name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := daemon.validateAttackRequest(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestBuildAttackOptions_TargetNameResolution tests target name lookup
func TestBuildAttackOptions_TargetNameResolution(t *testing.T) {
	tests := []struct {
		name      string
		req       api.AttackRequest
		mockSetup func() *mockTargetDAO
		wantErr   bool
		check     func(t *testing.T, opts *attack.AttackOptions)
	}{
		{
			name: "resolve target by name",
			req: api.AttackRequest{
				TargetName: "demo-target",
				AgentID:    "test-agent",
			},
			mockSetup: func() *mockTargetDAO {
				return &mockTargetDAO{
					getByNameFunc: func(ctx context.Context, name string) (*types.Target, error) {
						return &types.Target{
							ID:   types.NewID(),
							Name: "demo-target",
							Type: "http_api",
							Connection: map[string]any{
								"url": "https://api.example.com/v1/chat",
							},
						}, nil
					},
				}
			},
			wantErr: false,
			check: func(t *testing.T, opts *attack.AttackOptions) {
				assert.Equal(t, "https://api.example.com/v1/chat", opts.TargetURL)
				assert.Equal(t, "demo-target", opts.TargetName)
				assert.Equal(t, "http_api", string(opts.TargetType))
			},
		},
		{
			name: "target not found error",
			req: api.AttackRequest{
				TargetName: "missing-target",
				AgentID:    "test-agent",
			},
			mockSetup: func() *mockTargetDAO {
				return &mockTargetDAO{
					getByNameFunc: func(ctx context.Context, name string) (*types.Target, error) {
						return nil, fmt.Errorf("target not found")
					},
				}
			},
			wantErr: true,
		},
		{
			name: "target with no URL",
			req: api.AttackRequest{
				TargetName: "no-url-target",
				AgentID:    "test-agent",
			},
			mockSetup: func() *mockTargetDAO {
				return &mockTargetDAO{
					getByNameFunc: func(ctx context.Context, name string) (*types.Target, error) {
						return &types.Target{
							ID:         types.NewID(),
							Name:       "no-url-target",
							Type:       "http_api",
							Connection: map[string]any{},
						}, nil
					},
				}
			},
			wantErr: true,
		},
		{
			name: "backward compatibility with inline target",
			req: api.AttackRequest{
				Target:  "https://example.com",
				AgentID: "test-agent",
			},
			mockSetup: func() *mockTargetDAO {
				return &mockTargetDAO{}
			},
			wantErr: false,
			check: func(t *testing.T, opts *attack.AttackOptions) {
				assert.Equal(t, "https://example.com", opts.TargetURL)
				assert.Equal(t, "", opts.TargetName)
			},
		},
		{
			name: "target with credential",
			req: api.AttackRequest{
				TargetName: "target-with-cred",
				AgentID:    "test-agent",
			},
			mockSetup: func() *mockTargetDAO {
				credID := types.NewID()
				return &mockTargetDAO{
					getByNameFunc: func(ctx context.Context, name string) (*types.Target, error) {
						return &types.Target{
							ID:   types.NewID(),
							Name: "target-with-cred",
							Type: "http_api",
							Connection: map[string]any{
								"url": "https://api.example.com/v1/chat",
							},
							CredentialID: &credID,
						}, nil
					},
				}
			},
			wantErr: false,
			check: func(t *testing.T, opts *attack.AttackOptions) {
				assert.Equal(t, "https://api.example.com/v1/chat", opts.TargetURL)
				assert.NotEmpty(t, opts.Credential)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDAO := tt.mockSetup()
			daemon := &daemonImpl{
				targetStore: mockDAO,
				logger:      observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
			}

			opts, err := daemon.buildAttackOptions(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, opts)
				if tt.check != nil {
					tt.check(t, opts)
				}
			}
		})
	}
}

// TestBuildAttackOptions_TargetPropagation tests that target info is correctly propagated
func TestBuildAttackOptions_TargetPropagation(t *testing.T) {
	mockDAO := &mockTargetDAO{
		getByNameFunc: func(ctx context.Context, name string) (*types.Target, error) {
			return &types.Target{
				ID:   types.NewID(),
				Name: "test-target",
				Type: "http_api",
				Connection: map[string]any{
					"url": "https://api.example.com",
				},
			}, nil
		},
	}

	tests := []struct {
		name        string
		req         api.AttackRequest
		expectedURL string
	}{
		{
			name: "target from database",
			req: api.AttackRequest{
				TargetName: "test-target",
				AgentID:    "test-agent",
				AttackType: "sql-injection",
			},
			expectedURL: "https://api.example.com",
		},
		{
			name: "direct target URL",
			req: api.AttackRequest{
				Target:     "https://direct.example.com",
				AgentID:    "test-agent",
				AttackType: "prompt-injection",
			},
			expectedURL: "https://direct.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &daemonImpl{
				targetStore: mockDAO,
				logger:      observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
			}

			opts, err := daemon.buildAttackOptions(tt.req)
			require.NoError(t, err)
			require.NotNil(t, opts)
			assert.Equal(t, tt.expectedURL, opts.TargetURL)
		})
	}
}

// Component handler tests

// mockComponentStore is a mock implementation of component.ComponentStore for testing
type mockComponentStore struct {
	getByNameFunc func(ctx context.Context, kind component.ComponentKind, name string) (*component.Component, error)
	listFunc      func(ctx context.Context, kind component.ComponentKind) ([]*component.Component, error)
	createFunc    func(ctx context.Context, comp *component.Component) error
	updateFunc    func(ctx context.Context, comp *component.Component) error
	deleteFunc    func(ctx context.Context, kind component.ComponentKind, name string) error
}

func (m *mockComponentStore) GetByName(ctx context.Context, kind component.ComponentKind, name string) (*component.Component, error) {
	if m.getByNameFunc != nil {
		return m.getByNameFunc(ctx, kind, name)
	}
	return nil, fmt.Errorf("component not found")
}

func (m *mockComponentStore) List(ctx context.Context, kind component.ComponentKind) ([]*component.Component, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, kind)
	}
	return []*component.Component{}, nil
}

func (m *mockComponentStore) ListAll(ctx context.Context) (map[component.ComponentKind][]*component.Component, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockComponentStore) Create(ctx context.Context, comp *component.Component) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, comp)
	}
	return nil
}

func (m *mockComponentStore) Update(ctx context.Context, comp *component.Component) error {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, comp)
	}
	return nil
}

func (m *mockComponentStore) Delete(ctx context.Context, kind component.ComponentKind, name string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, kind, name)
	}
	return nil
}

func (m *mockComponentStore) ListInstances(ctx context.Context, kind component.ComponentKind, name string) ([]sdkregistry.ServiceInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

// mockComponentInstaller is a mock implementation of component.Installer for testing
type mockComponentInstaller struct {
	installFunc   func(ctx context.Context, repoURL string, kind component.ComponentKind, opts component.InstallOptions) (*component.InstallResult, error)
	updateFunc    func(ctx context.Context, kind component.ComponentKind, name string, opts component.UpdateOptions) (*component.UpdateResult, error)
	uninstallFunc func(ctx context.Context, kind component.ComponentKind, name string) (*component.UninstallResult, error)
}

func (m *mockComponentInstaller) Install(ctx context.Context, repoURL string, kind component.ComponentKind, opts component.InstallOptions) (*component.InstallResult, error) {
	if m.installFunc != nil {
		return m.installFunc(ctx, repoURL, kind, opts)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockComponentInstaller) InstallAll(ctx context.Context, repoURL string, kind component.ComponentKind, opts component.InstallOptions) (*component.InstallAllResult, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockComponentInstaller) Update(ctx context.Context, kind component.ComponentKind, name string, opts component.UpdateOptions) (*component.UpdateResult, error) {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, kind, name, opts)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockComponentInstaller) UpdateAll(ctx context.Context, kind component.ComponentKind, opts component.UpdateOptions) ([]component.UpdateResult, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockComponentInstaller) Uninstall(ctx context.Context, kind component.ComponentKind, name string) (*component.UninstallResult, error) {
	if m.uninstallFunc != nil {
		return m.uninstallFunc(ctx, kind, name)
	}
	return nil, fmt.Errorf("not implemented")
}

// mockBuildExecutor is a mock implementation of build.BuildExecutor for testing
type mockBuildExecutor struct {
	buildFunc func(ctx context.Context, config build.BuildConfig, componentName, componentVersion, gibsonVersion string) (*build.BuildResult, error)
	cleanFunc func(ctx context.Context, workDir string) (*build.CleanResult, error)
	testFunc  func(ctx context.Context, workDir string) (*build.TestResult, error)
}

func (m *mockBuildExecutor) Build(ctx context.Context, config build.BuildConfig, componentName, componentVersion, gibsonVersion string) (*build.BuildResult, error) {
	if m.buildFunc != nil {
		return m.buildFunc(ctx, config, componentName, componentVersion, gibsonVersion)
	}
	return &build.BuildResult{Success: true}, nil
}

func (m *mockBuildExecutor) Clean(ctx context.Context, workDir string) (*build.CleanResult, error) {
	if m.cleanFunc != nil {
		return m.cleanFunc(ctx, workDir)
	}
	return &build.CleanResult{Success: true}, nil
}

func (m *mockBuildExecutor) Test(ctx context.Context, workDir string) (*build.TestResult, error) {
	if m.testFunc != nil {
		return m.testFunc(ctx, workDir)
	}
	return &build.TestResult{Success: true}, nil
}

// TestInstallComponent_Success tests successful component installation
func TestInstallComponent_Success(t *testing.T) {
	mockInstaller := &mockComponentInstaller{
		installFunc: func(ctx context.Context, repoURL string, kind component.ComponentKind, opts component.InstallOptions) (*component.InstallResult, error) {
			return &component.InstallResult{
				Component: &component.Component{
					Name:     "test-agent",
					Version:  "1.0.0",
					RepoPath: "/tmp/repos/test-agent",
					BinPath:  "/tmp/bin/test-agent",
				},
				BuildOutput: "Build successful",
				Duration:    5 * time.Second,
			}, nil
		},
	}

	daemon := &daemonImpl{
		componentInstaller: mockInstaller,
		logger:             observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	result, err := daemon.InstallComponent(ctx, "agent", "https://github.com/test/agent.git", "", "", false, false, false)

	require.NoError(t, err)
	assert.Equal(t, "test-agent", result.Name)
	assert.Equal(t, "1.0.0", result.Version)
	assert.Equal(t, "/tmp/repos/test-agent", result.RepoPath)
	assert.Equal(t, "/tmp/bin/test-agent", result.BinPath)
	assert.Contains(t, result.BuildOutput, "Build successful")
	assert.Equal(t, int64(5000), result.DurationMs)
}

// TestInstallComponent_InvalidKind tests installation with invalid kind
func TestInstallComponent_InvalidKind(t *testing.T) {
	daemon := &daemonImpl{
		componentInstaller: &mockComponentInstaller{},
		logger:             observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	result, err := daemon.InstallComponent(ctx, "invalid", "https://github.com/test/agent.git", "", "", false, false, false)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid component kind")
	assert.Equal(t, api.InstallComponentResult{}, result)
}

// TestInstallComponent_InstallerNotAvailable tests when installer is nil
func TestInstallComponent_InstallerNotAvailable(t *testing.T) {
	daemon := &daemonImpl{
		componentInstaller: nil,
		logger:             observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	result, err := daemon.InstallComponent(ctx, "agent", "https://github.com/test/agent.git", "", "", false, false, false)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "component installer not available")
	assert.Equal(t, api.InstallComponentResult{}, result)
}

// TestInstallComponent_InstallationError tests handling of installation errors
func TestInstallComponent_InstallationError(t *testing.T) {
	mockInstaller := &mockComponentInstaller{
		installFunc: func(ctx context.Context, repoURL string, kind component.ComponentKind, opts component.InstallOptions) (*component.InstallResult, error) {
			return nil, fmt.Errorf("failed to clone repository")
		},
	}

	daemon := &daemonImpl{
		componentInstaller: mockInstaller,
		logger:             observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	result, err := daemon.InstallComponent(ctx, "agent", "https://github.com/test/agent.git", "", "", false, false, false)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to install component")
	assert.Equal(t, api.InstallComponentResult{}, result)
}

// TestInstallComponent_WithOptions tests installation with various options
func TestInstallComponent_WithOptions(t *testing.T) {
	var capturedOpts component.InstallOptions

	mockInstaller := &mockComponentInstaller{
		installFunc: func(ctx context.Context, repoURL string, kind component.ComponentKind, opts component.InstallOptions) (*component.InstallResult, error) {
			capturedOpts = opts
			return &component.InstallResult{
				Component: &component.Component{
					Name:    "test-tool",
					Version: "2.0.0",
				},
				Duration: 3 * time.Second,
			}, nil
		},
	}

	daemon := &daemonImpl{
		componentInstaller: mockInstaller,
		logger:             observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	result, err := daemon.InstallComponent(ctx, "tool", "https://github.com/test/tool.git", "dev", "v2.0.0", true, true, true)

	require.NoError(t, err)
	assert.Equal(t, "test-tool", result.Name)
	assert.Equal(t, "dev", capturedOpts.Branch)
	assert.Equal(t, "v2.0.0", capturedOpts.Tag)
	assert.True(t, capturedOpts.Force)
	assert.True(t, capturedOpts.SkipBuild)
	assert.True(t, capturedOpts.Verbose)
}

// TestUninstallComponent_Success tests successful component uninstallation
func TestUninstallComponent_Success(t *testing.T) {
	mockStore := &mockComponentStore{
		getByNameFunc: func(ctx context.Context, kind component.ComponentKind, name string) (*component.Component, error) {
			return &component.Component{
				Name:    "test-agent",
				Version: "1.0.0",
				Status:  component.ComponentStatusStopped,
			}, nil
		},
	}

	mockInstaller := &mockComponentInstaller{
		uninstallFunc: func(ctx context.Context, kind component.ComponentKind, name string) (*component.UninstallResult, error) {
			return &component.UninstallResult{
				Name: name,
				Kind: kind,
			}, nil
		},
	}

	daemon := &daemonImpl{
		componentStore:     mockStore,
		componentInstaller: mockInstaller,
		logger:             observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	err := daemon.UninstallComponent(ctx, "agent", "test-agent", false)

	assert.NoError(t, err)
}

// TestUninstallComponent_InvalidKind tests uninstall with invalid kind
func TestUninstallComponent_InvalidKind(t *testing.T) {
	daemon := &daemonImpl{
		componentInstaller: &mockComponentInstaller{},
		logger:             observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	err := daemon.UninstallComponent(ctx, "invalid", "test-agent", false)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid component kind")
}

// TestUninstallComponent_ComponentRunning tests uninstall when component is running
func TestUninstallComponent_ComponentRunning(t *testing.T) {
	mockStore := &mockComponentStore{
		getByNameFunc: func(ctx context.Context, kind component.ComponentKind, name string) (*component.Component, error) {
			return &component.Component{
				Name:   "test-agent",
				Status: component.ComponentStatusRunning,
				PID:    12345,
			}, nil
		},
	}

	daemon := &daemonImpl{
		componentStore:     mockStore,
		componentInstaller: &mockComponentInstaller{},
		logger:             observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	err := daemon.UninstallComponent(ctx, "agent", "test-agent", false)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "is running")
}

// TestUninstallComponent_ForceWhenRunning tests force uninstall when component is running
func TestUninstallComponent_ForceWhenRunning(t *testing.T) {
	mockInstaller := &mockComponentInstaller{
		uninstallFunc: func(ctx context.Context, kind component.ComponentKind, name string) (*component.UninstallResult, error) {
			return &component.UninstallResult{
				Name: name,
				Kind: kind,
			}, nil
		},
	}

	daemon := &daemonImpl{
		componentStore:     &mockComponentStore{},
		componentInstaller: mockInstaller,
		logger:             observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	err := daemon.UninstallComponent(ctx, "agent", "test-agent", true)

	assert.NoError(t, err)
}

// TestUninstallComponent_ComponentNotFound tests uninstall of non-existent component
func TestUninstallComponent_ComponentNotFound(t *testing.T) {
	mockStore := &mockComponentStore{
		getByNameFunc: func(ctx context.Context, kind component.ComponentKind, name string) (*component.Component, error) {
			return nil, fmt.Errorf("component not found")
		},
	}

	daemon := &daemonImpl{
		componentStore:     mockStore,
		componentInstaller: &mockComponentInstaller{},
		logger:             observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	err := daemon.UninstallComponent(ctx, "agent", "nonexistent", false)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get component")
}

// TestUpdateComponent_Success tests successful component update
func TestUpdateComponent_Success(t *testing.T) {
	mockInstaller := &mockComponentInstaller{
		updateFunc: func(ctx context.Context, kind component.ComponentKind, name string, opts component.UpdateOptions) (*component.UpdateResult, error) {
			return &component.UpdateResult{
				Updated:     true,
				OldVersion:  "1.0.0",
				NewVersion:  "1.1.0",
				BuildOutput: "Update successful",
				Duration:    3 * time.Second,
			}, nil
		},
	}

	daemon := &daemonImpl{
		componentInstaller: mockInstaller,
		logger:             observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	result, err := daemon.UpdateComponent(ctx, "agent", "test-agent", false, false, false)

	require.NoError(t, err)
	assert.True(t, result.Updated)
	assert.Equal(t, "1.0.0", result.OldVersion)
	assert.Equal(t, "1.1.0", result.NewVersion)
	assert.Contains(t, result.BuildOutput, "Update successful")
	assert.Equal(t, int64(3000), result.DurationMs)
}

// TestUpdateComponent_InvalidKind tests update with invalid kind
func TestUpdateComponent_InvalidKind(t *testing.T) {
	daemon := &daemonImpl{
		componentInstaller: &mockComponentInstaller{},
		logger:             observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	result, err := daemon.UpdateComponent(ctx, "invalid", "test-agent", false, false, false)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid component kind")
	assert.Equal(t, api.UpdateComponentResult{}, result)
}

// TestUpdateComponent_NoChanges tests update when component is already up-to-date
func TestUpdateComponent_NoChanges(t *testing.T) {
	mockInstaller := &mockComponentInstaller{
		updateFunc: func(ctx context.Context, kind component.ComponentKind, name string, opts component.UpdateOptions) (*component.UpdateResult, error) {
			return &component.UpdateResult{
				Updated:     false,
				OldVersion:  "1.0.0",
				NewVersion:  "1.0.0",
				BuildOutput: "Already up-to-date",
				Duration:    1 * time.Second,
			}, nil
		},
	}

	daemon := &daemonImpl{
		componentInstaller: mockInstaller,
		logger:             observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	result, err := daemon.UpdateComponent(ctx, "tool", "test-tool", false, false, false)

	require.NoError(t, err)
	assert.False(t, result.Updated)
	assert.Equal(t, "1.0.0", result.OldVersion)
	assert.Equal(t, "1.0.0", result.NewVersion)
}

// TestUpdateComponent_WithOptions tests update with various options
func TestUpdateComponent_WithOptions(t *testing.T) {
	var capturedOpts component.UpdateOptions

	mockInstaller := &mockComponentInstaller{
		updateFunc: func(ctx context.Context, kind component.ComponentKind, name string, opts component.UpdateOptions) (*component.UpdateResult, error) {
			capturedOpts = opts
			return &component.UpdateResult{
				Updated:    true,
				OldVersion: "1.0.0",
				NewVersion: "1.1.0",
				Duration:   2 * time.Second,
			}, nil
		},
	}

	daemon := &daemonImpl{
		componentInstaller: mockInstaller,
		logger:             observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	result, err := daemon.UpdateComponent(ctx, "plugin", "test-plugin", true, true, true)

	require.NoError(t, err)
	assert.True(t, capturedOpts.Restart)
	assert.True(t, capturedOpts.SkipBuild)
	assert.True(t, capturedOpts.Verbose)
	assert.True(t, result.Updated)
}

// TestBuildComponent_Success tests successful component build
func TestBuildComponent_Success(t *testing.T) {
	mockStore := &mockComponentStore{
		getByNameFunc: func(ctx context.Context, kind component.ComponentKind, name string) (*component.Component, error) {
			return &component.Component{
				Name:     "test-agent",
				Version:  "1.0.0",
				RepoPath: "/tmp/repos/test-agent",
				Manifest: &component.Manifest{
					Build: &component.BuildConfig{
						Command: "make build",
						WorkDir: "",
					},
				},
			}, nil
		},
	}

	mockBuildExec := &mockBuildExecutor{
		buildFunc: func(ctx context.Context, config build.BuildConfig, componentName, componentVersion, gibsonVersion string) (*build.BuildResult, error) {
			return &build.BuildResult{
				Success: true,
				Stdout:  "Build output",
				Stderr:  "",
			}, nil
		},
	}

	daemon := &daemonImpl{
		componentStore:         mockStore,
		componentBuildExecutor: mockBuildExec,
		logger:                 observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	result, err := daemon.BuildComponent(ctx, "agent", "test-agent")

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Stdout, "Build output")
	assert.Empty(t, result.Stderr)
}

// TestBuildComponent_InvalidKind tests build with invalid kind
func TestBuildComponent_InvalidKind(t *testing.T) {
	daemon := &daemonImpl{
		componentStore: &mockComponentStore{},
		logger:         observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	result, err := daemon.BuildComponent(ctx, "invalid", "test-agent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid component kind")
	assert.Equal(t, api.BuildComponentResult{}, result)
}

// TestBuildComponent_ComponentNotFound tests build of non-existent component
func TestBuildComponent_ComponentNotFound(t *testing.T) {
	mockStore := &mockComponentStore{
		getByNameFunc: func(ctx context.Context, kind component.ComponentKind, name string) (*component.Component, error) {
			return nil, fmt.Errorf("component not found")
		},
	}

	daemon := &daemonImpl{
		componentStore: mockStore,
		logger:         observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	result, err := daemon.BuildComponent(ctx, "agent", "nonexistent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get component")
	assert.Equal(t, api.BuildComponentResult{}, result)
}

// TestBuildComponent_NoBuildConfig tests build when component has no build configuration
func TestBuildComponent_NoBuildConfig(t *testing.T) {
	mockStore := &mockComponentStore{
		getByNameFunc: func(ctx context.Context, kind component.ComponentKind, name string) (*component.Component, error) {
			return &component.Component{
				Name:     "test-agent",
				Version:  "1.0.0",
				Manifest: nil, // No manifest
			}, nil
		},
	}

	daemon := &daemonImpl{
		componentStore:         mockStore,
		componentBuildExecutor: &mockBuildExecutor{},
		logger:                 observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	result, err := daemon.BuildComponent(ctx, "agent", "test-agent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no build configuration")
	assert.Equal(t, api.BuildComponentResult{}, result)
}

// TestBuildComponent_BuildFailure tests handling of build failures
func TestBuildComponent_BuildFailure(t *testing.T) {
	mockStore := &mockComponentStore{
		getByNameFunc: func(ctx context.Context, kind component.ComponentKind, name string) (*component.Component, error) {
			return &component.Component{
				Name:     "test-agent",
				Version:  "1.0.0",
				RepoPath: "/tmp/repos/test-agent",
				Manifest: &component.Manifest{
					Build: &component.BuildConfig{
						Command: "make build",
					},
				},
			}, nil
		},
	}

	mockBuildExec := &mockBuildExecutor{
		buildFunc: func(ctx context.Context, config build.BuildConfig, componentName, componentVersion, gibsonVersion string) (*build.BuildResult, error) {
			return &build.BuildResult{
				Success: false,
				Stdout:  "Build output",
				Stderr:  "compilation error",
			}, fmt.Errorf("build failed")
		},
	}

	daemon := &daemonImpl{
		componentStore:         mockStore,
		componentBuildExecutor: mockBuildExec,
		logger:                 observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	result, err := daemon.BuildComponent(ctx, "agent", "test-agent")

	require.NoError(t, err) // Error is returned in result, not as error
	assert.False(t, result.Success)
	assert.Contains(t, result.Stderr, "compilation error")
}

// TestShowComponent_Success tests successful component details retrieval
func TestShowComponent_Success(t *testing.T) {
	now := time.Now()
	mockStore := &mockComponentStore{
		getByNameFunc: func(ctx context.Context, kind component.ComponentKind, name string) (*component.Component, error) {
			return &component.Component{
				Name:      "test-agent",
				Version:   "1.0.0",
				Kind:      component.ComponentKindAgent,
				Status:    component.ComponentStatusRunning,
				Source:    component.ComponentSourceExternal,
				RepoPath:  "/tmp/repos/test-agent",
				BinPath:   "/tmp/bin/test-agent",
				Port:      5000,
				PID:       12345,
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
	}

	daemon := &daemonImpl{
		componentStore: mockStore,
		logger:         observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	result, err := daemon.ShowComponent(ctx, "agent", "test-agent")

	require.NoError(t, err)
	assert.Equal(t, "test-agent", result.Name)
	assert.Equal(t, "1.0.0", result.Version)
	assert.Equal(t, "agent", result.Kind)
	assert.Equal(t, "running", result.Status)
	assert.Equal(t, "external", result.Source)
	assert.Equal(t, "/tmp/repos/test-agent", result.RepoPath)
	assert.Equal(t, "/tmp/bin/test-agent", result.BinPath)
	assert.Equal(t, 5000, result.Port)
	assert.Equal(t, 12345, result.PID)
}

// TestShowComponent_InvalidKind tests show with invalid kind
func TestShowComponent_InvalidKind(t *testing.T) {
	daemon := &daemonImpl{
		componentStore: &mockComponentStore{},
		logger:         observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	result, err := daemon.ShowComponent(ctx, "invalid", "test-agent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid component kind")
	assert.Equal(t, api.ComponentInfoInternal{}, result)
}

// TestShowComponent_ComponentNotFound tests show of non-existent component
func TestShowComponent_ComponentNotFound(t *testing.T) {
	mockStore := &mockComponentStore{
		getByNameFunc: func(ctx context.Context, kind component.ComponentKind, name string) (*component.Component, error) {
			return nil, fmt.Errorf("component not found")
		},
	}

	daemon := &daemonImpl{
		componentStore: mockStore,
		logger:         observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	result, err := daemon.ShowComponent(ctx, "agent", "nonexistent")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get component")
	assert.Equal(t, api.ComponentInfoInternal{}, result)
}

// TestGetComponentLogs_Success tests successful log streaming
func TestGetComponentLogs_Success(t *testing.T) {
	// Create a temporary log file
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "logs")
	err := os.MkdirAll(logDir, 0755)
	require.NoError(t, err)
	logFilePath := filepath.Join(logDir, "test-agent.log")
	err = os.WriteFile(logFilePath, []byte("line 1\nline 2\nline 3\n"), 0644)
	require.NoError(t, err)

	mockStore := &mockComponentStore{
		getByNameFunc: func(ctx context.Context, kind component.ComponentKind, name string) (*component.Component, error) {
			return &component.Component{
				Name:    "test-agent",
				Version: "1.0.0",
			}, nil
		},
	}

	daemon := &daemonImpl{
		componentStore: mockStore,
		config: &config.Config{
			Core: config.CoreConfig{
				HomeDir: tmpDir,
			},
		},
		logger: observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logChan, err := daemon.GetComponentLogs(ctx, "agent", "test-agent", false, 10)

	require.NoError(t, err)
	require.NotNil(t, logChan)

	// Collect log entries
	var logs []api.LogEntryData
	for log := range logChan {
		logs = append(logs, log)
	}

	assert.GreaterOrEqual(t, len(logs), 3)
}

// TestGetComponentLogs_InvalidKind tests log streaming with invalid kind
func TestGetComponentLogs_InvalidKind(t *testing.T) {
	daemon := &daemonImpl{
		componentStore: &mockComponentStore{},
		logger:         observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	logChan, err := daemon.GetComponentLogs(ctx, "invalid", "test-agent", false, 10)

	assert.Error(t, err)
	assert.Nil(t, logChan)
	assert.Contains(t, err.Error(), "invalid component kind")
}

// TestGetComponentLogs_ComponentNotFound tests log streaming for non-existent component
func TestGetComponentLogs_ComponentNotFound(t *testing.T) {
	mockStore := &mockComponentStore{
		getByNameFunc: func(ctx context.Context, kind component.ComponentKind, name string) (*component.Component, error) {
			return nil, fmt.Errorf("component not found")
		},
	}

	daemon := &daemonImpl{
		componentStore: mockStore,
		logger:         observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	logChan, err := daemon.GetComponentLogs(ctx, "agent", "nonexistent", false, 10)

	assert.Error(t, err)
	assert.Nil(t, logChan)
	assert.Contains(t, err.Error(), "failed to get component")
}

// TestGetComponentLogs_LogFileNotFound tests log streaming when log file doesn't exist
func TestGetComponentLogs_LogFileNotFound(t *testing.T) {
	tmpDir := t.TempDir()

	mockStore := &mockComponentStore{
		getByNameFunc: func(ctx context.Context, kind component.ComponentKind, name string) (*component.Component, error) {
			return &component.Component{
				Name:    "test-agent",
				Version: "1.0.0",
			}, nil
		},
	}

	daemon := &daemonImpl{
		componentStore: mockStore,
		config: &config.Config{
			Core: config.CoreConfig{
				HomeDir: tmpDir,
			},
		},
		logger: observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	logChan, err := daemon.GetComponentLogs(ctx, "agent", "test-agent", false, 10)

	assert.Error(t, err)
	assert.Nil(t, logChan)
	assert.Contains(t, err.Error(), "log file not found")
}

// mockRedisToolRegistry is a mock implementation of redisToolDiscovery for testing
type mockRedisToolRegistry struct {
	refreshFunc        func(ctx context.Context) error
	getAllMetadataFunc func() []queue.ToolMeta
	isHealthyFunc      func(ctx context.Context, name string) bool
}

func (m *mockRedisToolRegistry) Refresh(ctx context.Context) error {
	if m.refreshFunc != nil {
		return m.refreshFunc(ctx)
	}
	return nil
}

func (m *mockRedisToolRegistry) GetAllMetadata() []queue.ToolMeta {
	if m.getAllMetadataFunc != nil {
		return m.getAllMetadataFunc()
	}
	return []queue.ToolMeta{}
}

func (m *mockRedisToolRegistry) IsHealthy(ctx context.Context, name string) bool {
	if m.isHealthyFunc != nil {
		return m.isHealthyFunc(ctx, name)
	}
	return true
}

// TestListTools_RedisToolsOnly tests ListTools when only Redis tools are available
func TestListTools_RedisToolsOnly(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]registry.ToolInfo, error) {
			return []registry.ToolInfo{}, nil // No etcd tools
		},
	}

	mockComponentStore := &mockComponentStore{
		listFunc: func(ctx context.Context, kind component.ComponentKind) ([]*component.Component, error) {
			return []*component.Component{}, nil // No component store tools
		},
	}

	mockRedisRegistry := &mockRedisToolRegistry{
		getAllMetadataFunc: func() []queue.ToolMeta {
			return []queue.ToolMeta{
				{Name: "nmap", Version: "7.92", Description: "Network scanner"},
				{Name: "dnsx", Version: "1.0.0", Description: "DNS toolkit"},
				{Name: "httpx", Version: "1.2.0", Description: "HTTP toolkit"},
				{Name: "nuclei", Version: "2.5.0", Description: "Vulnerability scanner"},
				{Name: "subfinder", Version: "2.4.0", Description: "Subdomain finder"},
				{Name: "wappalyzer", Version: "1.0.0", Description: "Technology detector"},
			}
		},
		isHealthyFunc: func(ctx context.Context, name string) bool {
			return true // All tools healthy
		},
	}

	daemon := &daemonImpl{
		registryAdapter:   mockRegistry,
		componentStore:    mockComponentStore,
		redisToolRegistry: mockRedisRegistry,
		logger:            observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	tools, err := daemon.ListTools(ctx)

	require.NoError(t, err)
	assert.Len(t, tools, 6)

	// Verify tools are present
	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolNames[tool.Name] = true
		assert.Equal(t, "running", tool.Health)
	}

	assert.True(t, toolNames["nmap"])
	assert.True(t, toolNames["dnsx"])
	assert.True(t, toolNames["httpx"])
	assert.True(t, toolNames["nuclei"])
	assert.True(t, toolNames["subfinder"])
	assert.True(t, toolNames["wappalyzer"])
}

// TestListTools_MixedSources tests ListTools with tools from both componentStore and Redis
func TestListTools_MixedSources(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]registry.ToolInfo, error) {
			return []registry.ToolInfo{
				{Name: "local-tool", Version: "1.0.0", Endpoints: []string{"localhost:50300"}, Instances: 1},
			}, nil
		},
	}

	mockComponentStore := &mockComponentStore{
		listFunc: func(ctx context.Context, kind component.ComponentKind) ([]*component.Component, error) {
			return []*component.Component{
				{Name: "local-tool", Version: "1.0.0"},
				{Name: "another-local", Version: "2.0.0"},
			}, nil
		},
	}

	mockRedisRegistry := &mockRedisToolRegistry{
		getAllMetadataFunc: func() []queue.ToolMeta {
			return []queue.ToolMeta{
				{Name: "nmap", Version: "7.92", Description: "Network scanner"},
				{Name: "dnsx", Version: "1.0.0", Description: "DNS toolkit"},
				{Name: "httpx", Version: "1.2.0", Description: "HTTP toolkit"},
			}
		},
		isHealthyFunc: func(ctx context.Context, name string) bool {
			return true
		},
	}

	daemon := &daemonImpl{
		registryAdapter:   mockRegistry,
		componentStore:    mockComponentStore,
		redisToolRegistry: mockRedisRegistry,
		logger:            observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	tools, err := daemon.ListTools(ctx)

	require.NoError(t, err)
	assert.Len(t, tools, 5) // 2 local + 3 Redis

	// Verify all tools are present
	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolNames[tool.Name] = true
	}

	assert.True(t, toolNames["local-tool"])
	assert.True(t, toolNames["another-local"])
	assert.True(t, toolNames["nmap"])
	assert.True(t, toolNames["dnsx"])
	assert.True(t, toolNames["httpx"])
}

// TestListTools_Deduplication tests that duplicate tools are handled correctly
func TestListTools_Deduplication(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]registry.ToolInfo, error) {
			return []registry.ToolInfo{
				{Name: "nmap", Version: "7.90", Endpoints: []string{"localhost:50300"}, Instances: 1},
			}, nil
		},
	}

	mockComponentStore := &mockComponentStore{
		listFunc: func(ctx context.Context, kind component.ComponentKind) ([]*component.Component, error) {
			return []*component.Component{
				{Name: "nmap", Version: "7.90"}, // Same tool in component store
			}, nil
		},
	}

	mockRedisRegistry := &mockRedisToolRegistry{
		getAllMetadataFunc: func() []queue.ToolMeta {
			return []queue.ToolMeta{
				{Name: "nmap", Version: "7.92", Description: "Network scanner"}, // Duplicate in Redis
			}
		},
		isHealthyFunc: func(ctx context.Context, name string) bool {
			return true
		},
	}

	daemon := &daemonImpl{
		registryAdapter:   mockRegistry,
		componentStore:    mockComponentStore,
		redisToolRegistry: mockRedisRegistry,
		logger:            observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	tools, err := daemon.ListTools(ctx)

	require.NoError(t, err)
	assert.Len(t, tools, 1) // Should be deduplicated to 1

	// Should have the component store version (first source wins)
	assert.Equal(t, "nmap", tools[0].Name)
	assert.Equal(t, "7.90", tools[0].Version)
}

// TestListTools_RedisRefreshError tests ListTools when Redis refresh fails
func TestListTools_RedisRefreshError(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]registry.ToolInfo, error) {
			return []registry.ToolInfo{}, nil
		},
	}

	mockComponentStore := &mockComponentStore{
		listFunc: func(ctx context.Context, kind component.ComponentKind) ([]*component.Component, error) {
			return []*component.Component{
				{Name: "local-tool", Version: "1.0.0"},
			}, nil
		},
	}

	mockRedisRegistry := &mockRedisToolRegistry{
		refreshFunc: func(ctx context.Context) error {
			return fmt.Errorf("Redis connection failed")
		},
	}

	daemon := &daemonImpl{
		registryAdapter:   mockRegistry,
		componentStore:    mockComponentStore,
		redisToolRegistry: mockRedisRegistry,
		logger:            observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	tools, err := daemon.ListTools(ctx)

	// Should succeed with partial results (Redis tools not included)
	require.NoError(t, err)
	assert.Len(t, tools, 1)
	assert.Equal(t, "local-tool", tools[0].Name)
}

// TestListTools_RedisToolsHealthStatus tests health status from Redis tools
func TestListTools_RedisToolsHealthStatus(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]registry.ToolInfo, error) {
			return []registry.ToolInfo{}, nil
		},
	}

	mockComponentStore := &mockComponentStore{
		listFunc: func(ctx context.Context, kind component.ComponentKind) ([]*component.Component, error) {
			return []*component.Component{}, nil
		},
	}

	mockRedisRegistry := &mockRedisToolRegistry{
		getAllMetadataFunc: func() []queue.ToolMeta {
			return []queue.ToolMeta{
				{Name: "healthy-tool", Version: "1.0.0", Description: "A healthy tool"},
				{Name: "unhealthy-tool", Version: "1.0.0", Description: "An unhealthy tool"},
			}
		},
		isHealthyFunc: func(ctx context.Context, name string) bool {
			return name == "healthy-tool" // Only healthy-tool is healthy
		},
	}

	daemon := &daemonImpl{
		registryAdapter:   mockRegistry,
		componentStore:    mockComponentStore,
		redisToolRegistry: mockRedisRegistry,
		logger:            observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	tools, err := daemon.ListTools(ctx)

	require.NoError(t, err)
	assert.Len(t, tools, 2)

	// Find tools by name and verify health
	healthyFound := false
	unhealthyFound := false
	for _, tool := range tools {
		if tool.Name == "healthy-tool" {
			assert.Equal(t, "running", tool.Health)
			healthyFound = true
		}
		if tool.Name == "unhealthy-tool" {
			assert.Equal(t, "stopped", tool.Health)
			unhealthyFound = true
		}
	}
	assert.True(t, healthyFound, "healthy-tool should be present")
	assert.True(t, unhealthyFound, "unhealthy-tool should be present")
}

// TestListTools_NoRedisRegistry tests ListTools when Redis registry is nil
func TestListTools_NoRedisRegistry(t *testing.T) {
	mockRegistry := &mockComponentDiscovery{
		listToolsFunc: func(ctx context.Context) ([]registry.ToolInfo, error) {
			return []registry.ToolInfo{}, nil
		},
	}

	mockComponentStore := &mockComponentStore{
		listFunc: func(ctx context.Context, kind component.ComponentKind) ([]*component.Component, error) {
			return []*component.Component{
				{Name: "local-tool", Version: "1.0.0"},
			}, nil
		},
	}

	daemon := &daemonImpl{
		registryAdapter:   mockRegistry,
		componentStore:    mockComponentStore,
		redisToolRegistry: nil, // No Redis registry
		logger:            observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
	}

	ctx := context.Background()
	tools, err := daemon.ListTools(ctx)

	require.NoError(t, err)
	assert.Len(t, tools, 1)
	assert.Equal(t, "local-tool", tools[0].Name)
}
