package attack

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/plugin"
	"github.com/zero-day-ai/gibson/internal/tool"
	"github.com/zero-day-ai/gibson/internal/types"
)

// MockComponentDiscovery is a mock implementation of component.ComponentDiscovery
type MockComponentDiscovery struct {
	mock.Mock
}

func (m *MockComponentDiscovery) DiscoverAgent(ctx context.Context, name string) (agent.Agent, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(agent.Agent), args.Error(1)
}

func (m *MockComponentDiscovery) DiscoverTool(ctx context.Context, name string) (tool.Tool, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(tool.Tool), args.Error(1)
}

func (m *MockComponentDiscovery) DiscoverPlugin(ctx context.Context, name string) (plugin.Plugin, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(plugin.Plugin), args.Error(1)
}

func (m *MockComponentDiscovery) ListAgents(ctx context.Context) ([]component.AgentInfo, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]component.AgentInfo), args.Error(1)
}

func (m *MockComponentDiscovery) ListTools(ctx context.Context) ([]component.ToolInfo, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]component.ToolInfo), args.Error(1)
}

func (m *MockComponentDiscovery) ListPlugins(ctx context.Context) ([]component.PluginInfo, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]component.PluginInfo), args.Error(1)
}

func (m *MockComponentDiscovery) DelegateToAgent(ctx context.Context, name string, task agent.Task, harness agent.AgentHarness) (agent.Result, error) {
	args := m.Called(ctx, name, task, harness)
	return args.Get(0).(agent.Result), args.Error(1)
}

// MockAgent is a mock implementation of agent.Agent
type MockAgent struct {
	mock.Mock
}

func (m *MockAgent) Name() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAgent) Version() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAgent) Description() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAgent) Capabilities() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

func (m *MockAgent) TargetTypes() []component.TargetType {
	args := m.Called()
	return args.Get(0).([]component.TargetType)
}

func (m *MockAgent) TechniqueTypes() []component.TechniqueType {
	args := m.Called()
	return args.Get(0).([]component.TechniqueType)
}

func (m *MockAgent) LLMSlots() []agent.SlotDefinition {
	args := m.Called()
	return args.Get(0).([]agent.SlotDefinition)
}

func (m *MockAgent) Execute(ctx context.Context, task agent.Task, harness agent.AgentHarness) (agent.Result, error) {
	args := m.Called(ctx, task, harness)
	return args.Get(0).(agent.Result), args.Error(1)
}

func (m *MockAgent) Initialize(ctx context.Context, cfg agent.AgentConfig) error {
	args := m.Called(ctx, cfg)
	return args.Error(0)
}

func (m *MockAgent) Shutdown(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockAgent) Health(ctx context.Context) types.HealthStatus {
	args := m.Called(ctx)
	return args.Get(0).(types.HealthStatus)
}

// Helper function to create test registry agent info
func createTestRegistryAgentInfo(name, version, description string) component.AgentInfo {
	return component.AgentInfo{
		Name:        name,
		Version:     version,
		Description: description,
		Instances:   1,
		Endpoints:   []string{"localhost:50051"},
		Capabilities: []string{
			"llm_interaction",
			"payload_execution",
		},
		TargetTypes: []string{
			string(component.TargetTypeLLMChat),
			string(component.TargetTypeLLMAPI),
		},
		TechniqueTypes: []string{
			string(component.TechniquePromptInjection),
			string(component.TechniqueJailbreak),
		},
	}
}

func TestAgentSelector_Select_Success(t *testing.T) {
	ctx := context.Background()

	// Create mock discovery
	mockDiscovery := new(MockComponentDiscovery)
	mockAgent := new(MockAgent)

	// Setup expectations
	mockDiscovery.On("DiscoverAgent", ctx, "test-agent").
		Return(mockAgent, nil)

	// Create selector
	selector := NewAgentSelector(mockDiscovery)

	// Test agent selection
	result, err := selector.Select(ctx, "test-agent")

	// Verify
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, mockAgent, result)
	mockDiscovery.AssertExpectations(t)
}

func TestAgentSelector_Select_AgentNotFound(t *testing.T) {
	ctx := context.Background()

	// Create mock discovery
	mockDiscovery := new(MockComponentDiscovery)

	// Setup expectations - agent not found
	notFoundErr := &component.AgentNotFoundError{
		Name:      "nonexistent-agent",
		Available: []string{"agent1", "agent2"},
	}
	mockDiscovery.On("DiscoverAgent", ctx, "nonexistent-agent").
		Return(nil, notFoundErr)

	// Create selector
	selector := NewAgentSelector(mockDiscovery)

	// Test agent selection
	result, err := selector.Select(ctx, "nonexistent-agent")

	// Verify
	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, IsAgentNotFoundError(err), "Expected AgentNotFoundError")

	// Verify error contains agent name and available agents
	attackErr := err.(*AttackError)
	assert.Equal(t, "nonexistent-agent", attackErr.Context["agent_name"])
	availableAgents := attackErr.Context["available_agents"].([]string)
	assert.Contains(t, availableAgents, "agent1")
	assert.Contains(t, availableAgents, "agent2")

	mockDiscovery.AssertExpectations(t)
}

func TestAgentSelector_Select_AgentRequired(t *testing.T) {
	ctx := context.Background()

	// Create mock discovery
	mockDiscovery := new(MockComponentDiscovery)

	// Setup ListAgents() for error message generation
	agentInfos := []component.AgentInfo{
		createTestRegistryAgentInfo("agent1", "1.0.0", "First test agent"),
		createTestRegistryAgentInfo("agent2", "1.0.0", "Second test agent"),
	}
	mockDiscovery.On("ListAgents", ctx).Return(agentInfos, nil)

	// Create selector
	selector := NewAgentSelector(mockDiscovery)

	// Test with empty agent name
	result, err := selector.Select(ctx, "")

	// Verify
	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, IsAgentRequiredError(err), "Expected AgentRequiredError")

	// Verify error contains available agents
	attackErr := err.(*AttackError)
	availableAgents := attackErr.Context["available_agents"].([]string)
	assert.Contains(t, availableAgents, "agent1")
	assert.Contains(t, availableAgents, "agent2")

	mockDiscovery.AssertExpectations(t)
}

func TestAgentSelector_ListAvailable_Success(t *testing.T) {
	ctx := context.Background()

	// Create mock discovery
	mockDiscovery := new(MockComponentDiscovery)

	// Setup test data
	agentInfos := []component.AgentInfo{
		createTestRegistryAgentInfo("agent-alpha", "1.0.0", "Alpha test agent"),
		createTestRegistryAgentInfo("agent-beta", "2.0.0", "Beta test agent"),
		createTestRegistryAgentInfo("agent-gamma", "1.5.0", "Gamma test agent"),
	}

	mockDiscovery.On("ListAgents", ctx).Return(agentInfos, nil)

	// Create selector
	selector := NewAgentSelector(mockDiscovery)

	// Test listing agents
	infos, err := selector.ListAvailable(ctx)

	// Verify
	require.NoError(t, err)
	require.Len(t, infos, 3)

	// Verify agents are sorted by name
	assert.Equal(t, "agent-alpha", infos[0].Name)
	assert.Equal(t, "agent-beta", infos[1].Name)
	assert.Equal(t, "agent-gamma", infos[2].Name)

	// Verify agent info contents
	assert.Equal(t, "1.0.0", infos[0].Version)
	assert.Equal(t, "Alpha test agent", infos[0].Description)
	assert.Len(t, infos[0].Capabilities, 2)
	assert.Contains(t, infos[0].Capabilities, "llm_interaction")
	assert.Len(t, infos[0].TargetTypes, 2)
	assert.Contains(t, infos[0].TargetTypes, component.TargetTypeLLMChat)
	assert.Len(t, infos[0].TechniqueTypes, 2)
	assert.Contains(t, infos[0].TechniqueTypes, component.TechniquePromptInjection)

	mockDiscovery.AssertExpectations(t)
}

func TestAgentSelector_ListAvailable_Empty(t *testing.T) {
	ctx := context.Background()

	// Create mock discovery
	mockDiscovery := new(MockComponentDiscovery)

	// Return empty list
	mockDiscovery.On("ListAgents", ctx).Return([]component.AgentInfo{}, nil)

	// Create selector
	selector := NewAgentSelector(mockDiscovery)

	// Test listing agents
	infos, err := selector.ListAvailable(ctx)

	// Verify
	require.NoError(t, err)
	assert.Empty(t, infos)

	mockDiscovery.AssertExpectations(t)
}

func TestValidateAgentName_ValidAgent(t *testing.T) {
	ctx := context.Background()

	// Create mock discovery
	mockDiscovery := new(MockComponentDiscovery)
	mockAgent := new(MockAgent)

	// Setup expectations
	mockDiscovery.On("DiscoverAgent", ctx, "valid-agent").
		Return(mockAgent, nil)

	// Create selector
	selector := NewAgentSelector(mockDiscovery)

	// Test validation
	err := ValidateAgentName(ctx, selector, "valid-agent")

	// Verify
	assert.NoError(t, err)
	mockDiscovery.AssertExpectations(t)
}

func TestValidateAgentName_EmptyName(t *testing.T) {
	ctx := context.Background()

	// Create mock discovery
	mockDiscovery := new(MockComponentDiscovery)

	// Setup ListAgents() for error message
	agentInfos := []component.AgentInfo{
		createTestRegistryAgentInfo("agent1", "1.0.0", "Test agent 1"),
	}
	mockDiscovery.On("ListAgents", ctx).Return(agentInfos, nil)

	// Create selector
	selector := NewAgentSelector(mockDiscovery)

	// Test validation
	err := ValidateAgentName(ctx, selector, "")

	// Verify
	require.Error(t, err)
	assert.True(t, IsAgentRequiredError(err))
	mockDiscovery.AssertExpectations(t)
}

func TestValidateAgentName_InvalidAgent(t *testing.T) {
	ctx := context.Background()

	// Create mock discovery
	mockDiscovery := new(MockComponentDiscovery)

	// Setup expectations - agent not found
	notFoundErr := &component.AgentNotFoundError{
		Name:      "invalid-agent",
		Available: []string{"agent1"},
	}
	mockDiscovery.On("DiscoverAgent", ctx, "invalid-agent").
		Return(nil, notFoundErr)

	// Create selector
	selector := NewAgentSelector(mockDiscovery)

	// Test validation
	err := ValidateAgentName(ctx, selector, "invalid-agent")

	// Verify
	require.Error(t, err)
	assert.True(t, IsAgentNotFoundError(err))
	mockDiscovery.AssertExpectations(t)
}

func TestFormatAgentList(t *testing.T) {
	tests := []struct {
		name     string
		agents   []string
		expected string
	}{
		{
			name:     "empty list",
			agents:   []string{},
			expected: "(no agents available)",
		},
		{
			name:     "single agent",
			agents:   []string{"agent1"},
			expected: "agent1",
		},
		{
			name:     "multiple agents",
			agents:   []string{"agent3", "agent1", "agent2"},
			expected: "agent1, agent2, agent3", // Should be sorted
		},
		{
			name:     "already sorted",
			agents:   []string{"alpha", "beta", "gamma"},
			expected: "alpha, beta, gamma",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatAgentList(tt.agents)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatAgentInfoList(t *testing.T) {
	tests := []struct {
		name     string
		infos    []AgentInfo
		contains []string
	}{
		{
			name:  "empty list",
			infos: []AgentInfo{},
			contains: []string{
				"No agents available",
			},
		},
		{
			name: "single agent",
			infos: []AgentInfo{
				{
					Name:        "test-agent",
					Version:     "1.0.0",
					Description: "A test agent",
				},
			},
			contains: []string{
				"Available agents:",
				"test-agent",
				"1.0.0",
				"A test agent",
			},
		},
		{
			name: "multiple agents",
			infos: []AgentInfo{
				{
					Name:        "agent1",
					Version:     "1.0.0",
					Description: "First agent",
				},
				{
					Name:        "agent2",
					Version:     "2.0.0",
					Description: "Second agent",
				},
			},
			contains: []string{
				"Available agents:",
				"agent1",
				"1.0.0",
				"First agent",
				"agent2",
				"2.0.0",
				"Second agent",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatAgentInfoList(tt.infos)
			for _, expected := range tt.contains {
				assert.Contains(t, result, expected)
			}
		})
	}
}

// Table-driven test for agent selection scenarios
func TestAgentSelector_Select_TableDriven(t *testing.T) {
	tests := []struct {
		name         string
		agentName    string
		setupMock    func(*MockComponentDiscovery)
		expectError  bool
		errorChecker func(*testing.T, error)
	}{
		{
			name:      "successful selection",
			agentName: "test-agent",
			setupMock: func(m *MockComponentDiscovery) {
				mockAgent := new(MockAgent)
				m.On("DiscoverAgent", mock.Anything, "test-agent").
					Return(mockAgent, nil)
			},
			expectError: false,
		},
		{
			name:      "empty agent name",
			agentName: "",
			setupMock: func(m *MockComponentDiscovery) {
				agentInfos := []component.AgentInfo{
					createTestRegistryAgentInfo("agent1", "1.0.0", "Test agent"),
				}
				m.On("ListAgents", mock.Anything).Return(agentInfos, nil)
			},
			expectError: true,
			errorChecker: func(t *testing.T, err error) {
				assert.True(t, IsAgentRequiredError(err))
			},
		},
		{
			name:      "agent not found",
			agentName: "nonexistent",
			setupMock: func(m *MockComponentDiscovery) {
				notFoundErr := &component.AgentNotFoundError{
					Name:      "nonexistent",
					Available: []string{"agent1"},
				}
				m.On("DiscoverAgent", mock.Anything, "nonexistent").
					Return(nil, notFoundErr)
			},
			expectError: true,
			errorChecker: func(t *testing.T, err error) {
				assert.True(t, IsAgentNotFoundError(err))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mockDiscovery := new(MockComponentDiscovery)
			tt.setupMock(mockDiscovery)

			selector := NewAgentSelector(mockDiscovery)
			result, err := selector.Select(ctx, tt.agentName)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, result)
				if tt.errorChecker != nil {
					tt.errorChecker(t, err)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
			}

			mockDiscovery.AssertExpectations(t)
		})
	}
}
