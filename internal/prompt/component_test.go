package prompt

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/component"
	"github.com/zeroroot-ai/gibson/internal/tool"
	"github.com/zeroroot-ai/gibson/internal/types"
	"google.golang.org/protobuf/proto"
)

// Mock implementations for testing

// mockTool is a basic tool implementation without prompts
type mockTool struct{}

func (m *mockTool) Name() string              { return "mock-tool" }
func (m *mockTool) Description() string       { return "A mock tool" }
func (m *mockTool) Version() string           { return "1.0.0" }
func (m *mockTool) Tags() []string            { return []string{"test"} }
func (m *mockTool) InputMessageType() string  { return "" }
func (m *mockTool) OutputMessageType() string { return "" }
func (m *mockTool) ExecuteProto(_ context.Context, _ proto.Message) (proto.Message, error) {
	return nil, nil
}
func (m *mockTool) Health(ctx context.Context) types.HealthStatus {
	return types.Healthy("mock tool is healthy")
}

// mockToolWithPrompt is a tool implementation with prompts
type mockToolWithPrompt struct {
	mockTool
	prompts []Prompt
}

func (m *mockToolWithPrompt) Prompts() []Prompt {
	return m.prompts
}

// mockPlugin is a basic plugin-shaped value without prompts.
//
// Post plugin-runtime Spec 2 Phase 7, the in-process Plugin interface is gone;
// PluginPromptSource only requires Name + Version, which is what the prompt
// helpers test against.
type mockPlugin struct{}

func (m *mockPlugin) Name() string    { return "mock-plugin" }
func (m *mockPlugin) Version() string { return "1.0.0" }

// mockPluginWithPrompts is a plugin implementation with prompts
type mockPluginWithPrompts struct {
	mockPlugin
	prompts []Prompt
}

func (m *mockPluginWithPrompts) Prompts() []Prompt {
	return m.prompts
}

// mockAgent is a basic agent implementation without prompts
type mockAgent struct{}

func (m *mockAgent) Name() string        { return "mock-agent" }
func (m *mockAgent) Version() string     { return "1.0.0" }
func (m *mockAgent) Description() string { return "A mock agent" }
func (m *mockAgent) Capabilities() []string {
	return []string{"test"}
}
func (m *mockAgent) TargetTypes() []component.TargetType { return nil }
func (m *mockAgent) TechniqueTypes() []component.TechniqueType {
	return nil
}
func (m *mockAgent) LLMSlots() []agent.SlotDefinition { return nil }
func (m *mockAgent) Execute(ctx context.Context, task agent.Task, harness agent.AgentHarness) (agent.Result, error) {
	return agent.Result{}, nil
}
func (m *mockAgent) Initialize(ctx context.Context, cfg agent.AgentConfig) error {
	return nil
}
func (m *mockAgent) Shutdown(ctx context.Context) error { return nil }
func (m *mockAgent) Health(ctx context.Context) types.HealthStatus {
	return types.Healthy("mock agent is healthy")
}

// mockAgentWithPrompts is an agent implementation with prompts
type mockAgentWithPrompts struct {
	mockAgent
	systemPrompt *Prompt
	taskPrompt   *Prompt
	personas     []Prompt
}

func (m *mockAgentWithPrompts) SystemPrompt() *Prompt {
	return m.systemPrompt
}

func (m *mockAgentWithPrompts) TaskPrompt() *Prompt {
	return m.taskPrompt
}

func (m *mockAgentWithPrompts) Personas() []Prompt {
	return m.personas
}

// Test ToolWithPrompt interface

func TestToolHasPrompts(t *testing.T) {
	tests := []struct {
		name     string
		tool     tool.Tool
		expected bool
	}{
		{
			name:     "tool without prompts",
			tool:     &mockTool{},
			expected: false,
		},
		{
			name:     "tool with prompts",
			tool:     &mockToolWithPrompt{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToolHasPrompts(tt.tool)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetToolPrompts(t *testing.T) {
	tests := []struct {
		name     string
		tool     tool.Tool
		expected []Prompt
	}{
		{
			name:     "tool without prompts returns empty slice",
			tool:     &mockTool{},
			expected: []Prompt{},
		},
		{
			name: "tool with prompts returns prompts",
			tool: &mockToolWithPrompt{
				prompts: []Prompt{
					{
						ID:       "tool-prompt-1",
						Name:     "Tool Usage",
						Position: PositionTools,
						Content:  "Use this tool for testing",
					},
					{
						ID:       "tool-prompt-2",
						Name:     "Tool Examples",
						Position: PositionExamples,
						Content:  "Example: test()",
					},
				},
			},
			expected: []Prompt{
				{
					ID:       "tool-prompt-1",
					Name:     "Tool Usage",
					Position: PositionTools,
					Content:  "Use this tool for testing",
				},
				{
					ID:       "tool-prompt-2",
					Name:     "Tool Examples",
					Position: PositionExamples,
					Content:  "Example: test()",
				},
			},
		},
		{
			name: "tool with nil prompts returns empty slice",
			tool: &mockToolWithPrompt{
				prompts: nil,
			},
			expected: []Prompt{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetToolPrompts(tt.tool)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test PluginWithPrompts interface

func TestPluginHasPrompts(t *testing.T) {
	tests := []struct {
		name     string
		plugin   PluginPromptSource
		expected bool
	}{
		{
			name:     "plugin without prompts",
			plugin:   &mockPlugin{},
			expected: false,
		},
		{
			name:     "plugin with prompts",
			plugin:   &mockPluginWithPrompts{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PluginHasPrompts(tt.plugin)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetPluginPrompts(t *testing.T) {
	tests := []struct {
		name     string
		plugin   PluginPromptSource
		expected []Prompt
	}{
		{
			name:     "plugin without prompts returns empty slice",
			plugin:   &mockPlugin{},
			expected: []Prompt{},
		},
		{
			name: "plugin with prompts returns prompts",
			plugin: &mockPluginWithPrompts{
				prompts: []Prompt{
					{
						ID:       "plugin-prompt-1",
						Name:     "Plugin Usage",
						Position: PositionPlugins,
						Content:  "Use this plugin for data access",
					},
					{
						ID:       "plugin-prompt-2",
						Name:     "Plugin Methods",
						Position: PositionPlugins,
						Content:  "Available methods: query, update",
					},
				},
			},
			expected: []Prompt{
				{
					ID:       "plugin-prompt-1",
					Name:     "Plugin Usage",
					Position: PositionPlugins,
					Content:  "Use this plugin for data access",
				},
				{
					ID:       "plugin-prompt-2",
					Name:     "Plugin Methods",
					Position: PositionPlugins,
					Content:  "Available methods: query, update",
				},
			},
		},
		{
			name: "plugin with nil prompts returns empty slice",
			plugin: &mockPluginWithPrompts{
				prompts: nil,
			},
			expected: []Prompt{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPluginPrompts(tt.plugin)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test AgentWithPrompts interface

func TestAgentHasPrompts(t *testing.T) {
	tests := []struct {
		name     string
		agent    agent.Agent
		expected bool
	}{
		{
			name:     "agent without prompts",
			agent:    &mockAgent{},
			expected: false,
		},
		{
			name:     "agent with prompts",
			agent:    &mockAgentWithPrompts{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AgentHasPrompts(tt.agent)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetAgentPrompts(t *testing.T) {
	systemPrompt := Prompt{
		ID:       "system-prompt",
		Name:     "System",
		Position: PositionSystem,
		Content:  "You are a security testing agent",
	}

	taskPrompt := Prompt{
		ID:       "task-prompt",
		Name:     "Task",
		Position: PositionUser,
		Content:  "Execute the security scan",
	}

	persona1 := Prompt{
		ID:       "persona-1",
		Name:     "Expert Mode",
		Position: PositionContext,
		Content:  "Operate as an expert penetration tester",
	}

	persona2 := Prompt{
		ID:       "persona-2",
		Name:     "Stealthy Mode",
		Position: PositionContext,
		Content:  "Minimize detection during testing",
	}

	tests := []struct {
		name     string
		agent    agent.Agent
		expected []Prompt
	}{
		{
			name:     "agent without prompts returns empty slice",
			agent:    &mockAgent{},
			expected: []Prompt{},
		},
		{
			name: "agent with all prompts returns all in order",
			agent: &mockAgentWithPrompts{
				systemPrompt: &systemPrompt,
				taskPrompt:   &taskPrompt,
				personas:     []Prompt{persona1, persona2},
			},
			expected: []Prompt{systemPrompt, taskPrompt, persona1, persona2},
		},
		{
			name: "agent with only system prompt",
			agent: &mockAgentWithPrompts{
				systemPrompt: &systemPrompt,
				taskPrompt:   nil,
				personas:     nil,
			},
			expected: []Prompt{systemPrompt},
		},
		{
			name: "agent with only task prompt",
			agent: &mockAgentWithPrompts{
				systemPrompt: nil,
				taskPrompt:   &taskPrompt,
				personas:     nil,
			},
			expected: []Prompt{taskPrompt},
		},
		{
			name: "agent with only personas",
			agent: &mockAgentWithPrompts{
				systemPrompt: nil,
				taskPrompt:   nil,
				personas:     []Prompt{persona1, persona2},
			},
			expected: []Prompt{persona1, persona2},
		},
		{
			name: "agent with nil all prompts returns empty slice",
			agent: &mockAgentWithPrompts{
				systemPrompt: nil,
				taskPrompt:   nil,
				personas:     nil,
			},
			expected: []Prompt{},
		},
		{
			name: "agent with system and personas only",
			agent: &mockAgentWithPrompts{
				systemPrompt: &systemPrompt,
				taskPrompt:   nil,
				personas:     []Prompt{persona1, persona2},
			},
			expected: []Prompt{systemPrompt, persona1, persona2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetAgentPrompts(tt.agent)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test interface type assertions work correctly

func TestToolWithPromptTypeAssertion(t *testing.T) {
	var toolWithPrompt tool.Tool = &mockToolWithPrompt{
		prompts: []Prompt{
			{
				ID:       "test",
				Position: PositionTools,
				Content:  "test content",
			},
		},
	}

	// Verify type assertion works
	twp, ok := toolWithPrompt.(ToolWithPrompt)
	require.True(t, ok, "type assertion should succeed")
	require.NotNil(t, twp, "type assertion result should not be nil")

	// Verify we can call the Prompts method
	prompts := twp.Prompts()
	require.Len(t, prompts, 1)
	assert.Equal(t, "test", prompts[0].ID)
}

func TestPluginWithPromptsTypeAssertion(t *testing.T) {
	var pluginWithPrompts PluginPromptSource = &mockPluginWithPrompts{
		prompts: []Prompt{
			{
				ID:       "test",
				Position: PositionPlugins,
				Content:  "test content",
			},
		},
	}

	// Verify type assertion works
	pwp, ok := pluginWithPrompts.(PluginWithPrompts)
	require.True(t, ok, "type assertion should succeed")
	require.NotNil(t, pwp, "type assertion result should not be nil")

	// Verify we can call the Prompts method
	prompts := pwp.Prompts()
	require.Len(t, prompts, 1)
	assert.Equal(t, "test", prompts[0].ID)
}

func TestAgentWithPromptsTypeAssertion(t *testing.T) {
	systemPrompt := Prompt{
		ID:       "system",
		Position: PositionSystem,
		Content:  "system content",
	}

	var agentWithPrompts agent.Agent = &mockAgentWithPrompts{
		systemPrompt: &systemPrompt,
	}

	// Verify type assertion works
	awp, ok := agentWithPrompts.(AgentWithPrompts)
	require.True(t, ok, "type assertion should succeed")
	require.NotNil(t, awp, "type assertion result should not be nil")

	// Verify we can call the interface methods
	sp := awp.SystemPrompt()
	require.NotNil(t, sp)
	assert.Equal(t, "system", sp.ID)

	tp := awp.TaskPrompt()
	assert.Nil(t, tp)

	personas := awp.Personas()
	assert.Nil(t, personas)
}

// Test that helper functions handle edge cases properly

func TestGetToolPromptsWithEmptyPromptSlice(t *testing.T) {
	tool := &mockToolWithPrompt{
		prompts: []Prompt{},
	}

	result := GetToolPrompts(tool)
	assert.NotNil(t, result, "result should not be nil")
	assert.Empty(t, result, "result should be empty")
}

func TestGetPluginPromptsWithEmptyPromptSlice(t *testing.T) {
	plugin := &mockPluginWithPrompts{
		prompts: []Prompt{},
	}

	result := GetPluginPrompts(plugin)
	assert.NotNil(t, result, "result should not be nil")
	assert.Empty(t, result, "result should be empty")
}

func TestGetAgentPromptsWithEmptyPersonas(t *testing.T) {
	systemPrompt := Prompt{
		ID:       "system",
		Position: PositionSystem,
		Content:  "system content",
	}

	agent := &mockAgentWithPrompts{
		systemPrompt: &systemPrompt,
		personas:     []Prompt{},
	}

	result := GetAgentPrompts(agent)
	assert.Len(t, result, 1, "should only contain system prompt")
	assert.Equal(t, "system", result[0].ID)
}

// Integration tests combining multiple interfaces

func TestMultipleComponentsWithPrompts(t *testing.T) {
	// Create components with prompts
	tool := &mockToolWithPrompt{
		prompts: []Prompt{
			{ID: "tool-1", Position: PositionTools, Content: "tool content"},
		},
	}

	plugin := &mockPluginWithPrompts{
		prompts: []Prompt{
			{ID: "plugin-1", Position: PositionPlugins, Content: "plugin content"},
		},
	}

	agent := &mockAgentWithPrompts{
		systemPrompt: &Prompt{
			ID:       "agent-system",
			Position: PositionSystem,
			Content:  "agent system content",
		},
	}

	// Verify all components have prompts
	assert.True(t, ToolHasPrompts(tool))
	assert.True(t, PluginHasPrompts(plugin))
	assert.True(t, AgentHasPrompts(agent))

	// Collect all prompts
	var allPrompts []Prompt
	allPrompts = append(allPrompts, GetToolPrompts(tool)...)
	allPrompts = append(allPrompts, GetPluginPrompts(plugin)...)
	allPrompts = append(allPrompts, GetAgentPrompts(agent)...)

	// Verify we collected all prompts
	assert.Len(t, allPrompts, 3)
	assert.Contains(t, []string{"tool-1", "plugin-1", "agent-system"}, allPrompts[0].ID)
	assert.Contains(t, []string{"tool-1", "plugin-1", "agent-system"}, allPrompts[1].ID)
	assert.Contains(t, []string{"tool-1", "plugin-1", "agent-system"}, allPrompts[2].ID)
}
