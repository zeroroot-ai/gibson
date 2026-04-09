package plan

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/guardrail"
	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/trace"
)

// MockHarness is a test harness implementation for testing plan execution
type MockHarness struct {
	tools            map[string]harness.ToolDescriptor
	toolProtoOutputs map[string]proto.Message
	toolErrors       map[string]error
	plugins          map[string]harness.PluginDescriptor
	pluginOutputs    map[string]map[string]any
	pluginErrors     map[string]error
	agents           map[string]harness.AgentDescriptor
	agentResults     map[string]agent.Result
	agentErrors      map[string]error
	llmResponses     []string
	llmResponseIndex int
	findings         []agent.Finding
	missionCtx       harness.MissionContext
	targetInfo       harness.TargetInfo
	logger           *slog.Logger
}

// Verify MockHarness implements AgentHarness interface
var _ harness.AgentHarness = (*MockHarness)(nil)

// createMockHarness returns a basic mock harness for testing
func createMockHarness() *MockHarness {
	return &MockHarness{
		tools:            make(map[string]harness.ToolDescriptor),
		toolProtoOutputs: make(map[string]proto.Message),
		toolErrors:       make(map[string]error),
		plugins:          make(map[string]harness.PluginDescriptor),
		pluginOutputs:    make(map[string]map[string]any),
		pluginErrors:     make(map[string]error),
		agents:           make(map[string]harness.AgentDescriptor),
		agentResults:     make(map[string]agent.Result),
		agentErrors:      make(map[string]error),
		llmResponses:     []string{},
		findings:         []agent.Finding{},
		missionCtx: harness.MissionContext{
			ID:           types.NewID(),
			Name:         "test_mission",
			CurrentAgent: "test_agent",
		},
		targetInfo: harness.TargetInfo{
			URL: "https://example.com",
		},
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
}

// Complete implements harness.AgentHarness
func (m *MockHarness) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...harness.CompletionOption) (*llm.CompletionResponse, error) {
	if m.llmResponseIndex >= len(m.llmResponses) {
		return nil, errors.New("no more LLM responses available")
	}

	response := m.llmResponses[m.llmResponseIndex]
	m.llmResponseIndex++

	return &llm.CompletionResponse{
		Message: llm.Message{
			Role:    llm.RoleAssistant,
			Content: response,
		},
		Usage: llm.CompletionTokenUsage{
			PromptTokens:     100,
			CompletionTokens: 50,
			TotalTokens:      150,
		},
	}, nil
}

// CompleteWithTools implements harness.AgentHarness
func (m *MockHarness) CompleteWithTools(ctx context.Context, slot string, messages []llm.Message, tools []llm.ToolDef, opts ...harness.CompletionOption) (*llm.CompletionResponse, error) {
	return m.Complete(ctx, slot, messages, opts...)
}

// CompleteStructuredAny implements harness.AgentHarness
func (m *MockHarness) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...harness.CompletionOption) (any, error) {
	return nil, errors.New("CompleteStructuredAny not implemented in mock")
}

// CompleteStructuredAnyWithUsage implements harness.AgentHarness
func (m *MockHarness) CompleteStructuredAnyWithUsage(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...harness.CompletionOption) (*harness.StructuredCompletionResult, error) {
	return nil, errors.New("CompleteStructuredAnyWithUsage not implemented in mock")
}

// Stream implements harness.AgentHarness
func (m *MockHarness) Stream(ctx context.Context, slot string, messages []llm.Message, opts ...harness.CompletionOption) (<-chan llm.StreamChunk, error) {
	return nil, errors.New("streaming not implemented in mock")
}

// CallToolProto implements harness.AgentHarness
func (m *MockHarness) CallToolProto(ctx context.Context, name string, request proto.Message, response proto.Message) error {
	if err, ok := m.toolErrors[name]; ok {
		return err
	}
	// If a proto output is set for this tool, copy it to the response
	if protoOut, ok := m.toolProtoOutputs[name]; ok {
		// Use proto.Merge to copy fields from the mock output to the response
		proto.Merge(response, protoOut)
		return nil
	}
	// For testing with generic responses, provide a successful default
	// The actual tests don't validate proto structure, just that the mock works
	return nil
}

// ListTools implements harness.AgentHarness
func (m *MockHarness) ListTools() []harness.ToolDescriptor {
	tools := make([]harness.ToolDescriptor, 0, len(m.tools))
	for _, tool := range m.tools {
		tools = append(tools, tool)
	}
	return tools
}

// GetToolDescriptor implements harness.AgentHarness
func (m *MockHarness) GetToolDescriptor(ctx context.Context, name string) (*harness.ToolDescriptor, error) {
	if tool, exists := m.tools[name]; exists {
		return &tool, nil
	}
	return nil, errors.New("tool not found")
}

// QueryPlugin implements harness.AgentHarness
func (m *MockHarness) QueryPlugin(ctx context.Context, name string, method string, params map[string]any) (any, error) {
	key := name + "." + method
	if err, exists := m.pluginErrors[key]; exists {
		return nil, err
	}
	if output, exists := m.pluginOutputs[key]; exists {
		return output, nil
	}
	return map[string]any{"status": "success"}, nil
}

// ListPlugins implements harness.AgentHarness
func (m *MockHarness) ListPlugins() []harness.PluginDescriptor {
	plugins := make([]harness.PluginDescriptor, 0, len(m.plugins))
	for _, plugin := range m.plugins {
		plugins = append(plugins, plugin)
	}
	return plugins
}

// DelegateToAgent implements harness.AgentHarness
func (m *MockHarness) DelegateToAgent(ctx context.Context, name string, task agent.Task) (agent.Result, error) {
	if err, exists := m.agentErrors[name]; exists {
		return agent.Result{}, err
	}
	if result, exists := m.agentResults[name]; exists {
		return result, nil
	}
	result := agent.NewResult(task.ID)
	result.Complete(map[string]any{"status": "success"})
	return result, nil
}

// ListAgents implements harness.AgentHarness
func (m *MockHarness) ListAgents() []harness.AgentDescriptor {
	agents := make([]harness.AgentDescriptor, 0, len(m.agents))
	for _, a := range m.agents {
		agents = append(agents, a)
	}
	return agents
}

// SubmitFinding implements harness.AgentHarness
func (m *MockHarness) SubmitFinding(ctx context.Context, finding agent.Finding) error {
	m.findings = append(m.findings, finding)
	return nil
}

// GetFindings implements harness.AgentHarness
func (m *MockHarness) GetFindings(ctx context.Context, filter harness.FindingFilter) ([]agent.Finding, error) {
	return m.findings, nil
}

// GetPreviousRunFindings implements harness.AgentHarness
func (m *MockHarness) GetPreviousRunFindings(ctx context.Context, filter harness.FindingFilter) ([]agent.Finding, error) {
	return []agent.Finding{}, nil
}

// GetAllRunFindings implements harness.AgentHarness
func (m *MockHarness) GetAllRunFindings(ctx context.Context, filter harness.FindingFilter) ([]agent.Finding, error) {
	return m.findings, nil
}

// MissionExecutionContext implements harness.AgentHarness
func (m *MockHarness) MissionExecutionContext() harness.MissionExecutionContextSDK {
	return harness.MissionExecutionContextSDK{}
}

// GetMissionRunHistory implements harness.AgentHarness
func (m *MockHarness) GetMissionRunHistory(ctx context.Context) ([]harness.MissionRunSummarySDK, error) {
	return []harness.MissionRunSummarySDK{}, nil
}

// MissionID implements harness.AgentHarness
func (m *MockHarness) MissionID() types.ID {
	return m.missionCtx.ID
}

// Memory implements harness.AgentHarness
func (m *MockHarness) Memory() memory.MemoryStore {
	return nil // Not needed for these tests
}

// Mission implements harness.AgentHarness
func (m *MockHarness) Mission() harness.MissionContext {
	return m.missionCtx
}

// Target implements harness.AgentHarness
func (m *MockHarness) Target() harness.TargetInfo {
	return m.targetInfo
}

// Tracer implements harness.AgentHarness
func (m *MockHarness) Tracer() trace.Tracer {
	return nil
}

// Logger implements harness.AgentHarness
func (m *MockHarness) Logger() *slog.Logger {
	return m.logger
}

// Metrics implements harness.AgentHarness
func (m *MockHarness) Metrics() harness.MetricsRecorder {
	return nil
}

// TokenUsage implements harness.AgentHarness
func (m *MockHarness) TokenUsage() *llm.TokenTracker {
	return nil
}

// AddTool adds a tool to the mock harness
func (m *MockHarness) AddTool(name, description string) *MockHarness {
	m.tools[name] = harness.ToolDescriptor{
		Name:            name,
		Description:     description,
		Tags:            []string{},
		InputProtoType:  "google.protobuf.Struct", // Generic proto type for testing
		OutputProtoType: "google.protobuf.Struct", // Generic proto type for testing
	}
	return m
}

// SetToolProtoOutput sets the proto output for a tool call
func (m *MockHarness) SetToolProtoOutput(name string, output proto.Message) *MockHarness {
	m.toolProtoOutputs[name] = output
	return m
}

// SetToolOutput sets the output for a tool call as a map (for convenience in tests)
// The map will be converted to proto Struct internally when CallToolProto is called
func (m *MockHarness) SetToolOutput(name string, output map[string]any) *MockHarness {
	// Convert map to proto Struct for storage
	protoOutput, err := mapToProtoMessage(output, "google.protobuf.Struct")
	if err != nil {
		// If conversion fails, store error for this tool
		m.toolErrors[name] = err
		return m
	}
	m.toolProtoOutputs[name] = protoOutput
	return m
}

// SetToolError sets an error for a tool call
func (m *MockHarness) SetToolError(name string, err error) *MockHarness {
	m.toolErrors[name] = err
	return m
}

// AddLLMResponse adds an LLM response to the queue
func (m *MockHarness) AddLLMResponse(response string) *MockHarness {
	m.llmResponses = append(m.llmResponses, response)
	return m
}

// createSimplePlan returns a basic test plan with 2-3 tool steps
func createSimplePlan(missionID types.ID) *ExecutionPlan {
	step1ID := types.NewID()
	step2ID := types.NewID()

	return &ExecutionPlan{
		ID:        types.NewID(),
		MissionID: missionID,
		AgentName: "test_agent",
		Status:    PlanStatusDraft,
		Steps: []ExecutionStep{
			{
				ID:          step1ID,
				Sequence:    1,
				Type:        StepTypeTool,
				Name:        "scan_ports",
				Description: "Scan target ports",
				ToolName:    "nmap",
				ToolInput: map[string]any{
					"target": "192.168.1.1",
					"ports":  "1-1024",
				},
				RiskLevel:        RiskLevelLow,
				RequiresApproval: false,
				Status:           StepStatusPending,
				DependsOn:        []types.ID{},
				Metadata:         make(map[string]any),
			},
			{
				ID:          step2ID,
				Sequence:    2,
				Type:        StepTypeTool,
				Name:        "analyze_services",
				Description: "Analyze discovered services",
				ToolName:    "service_analyzer",
				ToolInput: map[string]any{
					"scan_results": "{{ step1.output }}",
				},
				RiskLevel:        RiskLevelMedium,
				RequiresApproval: false,
				Status:           StepStatusPending,
				DependsOn:        []types.ID{step1ID},
				Metadata:         make(map[string]any),
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// assertPlanStatus is a helper for status assertions
func assertPlanStatus(t *testing.T, plan *ExecutionPlan, expectedStatus PlanStatus) {
	t.Helper()
	assert.Equal(t, expectedStatus, plan.Status, "plan status should match")
}

// assertStepStatus is a helper for step status assertions
func assertStepStatus(t *testing.T, step *ExecutionStep, expectedStatus StepStatus) {
	t.Helper()
	assert.Equal(t, expectedStatus, step.Status, "step status should match")
}

// Test full plan lifecycle: generate -> approve -> execute -> complete
func TestFullPlanLifecycle(t *testing.T) {
	ctx := context.Background()

	// Create mock harness with canned LLM response
	h := createMockHarness()
	h.AddTool("nmap", "Network port scanner")
	h.AddTool("service_analyzer", "Service analysis tool")

	// Add LLM response that generates a simple plan
	planJSON := `{
		"steps": [
			{
				"name": "scan_ports",
				"description": "Scan target ports",
				"type": "tool",
				"tool_name": "nmap",
				"tool_input": {"target": "192.168.1.1", "ports": "1-1024"},
				"depends_on": []
			},
			{
				"name": "analyze_services",
				"description": "Analyze discovered services",
				"type": "tool",
				"tool_name": "service_analyzer",
				"tool_input": {"scan_results": "placeholder"},
				"depends_on": ["scan_ports"]
			}
		]
	}`
	h.AddLLMResponse(planJSON)

	// Set up tool outputs
	h.SetToolOutput("nmap", map[string]any{
		"open_ports": []int{22, 80, 443},
		"status":     "complete",
	})
	h.SetToolOutput("service_analyzer", map[string]any{
		"services": []string{"ssh", "http", "https"},
		"status":   "complete",
	})

	// 1. Generate plan using LLMPlanGenerator
	generator := NewLLMPlanGenerator(WithSlot("planner"))

	missionID := types.NewID()
	task := agent.NewTask("port_scan", "Scan target network", map[string]any{
		"target": "192.168.1.1",
	}).WithMission(missionID)

	input := GenerateInput{
		Task:             task,
		AvailableTools:   h.ListTools(),
		AvailablePlugins: []harness.PluginDescriptor{},
		AvailableAgents:  []harness.AgentDescriptor{},
	}

	plan, err := generator.Generate(ctx, input, h)
	require.NoError(t, err, "plan generation should succeed")
	require.NotNil(t, plan, "plan should not be nil")
	assert.Len(t, plan.Steps, 2, "plan should have 2 steps")
	assertPlanStatus(t, plan, PlanStatusDraft)

	// 2. Manually transition to approved status
	plan.Status = PlanStatusApproved

	// 3. Execute with PlanExecutor
	executor := NewPlanExecutor(
		WithExecutorLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))),
		WithStepTimeout(10*time.Second),
	)

	result, err := executor.Execute(ctx, plan, h)
	require.NoError(t, err, "plan execution should succeed")
	require.NotNil(t, result, "result should not be nil")

	// 4. Verify completed status and results
	assertPlanStatus(t, plan, PlanStatusCompleted)
	assert.Equal(t, PlanStatusCompleted, result.Status, "result status should be completed")
	assert.Len(t, result.StepResults, 2, "should have 2 step results")

	// Verify step 1 completed
	assert.Equal(t, StepStatusCompleted, result.StepResults[0].Status)
	assert.Contains(t, result.StepResults[0].Output, "open_ports")

	// Verify step 2 completed
	assert.Equal(t, StepStatusCompleted, result.StepResults[1].Status)
	assert.Contains(t, result.StepResults[1].Output, "services")

	// Verify plan metadata
	assert.NotNil(t, plan.StartedAt, "plan should have started timestamp")
	assert.NotNil(t, plan.CompletedAt, "plan should have completed timestamp")
	assert.True(t, plan.CompletedAt.After(*plan.StartedAt), "completed should be after started")
}

// Test plan with guardrail blocks
func TestPlanWithGuardrailBlocks(t *testing.T) {
	ctx := context.Background()

	// Create mock harness
	h := createMockHarness()
	h.AddTool("dangerous_tool", "A dangerous operation")

	// Create a mock guardrail that blocks specific content
	blockingGuardrail := &MockBlockingGuardrail{
		blockContent: "dangerous_tool",
	}

	pipeline := guardrail.NewGuardrailPipeline(blockingGuardrail)

	// Create plan with step that will be blocked
	missionID := types.NewID()
	plan := &ExecutionPlan{
		ID:        types.NewID(),
		MissionID: missionID,
		AgentName: "test_agent",
		Status:    PlanStatusApproved,
		Steps: []ExecutionStep{
			{
				ID:          types.NewID(),
				Sequence:    1,
				Type:        StepTypeTool,
				Name:        "dangerous_operation",
				Description: "Execute dangerous_tool",
				ToolName:    "dangerous_tool",
				ToolInput:   map[string]any{},
				Status:      StepStatusPending,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Execute with guardrails
	executor := NewPlanExecutor(
		WithGuardrails(pipeline),
		WithExecutorLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))),
	)

	result, err := executor.Execute(ctx, plan, h)

	// Verify execution failed with guardrail error
	require.Error(t, err, "execution should fail")
	assert.Contains(t, err.Error(), "guardrail", "error should mention guardrail")

	assert.Equal(t, PlanStatusFailed, result.Status)
	assert.NotNil(t, result.Error)
	// The error code is ErrStepExecutionFailed, but the cause is a guardrail block
	assert.Equal(t, ErrStepExecutionFailed, result.Error.Code)
	assert.Contains(t, result.Error.Message, "failed", "error message should mention failure")
}

// MockBlockingGuardrail is a guardrail that blocks specific content
type MockBlockingGuardrail struct {
	blockContent string
}

func (m *MockBlockingGuardrail) Name() string {
	return "mock_blocker"
}

func (m *MockBlockingGuardrail) Type() guardrail.GuardrailType {
	return guardrail.GuardrailTypeTool
}

func (m *MockBlockingGuardrail) CheckInput(ctx context.Context, input guardrail.GuardrailInput) (guardrail.GuardrailResult, error) {
	if input.Content == m.blockContent || input.ToolName == m.blockContent {
		return guardrail.NewBlockResult("blocked by test guardrail"), errors.New("guardrail blocked")
	}
	return guardrail.NewAllowResult(), nil
}

func (m *MockBlockingGuardrail) CheckOutput(ctx context.Context, output guardrail.GuardrailOutput) (guardrail.GuardrailResult, error) {
	return guardrail.NewAllowResult(), nil
}

// Test multi-step plan with dependencies
func TestMultiStepPlanWithDependencies(t *testing.T) {
	ctx := context.Background()

	// Create mock harness
	h := createMockHarness()
	h.AddTool("step1_tool", "First tool")
	h.AddTool("step2_tool", "Second tool (depends on step1)")
	h.AddTool("step3_tool", "Third tool")

	// Make step1 fail
	h.SetToolError("step1_tool", errors.New("step1 failed"))

	// Create plan with dependencies
	step1ID := types.NewID()
	step2ID := types.NewID()
	step3ID := types.NewID()

	missionID := types.NewID()
	plan := &ExecutionPlan{
		ID:        types.NewID(),
		MissionID: missionID,
		AgentName: "test_agent",
		Status:    PlanStatusApproved,
		Steps: []ExecutionStep{
			{
				ID:          step1ID,
				Sequence:    1,
				Type:        StepTypeTool,
				Name:        "step1",
				Description: "First step",
				ToolName:    "step1_tool",
				ToolInput:   map[string]any{},
				Status:      StepStatusPending,
				DependsOn:   []types.ID{},
			},
			{
				ID:          step2ID,
				Sequence:    2,
				Type:        StepTypeTool,
				Name:        "step2",
				Description: "Second step (depends on step1)",
				ToolName:    "step2_tool",
				ToolInput:   map[string]any{},
				Status:      StepStatusPending,
				DependsOn:   []types.ID{step1ID},
			},
			{
				ID:          step3ID,
				Sequence:    3,
				Type:        StepTypeTool,
				Name:        "step3",
				Description: "Third step (independent)",
				ToolName:    "step3_tool",
				ToolInput:   map[string]any{},
				Status:      StepStatusPending,
				DependsOn:   []types.ID{},
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	executor := NewPlanExecutor(
		WithExecutorLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))),
	)

	result, err := executor.Execute(ctx, plan, h)

	// Verify execution failed due to step1 failure
	require.Error(t, err, "execution should fail when step fails")
	assert.Equal(t, PlanStatusFailed, result.Status)

	// Step 1 should fail
	assert.Len(t, result.StepResults, 1, "should have executed only step1")
	assert.Equal(t, StepStatusFailed, result.StepResults[0].Status)

	// Step 2 should be skipped (dependency failed)
	// Step 3 would not be executed because we stop on first failure
}

// Test approval workflow integration
func TestApprovalWorkflowIntegration(t *testing.T) {
	ctx := context.Background()

	t.Run("auto approve", func(t *testing.T) {
		h := createMockHarness()
		h.AddTool("high_risk_tool", "High risk operation")
		h.SetToolOutput("high_risk_tool", map[string]any{"status": "success"})

		// Create plan with high-risk step
		missionID := types.NewID()
		plan := &ExecutionPlan{
			ID:        types.NewID(),
			MissionID: missionID,
			AgentName: "test_agent",
			Status:    PlanStatusApproved,
			Steps: []ExecutionStep{
				{
					ID:               types.NewID(),
					Sequence:         1,
					Type:             StepTypeTool,
					Name:             "high_risk_operation",
					Description:      "Execute high risk tool",
					ToolName:         "high_risk_tool",
					ToolInput:        map[string]any{},
					RiskLevel:        RiskLevelHigh,
					RequiresApproval: true,
					Status:           StepStatusPending,
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		// Create executor with auto-approve mock service
		approvalService := NewMockApprovalService(WithAutoApprove())
		executor := NewPlanExecutor(
			WithApprovalService(approvalService),
			WithExecutorLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))),
		)

		result, err := executor.Execute(ctx, plan, h)

		require.NoError(t, err, "execution should succeed with auto-approve")
		assert.Equal(t, PlanStatusCompleted, result.Status)
		assert.Len(t, result.StepResults, 1)
		assert.Equal(t, StepStatusCompleted, result.StepResults[0].Status)

		// Verify approval was requested (check pending count went to 0)
		assert.Equal(t, 0, approvalService.PendingCount(), "approval should have been processed")
	})

	t.Run("auto deny", func(t *testing.T) {
		h := createMockHarness()
		h.AddTool("high_risk_tool", "High risk operation")

		missionID := types.NewID()
		plan := &ExecutionPlan{
			ID:        types.NewID(),
			MissionID: missionID,
			AgentName: "test_agent",
			Status:    PlanStatusApproved,
			Steps: []ExecutionStep{
				{
					ID:               types.NewID(),
					Sequence:         1,
					Type:             StepTypeTool,
					Name:             "high_risk_operation",
					Description:      "Execute high risk tool",
					ToolName:         "high_risk_tool",
					ToolInput:        map[string]any{},
					RiskLevel:        RiskLevelHigh,
					RequiresApproval: true,
					Status:           StepStatusPending,
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		// Create executor with auto-deny mock service
		approvalService := NewMockApprovalService(WithAutoDeny("test denial"))
		executor := NewPlanExecutor(
			WithApprovalService(approvalService),
			WithExecutorLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))),
		)

		result, err := executor.Execute(ctx, plan, h)

		require.Error(t, err, "execution should fail with auto-deny")
		assert.Equal(t, PlanStatusFailed, result.Status)
		assert.NotNil(t, result.Error)
		assert.Equal(t, ErrApprovalDenied, result.Error.Code)
		assert.Contains(t, result.Error.Message, "denied")
	})
}

// Test concurrent step execution
func TestConcurrentStepExecution(t *testing.T) {
	ctx := context.Background()

	h := createMockHarness()
	h.AddTool("parallel_tool_1", "Tool 1")
	h.AddTool("parallel_tool_2", "Tool 2")
	h.AddTool("parallel_tool_3", "Tool 3")

	// Set outputs for parallel tools
	h.SetToolOutput("parallel_tool_1", map[string]any{"result": "tool1_result"})
	h.SetToolOutput("parallel_tool_2", map[string]any{"result": "tool2_result"})
	h.SetToolOutput("parallel_tool_3", map[string]any{"result": "tool3_result"})

	// Create parallel steps
	parallelSteps := []ExecutionStep{
		{
			ID:          types.NewID(),
			Sequence:    1,
			Type:        StepTypeTool,
			Name:        "parallel_step_1",
			Description: "First parallel step",
			ToolName:    "parallel_tool_1",
			ToolInput:   map[string]any{},
			Status:      StepStatusPending,
		},
		{
			ID:          types.NewID(),
			Sequence:    2,
			Type:        StepTypeTool,
			Name:        "parallel_step_2",
			Description: "Second parallel step",
			ToolName:    "parallel_tool_2",
			ToolInput:   map[string]any{},
			Status:      StepStatusPending,
		},
		{
			ID:          types.NewID(),
			Sequence:    3,
			Type:        StepTypeTool,
			Name:        "parallel_step_3",
			Description: "Third parallel step",
			ToolName:    "parallel_tool_3",
			ToolInput:   map[string]any{},
			Status:      StepStatusPending,
		},
	}

	missionID := types.NewID()
	plan := &ExecutionPlan{
		ID:        types.NewID(),
		MissionID: missionID,
		AgentName: "test_agent",
		Status:    PlanStatusApproved,
		Steps: []ExecutionStep{
			{
				ID:            types.NewID(),
				Sequence:      1,
				Type:          StepTypeParallel,
				Name:          "parallel_execution",
				Description:   "Execute steps in parallel",
				ParallelSteps: parallelSteps,
				Status:        StepStatusPending,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	executor := NewPlanExecutor(
		WithExecutorLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))),
	)

	result, err := executor.Execute(ctx, plan, h)

	require.NoError(t, err, "parallel execution should succeed")
	assert.Equal(t, PlanStatusCompleted, result.Status)
	assert.Len(t, result.StepResults, 1, "should have 1 step result for parallel step")

	// Verify parallel results were aggregated
	parallelResult := result.StepResults[0]
	assert.Equal(t, StepStatusCompleted, parallelResult.Status)
	assert.Contains(t, parallelResult.Output, "parallel_results")

	// Verify all 3 parallel steps completed
	parallelResultsData, ok := parallelResult.Output["parallel_results"].([]map[string]any)
	require.True(t, ok, "parallel_results should be slice of maps")
	assert.Len(t, parallelResultsData, 3, "should have 3 parallel step results")
}

// Test LLM plan generation with error handling
func TestLLMPlanGenerationWithRetry(t *testing.T) {
	ctx := context.Background()

	h := createMockHarness()
	h.AddTool("test_tool", "A test tool")

	// First response is invalid JSON, second is valid
	invalidJSON := `{"steps": [invalid json]}`
	validJSON := `{
		"steps": [
			{
				"name": "test_step",
				"description": "Test step",
				"type": "tool",
				"tool_name": "test_tool",
				"tool_input": {},
				"depends_on": []
			}
		]
	}`

	h.AddLLMResponse(invalidJSON)
	h.AddLLMResponse(validJSON)

	generator := NewLLMPlanGenerator(
		WithSlot("planner"),
		WithMaxRetries(1),
	)

	missionID := types.NewID()
	task := agent.NewTask("test_task", "Test task", map[string]any{}).WithMission(missionID)
	input := GenerateInput{
		Task:             task,
		AvailableTools:   h.ListTools(),
		AvailablePlugins: []harness.PluginDescriptor{},
		AvailableAgents:  []harness.AgentDescriptor{},
	}

	plan, err := generator.Generate(ctx, input, h)

	require.NoError(t, err, "generation should succeed after retry")
	require.NotNil(t, plan)
	assert.Len(t, plan.Steps, 1, "plan should have 1 step")
	assert.Equal(t, "test_step", plan.Steps[0].Name)
}

// Test plan result aggregation
func TestPlanResultAggregation(t *testing.T) {
	ctx := context.Background()

	h := createMockHarness()
	h.AddTool("scanner", "Security scanner")

	// Tool returns findings
	finding1 := agent.NewFinding("XSS Vulnerability", "Found XSS in form", agent.SeverityHigh)
	finding2 := agent.NewFinding("SQL Injection", "Found SQLi in query", agent.SeverityCritical)

	// Since tools don't return findings directly in our implementation,
	// we'll test with an agent delegation that returns findings
	h.AddTool("test_tool", "Test tool")

	agentResult := agent.NewResult(types.NewID())
	agentResult.Complete(map[string]any{"status": "success"})
	agentResult.AddFinding(finding1)
	agentResult.AddFinding(finding2)

	h.agentResults["scanner_agent"] = agentResult

	missionID := types.NewID()
	agentTask := agent.NewTask("scan_task", "Scan for vulnerabilities", map[string]any{})
	plan := &ExecutionPlan{
		ID:        types.NewID(),
		MissionID: missionID,
		AgentName: "test_agent",
		Status:    PlanStatusApproved,
		Steps: []ExecutionStep{
			{
				ID:          types.NewID(),
				Sequence:    1,
				Type:        StepTypeAgent,
				Name:        "security_scan",
				Description: "Perform security scan",
				AgentName:   "scanner_agent",
				AgentTask:   &agentTask,
				Status:      StepStatusPending,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	executor := NewPlanExecutor(
		WithExecutorLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))),
	)

	result, err := executor.Execute(ctx, plan, h)

	require.NoError(t, err, "execution should succeed")
	assert.Equal(t, PlanStatusCompleted, result.Status)

	// Verify findings were aggregated
	assert.Len(t, result.Findings, 2, "should have 2 findings")
	assert.Equal(t, "XSS Vulnerability", result.Findings[0].Title)
	assert.Equal(t, "SQL Injection", result.Findings[1].Title)
}

// Test plan validation errors
func TestPlanValidation(t *testing.T) {
	ctx := context.Background()

	h := createMockHarness()

	t.Run("not approved plan", func(t *testing.T) {
		plan := createSimplePlan(types.NewID())
		plan.Status = PlanStatusDraft // Not approved

		executor := NewPlanExecutor()
		result, err := executor.Execute(ctx, plan, h)

		require.Error(t, err, "should fail for non-approved plan")
		assert.Contains(t, err.Error(), "approved")
		if result != nil {
			assert.NotNil(t, result.Error)
			assert.Equal(t, ErrPlanNotApproved, result.Error.Code)
		}
	})

	t.Run("invalid input to generator", func(t *testing.T) {
		generator := NewLLMPlanGenerator()

		// Empty task name
		input := GenerateInput{
			Task: agent.Task{
				Name:        "", // Invalid
				Description: "Test",
			},
		}

		plan, err := generator.Generate(ctx, input, h)

		require.Error(t, err, "should fail for invalid input")
		assert.Nil(t, plan)
		assert.Contains(t, err.Error(), "invalid input")
	})
}

// Test step timeout handling
func TestStepTimeout(t *testing.T) {
	ctx := context.Background()

	h := createMockHarness()

	// Create a slow tool that would exceed timeout
	h.AddTool("slow_tool", "A slow tool")
	// We can't easily simulate timeout in this test without actual blocking,
	// so this is more of a structural test

	missionID := types.NewID()
	plan := &ExecutionPlan{
		ID:        types.NewID(),
		MissionID: missionID,
		AgentName: "test_agent",
		Status:    PlanStatusApproved,
		Steps: []ExecutionStep{
			{
				ID:          types.NewID(),
				Sequence:    1,
				Type:        StepTypeTool,
				Name:        "slow_operation",
				Description: "Execute slow tool",
				ToolName:    "slow_tool",
				ToolInput:   map[string]any{},
				Status:      StepStatusPending,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Set very short timeout
	executor := NewPlanExecutor(
		WithStepTimeout(1*time.Millisecond),
		WithExecutorLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))),
	)

	// Execution should complete quickly with mock (not actually timeout)
	result, err := executor.Execute(ctx, plan, h)

	// With our mock, this should succeed, but the timeout mechanism is in place
	require.NoError(t, err)
	assert.Equal(t, PlanStatusCompleted, result.Status)
}

// Test JSON serialization of plan structures
func TestPlanSerialization(t *testing.T) {
	plan := createSimplePlan(types.NewID())

	// Serialize to JSON
	data, err := json.Marshal(plan)
	require.NoError(t, err, "should serialize to JSON")

	// Deserialize from JSON
	var decoded ExecutionPlan
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err, "should deserialize from JSON")

	// Verify key fields
	assert.Equal(t, plan.ID, decoded.ID)
	assert.Equal(t, plan.MissionID, decoded.MissionID)
	assert.Equal(t, plan.AgentName, decoded.AgentName)
	assert.Len(t, decoded.Steps, len(plan.Steps))
}
