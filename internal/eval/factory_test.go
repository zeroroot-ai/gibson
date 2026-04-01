package eval

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/types"
	sdktypes "github.com/zero-day-ai/sdk/types"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
)

// createTempGroundTruth creates a temporary ground truth file for testing
func createTempGroundTruth(t *testing.T) string {
	tmpFile, err := os.CreateTemp("", "ground_truth_test_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.WriteString("{}")
	tmpFile.Close()
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })
	return tmpFile.Name()
}

// mockHarnessFactory is a mock implementation of HarnessFactoryInterface for testing
type mockHarnessFactory struct {
	createFunc      func(agentName string, missionCtx harness.MissionContext, target harness.TargetInfo) (harness.AgentHarness, error)
	createChildFunc func(parent harness.AgentHarness, agentName string) (harness.AgentHarness, error)
}

func (m *mockHarnessFactory) Create(agentName string, missionCtx harness.MissionContext, target harness.TargetInfo) (harness.AgentHarness, error) {
	if m.createFunc != nil {
		return m.createFunc(agentName, missionCtx, target)
	}
	return &mockAgentHarness{
		agentName:  agentName,
		missionCtx: missionCtx,
		targetInfo: target,
	}, nil
}

func (m *mockHarnessFactory) CreateChild(parent harness.AgentHarness, agentName string) (harness.AgentHarness, error) {
	if m.createChildFunc != nil {
		return m.createChildFunc(parent, agentName)
	}
	return &mockAgentHarness{
		agentName:  agentName,
		missionCtx: parent.Mission(),
		targetInfo: parent.Target(),
	}, nil
}

// mockAgentHarness is a minimal mock harness for testing
type mockAgentHarness struct {
	agentName        string
	missionCtx       harness.MissionContext
	targetInfo       harness.TargetInfo
	toolProtoOutputs map[string]proto.Message
	toolErrors       map[string]error
}

func (m *mockAgentHarness) Mission() harness.MissionContext {
	return m.missionCtx
}

func (m *mockAgentHarness) Target() harness.TargetInfo {
	return m.targetInfo
}

// Implement harness interface methods with correct signatures
func (m *mockAgentHarness) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...harness.CompletionOption) (*llm.CompletionResponse, error) {
	return &llm.CompletionResponse{}, nil
}
func (m *mockAgentHarness) CompleteWithTools(ctx context.Context, slot string, messages []llm.Message, tools []llm.ToolDef, opts ...harness.CompletionOption) (*llm.CompletionResponse, error) {
	return &llm.CompletionResponse{}, nil
}
func (m *mockAgentHarness) Stream(ctx context.Context, slot string, messages []llm.Message, opts ...harness.CompletionOption) (<-chan llm.StreamChunk, error) {
	ch := make(chan llm.StreamChunk)
	close(ch)
	return ch, nil
}
func (m *mockAgentHarness) CallToolProto(ctx context.Context, name string, request, response proto.Message) error {
	if err, ok := m.toolErrors[name]; ok {
		return err
	}
	if protoOut, ok := m.toolProtoOutputs[name]; ok {
		proto.Merge(response, protoOut)
	}
	return nil
}
func (m *mockAgentHarness) ListTools() []harness.ToolDescriptor {
	return []harness.ToolDescriptor{}
}
func (m *mockAgentHarness) GetToolDescriptor(ctx context.Context, name string) (*harness.ToolDescriptor, error) {
	return nil, nil
}
func (m *mockAgentHarness) QueryPlugin(ctx context.Context, name string, method string, params map[string]any) (any, error) {
	return nil, nil
}
func (m *mockAgentHarness) ListPlugins() []harness.PluginDescriptor {
	return []harness.PluginDescriptor{}
}
func (m *mockAgentHarness) DelegateToAgent(ctx context.Context, name string, task agent.Task) (agent.Result, error) {
	return agent.Result{}, nil
}
func (m *mockAgentHarness) ListAgents() []harness.AgentDescriptor {
	return []harness.AgentDescriptor{}
}
func (m *mockAgentHarness) SubmitFinding(ctx context.Context, finding agent.Finding) error {
	return nil
}
func (m *mockAgentHarness) GetFindings(ctx context.Context, filter harness.FindingFilter) ([]agent.Finding, error) {
	return []agent.Finding{}, nil
}
func (m *mockAgentHarness) Memory() memory.MemoryStore {
	return nil
}
func (m *mockAgentHarness) Tracer() trace.Tracer {
	return nil
}
func (m *mockAgentHarness) Logger() *slog.Logger {
	return slog.Default()
}
func (m *mockAgentHarness) TokenUsage() *llm.TokenTracker {
	return nil
}
func (m *mockAgentHarness) Metrics() harness.MetricsRecorder {
	return nil
}
func (m *mockAgentHarness) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...harness.CompletionOption) (any, error) {
	return nil, nil
}
func (m *mockAgentHarness) CompleteStructuredAnyWithUsage(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...harness.CompletionOption) (*harness.StructuredCompletionResult, error) {
	return &harness.StructuredCompletionResult{}, nil
}
func (m *mockAgentHarness) GetAllRunFindings(ctx context.Context, filter harness.FindingFilter) ([]agent.Finding, error) {
	return []agent.Finding{}, nil
}
func (m *mockAgentHarness) GetMissionRunHistory(ctx context.Context) ([]harness.MissionRunSummarySDK, error) {
	return []harness.MissionRunSummarySDK{}, nil
}
func (m *mockAgentHarness) GetPreviousRunFindings(ctx context.Context, filter harness.FindingFilter) ([]agent.Finding, error) {
	return []agent.Finding{}, nil
}
func (m *mockAgentHarness) MissionExecutionContext() harness.MissionExecutionContextSDK {
	return harness.MissionExecutionContextSDK{}
}
func (m *mockAgentHarness) MissionID() types.ID {
	return types.NewID()
}
func (m *mockAgentHarness) RunNumber() int {
	return 1
}
func (m *mockAgentHarness) CurrentAgentName() string {
	return m.agentName
}
func (m *mockAgentHarness) GetToolCapabilities(ctx context.Context, toolName string) (*sdktypes.Capabilities, error) {
	return nil, nil
}
func (m *mockAgentHarness) GetAllToolCapabilities(ctx context.Context) (map[string]*sdktypes.Capabilities, error) {
	return nil, nil
}
func (m *mockAgentHarness) Checkpoint() harness.CheckpointAccess {
	return harness.NewHarnessCheckpointMethods(nil, "", "", 0)
}

// TestNewEvalHarnessFactory tests factory creation
func TestNewEvalHarnessFactory(t *testing.T) {
	t.Run("ValidFactory", func(t *testing.T) {
		innerFactory := &mockHarnessFactory{}
		opts := NewEvalOptions()
		// Disable evaluation to skip ground truth path validation
		opts.Enabled = false

		factory, err := NewEvalHarnessFactory(innerFactory, opts)
		require.NoError(t, err)
		assert.NotNil(t, factory)
		assert.Equal(t, innerFactory, factory.inner)
		assert.Equal(t, opts, factory.options)
		assert.NotNil(t, factory.collector)
	})

	t.Run("NilInnerFactory", func(t *testing.T) {
		opts := NewEvalOptions()
		opts.Enabled = false

		factory, err := NewEvalHarnessFactory(nil, opts)
		assert.Error(t, err)
		assert.Nil(t, factory)
		assert.Contains(t, err.Error(), "inner harness factory cannot be nil")
	})

	t.Run("NilOptions", func(t *testing.T) {
		innerFactory := &mockHarnessFactory{}

		factory, err := NewEvalHarnessFactory(innerFactory, nil)
		assert.Error(t, err)
		assert.Nil(t, factory)
		assert.Contains(t, err.Error(), "evaluation options cannot be nil")
	})

	t.Run("InvalidOptions", func(t *testing.T) {
		innerFactory := &mockHarnessFactory{}
		opts := NewEvalOptions()
		opts.Enabled = true
		opts.GroundTruthPath = "" // Missing required field when enabled

		factory, err := NewEvalHarnessFactory(innerFactory, opts)
		assert.Error(t, err)
		assert.Nil(t, factory)
		assert.Contains(t, err.Error(), "invalid evaluation options")
	})
}

// TestEvalHarnessFactory_Create tests harness creation
func TestEvalHarnessFactory_Create(t *testing.T) {
	missionCtx := harness.MissionContext{
		ID:           types.NewID(),
		Name:         "test-mission",
		CurrentAgent: "test-agent",
	}

	targetInfo := harness.TargetInfo{
		URL: "https://example.com",
	}

	t.Run("EvaluationDisabled", func(t *testing.T) {
		innerFactory := &mockHarnessFactory{}
		opts := NewEvalOptions()
		opts.Enabled = false

		factory, err := NewEvalHarnessFactory(innerFactory, opts)
		require.NoError(t, err)

		h, err := factory.Create("test-agent", missionCtx, targetInfo)
		require.NoError(t, err)
		assert.NotNil(t, h)

		// Should return base harness directly (mock)
		_, isMock := h.(*mockAgentHarness)
		assert.True(t, isMock, "Expected mock harness when eval disabled")
	})

	t.Run("EvaluationEnabledFeedbackDisabled", func(t *testing.T) {
		innerFactory := &mockHarnessFactory{}
		opts := NewEvalOptions()
		opts.Enabled = true
		opts.FeedbackEnabled = false
		opts.GroundTruthPath = createTempGroundTruth(t)

		factory, err := NewEvalHarnessFactory(innerFactory, opts)
		require.NoError(t, err)

		h, err := factory.Create("test-agent", missionCtx, targetInfo)
		require.NoError(t, err)
		assert.NotNil(t, h)

		// For now, should return base harness (mock) until adapter is implemented
		_, isMock := h.(*mockAgentHarness)
		assert.True(t, isMock, "Expected base harness when eval enabled (adapter not yet implemented)")
	})

	t.Run("EvaluationAndFeedbackEnabled", func(t *testing.T) {
		innerFactory := &mockHarnessFactory{}
		opts := NewEvalOptions()
		opts.Enabled = true
		opts.GroundTruthPath = createTempGroundTruth(t)
		opts.FeedbackEnabled = true
		opts.WarningThreshold = 0.6
		opts.CriticalThreshold = 0.3

		factory, err := NewEvalHarnessFactory(innerFactory, opts)
		require.NoError(t, err)

		h, err := factory.Create("test-agent", missionCtx, targetInfo)
		require.NoError(t, err)
		assert.NotNil(t, h)

		// For now, should return base harness until adapter is implemented
		_, isMock := h.(*mockAgentHarness)
		assert.True(t, isMock, "Expected base harness when feedback enabled (adapter not yet implemented)")

		// Verify collector exists
		assert.NotNil(t, factory.collector)
	})

	t.Run("InnerFactoryError", func(t *testing.T) {
		expectedErr := types.NewError(types.CONFIG_VALIDATION_FAILED, "mock error")
		innerFactory := &mockHarnessFactory{
			createFunc: func(agentName string, missionCtx harness.MissionContext, target harness.TargetInfo) (harness.AgentHarness, error) {
				return nil, expectedErr
			},
		}

		opts := NewEvalOptions()
		opts.Enabled = true
		opts.GroundTruthPath = createTempGroundTruth(t)

		factory, err := NewEvalHarnessFactory(innerFactory, opts)
		require.NoError(t, err)

		h, err := factory.Create("test-agent", missionCtx, targetInfo)
		assert.Error(t, err)
		assert.Nil(t, h)
	})

	t.Run("MissionIDPropagation", func(t *testing.T) {
		innerFactory := &mockHarnessFactory{}
		opts := NewEvalOptions()
		opts.Enabled = true
		opts.GroundTruthPath = createTempGroundTruth(t)
		opts.FeedbackEnabled = true

		factory, err := NewEvalHarnessFactory(innerFactory, opts)
		require.NoError(t, err)

		// First harness creation should set mission ID
		_, err = factory.Create("agent1", missionCtx, targetInfo)
		require.NoError(t, err)

		// Verify mission ID was set in collector
		assert.Equal(t, missionCtx.ID, factory.collector.missionID)

		// Second harness creation should preserve mission ID
		_, err = factory.Create("agent2", missionCtx, targetInfo)
		require.NoError(t, err)

		assert.Equal(t, missionCtx.ID, factory.collector.missionID)
	})
}

// TestEvalHarnessFactory_CreateChild tests child harness creation
func TestEvalHarnessFactory_CreateChild(t *testing.T) {
	missionCtx := harness.MissionContext{
		ID:           types.NewID(),
		Name:         "test-mission",
		CurrentAgent: "parent-agent",
	}

	targetInfo := harness.TargetInfo{
		URL: "https://example.com",
	}

	t.Run("EvaluationDisabled", func(t *testing.T) {
		innerFactory := &mockHarnessFactory{}
		opts := NewEvalOptions()
		opts.Enabled = false

		factory, err := NewEvalHarnessFactory(innerFactory, opts)
		require.NoError(t, err)

		parent := &mockAgentHarness{
			agentName:  "parent",
			missionCtx: missionCtx,
			targetInfo: targetInfo,
		}

		child, err := factory.CreateChild(parent, "child-agent")
		require.NoError(t, err)
		assert.NotNil(t, child)

		_, isMock := child.(*mockAgentHarness)
		assert.True(t, isMock)
	})

	t.Run("EvaluationEnabled", func(t *testing.T) {
		innerFactory := &mockHarnessFactory{}
		opts := NewEvalOptions()
		opts.Enabled = true
		opts.GroundTruthPath = createTempGroundTruth(t)
		opts.FeedbackEnabled = true

		factory, err := NewEvalHarnessFactory(innerFactory, opts)
		require.NoError(t, err)

		parent := &mockAgentHarness{
			agentName:  "parent",
			missionCtx: missionCtx,
			targetInfo: targetInfo,
		}

		child, err := factory.CreateChild(parent, "child-agent")
		require.NoError(t, err)
		assert.NotNil(t, child)

		// For now, should return base harness until adapter is implemented
		_, isMock := child.(*mockAgentHarness)
		assert.True(t, isMock)
	})

	t.Run("NilParent", func(t *testing.T) {
		innerFactory := &mockHarnessFactory{}
		opts := NewEvalOptions()
		opts.Enabled = true
		opts.GroundTruthPath = createTempGroundTruth(t)

		factory, err := NewEvalHarnessFactory(innerFactory, opts)
		require.NoError(t, err)

		child, err := factory.CreateChild(nil, "child-agent")
		assert.Error(t, err)
		assert.Nil(t, child)
		assert.Contains(t, err.Error(), "parent harness cannot be nil")
	})

	t.Run("EmptyAgentName", func(t *testing.T) {
		innerFactory := &mockHarnessFactory{}
		opts := NewEvalOptions()
		opts.Enabled = true
		opts.GroundTruthPath = createTempGroundTruth(t)

		factory, err := NewEvalHarnessFactory(innerFactory, opts)
		require.NoError(t, err)

		parent := &mockAgentHarness{
			agentName:  "parent",
			missionCtx: missionCtx,
			targetInfo: targetInfo,
		}

		child, err := factory.CreateChild(parent, "")
		assert.Error(t, err)
		assert.Nil(t, child)
		assert.Contains(t, err.Error(), "agent name cannot be empty")
	})

	t.Run("ParentIsBase", func(t *testing.T) {
		innerFactory := &mockHarnessFactory{}
		opts := NewEvalOptions()
		opts.Enabled = true
		opts.GroundTruthPath = createTempGroundTruth(t)
		opts.FeedbackEnabled = true

		factory, err := NewEvalHarnessFactory(innerFactory, opts)
		require.NoError(t, err)

		// Create a parent harness
		parentBase := &mockAgentHarness{
			agentName:  "parent",
			missionCtx: missionCtx,
			targetInfo: targetInfo,
		}

		// Create child from base parent
		child, err := factory.CreateChild(parentBase, "child-agent")
		require.NoError(t, err)
		assert.NotNil(t, child)

		// Child should be a mock harness (base type)
		_, isMock := child.(*mockAgentHarness)
		assert.True(t, isMock)
	})
}

// TestEvalHarnessFactory_Results tests result collector access
func TestEvalHarnessFactory_Results(t *testing.T) {
	innerFactory := &mockHarnessFactory{}
	opts := NewEvalOptions()
	opts.Enabled = true
	opts.FeedbackEnabled = true
	opts.GroundTruthPath = createTempGroundTruth(t)

	factory, err := NewEvalHarnessFactory(innerFactory, opts)
	require.NoError(t, err)

	// Get results before creating any harnesses
	results := factory.Results()
	assert.NotNil(t, results)
	assert.NotNil(t, results.trajectories)
	assert.NotNil(t, results.feedbackHist)
	assert.NotNil(t, results.harnesses)

	// Create a harness
	missionCtx := harness.MissionContext{
		ID:           types.NewID(),
		Name:         "test-mission",
		CurrentAgent: "test-agent",
	}
	targetInfo := harness.TargetInfo{
		URL: "https://example.com",
	}

	_, err = factory.Create("test-agent", missionCtx, targetInfo)
	require.NoError(t, err)

	// Results should still be the same collector instance
	results2 := factory.Results()
	assert.Same(t, results, results2)
}

// TestEvalHarnessFactory_Integration tests end-to-end workflow
func TestEvalHarnessFactory_Integration(t *testing.T) {
	innerFactory := &mockHarnessFactory{}
	opts := NewEvalOptions()
	opts.Enabled = true
	opts.FeedbackEnabled = true
	opts.WarningThreshold = 0.5
	opts.CriticalThreshold = 0.2
	opts.GroundTruthPath = createTempGroundTruth(t)

	factory, err := NewEvalHarnessFactory(innerFactory, opts)
	require.NoError(t, err)

	missionCtx := harness.MissionContext{
		ID:           types.NewID(),
		Name:         "integration-test",
		CurrentAgent: "agent1",
	}
	targetInfo := harness.TargetInfo{
		URL: "https://example.com",
	}

	// Create first agent harness
	h1, err := factory.Create("agent1", missionCtx, targetInfo)
	require.NoError(t, err)
	assert.NotNil(t, h1)

	// Create second agent harness
	h2, err := factory.Create("agent2", missionCtx, targetInfo)
	require.NoError(t, err)
	assert.NotNil(t, h2)

	// Verify collector exists
	collector := factory.Results()
	assert.NotNil(t, collector)
	// Note: Harnesses aren't registered yet since wrapping is not implemented
	// assert.Equal(t, 2, len(collector.harnesses))

	// Get summary (should be empty initially)
	summary := collector.GetSummary()
	assert.NotNil(t, summary)
	assert.Equal(t, missionCtx.ID, summary.MissionID)
	assert.Equal(t, 0, summary.TotalSteps)
}

// TestEvalHarnessFactory_InterfaceCompliance verifies the factory implements the interface
func TestEvalHarnessFactory_InterfaceCompliance(t *testing.T) {
	var _ harness.HarnessFactoryInterface = (*EvalHarnessFactory)(nil)
}
