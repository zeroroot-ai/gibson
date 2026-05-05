package eval

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gibsonAgent "github.com/zero-day-ai/gibson/internal/agent"
	gibsonHarness "github.com/zero-day-ai/gibson/internal/harness"
	gibsonLLM "github.com/zero-day-ai/gibson/internal/llm"
	gibsonMemory "github.com/zero-day-ai/gibson/internal/memory"
	gibsonTypes "github.com/zero-day-ai/gibson/internal/types"
	sdkAgent "github.com/zero-day-ai/sdk/agent"
	"github.com/zero-day-ai/sdk/finding"
	"github.com/zero-day-ai/sdk/graphrag"
	"github.com/zero-day-ai/sdk/llm"
	sdktypes "github.com/zero-day-ai/sdk/types"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/proto"
)

// mockInnerHarness is a mock of gibsonHarness.AgentHarness for adapter tests.
// It records call arguments and returns configured responses to verify type conversion.
type mockInnerHarness struct {
	// Configured responses
	completeResp          *gibsonLLM.CompletionResponse
	completeErr           error
	completeWithToolsResp *gibsonLLM.CompletionResponse
	completeWithToolsErr  error
	streamChunks          []gibsonLLM.StreamChunk
	streamErr             error
	submitFindingErr      error
	getFindingsResult     []gibsonAgent.Finding
	getFindingsErr        error

	// Captured call arguments
	capturedSlot     string
	capturedMessages []gibsonLLM.Message
	capturedTools    []gibsonLLM.ToolDef
}

func (m *mockInnerHarness) Complete(ctx context.Context, slot string, messages []gibsonLLM.Message, opts ...gibsonHarness.CompletionOption) (*gibsonLLM.CompletionResponse, error) {
	m.capturedSlot = slot
	m.capturedMessages = messages
	if m.completeErr != nil {
		return nil, m.completeErr
	}
	if m.completeResp != nil {
		return m.completeResp, nil
	}
	return &gibsonLLM.CompletionResponse{
		Message: gibsonLLM.Message{Role: "assistant", Content: "default"},
	}, nil
}

func (m *mockInnerHarness) CompleteWithTools(ctx context.Context, slot string, messages []gibsonLLM.Message, tools []gibsonLLM.ToolDef, opts ...gibsonHarness.CompletionOption) (*gibsonLLM.CompletionResponse, error) {
	m.capturedSlot = slot
	m.capturedMessages = messages
	m.capturedTools = tools
	if m.completeWithToolsErr != nil {
		return nil, m.completeWithToolsErr
	}
	if m.completeWithToolsResp != nil {
		return m.completeWithToolsResp, nil
	}
	return &gibsonLLM.CompletionResponse{}, nil
}

func (m *mockInnerHarness) Stream(ctx context.Context, slot string, messages []gibsonLLM.Message, opts ...gibsonHarness.CompletionOption) (<-chan gibsonLLM.StreamChunk, error) {
	if m.streamErr != nil {
		return nil, m.streamErr
	}
	ch := make(chan gibsonLLM.StreamChunk, len(m.streamChunks)+1)
	for _, chunk := range m.streamChunks {
		ch <- chunk
	}
	close(ch)
	return ch, nil
}

func (m *mockInnerHarness) CompleteStructuredAny(ctx context.Context, slot string, messages []gibsonLLM.Message, schemaType any, opts ...gibsonHarness.CompletionOption) (any, error) {
	return nil, errors.New("not implemented")
}

func (m *mockInnerHarness) CompleteStructuredAnyWithUsage(ctx context.Context, slot string, messages []gibsonLLM.Message, schemaType any, opts ...gibsonHarness.CompletionOption) (*gibsonHarness.StructuredCompletionResult, error) {
	return nil, errors.New("not implemented")
}

func (m *mockInnerHarness) CallToolProto(ctx context.Context, name string, request, response proto.Message) error {
	return errors.New("not implemented")
}

func (m *mockInnerHarness) CallToolProtoStream(ctx context.Context, name string, request, response proto.Message, callback sdkAgent.ToolStreamCallback) error {
	return errors.New("not implemented")
}

func (m *mockInnerHarness) ListTools() []gibsonHarness.ToolDescriptor {
	return []gibsonHarness.ToolDescriptor{
		{Name: "test_tool", Description: "A test tool", Version: "1.0"},
	}
}

func (m *mockInnerHarness) GetToolDescriptor(ctx context.Context, name string) (*gibsonHarness.ToolDescriptor, error) {
	return nil, errors.New("not implemented")
}

func (m *mockInnerHarness) GetToolCapabilities(ctx context.Context, toolName string) (*sdktypes.Capabilities, error) {
	return nil, errors.New("not implemented")
}

func (m *mockInnerHarness) GetAllToolCapabilities(ctx context.Context) (map[string]*sdktypes.Capabilities, error) {
	return nil, errors.New("not implemented")
}

func (m *mockInnerHarness) QueryPlugin(ctx context.Context, name string, method string, params map[string]any) (any, error) {
	return map[string]any{"status": "ok"}, nil
}

func (m *mockInnerHarness) ListPlugins() []gibsonHarness.PluginDescriptor {
	return []gibsonHarness.PluginDescriptor{
		{Name: "test_plugin", Version: "1.0"},
	}
}

func (m *mockInnerHarness) DelegateToAgent(ctx context.Context, name string, task gibsonAgent.Task) (gibsonAgent.Result, error) {
	return gibsonAgent.NewResult(gibsonTypes.NewID()), nil
}

func (m *mockInnerHarness) ListAgents() []gibsonHarness.AgentDescriptor {
	return []gibsonHarness.AgentDescriptor{
		{Name: "test_agent", Version: "1.0", Capabilities: []string{"scan"}},
	}
}

func (m *mockInnerHarness) SubmitFinding(ctx context.Context, f gibsonAgent.Finding) error {
	return m.submitFindingErr
}

func (m *mockInnerHarness) GetFindings(ctx context.Context, filter gibsonHarness.FindingFilter) ([]gibsonAgent.Finding, error) {
	if m.getFindingsErr != nil {
		return nil, m.getFindingsErr
	}
	return m.getFindingsResult, nil
}

func (m *mockInnerHarness) Memory() gibsonMemory.MemoryStore {
	return &mockGibsonMemoryStore{}
}

func (m *mockInnerHarness) MissionID() gibsonTypes.ID {
	return gibsonTypes.NewID()
}

func (m *mockInnerHarness) Mission() gibsonHarness.MissionContext {
	return gibsonHarness.MissionContext{
		ID:           gibsonTypes.ID("mission-123"),
		Name:         "Test Mission",
		CurrentAgent: "test-agent",
		Phase:        "reconnaissance",
	}
}

func (m *mockInnerHarness) MissionExecutionContext() gibsonHarness.MissionExecutionContextSDK {
	return gibsonHarness.MissionExecutionContextSDK{}
}

func (m *mockInnerHarness) GetMissionRunHistory(ctx context.Context) ([]gibsonHarness.MissionRunSummarySDK, error) {
	return nil, nil
}

func (m *mockInnerHarness) GetPreviousRunFindings(ctx context.Context, filter gibsonHarness.FindingFilter) ([]gibsonAgent.Finding, error) {
	return nil, nil
}

func (m *mockInnerHarness) GetAllRunFindings(ctx context.Context, filter gibsonHarness.FindingFilter) ([]gibsonAgent.Finding, error) {
	return nil, nil
}

func (m *mockInnerHarness) Target() gibsonHarness.TargetInfo {
	return gibsonHarness.TargetInfo{
		URL:  "https://example.com",
		Type: "web",
	}
}

func (m *mockInnerHarness) Tracer() trace.Tracer {
	return noop.NewTracerProvider().Tracer("test")
}

func (m *mockInnerHarness) Logger() *slog.Logger {
	return slog.Default()
}

func (m *mockInnerHarness) Metrics() gibsonHarness.MetricsRecorder {
	return nil
}

func (m *mockInnerHarness) TokenUsage() *gibsonLLM.TokenTracker {
	return nil
}

func (m *mockInnerHarness) Checkpoint() gibsonHarness.CheckpointAccess {
	return gibsonHarness.NewHarnessCheckpointMethods(nil, "", "", 0)
}

// mockGibsonMemoryStore is a minimal implementation of gibsonMemory.MemoryStore for tests.
type mockGibsonMemoryStore struct{}

func (s *mockGibsonMemoryStore) Working() gibsonMemory.WorkingMemory {
	return gibsonMemory.NewWorkingMemory(100000)
}

func (s *mockGibsonMemoryStore) Mission() gibsonMemory.MissionMemory {
	return nil
}

func (s *mockGibsonMemoryStore) LongTerm() gibsonMemory.LongTermMemory {
	return nil
}

// TestNewGibsonHarnessAdapter verifies the adapter is created correctly.
func TestNewGibsonHarnessAdapter(t *testing.T) {
	inner := &mockInnerHarness{}
	adapter := NewGibsonHarnessAdapter(inner)

	require.NotNil(t, adapter)
	assert.Equal(t, inner, adapter.inner)
}

// TestGibsonHarnessAdapter_Complete tests LLM completion type conversion.
func TestGibsonHarnessAdapter_Complete(t *testing.T) {
	ctx := context.Background()

	t.Run("SuccessfulCompletion", func(t *testing.T) {
		inner := &mockInnerHarness{
			completeResp: &gibsonLLM.CompletionResponse{
				Message: gibsonLLM.Message{
					Role:    "assistant",
					Content: "Hello from the model",
				},
				FinishReason: "stop",
				Usage: gibsonLLM.CompletionTokenUsage{
					PromptTokens:     10,
					CompletionTokens: 5,
					TotalTokens:      15,
				},
			},
		}

		adapter := NewGibsonHarnessAdapter(inner)
		messages := []llm.Message{{Role: "user", Content: "Hello"}}

		resp, err := adapter.Complete(ctx, "primary", messages)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Equal(t, "Hello from the model", resp.Content)
		assert.Equal(t, "stop", resp.FinishReason)
		assert.Equal(t, 10, resp.Usage.InputTokens)
		assert.Equal(t, 5, resp.Usage.OutputTokens)
		assert.Equal(t, 15, resp.Usage.TotalTokens)

		// Verify slot and message were forwarded
		assert.Equal(t, "primary", inner.capturedSlot)
		require.Len(t, inner.capturedMessages, 1)
		assert.Equal(t, "Hello", inner.capturedMessages[0].Content)
	})

	t.Run("ErrorPropagation", func(t *testing.T) {
		inner := &mockInnerHarness{
			completeErr: errors.New("LLM unavailable"),
		}

		adapter := NewGibsonHarnessAdapter(inner)
		resp, err := adapter.Complete(ctx, "primary", []llm.Message{{Role: "user", Content: "Hi"}})

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "LLM unavailable")
	})

	t.Run("ToolCallConversion", func(t *testing.T) {
		inner := &mockInnerHarness{
			completeResp: &gibsonLLM.CompletionResponse{
				Message: gibsonLLM.Message{
					Role: "assistant",
					ToolCalls: []gibsonLLM.ToolCall{
						{
							ID:        "call_abc",
							Name:      "get_weather",
							Arguments: `{"location":"NYC"}`,
						},
					},
				},
				FinishReason: "tool_calls",
			},
		}

		adapter := NewGibsonHarnessAdapter(inner)
		resp, err := adapter.Complete(ctx, "primary", []llm.Message{{Role: "user", Content: "Weather?"}})

		require.NoError(t, err)
		require.Len(t, resp.ToolCalls, 1)
		assert.Equal(t, "call_abc", resp.ToolCalls[0].ID)
		assert.Equal(t, "get_weather", resp.ToolCalls[0].Name)
		assert.Equal(t, `{"location":"NYC"}`, resp.ToolCalls[0].Arguments)
		assert.Equal(t, "tool_calls", resp.FinishReason)
	})
}

// TestGibsonHarnessAdapter_CompleteWithTools tests tool-calling completion type conversion.
func TestGibsonHarnessAdapter_CompleteWithTools(t *testing.T) {
	ctx := context.Background()

	inner := &mockInnerHarness{
		completeWithToolsResp: &gibsonLLM.CompletionResponse{
			Message: gibsonLLM.Message{
				Role: "assistant",
				ToolCalls: []gibsonLLM.ToolCall{
					{ID: "call_1", Name: "nmap_scan", Arguments: `{"target":"192.168.1.1"}`},
				},
			},
			FinishReason: "tool_calls",
		},
	}

	adapter := NewGibsonHarnessAdapter(inner)

	messages := []llm.Message{{Role: "user", Content: "Scan the network"}}
	tools := []llm.ToolDef{
		{
			Name:        "nmap_scan",
			Description: "Scan network targets",
			Parameters:  map[string]any{"type": "object"},
		},
	}

	resp, err := adapter.CompleteWithTools(ctx, "primary", messages, tools)
	require.NoError(t, err)
	require.Len(t, resp.ToolCalls, 1)
	assert.Equal(t, "nmap_scan", resp.ToolCalls[0].Name)

	// Verify tools were converted and forwarded to inner harness
	require.Len(t, inner.capturedTools, 1)
	assert.Equal(t, "nmap_scan", inner.capturedTools[0].Name)
}

// TestGibsonHarnessAdapter_Stream tests streaming completion with chunk conversion.
func TestGibsonHarnessAdapter_Stream(t *testing.T) {
	ctx := context.Background()

	t.Run("SuccessfulStream", func(t *testing.T) {
		inner := &mockInnerHarness{
			streamChunks: []gibsonLLM.StreamChunk{
				{Delta: gibsonLLM.StreamDelta{Content: "Hello "}},
				{Delta: gibsonLLM.StreamDelta{Content: "world"}, FinishReason: "stop"},
			},
		}

		adapter := NewGibsonHarnessAdapter(inner)
		ch, err := adapter.Stream(ctx, "primary", []llm.Message{{Role: "user", Content: "Hi"}})
		require.NoError(t, err)

		var collected string
		for chunk := range ch {
			collected += chunk.Delta
		}
		assert.Equal(t, "Hello world", collected)
	})

	t.Run("StreamError", func(t *testing.T) {
		inner := &mockInnerHarness{
			streamErr: errors.New("stream unavailable"),
		}

		adapter := NewGibsonHarnessAdapter(inner)
		ch, err := adapter.Stream(ctx, "primary", []llm.Message{{Role: "user", Content: "Hi"}})

		assert.Error(t, err)
		assert.Nil(t, ch)
	})
}

// TestGibsonHarnessAdapter_MessageConversion tests SDK message -> Gibson message conversion.
func TestGibsonHarnessAdapter_MessageConversion(t *testing.T) {
	ctx := context.Background()

	t.Run("ToolCallsInMessages", func(t *testing.T) {
		inner := &mockInnerHarness{
			completeResp: &gibsonLLM.CompletionResponse{
				Message: gibsonLLM.Message{Role: "assistant", Content: "done"},
			},
		}

		adapter := NewGibsonHarnessAdapter(inner)
		messages := []llm.Message{
			{Role: "user", Content: "Use the tool"},
			{
				Role: "assistant",
				ToolCalls: []llm.ToolCall{
					{ID: "call_x", Name: "my_tool", Arguments: `{"k":"v"}`},
				},
			},
			{
				Role: "tool",
				ToolResults: []llm.ToolResult{
					{ToolCallID: "call_x", Content: "result_data"},
				},
			},
		}

		_, err := adapter.Complete(ctx, "primary", messages)
		require.NoError(t, err)

		// Verify tool call was forwarded in inner messages
		require.Len(t, inner.capturedMessages, 3)
		assert.Len(t, inner.capturedMessages[1].ToolCalls, 1)
		assert.Equal(t, "my_tool", inner.capturedMessages[1].ToolCalls[0].Name)
		// Tool result ToolCallID should be mapped from ToolResults[0]
		assert.Equal(t, "call_x", inner.capturedMessages[2].ToolCallID)
	})
}

// TestGibsonHarnessAdapter_ListTools tests tool descriptor conversion.
func TestGibsonHarnessAdapter_ListTools(t *testing.T) {
	ctx := context.Background()
	inner := &mockInnerHarness{}
	adapter := NewGibsonHarnessAdapter(inner)

	tools, err := adapter.ListTools(ctx)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Equal(t, "test_tool", tools[0].Name)
	assert.Equal(t, "A test tool", tools[0].Description)
	assert.Equal(t, "1.0", tools[0].Version)
}

// TestGibsonHarnessAdapter_QueryPlugin tests plugin query delegation.
func TestGibsonHarnessAdapter_QueryPlugin(t *testing.T) {
	ctx := context.Background()
	inner := &mockInnerHarness{}
	adapter := NewGibsonHarnessAdapter(inner)

	result, err := adapter.QueryPlugin(ctx, "test_plugin", "query", map[string]any{"k": "v"})
	require.NoError(t, err)
	resultMap, ok := result.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "ok", resultMap["status"])
}

// TestGibsonHarnessAdapter_ListPlugins tests plugin descriptor conversion.
func TestGibsonHarnessAdapter_ListPlugins(t *testing.T) {
	ctx := context.Background()
	inner := &mockInnerHarness{}
	adapter := NewGibsonHarnessAdapter(inner)

	plugins, err := adapter.ListPlugins(ctx)
	require.NoError(t, err)
	require.Len(t, plugins, 1)
	assert.Equal(t, "test_plugin", plugins[0].Name)
	assert.Equal(t, "1.0", plugins[0].Version)
}

// TestGibsonHarnessAdapter_ListAgents tests agent descriptor conversion.
func TestGibsonHarnessAdapter_ListAgents(t *testing.T) {
	ctx := context.Background()
	inner := &mockInnerHarness{}
	adapter := NewGibsonHarnessAdapter(inner)

	agents, err := adapter.ListAgents(ctx)
	require.NoError(t, err)
	require.Len(t, agents, 1)
	assert.Equal(t, "test_agent", agents[0].Name)
	assert.Equal(t, "1.0", agents[0].Version)
	assert.Contains(t, agents[0].Capabilities, "scan")
}

// TestGibsonHarnessAdapter_SubmitFinding tests finding submission with severity conversion.
func TestGibsonHarnessAdapter_SubmitFinding(t *testing.T) {
	ctx := context.Background()

	t.Run("HighSeverityFinding", func(t *testing.T) {
		inner := &mockInnerHarness{}
		adapter := NewGibsonHarnessAdapter(inner)

		f := &finding.Finding{
			ID:          "finding-1",
			Title:       "SQL Injection",
			Description: "Blind SQLi in login form",
			Severity:    finding.SeverityHigh,
			Confidence:  0.9,
		}

		err := adapter.SubmitFinding(ctx, f)
		assert.NoError(t, err)
	})

	t.Run("SubmitFindingError", func(t *testing.T) {
		inner := &mockInnerHarness{
			submitFindingErr: errors.New("storage failure"),
		}
		adapter := NewGibsonHarnessAdapter(inner)

		err := adapter.SubmitFinding(ctx, &finding.Finding{ID: "f1", Severity: finding.SeverityLow})
		assert.Error(t, err)
	})
}

// TestGibsonHarnessAdapter_GetFindings tests finding retrieval with filter and severity conversion.
func TestGibsonHarnessAdapter_GetFindings(t *testing.T) {
	ctx := context.Background()

	inner := &mockInnerHarness{
		getFindingsResult: []gibsonAgent.Finding{
			{
				ID:          gibsonTypes.ID("finding-1"),
				Title:       "XSS Vulnerability",
				Description: "Reflected XSS in search",
				Severity:    gibsonAgent.SeverityHigh,
				Confidence:  0.8,
				Category:    "injection",
			},
			{
				ID:          gibsonTypes.ID("finding-2"),
				Title:       "Weak Password",
				Description: "Default credentials in use",
				Severity:    gibsonAgent.SeverityMedium,
				Confidence:  0.95,
				Category:    "auth",
			},
		},
	}

	adapter := NewGibsonHarnessAdapter(inner)
	filter := finding.Filter{
		Severities: []finding.Severity{finding.SeverityHigh},
	}

	findings, err := adapter.GetFindings(ctx, filter)
	require.NoError(t, err)
	require.Len(t, findings, 2)
	assert.Equal(t, "finding-1", findings[0].ID)
	assert.Equal(t, finding.SeverityHigh, findings[0].Severity)
	assert.Equal(t, "finding-2", findings[1].ID)
	assert.Equal(t, finding.SeverityMedium, findings[1].Severity)
}

// TestGibsonHarnessAdapter_Mission tests mission context conversion.
func TestGibsonHarnessAdapter_Mission(t *testing.T) {
	inner := &mockInnerHarness{}
	adapter := NewGibsonHarnessAdapter(inner)

	missionCtx := adapter.Mission()
	assert.Equal(t, "mission-123", missionCtx.ID)
	assert.Equal(t, "Test Mission", missionCtx.Name)
	assert.Equal(t, "test-agent", missionCtx.CurrentAgent)
	assert.Equal(t, "reconnaissance", missionCtx.Phase)
}

// TestGibsonHarnessAdapter_Target tests target info conversion including URL->Connection mapping.
func TestGibsonHarnessAdapter_Target(t *testing.T) {
	inner := &mockInnerHarness{}
	adapter := NewGibsonHarnessAdapter(inner)

	target := adapter.Target()
	assert.Equal(t, "web", target.Type)
	// URL should be placed into the Connection map for schema-based target compatibility
	connectionURL, ok := target.Connection["url"]
	assert.True(t, ok, "URL should be in Connection map")
	assert.Equal(t, "https://example.com", connectionURL)
}

// TestGibsonHarnessAdapter_Observability tests tracer and logger delegation.
func TestGibsonHarnessAdapter_Observability(t *testing.T) {
	inner := &mockInnerHarness{}
	adapter := NewGibsonHarnessAdapter(inner)

	tracer := adapter.Tracer()
	assert.NotNil(t, tracer)

	logger := adapter.Logger()
	assert.NotNil(t, logger)
}

// TestGibsonHarnessAdapter_TokenUsage tests the token tracker adapter.
func TestGibsonHarnessAdapter_TokenUsage(t *testing.T) {
	inner := &mockInnerHarness{}
	adapter := NewGibsonHarnessAdapter(inner)

	tracker := adapter.TokenUsage()
	require.NotNil(t, tracker)

	// Starts at zero
	total := tracker.Total()
	assert.Equal(t, 0, total.TotalTokens)

	// Add usage across slots and verify aggregation
	tracker.Add("primary", llm.TokenUsage{InputTokens: 100, OutputTokens: 50, TotalTokens: 150})
	tracker.Add("reasoning", llm.TokenUsage{InputTokens: 200, OutputTokens: 80, TotalTokens: 280})

	total = tracker.Total()
	assert.Equal(t, 300, total.InputTokens)
	assert.Equal(t, 130, total.OutputTokens)
	assert.Equal(t, 430, total.TotalTokens)

	// Per-slot access
	primary := tracker.BySlot("primary")
	assert.Equal(t, 150, primary.TotalTokens)

	// Slots listing
	slots := tracker.Slots()
	assert.Len(t, slots, 2)

	// Reset clears all usage
	tracker.Reset()
	assert.Equal(t, 0, tracker.Total().TotalTokens)
}

// TestGibsonHarnessAdapter_GraphRAG tests that GraphRAG methods return ErrNotSupported
// when the inner harness does not implement the graphragProvider interface.
func TestGibsonHarnessAdapter_GraphRAG(t *testing.T) {
	ctx := context.Background()
	inner := &mockInnerHarness{}
	adapter := NewGibsonHarnessAdapter(inner)

	t.Run("QueryGraphRAG", func(t *testing.T) {
		_, err := adapter.QueryGraphRAG(ctx, graphrag.Query{Text: "test"})
		assert.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("FindSimilarAttacks", func(t *testing.T) {
		_, err := adapter.FindSimilarAttacks(ctx, "payload", 5)
		assert.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("FindSimilarFindings", func(t *testing.T) {
		_, err := adapter.FindSimilarFindings(ctx, "finding-1", 5)
		assert.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("StoreGraphNode", func(t *testing.T) {
		_, err := adapter.StoreGraphNode(ctx, graphrag.GraphNode{Type: "Finding"})
		assert.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("GraphRAGHealth", func(t *testing.T) {
		health := adapter.GraphRAGHealth(ctx)
		assert.Equal(t, "unavailable", health.Status)
	})
}

// TestGibsonHarnessAdapter_Memory tests the memory store adapter with working memory operations.
func TestGibsonHarnessAdapter_Memory(t *testing.T) {
	ctx := context.Background()
	inner := &mockInnerHarness{}
	adapter := NewGibsonHarnessAdapter(inner)

	mem := adapter.Memory()
	require.NotNil(t, mem)

	// Working memory should be available
	working := mem.Working()
	require.NotNil(t, working)

	// Set a value
	err := working.Set(ctx, "key1", "value1")
	require.NoError(t, err)

	// Get the value back
	val, err := working.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, "value1", val)

	// Missing key returns an error
	_, err = working.Get(ctx, "nonexistent")
	assert.Error(t, err)

	// List keys
	keys, err := working.Keys(ctx)
	require.NoError(t, err)
	assert.Contains(t, keys, "key1")

	// Delete removes the key
	err = working.Delete(ctx, "key1")
	require.NoError(t, err)
	_, err = working.Get(ctx, "key1")
	assert.Error(t, err)
}

// TestGibsonHarnessAdapter_SeverityConversion tests bidirectional severity conversion.
func TestGibsonHarnessAdapter_SeverityConversion(t *testing.T) {
	tests := []struct {
		sdkSeverity    finding.Severity
		gibsonSeverity gibsonAgent.FindingSeverity
	}{
		{finding.SeverityCritical, gibsonAgent.SeverityCritical},
		{finding.SeverityHigh, gibsonAgent.SeverityHigh},
		{finding.SeverityMedium, gibsonAgent.SeverityMedium},
		{finding.SeverityLow, gibsonAgent.SeverityLow},
		{finding.SeverityInfo, gibsonAgent.SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(string(tt.sdkSeverity), func(t *testing.T) {
			// SDK -> Gibson
			got := convertSeverityToGibson(tt.sdkSeverity)
			assert.Equal(t, tt.gibsonSeverity, got)

			// Gibson -> SDK (round-trip)
			gotBack := convertSeverityFromGibson(tt.gibsonSeverity)
			assert.Equal(t, tt.sdkSeverity, gotBack)
		})
	}
}

// TestGibsonHarnessAdapter_SDKInterfaceCompliance verifies the adapter satisfies agent.Harness
// at compile time (the var _ assertion in harness_adapter.go) and at runtime.
func TestGibsonHarnessAdapter_SDKInterfaceCompliance(t *testing.T) {
	inner := &mockInnerHarness{}
	adapter := NewGibsonHarnessAdapter(inner)

	// Runtime check: adapter must satisfy the Complete method signature
	var h interface{} = adapter
	_, ok := h.(interface {
		Complete(context.Context, string, []llm.Message, ...llm.CompletionOption) (*llm.CompletionResponse, error)
	})
	assert.True(t, ok, "adapter must satisfy agent.Harness Complete method signature")
}

// TestGibsonHarnessAdapter_MissionManagementNotSupported verifies that all mission
// management methods return ErrNotSupported in the eval adapter.
func TestGibsonHarnessAdapter_MissionManagementNotSupported(t *testing.T) {
	ctx := context.Background()
	inner := &mockInnerHarness{}
	adapter := NewGibsonHarnessAdapter(inner)

	t.Run("CreateMission", func(t *testing.T) {
		_, err := adapter.CreateMission(ctx, nil, "", nil)
		assert.ErrorIs(t, err, ErrNotSupported)
		assert.Contains(t, err.Error(), "CreateMission")
	})

	t.Run("RunMission", func(t *testing.T) {
		err := adapter.RunMission(ctx, "mission-1", nil)
		assert.ErrorIs(t, err, ErrNotSupported)
		assert.Contains(t, err.Error(), "RunMission")
	})

	t.Run("GetMissionStatus", func(t *testing.T) {
		_, err := adapter.GetMissionStatus(ctx, "mission-1")
		assert.ErrorIs(t, err, ErrNotSupported)
		assert.Contains(t, err.Error(), "GetMissionStatus")
	})

	t.Run("WaitForMission", func(t *testing.T) {
		_, err := adapter.WaitForMission(ctx, "mission-1", 0)
		assert.ErrorIs(t, err, ErrNotSupported)
		assert.Contains(t, err.Error(), "WaitForMission")
	})

	t.Run("ListMissions", func(t *testing.T) {
		_, err := adapter.ListMissions(ctx, nil)
		assert.ErrorIs(t, err, ErrNotSupported)
		assert.Contains(t, err.Error(), "ListMissions")
	})

	t.Run("CancelMission", func(t *testing.T) {
		err := adapter.CancelMission(ctx, "mission-1")
		assert.ErrorIs(t, err, ErrNotSupported)
		assert.Contains(t, err.Error(), "CancelMission")
	})

	t.Run("GetMissionResults", func(t *testing.T) {
		_, err := adapter.GetMissionResults(ctx, "mission-1")
		assert.ErrorIs(t, err, ErrNotSupported)
		assert.Contains(t, err.Error(), "GetMissionResults")
	})
}

// TestGibsonHarnessAdapter_CredentialAndProtoOpsNotSupported verifies that credential
// and proto-based GraphRAG operations return ErrNotSupported.
func TestGibsonHarnessAdapter_CredentialAndProtoOpsNotSupported(t *testing.T) {
	ctx := context.Background()
	inner := &mockInnerHarness{}
	adapter := NewGibsonHarnessAdapter(inner)

	t.Run("GetCredential", func(t *testing.T) {
		_, err := adapter.GetCredential(ctx, "cred-name")
		assert.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("QueryNodes", func(t *testing.T) {
		_, err := adapter.QueryNodes(ctx, nil)
		assert.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("StoreNode", func(t *testing.T) {
		_, err := adapter.StoreNode(ctx, nil)
		assert.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("QueueToolWork", func(t *testing.T) {
		_, err := adapter.QueueToolWork(ctx, "tool-name", nil)
		assert.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("ToolResults", func(t *testing.T) {
		ch := adapter.ToolResults(ctx, "job-id")
		require.NotNil(t, ch)
		// Channel should be closed immediately (no work enqueued)
		_, open := <-ch
		assert.False(t, open, "ToolResults channel should be closed in eval adapter")
	})
}

// TestGibsonHarnessAdapter_GraphRAGPartialMethodsNotSupported verifies that
// StoreSemantic, StoreStructured, QuerySemantic, QueryStructured return ErrNotSupported
// when the inner harness doesn't implement the graphragProvider interface.
func TestGibsonHarnessAdapter_GraphRAGPartialMethodsNotSupported(t *testing.T) {
	ctx := context.Background()
	inner := &mockInnerHarness{}
	adapter := NewGibsonHarnessAdapter(inner)

	t.Run("StoreSemantic", func(t *testing.T) {
		_, err := adapter.StoreSemantic(ctx, graphrag.GraphNode{Type: "Host"})
		assert.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("StoreStructured", func(t *testing.T) {
		_, err := adapter.StoreStructured(ctx, graphrag.GraphNode{Type: "Port"})
		assert.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("QuerySemantic", func(t *testing.T) {
		_, err := adapter.QuerySemantic(ctx, graphrag.Query{Text: "test"})
		assert.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("QueryStructured", func(t *testing.T) {
		_, err := adapter.QueryStructured(ctx, graphrag.Query{Text: "test"})
		assert.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("GetAttackChains", func(t *testing.T) {
		_, err := adapter.GetAttackChains(ctx, "T1190", 3)
		assert.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("GetRelatedFindings", func(t *testing.T) {
		_, err := adapter.GetRelatedFindings(ctx, "finding-1")
		assert.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("CreateGraphRelationship", func(t *testing.T) {
		err := adapter.CreateGraphRelationship(ctx, graphrag.Relationship{})
		assert.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("StoreGraphBatch", func(t *testing.T) {
		_, err := adapter.StoreGraphBatch(ctx, graphrag.Batch{})
		assert.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("TraverseGraph", func(t *testing.T) {
		_, err := adapter.TraverseGraph(ctx, "node-1", graphrag.TraversalOptions{})
		assert.ErrorIs(t, err, ErrNotSupported)
	})
}

// TestGibsonHarnessAdapter_DelegateToAgent verifies that DelegateToAgent
// calls the inner harness and converts task/result types correctly.
func TestGibsonHarnessAdapter_DelegateToAgent(t *testing.T) {
	ctx := context.Background()
	inner := &mockInnerHarness{}
	adapter := NewGibsonHarnessAdapter(inner)

	result, err := adapter.DelegateToAgent(ctx, "security-agent", sdkAgent.Task{
		ID:      "task-1",
		Goal:    "scan the target",
		Context: map[string]any{"target": "example.com"},
	})

	require.NoError(t, err)
	// The mock returns a new result with pending status
	assert.NotEmpty(t, string(result.Status))
}

// TestGibsonHarnessAdapter_MemoryMissionNil verifies that Mission() returns nil
// when the inner memory store has no mission memory configured.
func TestGibsonHarnessAdapter_MemoryMissionNil(t *testing.T) {
	inner := &mockInnerHarness{}
	adapter := NewGibsonHarnessAdapter(inner)

	mem := adapter.Memory()
	require.NotNil(t, mem)

	// Mock returns nil for Mission() — adapter should propagate nil
	mission := mem.Mission()
	assert.Nil(t, mission, "Mission() should be nil when inner store has no mission memory")

	// Mock returns nil for LongTerm() — adapter should propagate nil
	lt := mem.LongTerm()
	assert.Nil(t, lt, "LongTerm() should be nil when inner store has no long-term memory")
}
