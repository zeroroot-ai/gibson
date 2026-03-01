package observability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/graphrag/schema"
	"github.com/zero-day-ai/gibson/internal/harness/middleware"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// mockTracer implements EventSender for testing middleware.
type mockTracer struct {
	mu               sync.Mutex
	events           []map[string]any
	sendEventError   error
	sendEventCallCnt int
}

func newMockTracer() *mockTracer {
	return &mockTracer{
		events: make([]map[string]any, 0),
	}
}

// SendEvent implements EventSender interface
func (m *mockTracer) SendEvent(ctx context.Context, event map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sendEventCallCnt++
	if m.sendEventError != nil {
		return m.sendEventError
	}
	m.events = append(m.events, event)
	return nil
}

func (m *mockTracer) getEvents() []map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]map[string]any{}, m.events...)
}

func (m *mockTracer) getEventCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func (m *mockTracer) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = make([]map[string]any, 0)
	m.sendEventCallCnt = 0
	m.sendEventError = nil
}

func (m *mockTracer) setSendEventError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendEventError = err
}

func (m *mockTracer) getSendEventCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sendEventCallCnt
}

// TestLangfuseTracingMiddleware_WrapComplete_Success tests successful LLM completion tracing.
func TestLangfuseTracingMiddleware_WrapComplete_Success(t *testing.T) {
	mockTracer := newMockTracer()
	executionID := types.NewID()

	parentLog := &AgentExecutionLog{
		Execution: &schema.AgentExecution{
			ID:             executionID,
			WorkflowNodeID: "node-1",
			StartedAt:      time.Now(),
		},
		AgentName: "test-agent",
		SpanID:    fmt.Sprintf("agent-exec-%s", executionID.String()),
	}

	// Create middleware
	mw := LangfuseTracingMiddleware(mockTracer, parentLog)

	// Create test request
	messages := []llm.Message{
		{Role: llm.RoleUser, Content: "Test prompt"},
	}
	req := &middleware.CompletionRequest{
		Slot:     "default",
		Messages: messages,
	}

	// Create test response
	resp := &llm.CompletionResponse{
		ID:      "comp-123",
		Model:   "claude-3-5-sonnet-20241022",
		Message: llm.Message{Role: llm.RoleAssistant, Content: "Test response"},
		Usage: llm.CompletionTokenUsage{
			PromptTokens:     100,
			CompletionTokens: 50,
		},
		FinishReason: llm.FinishReasonStop,
	}

	// Create mock operation
	called := false
	mockOp := func(ctx context.Context, reqData any) (any, error) {
		called = true
		assert.Equal(t, req, reqData)
		return resp, nil
	}

	// Wrap operation with middleware
	wrappedOp := mw(mockOp)

	// Execute with proper context
	ctx := middleware.WithOperationType(context.Background(), middleware.OpComplete)
	result, err := wrappedOp(ctx, req)

	// Verify operation was called and returned correctly
	require.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, resp, result)

	// Wait for async trace to complete
	time.Sleep(100 * time.Millisecond)

	// Verify event was sent
	events := mockTracer.getEvents()
	require.Len(t, events, 1)

	event := events[0]
	assert.Equal(t, "generation-create", event["type"])

	body, ok := event["body"].(map[string]any)
	require.True(t, ok)

	// Verify trace hierarchy
	assert.Equal(t, fmt.Sprintf("mission-%s", executionID.String()), body["traceId"])
	assert.Equal(t, parentLog.SpanID, body["parentObservationId"])

	// Verify LLM details
	assert.Contains(t, body["name"], "llm-call-default")
	assert.Equal(t, "claude-3-5-sonnet-20241022", body["model"])
	assert.Contains(t, body["input"], "Test prompt")
	assert.Contains(t, body["output"], "Test response")
	assert.Equal(t, 100, body["promptTokens"])
	assert.Equal(t, 50, body["completionTokens"])
	assert.Equal(t, "DEFAULT", body["level"])

	// Verify metadata
	metadata, ok := body["metadata"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "default", metadata["slot"])
	assert.Equal(t, "test-agent", metadata["agent_name"])
	assert.Equal(t, "stop", metadata["finish_reason"])
}

// TestLangfuseTracingMiddleware_WrapComplete_WithError tests LLM completion tracing with error.
func TestLangfuseTracingMiddleware_WrapComplete_WithError(t *testing.T) {
	mockTracer := newMockTracer()
	executionID := types.NewID()

	parentLog := &AgentExecutionLog{
		Execution: &schema.AgentExecution{
			ID:             executionID,
			WorkflowNodeID: "node-1",
			StartedAt:      time.Now(),
		},
		AgentName: "test-agent",
		SpanID:    fmt.Sprintf("agent-exec-%s", executionID.String()),
	}

	// Create middleware
	mw := LangfuseTracingMiddleware(mockTracer, parentLog)

	// Create test request
	messages := []llm.Message{
		{Role: llm.RoleUser, Content: "Test prompt"},
	}
	req := &middleware.CompletionRequest{
		Slot:     "default",
		Messages: messages,
	}

	// Create mock operation that returns error
	expectedErr := errors.New("LLM API rate limit exceeded")
	mockOp := func(ctx context.Context, reqData any) (any, error) {
		return nil, expectedErr
	}

	// Wrap operation with middleware
	wrappedOp := mw(mockOp)

	// Execute with proper context
	ctx := middleware.WithOperationType(context.Background(), middleware.OpComplete)
	result, err := wrappedOp(ctx, req)

	// Verify error is returned
	require.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, result)

	// Wait for async trace to complete
	time.Sleep(100 * time.Millisecond)

	// Verify event was sent with error details
	events := mockTracer.getEvents()
	require.Len(t, events, 1)

	event := events[0]
	body, ok := event["body"].(map[string]any)
	require.True(t, ok)

	// Verify error handling
	assert.Equal(t, "ERROR", body["level"])
	assert.Contains(t, body["output"], "[ERROR]")
	assert.Contains(t, body["output"], expectedErr.Error())
	assert.Equal(t, expectedErr.Error(), body["statusMessage"])

	metadata, ok := body["metadata"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "error", metadata["finish_reason"])
}

// TestLangfuseTracingMiddleware_WrapComplete_WithToolCalls tests completion with tool calls.
func TestLangfuseTracingMiddleware_WrapComplete_WithToolCalls(t *testing.T) {
	mockTracer := newMockTracer()
	executionID := types.NewID()

	parentLog := &AgentExecutionLog{
		Execution: &schema.AgentExecution{
			ID:        executionID,
			StartedAt: time.Now(),
		},
		AgentName: "test-agent",
		SpanID:    fmt.Sprintf("agent-exec-%s", executionID.String()),
	}

	// Create middleware
	mw := LangfuseTracingMiddleware(mockTracer, parentLog)

	// Create request
	req := &middleware.CompletionRequest{
		Slot: "default",
		Messages: []llm.Message{
			{Role: llm.RoleUser, Content: "Scan 192.168.1.1"},
		},
	}

	// Create response with tool calls
	resp := &llm.CompletionResponse{
		ID:    "comp-123",
		Model: "claude-3-5-sonnet-20241022",
		Message: llm.Message{
			Role:    llm.RoleAssistant,
			Content: "I'll scan the target.",
			ToolCalls: []llm.ToolCall{
				{
					ID:        "call-1",
					Name:      "nmap",
					Arguments: `{"target":"192.168.1.1","ports":"1-1000"}`,
				},
			},
		},
		Usage: llm.CompletionTokenUsage{
			PromptTokens:     150,
			CompletionTokens: 75,
		},
		FinishReason: llm.FinishReasonToolCalls,
	}

	mockOp := func(ctx context.Context, reqData any) (any, error) {
		return resp, nil
	}

	wrappedOp := mw(mockOp)
	ctx := middleware.WithOperationType(context.Background(), middleware.OpCompleteWithTools)
	result, err := wrappedOp(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, resp, result)

	// Wait for async trace
	time.Sleep(100 * time.Millisecond)

	events := mockTracer.getEvents()
	require.Len(t, events, 1)

	body, ok := events[0]["body"].(map[string]any)
	require.True(t, ok)

	// Verify tool calls are included in output
	output := body["output"].(string)
	assert.Contains(t, output, "I'll scan the target")
	assert.Contains(t, output, "[Tool Calls]")
	assert.Contains(t, output, "nmap")
}

// TestLangfuseTracingMiddleware_WrapCallToolProto_Success tests successful tool execution tracing.
func TestLangfuseTracingMiddleware_WrapCallToolProto_Success(t *testing.T) {
	mockTracer := newMockTracer()
	executionID := types.NewID()

	parentLog := &AgentExecutionLog{
		Execution: &schema.AgentExecution{
			ID:        executionID,
			StartedAt: time.Now(),
		},
		AgentName: "test-agent",
		SpanID:    fmt.Sprintf("agent-exec-%s", executionID.String()),
	}

	// Create middleware
	mw := LangfuseTracingMiddleware(mockTracer, parentLog)

	// Create tool request
	req := &middleware.ToolRequest{
		Name: "nmap",
		Input: map[string]any{
			"target": "192.168.1.1",
			"ports":  "1-1000",
		},
	}

	// Create tool response
	resp := map[string]any{
		"open_ports": []int{22, 80, 443},
		"status":     "success",
	}

	mockOp := func(ctx context.Context, reqData any) (any, error) {
		assert.Equal(t, req, reqData)
		return resp, nil
	}

	wrappedOp := mw(mockOp)
	ctx := middleware.WithOperationType(context.Background(), middleware.OpCallToolProto)
	result, err := wrappedOp(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, resp, result)

	// Wait for async trace
	time.Sleep(100 * time.Millisecond)

	events := mockTracer.getEvents()
	require.Len(t, events, 1)

	event := events[0]
	assert.Equal(t, "span-create", event["type"])

	body, ok := event["body"].(map[string]any)
	require.True(t, ok)

	// Verify trace hierarchy
	assert.Equal(t, fmt.Sprintf("mission-%s", executionID.String()), body["traceId"])
	assert.Equal(t, parentLog.SpanID, body["parentObservationId"])

	// Verify tool details
	assert.Contains(t, body["name"], "tool-call-nmap")
	assert.Equal(t, "DEFAULT", body["level"])

	metadata, ok := body["metadata"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "nmap", metadata["tool_name"])
	assert.Equal(t, "test-agent", metadata["agent_name"])

	// Verify input/output
	input, ok := metadata["input"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "192.168.1.1", input["target"])

	output, ok := metadata["output"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "success", output["status"])
}

// TestLangfuseTracingMiddleware_WrapCallToolProto_WithError tests tool execution tracing with error.
func TestLangfuseTracingMiddleware_WrapCallToolProto_WithError(t *testing.T) {
	mockTracer := newMockTracer()
	executionID := types.NewID()

	parentLog := &AgentExecutionLog{
		Execution: &schema.AgentExecution{
			ID:        executionID,
			StartedAt: time.Now(),
		},
		AgentName: "test-agent",
		SpanID:    fmt.Sprintf("agent-exec-%s", executionID.String()),
	}

	// Create middleware
	mw := LangfuseTracingMiddleware(mockTracer, parentLog)

	// Create tool request
	req := &middleware.ToolRequest{
		Name: "nmap",
		Input: map[string]any{
			"target": "192.168.1.1",
		},
	}

	// Create mock operation that returns error
	expectedErr := errors.New("nmap not found in PATH")
	mockOp := func(ctx context.Context, reqData any) (any, error) {
		return nil, expectedErr
	}

	wrappedOp := mw(mockOp)
	ctx := middleware.WithOperationType(context.Background(), middleware.OpCallToolProto)
	result, err := wrappedOp(ctx, req)

	// Verify error is propagated
	require.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, result)

	// Wait for async trace
	time.Sleep(100 * time.Millisecond)

	events := mockTracer.getEvents()
	require.Len(t, events, 1)

	body, ok := events[0]["body"].(map[string]any)
	require.True(t, ok)

	// Verify error handling
	assert.Equal(t, "ERROR", body["level"])
	assert.Equal(t, expectedErr.Error(), body["statusMessage"])

	metadata, ok := body["metadata"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, expectedErr.Error(), metadata["error"])
	assert.Equal(t, "nmap", metadata["tool_name"])
}

// TestLangfuseTracingMiddleware_NilTracer_PassThrough tests that nil tracer acts as pass-through.
func TestLangfuseTracingMiddleware_NilTracer_PassThrough(t *testing.T) {
	// Create middleware with nil tracer
	mw := LangfuseTracingMiddleware(nil, &AgentExecutionLog{
		Execution: &schema.AgentExecution{ID: types.NewID()},
		SpanID:    "test-span",
	})

	// Create mock operation
	expectedResp := map[string]any{"result": "success"}
	called := false
	mockOp := func(ctx context.Context, req any) (any, error) {
		called = true
		return expectedResp, nil
	}

	wrappedOp := mw(mockOp)
	ctx := middleware.WithOperationType(context.Background(), middleware.OpComplete)
	result, err := wrappedOp(ctx, nil)

	// Verify operation was called
	require.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, expectedResp, result)

	// No events should be traced
	time.Sleep(50 * time.Millisecond)
}

// TestLangfuseTracingMiddleware_NilParentLog_PassThrough tests that nil parent log acts as pass-through.
func TestLangfuseTracingMiddleware_NilParentLog_PassThrough(t *testing.T) {
	mockTracer := newMockTracer()

	// Create middleware with nil parent log
	mw := LangfuseTracingMiddleware(mockTracer, nil)

	// Create mock operation
	expectedResp := map[string]any{"result": "success"}
	mockOp := func(ctx context.Context, req any) (any, error) {
		return expectedResp, nil
	}

	wrappedOp := mw(mockOp)
	ctx := middleware.WithOperationType(context.Background(), middleware.OpComplete)
	result, err := wrappedOp(ctx, nil)

	// Verify operation completed
	require.NoError(t, err)
	assert.Equal(t, expectedResp, result)

	// No events should be traced
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, mockTracer.getEventCount())
}

// TestLangfuseTracingMiddleware_TraceError_DoesNotFailCall tests that trace errors don't affect operation.
func TestLangfuseTracingMiddleware_TraceError_DoesNotFailCall(t *testing.T) {
	mockTracer := newMockTracer()
	executionID := types.NewID()

	// Configure tracer to return error
	mockTracer.setSendEventError(errors.New("Langfuse API unavailable"))

	parentLog := &AgentExecutionLog{
		Execution: &schema.AgentExecution{
			ID:        executionID,
			StartedAt: time.Now(),
		},
		AgentName: "test-agent",
		SpanID:    fmt.Sprintf("agent-exec-%s", executionID.String()),
	}

	// Create middleware
	mw := LangfuseTracingMiddleware(mockTracer, parentLog)

	// Create request
	req := &middleware.CompletionRequest{
		Slot: "default",
		Messages: []llm.Message{
			{Role: llm.RoleUser, Content: "Test"},
		},
	}

	resp := &llm.CompletionResponse{
		ID:      "comp-123",
		Model:   "claude-3-5-sonnet-20241022",
		Message: llm.Message{Role: llm.RoleAssistant, Content: "Response"},
		Usage: llm.CompletionTokenUsage{
			PromptTokens:     50,
			CompletionTokens: 25,
		},
		FinishReason: llm.FinishReasonStop,
	}

	mockOp := func(ctx context.Context, reqData any) (any, error) {
		return resp, nil
	}

	wrappedOp := mw(mockOp)
	ctx := middleware.WithOperationType(context.Background(), middleware.OpComplete)
	result, err := wrappedOp(ctx, req)

	// Verify operation succeeded despite trace error
	require.NoError(t, err)
	assert.Equal(t, resp, result)

	// Wait for async trace attempt
	time.Sleep(100 * time.Millisecond)

	// Verify trace was attempted but failed (doesn't affect operation)
	assert.Equal(t, 1, mockTracer.getSendEventCallCount())
}

// TestLangfuseTracingMiddleware_UnknownOperationType tests handling of unknown operation types.
func TestLangfuseTracingMiddleware_UnknownOperationType(t *testing.T) {
	mockTracer := newMockTracer()
	executionID := types.NewID()

	parentLog := &AgentExecutionLog{
		Execution: &schema.AgentExecution{
			ID:        executionID,
			StartedAt: time.Now(),
		},
		AgentName: "test-agent",
		SpanID:    fmt.Sprintf("agent-exec-%s", executionID.String()),
	}

	mw := LangfuseTracingMiddleware(mockTracer, parentLog)

	mockOp := func(ctx context.Context, req any) (any, error) {
		return "success", nil
	}

	wrappedOp := mw(mockOp)

	// Execute with operation type that middleware doesn't trace
	ctx := middleware.WithOperationType(context.Background(), middleware.OpMemoryGet)
	result, err := wrappedOp(ctx, nil)

	require.NoError(t, err)
	assert.Equal(t, "success", result)

	// No events should be traced for unsupported operation types
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, mockTracer.getEventCount())
}

// TestLangfuseTracingMiddleware_MessageExtraction_FromContext tests message extraction from context.
func TestLangfuseTracingMiddleware_MessageExtraction_FromContext(t *testing.T) {
	mockTracer := newMockTracer()
	executionID := types.NewID()

	parentLog := &AgentExecutionLog{
		Execution: &schema.AgentExecution{
			ID:        executionID,
			StartedAt: time.Now(),
		},
		AgentName: "test-agent",
		SpanID:    fmt.Sprintf("agent-exec-%s", executionID.String()),
	}

	mw := LangfuseTracingMiddleware(mockTracer, parentLog)

	// Create request without messages (will use context)
	req := &middleware.CompletionRequest{
		Slot: "default",
	}

	resp := &llm.CompletionResponse{
		ID:           "comp-123",
		Model:        "claude-3-5-sonnet-20241022",
		Message:      llm.Message{Role: llm.RoleAssistant, Content: "Response"},
		Usage:        llm.CompletionTokenUsage{PromptTokens: 50, CompletionTokens: 25},
		FinishReason: llm.FinishReasonStop,
	}

	mockOp := func(ctx context.Context, reqData any) (any, error) {
		return resp, nil
	}

	wrappedOp := mw(mockOp)

	// Set messages in context
	ctx := middleware.WithOperationType(context.Background(), middleware.OpComplete)
	ctx = middleware.WithMessages(ctx, []middleware.Message{
		{Role: "user", Content: "Context message"},
	})

	result, err := wrappedOp(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, resp, result)

	// Wait for async trace
	time.Sleep(100 * time.Millisecond)

	events := mockTracer.getEvents()
	require.Len(t, events, 1)

	body, ok := events[0]["body"].(map[string]any)
	require.True(t, ok)

	// Verify prompt includes context messages
	prompt := body["input"].(string)
	assert.Contains(t, prompt, "Context message")
}

// TestLangfuseTracingMiddleware_ConcurrentCalls tests thread safety with concurrent operations.
func TestLangfuseTracingMiddleware_ConcurrentCalls(t *testing.T) {
	mockTracer := newMockTracer()
	executionID := types.NewID()

	parentLog := &AgentExecutionLog{
		Execution: &schema.AgentExecution{
			ID:        executionID,
			StartedAt: time.Now(),
		},
		AgentName: "test-agent",
		SpanID:    fmt.Sprintf("agent-exec-%s", executionID.String()),
	}

	mw := LangfuseTracingMiddleware(mockTracer, parentLog)

	numCalls := 10
	var wg sync.WaitGroup

	for i := 0; i < numCalls; i++ {
		wg.Add(1)
		go func(iteration int) {
			defer wg.Done()

			req := &middleware.CompletionRequest{
				Slot: fmt.Sprintf("slot-%d", iteration),
				Messages: []llm.Message{
					{Role: llm.RoleUser, Content: fmt.Sprintf("Request %d", iteration)},
				},
			}

			resp := &llm.CompletionResponse{
				ID:           fmt.Sprintf("comp-%d", iteration),
				Model:        "claude-3-5-sonnet-20241022",
				Message:      llm.Message{Role: llm.RoleAssistant, Content: fmt.Sprintf("Response %d", iteration)},
				Usage:        llm.CompletionTokenUsage{PromptTokens: 50, CompletionTokens: 25},
				FinishReason: llm.FinishReasonStop,
			}

			mockOp := func(ctx context.Context, reqData any) (any, error) {
				return resp, nil
			}

			wrappedOp := mw(mockOp)
			ctx := middleware.WithOperationType(context.Background(), middleware.OpComplete)
			result, err := wrappedOp(ctx, req)

			require.NoError(t, err)
			assert.Equal(t, resp, result)
		}(i)
	}

	wg.Wait()

	// Wait for all async traces to complete
	time.Sleep(200 * time.Millisecond)

	// Verify all events were traced
	events := mockTracer.getEvents()
	assert.Equal(t, numCalls, len(events))
}

// TestLangfuseTracingMiddleware_SlotExtraction_FromContext tests slot extraction from context.
func TestLangfuseTracingMiddleware_SlotExtraction_FromContext(t *testing.T) {
	mockTracer := newMockTracer()
	executionID := types.NewID()

	parentLog := &AgentExecutionLog{
		Execution: &schema.AgentExecution{
			ID:        executionID,
			StartedAt: time.Now(),
		},
		AgentName: "test-agent",
		SpanID:    fmt.Sprintf("agent-exec-%s", executionID.String()),
	}

	mw := LangfuseTracingMiddleware(mockTracer, parentLog)

	// Request without slot (will use context)
	req := &middleware.CompletionRequest{
		Messages: []llm.Message{
			{Role: llm.RoleUser, Content: "Test"},
		},
	}

	resp := &llm.CompletionResponse{
		ID:           "comp-123",
		Model:        "claude-3-5-sonnet-20241022",
		Message:      llm.Message{Role: llm.RoleAssistant, Content: "Response"},
		Usage:        llm.CompletionTokenUsage{PromptTokens: 50, CompletionTokens: 25},
		FinishReason: llm.FinishReasonStop,
	}

	mockOp := func(ctx context.Context, reqData any) (any, error) {
		return resp, nil
	}

	wrappedOp := mw(mockOp)

	// Set slot in context
	ctx := middleware.WithOperationType(context.Background(), middleware.OpComplete)
	ctx = middleware.WithSlotName(ctx, "context-slot")

	result, err := wrappedOp(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, resp, result)

	// Wait for async trace
	time.Sleep(100 * time.Millisecond)

	events := mockTracer.getEvents()
	require.Len(t, events, 1)

	body, ok := events[0]["body"].(map[string]any)
	require.True(t, ok)

	// Verify slot from context is used
	assert.Contains(t, body["name"], "context-slot")

	metadata, ok := body["metadata"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "context-slot", metadata["slot"])
}

// TestLangfuseTracingMiddleware_ToolNameExtraction_FromContext tests tool name extraction from context.
func TestLangfuseTracingMiddleware_ToolNameExtraction_FromContext(t *testing.T) {
	mockTracer := newMockTracer()
	executionID := types.NewID()

	parentLog := &AgentExecutionLog{
		Execution: &schema.AgentExecution{
			ID:        executionID,
			StartedAt: time.Now(),
		},
		AgentName: "test-agent",
		SpanID:    fmt.Sprintf("agent-exec-%s", executionID.String()),
	}

	mw := LangfuseTracingMiddleware(mockTracer, parentLog)

	// Request without tool name (will use context)
	req := &middleware.ToolRequest{
		Input: map[string]any{"target": "192.168.1.1"},
	}

	resp := map[string]any{"status": "success"}

	mockOp := func(ctx context.Context, reqData any) (any, error) {
		return resp, nil
	}

	wrappedOp := mw(mockOp)

	// Set tool name in context
	ctx := middleware.WithOperationType(context.Background(), middleware.OpCallToolProto)
	ctx = middleware.WithToolName(ctx, "context-tool")

	result, err := wrappedOp(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, resp, result)

	// Wait for async trace
	time.Sleep(100 * time.Millisecond)

	events := mockTracer.getEvents()
	require.Len(t, events, 1)

	body, ok := events[0]["body"].(map[string]any)
	require.True(t, ok)

	// Verify tool name from context is used
	assert.Contains(t, body["name"], "context-tool")

	metadata, ok := body["metadata"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "context-tool", metadata["tool_name"])
}

// TestBuildPromptString tests prompt string building from messages.
func TestBuildPromptString(t *testing.T) {
	tests := []struct {
		name     string
		messages []llm.Message
		expected string
	}{
		{
			name:     "empty messages",
			messages: []llm.Message{},
			expected: "",
		},
		{
			name: "single message",
			messages: []llm.Message{
				{Role: llm.RoleUser, Content: "Hello"},
			},
			expected: "[USER]:\nHello",
		},
		{
			name: "multiple messages",
			messages: []llm.Message{
				{Role: llm.RoleUser, Content: "Hello"},
				{Role: llm.RoleAssistant, Content: "Hi there"},
				{Role: llm.RoleUser, Content: "How are you?"},
			},
			expected: "[USER]:\nHello\n\n---\n\n[ASSISTANT]:\nHi there\n\n---\n\n[USER]:\nHow are you?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildFullPromptString(tt.messages)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDetermineLevel tests level determination based on error presence.
func TestDetermineLevel(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "no error",
			err:      nil,
			expected: "DEFAULT",
		},
		{
			name:     "with error",
			err:      errors.New("test error"),
			expected: "ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineLevel(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestGenerateEventID_Middleware tests event ID generation in middleware context.
func TestGenerateEventID_Middleware(t *testing.T) {
	id1 := generateEventID("gen", "test-id-123")
	id2 := generateEventID("gen", "test-id-123")

	// IDs should be unique
	assert.NotEqual(t, id1, id2)

	// Should contain prefix
	assert.Contains(t, id1, "gen-")
	assert.Contains(t, id2, "gen-")
}

// TestLangfuseTracingMiddleware_RespectsContinuation tests that wrapped result is correctly passed through.
func TestLangfuseTracingMiddleware_RespectsContinuation(t *testing.T) {
	mockTracer := newMockTracer()
	executionID := types.NewID()

	parentLog := &AgentExecutionLog{
		Execution: &schema.AgentExecution{
			ID:        executionID,
			StartedAt: time.Now(),
		},
		AgentName: "test-agent",
		SpanID:    fmt.Sprintf("agent-exec-%s", executionID.String()),
	}

	mw := LangfuseTracingMiddleware(mockTracer, parentLog)

	// Test that complex response objects are preserved
	complexResp := &llm.CompletionResponse{
		ID:    "comp-123",
		Model: "claude-3-5-sonnet-20241022",
		Message: llm.Message{
			Role:    llm.RoleAssistant,
			Content: "Response with metadata",
			ToolCalls: []llm.ToolCall{
				{ID: "tc-1", Name: "tool1", Arguments: `{"key":"value"}`},
			},
		},
		Usage:        llm.CompletionTokenUsage{PromptTokens: 100, CompletionTokens: 50},
		FinishReason: llm.FinishReasonToolCalls,
	}

	mockOp := func(ctx context.Context, req any) (any, error) {
		return complexResp, nil
	}

	wrappedOp := mw(mockOp)
	ctx := middleware.WithOperationType(context.Background(), middleware.OpComplete)

	req := &middleware.CompletionRequest{
		Slot:     "default",
		Messages: []llm.Message{{Role: llm.RoleUser, Content: "Test"}},
	}

	result, err := wrappedOp(ctx, req)

	require.NoError(t, err)

	// Verify the response object is completely preserved
	resultResp, ok := result.(*llm.CompletionResponse)
	require.True(t, ok)
	assert.Equal(t, complexResp.ID, resultResp.ID)
	assert.Equal(t, complexResp.Model, resultResp.Model)
	assert.Equal(t, complexResp.Message.Content, resultResp.Message.Content)
	assert.Len(t, resultResp.Message.ToolCalls, 1)
	assert.Equal(t, "tool1", resultResp.Message.ToolCalls[0].Name)
	assert.Equal(t, llm.FinishReasonToolCalls, resultResp.FinishReason)
	assert.Equal(t, 100, resultResp.Usage.PromptTokens)
	assert.Equal(t, 50, resultResp.Usage.CompletionTokens)
}

// TestLangfuseTracingMiddleware_ToolCallOutputPreservation tests tool output preservation.
func TestLangfuseTracingMiddleware_ToolCallOutputPreservation(t *testing.T) {
	mockTracer := newMockTracer()
	executionID := types.NewID()

	parentLog := &AgentExecutionLog{
		Execution: &schema.AgentExecution{
			ID:        executionID,
			StartedAt: time.Now(),
		},
		AgentName: "test-agent",
		SpanID:    fmt.Sprintf("agent-exec-%s", executionID.String()),
	}

	mw := LangfuseTracingMiddleware(mockTracer, parentLog)

	// Complex tool output with nested structures
	complexOutput := map[string]any{
		"ports": []map[string]any{
			{"port": 22, "service": "ssh", "version": "OpenSSH 8.0"},
			{"port": 80, "service": "http", "version": "nginx 1.18.0"},
		},
		"os": map[string]any{
			"family":  "Linux",
			"version": "5.4.0",
		},
		"metadata": map[string]any{
			"scan_time": 2.5,
			"accuracy":  0.95,
		},
	}

	req := &middleware.ToolRequest{
		Name:  "nmap",
		Input: map[string]any{"target": "192.168.1.1"},
	}

	mockOp := func(ctx context.Context, reqData any) (any, error) {
		return complexOutput, nil
	}

	wrappedOp := mw(mockOp)
	ctx := middleware.WithOperationType(context.Background(), middleware.OpCallToolProto)

	result, err := wrappedOp(ctx, req)

	require.NoError(t, err)

	// Verify complex output is completely preserved
	resultOutput, ok := result.(map[string]any)
	require.True(t, ok)

	// Deep comparison
	resultJSON, _ := json.Marshal(resultOutput)
	expectedJSON, _ := json.Marshal(complexOutput)
	assert.JSONEq(t, string(expectedJSON), string(resultJSON))
}

// TestMiddleware_BuildFullPromptString tests the buildFullPromptString function with various message types.
func TestMiddleware_BuildFullPromptString(t *testing.T) {
	tests := []struct {
		name     string
		messages []llm.Message
		expected []string // Strings that should be in output
	}{
		{
			name:     "empty messages",
			messages: []llm.Message{},
			expected: []string{},
		},
		{
			name: "messages with role prefixes",
			messages: []llm.Message{
				{Role: llm.RoleSystem, Content: "You are a helpful assistant"},
				{Role: llm.RoleUser, Content: "Hello"},
				{Role: llm.RoleAssistant, Content: "Hi there"},
			},
			expected: []string{
				"[SYSTEM]:", "You are a helpful assistant",
				"[USER]:", "Hello",
				"[ASSISTANT]:", "Hi there",
				"---",
			},
		},
		{
			name: "message with tool calls",
			messages: []llm.Message{
				{
					Role:    llm.RoleAssistant,
					Content: "Let me check that",
					ToolCalls: []llm.ToolCall{
						{ID: "call-1", Name: "get_weather", Arguments: `{"city":"Boston"}`},
					},
				},
			},
			expected: []string{
				"[ASSISTANT]:", "Let me check that",
				"[Tool Calls]:",
				"get_weather",
			},
		},
		{
			name: "message with tool call ID",
			messages: []llm.Message{
				{
					Role:       llm.RoleTool,
					Content:    `{"temperature": 72}`,
					ToolCallID: "call-1",
				},
			},
			expected: []string{
				"[TOOL]:",
				"[Tool Call ID]:", "call-1",
			},
		},
		{
			name: "message with delimiter between messages",
			messages: []llm.Message{
				{Role: llm.RoleUser, Content: "First message"},
				{Role: llm.RoleAssistant, Content: "Second message"},
			},
			expected: []string{
				"[USER]:", "First message",
				"\n\n---\n\n",
				"[ASSISTANT]:", "Second message",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildFullPromptString(tt.messages)

			for _, expected := range tt.expected {
				assert.Contains(t, result, expected, "Output should contain expected string")
			}
		})
	}
}

// TestMiddleware_ExtractCompletionOptions tests the extractCompletionOptions function.
func TestMiddleware_ExtractCompletionOptions(t *testing.T) {
	tests := []struct {
		name              string
		opts              any
		expectedTemp      float64
		expectedMaxTokens int
	}{
		{
			name:              "nil options",
			opts:              nil,
			expectedTemp:      0.0,
			expectedMaxTokens: 0,
		},
		{
			name:              "empty slice",
			opts:              []any{},
			expectedTemp:      0.0,
			expectedMaxTokens: 0,
		},
		{
			name: "valid options with temperature and max_tokens",
			opts: []any{
				map[string]any{
					"temperature": 0.7,
					"max_tokens":  2000,
				},
			},
			expectedTemp:      0.7,
			expectedMaxTokens: 2000,
		},
		{
			name: "only temperature",
			opts: []any{
				map[string]any{
					"temperature": 0.5,
				},
			},
			expectedTemp:      0.5,
			expectedMaxTokens: 0,
		},
		{
			name: "only max_tokens",
			opts: []any{
				map[string]any{
					"max_tokens": 1500,
				},
			},
			expectedTemp:      0.0,
			expectedMaxTokens: 1500,
		},
		{
			name: "multiple options - last wins",
			opts: []any{
				map[string]any{"temperature": 0.3},
				map[string]any{"temperature": 0.8, "max_tokens": 3000},
			},
			expectedTemp:      0.8,
			expectedMaxTokens: 3000,
		},
		{
			name:              "wrong type - not a slice",
			opts:              "invalid",
			expectedTemp:      0.0,
			expectedMaxTokens: 0,
		},
		{
			name: "wrong value types in map",
			opts: []any{
				map[string]any{
					"temperature": "not-a-float",
					"max_tokens":  "not-an-int",
				},
			},
			expectedTemp:      0.0,
			expectedMaxTokens: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			temp, maxTokens := extractCompletionOptions(tt.opts)
			assert.Equal(t, tt.expectedTemp, temp, "Temperature should match")
			assert.Equal(t, tt.expectedMaxTokens, maxTokens, "MaxTokens should match")
		})
	}
}

// TestMiddleware_TracesFullPrompt tests end-to-end full prompt tracing in middleware.
func TestMiddleware_TracesFullPrompt(t *testing.T) {
	mockTracer := newMockTracer()
	executionID := types.NewID()

	parentLog := &AgentExecutionLog{
		Execution: &schema.AgentExecution{
			ID:        executionID,
			StartedAt: time.Now(),
		},
		AgentName: "test-agent",
		SpanID:    fmt.Sprintf("agent-exec-%s", executionID.String()),
	}

	mw := LangfuseTracingMiddleware(mockTracer, parentLog)

	messages := []llm.Message{
		{Role: llm.RoleSystem, Content: "You are a security testing assistant"},
		{Role: llm.RoleUser, Content: "Scan the target for vulnerabilities"},
	}

	mockOp := func(ctx context.Context, req any) (any, error) {
		return &llm.CompletionResponse{
			ID:    "test-completion",
			Model: "gpt-4",
			Message: llm.Message{
				Role:    llm.RoleAssistant,
				Content: "Starting vulnerability scan",
			},
			Usage: llm.CompletionTokenUsage{
				PromptTokens:     150,
				CompletionTokens: 75,
				TotalTokens:      225,
			},
			FinishReason: llm.FinishReasonStop,
		}, nil
	}

	wrappedOp := mw(mockOp)
	ctx := middleware.WithOperationType(context.Background(), middleware.OpComplete)

	req := &middleware.CompletionRequest{
		Slot:     "primary",
		Messages: messages,
	}

	result, err := wrappedOp(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Wait for async trace
	time.Sleep(100 * time.Millisecond)

	events := mockTracer.getEvents()
	require.Len(t, events, 1, "Should have one trace event")

	event := events[0]
	assert.Equal(t, "generation-create", event["type"])

	body, ok := event["body"].(map[string]any)
	require.True(t, ok, "Event body should be a map")

	// Verify full prompt is in input field
	input, ok := body["input"].(string)
	require.True(t, ok, "Input should be a string")
	assert.Contains(t, input, "[SYSTEM]:", "Input should contain system role prefix")
	assert.Contains(t, input, "You are a security testing assistant", "Input should contain system prompt")
	assert.Contains(t, input, "[USER]:", "Input should contain user role prefix")
	assert.Contains(t, input, "Scan the target for vulnerabilities", "Input should contain user prompt")
	assert.Contains(t, input, "---", "Input should contain message delimiter")

	// Verify metadata contains request config
	metadata, ok := body["metadata"].(map[string]any)
	require.True(t, ok, "Metadata should be a map")

	// Check that message_count is present
	messageCount, ok := metadata["message_count"].(int)
	require.True(t, ok, "message_count should be an int")
	assert.Equal(t, 2, messageCount, "Should have 2 messages")

	// Verify slot is captured
	assert.Equal(t, "primary", metadata["slot"])

	// Verify model and tokens are captured
	assert.Equal(t, "gpt-4", body["model"])
	assert.Equal(t, 150, body["promptTokens"])
	assert.Equal(t, 75, body["completionTokens"])
}
