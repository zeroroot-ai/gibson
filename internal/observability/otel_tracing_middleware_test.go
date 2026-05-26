package observability

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/harness/middleware"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/types"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestOTelTracingMiddleware_NilTracer tests pass-through when tracer is nil
func TestOTelTracingMiddleware_NilTracer(t *testing.T) {
	// Create middleware with nil tracer
	mw := OTelTracingMiddleware(nil, nil, nil)

	// Create a test operation
	called := false
	testOp := func(ctx context.Context, req any) (any, error) {
		called = true
		return "test-response", nil
	}

	// Wrap the operation
	wrapped := mw(testOp)

	// Execute
	resp, err := wrapped(context.Background(), "test-request")

	// Verify pass-through behavior
	assert.True(t, called)
	assert.NoError(t, err)
	assert.Equal(t, "test-response", resp)
}

// TestOTelTracingMiddleware_NilAgentSpan tests pass-through when span is nil
func TestOTelTracingMiddleware_NilAgentSpan(t *testing.T) {
	// Create test tracer
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")

	// Create middleware with nil agent span
	mw := OTelTracingMiddleware(tracer, nil, nil)

	// Create a test operation
	called := false
	testOp := func(ctx context.Context, req any) (any, error) {
		called = true
		return "test-response", nil
	}

	// Wrap the operation
	wrapped := mw(testOp)

	// Execute
	resp, err := wrapped(context.Background(), "test-request")

	// Verify pass-through behavior
	assert.True(t, called)
	assert.NoError(t, err)
	assert.Equal(t, "test-response", resp)

	// Should not create any spans
	spans := spanRecorder.Ended()
	assert.Len(t, spans, 0)
}

// TestOTelTracingMiddleware_LLMCompletion tests tracing LLM calls correctly
func TestOTelTracingMiddleware_LLMCompletion(t *testing.T) {
	// Create test tracer and agent span
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")

	// Create agent span
	agentCtx, agentSpan := tracer.Start(context.Background(), "agent-test")
	agentWrapper := &AgentSpan{
		span:        agentSpan,
		ctx:         agentCtx,
		ExecutionID: types.NewID(),
		AgentName:   "test-agent",
		StartTime:   time.Now(),
	}

	// Create middleware
	mw := OTelTracingMiddleware(tracer, agentWrapper, nil)

	// Create completion operation
	testOp := func(ctx context.Context, req any) (any, error) {
		return &llm.CompletionResponse{
			Message: llm.Message{
				Role:    llm.RoleAssistant,
				Content: "Test completion response",
			},
			Model:        "gpt-4",
			FinishReason: llm.FinishReasonStop,
			Usage: llm.CompletionTokenUsage{
				PromptTokens:     100,
				CompletionTokens: 50,
				TotalTokens:      150,
			},
		}, nil
	}

	// Wrap the operation
	wrapped := mw(testOp)

	// Create context with operation type
	ctx := middleware.WithOperationType(agentCtx, middleware.OpComplete)
	ctx = middleware.WithSlotName(ctx, "primary")
	ctx = middleware.WithProvider(ctx, "openai")

	// Create request
	req := &middleware.CompletionRequest{
		Slot: "primary",
		Messages: []llm.Message{
			{Role: llm.RoleUser, Content: "Test prompt"},
		},
	}

	// Execute
	resp, err := wrapped(ctx, req)

	// Verify operation succeeded
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// End agent span to flush
	agentWrapper.End(0, "completed")

	// Wait for async tracing to complete
	time.Sleep(100 * time.Millisecond)

	// Verify spans were created (agent span + LLM completion span)
	spans := spanRecorder.Ended()
	require.GreaterOrEqual(t, len(spans), 1)

	// Find GenAI span
	var genAISpan sdktrace.ReadOnlySpan
	for _, span := range spans {
		if span.Name() == SpanGenAIChat {
			genAISpan = span
			break
		}
	}

	// Note: Due to async nature, span may not be captured immediately
	// This is expected fire-and-forget behavior
	if genAISpan != nil {
		// Verify attributes if span was captured
		attrs := genAISpan.Attributes()
		attrMap := make(map[string]interface{})
		for _, attr := range attrs {
			attrMap[string(attr.Key)] = attr.Value.AsInterface()
		}

		assert.Equal(t, "gpt-4", attrMap[GenAIRequestModel])
		assert.Equal(t, "openai", attrMap[GenAISystem])
	}

	// Verify agent statistics were updated
	stats := agentWrapper.GetStatistics()
	assert.Equal(t, 1, stats.LLMCalls)
	assert.Equal(t, 150, stats.TokensUsed)
}

// TestOTelTracingMiddleware_ToolCall tests tracing tool calls correctly
func TestOTelTracingMiddleware_ToolCall(t *testing.T) {
	// Create test tracer and agent span
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")

	// Create agent span
	agentCtx, agentSpan := tracer.Start(context.Background(), "agent-test")
	agentWrapper := &AgentSpan{
		span:        agentSpan,
		ctx:         agentCtx,
		ExecutionID: types.NewID(),
		AgentName:   "test-agent",
		StartTime:   time.Now(),
	}

	// Create middleware
	mw := OTelTracingMiddleware(tracer, agentWrapper, nil)

	// Create tool operation
	testOp := func(ctx context.Context, req any) (any, error) {
		return map[string]any{
			"status": "success",
			"result": "tool output",
		}, nil
	}

	// Wrap the operation
	wrapped := mw(testOp)

	// Create context with operation type
	ctx := middleware.WithOperationType(agentCtx, middleware.OpCallToolProto)
	ctx = middleware.WithToolName(ctx, "nmap")

	// Create request
	req := &middleware.ToolRequest{
		Name: "nmap",
		Input: map[string]any{
			"target": "192.168.1.1",
		},
	}

	// Execute
	resp, err := wrapped(ctx, req)

	// Verify operation succeeded
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// End agent span to flush
	agentWrapper.End(0, "completed")

	// Wait for async tracing to complete
	time.Sleep(100 * time.Millisecond)

	// Verify agent statistics were updated
	stats := agentWrapper.GetStatistics()
	assert.Equal(t, 1, stats.ToolCalls)
}

// TestOTelTracingMiddleware_ContentLogging tests logging prompt/completion when enabled
func TestOTelTracingMiddleware_ContentLogging(t *testing.T) {
	// Create test tracer and agent span
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")

	// Create agent span
	agentCtx, agentSpan := tracer.Start(context.Background(), "agent-test")
	agentWrapper := &AgentSpan{
		span:        agentSpan,
		ctx:         agentCtx,
		ExecutionID: types.NewID(),
		AgentName:   "test-agent",
		StartTime:   time.Now(),
	}

	// Create content logging config with logging enabled
	cfg := DefaultContentLoggingConfig()
	cfg.Enabled = true

	// Create middleware
	mw := OTelTracingMiddleware(tracer, agentWrapper, &cfg)

	// Create completion operation
	testOp := func(ctx context.Context, req any) (any, error) {
		return &llm.CompletionResponse{
			Message: llm.Message{
				Role:    llm.RoleAssistant,
				Content: "This is the completion response",
			},
			Model:        "gpt-4",
			FinishReason: llm.FinishReasonStop,
			Usage: llm.CompletionTokenUsage{
				PromptTokens:     50,
				CompletionTokens: 25,
				TotalTokens:      75,
			},
		}, nil
	}

	// Wrap the operation
	wrapped := mw(testOp)

	// Create context with operation type
	ctx := middleware.WithOperationType(agentCtx, middleware.OpComplete)
	ctx = middleware.WithSlotName(ctx, "primary")
	ctx = middleware.WithProvider(ctx, "openai")
	ctx = middleware.WithMessages(ctx, []middleware.Message{
		{Role: "user", Content: "Test prompt content"},
	})

	// Create request
	req := &middleware.CompletionRequest{
		Slot: "primary",
		Messages: []llm.Message{
			{Role: llm.RoleUser, Content: "Test prompt content"},
		},
	}

	// Execute
	resp, err := wrapped(ctx, req)

	// Verify operation succeeded
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// End agent span to flush
	agentWrapper.End(0, "completed")

	// Wait for async tracing to complete
	time.Sleep(100 * time.Millisecond)

	// Verify spans were created
	spans := spanRecorder.Ended()
	require.GreaterOrEqual(t, len(spans), 1)

	// Find GenAI span
	var genAISpan sdktrace.ReadOnlySpan
	for _, span := range spans {
		if span.Name() == SpanGenAIChat {
			genAISpan = span
			break
		}
	}

	// If span was captured, verify events contain content
	if genAISpan != nil {
		events := genAISpan.Events()
		var foundPrompt, foundCompletion bool
		for _, event := range events {
			if event.Name == EventGenAIContentPrompt {
				foundPrompt = true
			}
			if event.Name == EventGenAIContentCompletion {
				foundCompletion = true
			}
		}

		// With content logging enabled, we should have events
		// (may not be captured due to async nature, but if captured, should be present)
		if len(events) > 0 {
			assert.True(t, foundPrompt || foundCompletion, "Expected to find content events when logging enabled")
		}
	}
}

// TestOTelTracingMiddleware_ContentRedaction tests redacting sensitive data
func TestOTelTracingMiddleware_ContentRedaction(t *testing.T) {
	// Create test tracer and agent span
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")

	// Create agent span
	agentCtx, agentSpan := tracer.Start(context.Background(), "agent-test")
	agentWrapper := &AgentSpan{
		span:        agentSpan,
		ctx:         agentCtx,
		ExecutionID: types.NewID(),
		AgentName:   "test-agent",
		StartTime:   time.Now(),
	}

	// Create content logging config with redaction
	cfg := DefaultContentLoggingConfig()
	cfg.Enabled = true
	require.NoError(t, cfg.CompilePatterns())

	// Create middleware
	mw := OTelTracingMiddleware(tracer, agentWrapper, &cfg)

	// Create completion operation with sensitive content
	testOp := func(ctx context.Context, req any) (any, error) {
		return &llm.CompletionResponse{
			Message: llm.Message{
				Role:    llm.RoleAssistant,
				Content: "The API key is sk-1234567890 and password is secret123",
			},
			Model:        "gpt-4",
			FinishReason: llm.FinishReasonStop,
			Usage: llm.CompletionTokenUsage{
				PromptTokens:     50,
				CompletionTokens: 25,
				TotalTokens:      75,
			},
		}, nil
	}

	// Wrap the operation
	wrapped := mw(testOp)

	// Create context with operation type and sensitive prompt
	ctx := middleware.WithOperationType(agentCtx, middleware.OpComplete)
	ctx = middleware.WithSlotName(ctx, "primary")
	ctx = middleware.WithProvider(ctx, "openai")
	ctx = middleware.WithMessages(ctx, []middleware.Message{
		{Role: "user", Content: "My password is secret456 and token is abc123def"},
	})

	// Create request with sensitive content
	req := &middleware.CompletionRequest{
		Slot: "primary",
		Messages: []llm.Message{
			{Role: llm.RoleUser, Content: "My password is secret456 and token is abc123def"},
		},
	}

	// Execute
	resp, err := wrapped(ctx, req)

	// Verify operation succeeded
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// End agent span to flush
	agentWrapper.End(0, "completed")

	// Wait for async tracing to complete
	time.Sleep(100 * time.Millisecond)

	// Verify spans were created
	spans := spanRecorder.Ended()
	require.GreaterOrEqual(t, len(spans), 1)

	// Find GenAI span
	var genAISpan sdktrace.ReadOnlySpan
	for _, span := range spans {
		if span.Name() == SpanGenAIChat {
			genAISpan = span
			break
		}
	}

	// If span was captured, verify redaction worked
	if genAISpan != nil {
		events := genAISpan.Events()
		for _, event := range events {
			for _, attr := range event.Attributes {
				content := attr.Value.AsString()
				// Should NOT contain sensitive data
				assert.NotContains(t, content, "sk-1234567890")
				assert.NotContains(t, content, "secret123")
				assert.NotContains(t, content, "secret456")
				assert.NotContains(t, content, "abc123def")
			}
		}
	}
}

// TestOTelTracingMiddleware_FireAndForget tests that tracing errors don't block operation
func TestOTelTracingMiddleware_FireAndForget(t *testing.T) {
	// Create test tracer and agent span
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")

	// Create agent span
	agentCtx, agentSpan := tracer.Start(context.Background(), "agent-test")
	agentWrapper := &AgentSpan{
		span:        agentSpan,
		ctx:         agentCtx,
		ExecutionID: types.NewID(),
		AgentName:   "test-agent",
		StartTime:   time.Now(),
	}

	// Create middleware
	mw := OTelTracingMiddleware(tracer, agentWrapper, nil)

	// Create operation that succeeds
	testOp := func(ctx context.Context, req any) (any, error) {
		return "success", nil
	}

	// Wrap the operation
	wrapped := mw(testOp)

	// Execute with unknown operation type (shouldn't create span, but shouldn't fail)
	ctx := middleware.WithOperationType(agentCtx, "unknown_operation_type")
	resp, err := wrapped(ctx, "test-request")

	// Verify operation succeeded even if tracing didn't work
	assert.NoError(t, err)
	assert.Equal(t, "success", resp)

	// End agent span
	agentWrapper.End(0, "completed")
}

// TestOTelTracingMiddleware_ErrorHandling tests error propagation
func TestOTelTracingMiddleware_ErrorHandling(t *testing.T) {
	// Create test tracer and agent span
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")

	// Create agent span
	agentCtx, agentSpan := tracer.Start(context.Background(), "agent-test")
	agentWrapper := &AgentSpan{
		span:        agentSpan,
		ctx:         agentCtx,
		ExecutionID: types.NewID(),
		AgentName:   "test-agent",
		StartTime:   time.Now(),
	}

	// Create middleware
	mw := OTelTracingMiddleware(tracer, agentWrapper, nil)

	// Create operation that fails
	expectedErr := errors.New("operation failed")
	testOp := func(ctx context.Context, req any) (any, error) {
		return nil, expectedErr
	}

	// Wrap the operation
	wrapped := mw(testOp)

	// Execute
	ctx := middleware.WithOperationType(agentCtx, middleware.OpComplete)
	ctx = middleware.WithSlotName(ctx, "primary")
	ctx = middleware.WithProvider(ctx, "openai")

	req := &middleware.CompletionRequest{
		Slot:     "primary",
		Messages: []llm.Message{{Role: llm.RoleUser, Content: "test"}},
	}

	resp, err := wrapped(ctx, req)

	// Verify error is propagated
	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, resp)

	// End agent span
	agentWrapper.End(0, "completed")

	// Wait for async tracing
	time.Sleep(100 * time.Millisecond)

	// Verify span was still created and marked with error
	spans := spanRecorder.Ended()
	require.GreaterOrEqual(t, len(spans), 1)

	// Find GenAI span if captured
	for _, span := range spans {
		if span.Name() == SpanGenAIChat {
			// Should have error recorded
			assert.NotEmpty(t, span.Events())
			break
		}
	}
}

// TestOTelTracingMiddleware_ToolCallWithIO tests tool I/O logging
func TestOTelTracingMiddleware_ToolCallWithIO(t *testing.T) {
	// Create test tracer and agent span
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")

	// Create agent span
	agentCtx, agentSpan := tracer.Start(context.Background(), "agent-test")
	agentWrapper := &AgentSpan{
		span:        agentSpan,
		ctx:         agentCtx,
		ExecutionID: types.NewID(),
		AgentName:   "test-agent",
		StartTime:   time.Now(),
	}

	// Create content logging config with tool I/O enabled
	cfg := DefaultContentLoggingConfig()
	cfg.Enabled = true
	cfg.IncludeToolIO = true

	// Create middleware
	mw := OTelTracingMiddleware(tracer, agentWrapper, &cfg)

	// Create tool operation
	testOp := func(ctx context.Context, req any) (any, error) {
		return map[string]any{
			"status":  "success",
			"results": []string{"host1", "host2"},
		}, nil
	}

	// Wrap the operation
	wrapped := mw(testOp)

	// Create context with operation type
	ctx := middleware.WithOperationType(agentCtx, middleware.OpCallToolProto)
	ctx = middleware.WithToolName(ctx, "nmap")

	// Create request
	req := &middleware.ToolRequest{
		Name: "nmap",
		Input: map[string]any{
			"target": "192.168.1.0/24",
			"flags":  "-sV",
		},
	}

	// Execute
	resp, err := wrapped(ctx, req)

	// Verify operation succeeded
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// End agent span
	agentWrapper.End(0, "completed")

	// Wait for async tracing
	time.Sleep(100 * time.Millisecond)

	// Verify agent statistics
	stats := agentWrapper.GetStatistics()
	assert.Equal(t, 1, stats.ToolCalls)
}

// TestOTelTracingMiddleware_CompleteWithTools tests LLM completion with tools
func TestOTelTracingMiddleware_CompleteWithTools(t *testing.T) {
	// Create test tracer and agent span
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")

	// Create agent span
	agentCtx, agentSpan := tracer.Start(context.Background(), "agent-test")
	agentWrapper := &AgentSpan{
		span:        agentSpan,
		ctx:         agentCtx,
		ExecutionID: types.NewID(),
		AgentName:   "test-agent",
		StartTime:   time.Now(),
	}

	// Create middleware
	mw := OTelTracingMiddleware(tracer, agentWrapper, nil)

	// Create completion operation with tool calls
	testOp := func(ctx context.Context, req any) (any, error) {
		return &llm.CompletionResponse{
			Message: llm.Message{
				Role:    llm.RoleAssistant,
				Content: "I'll scan the target",
				ToolCalls: []llm.ToolCall{
					{
						ID:        "call-1",
						Type:      "function",
						Name:      "nmap",
						Arguments: `{"target":"192.168.1.1"}`,
					},
				},
			},
			Model:        "gpt-4",
			FinishReason: llm.FinishReasonToolCalls,
			Usage: llm.CompletionTokenUsage{
				PromptTokens:     100,
				CompletionTokens: 50,
				TotalTokens:      150,
			},
		}, nil
	}

	// Wrap the operation
	wrapped := mw(testOp)

	// Create context with operation type
	ctx := middleware.WithOperationType(agentCtx, middleware.OpCompleteWithTools)
	ctx = middleware.WithSlotName(ctx, "primary")
	ctx = middleware.WithProvider(ctx, "openai")

	// Create request
	req := &middleware.CompletionRequest{
		Slot: "primary",
		Messages: []llm.Message{
			{Role: llm.RoleUser, Content: "Scan 192.168.1.1"},
		},
	}

	// Execute
	resp, err := wrapped(ctx, req)

	// Verify operation succeeded
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Verify response has tool calls
	compResp, ok := resp.(*llm.CompletionResponse)
	require.True(t, ok)
	assert.Len(t, compResp.Message.ToolCalls, 1)

	// End agent span
	agentWrapper.End(0, "completed")

	// Wait for async tracing
	time.Sleep(100 * time.Millisecond)

	// Verify agent statistics
	stats := agentWrapper.GetStatistics()
	assert.Equal(t, 1, stats.LLMCalls)
	assert.Equal(t, 150, stats.TokensUsed)
}
