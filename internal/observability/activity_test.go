package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

func TestActivityLevel_String(t *testing.T) {
	tests := []struct {
		level    ActivityLevel
		expected string
	}{
		{ActivityLevelQuiet, "quiet"},
		{ActivityLevelNormal, "normal"},
		{ActivityLevelVerbose, "verbose"},
		{ActivityLevelDebug, "debug"},
		{ActivityLevel(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.level.String())
		})
	}
}

func TestParseActivityLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected ActivityLevel
	}{
		{"quiet", ActivityLevelQuiet},
		{"normal", ActivityLevelNormal},
		{"verbose", ActivityLevelVerbose},
		{"debug", ActivityLevelDebug},
		{"invalid", ActivityLevelNormal}, // defaults to normal
		{"", ActivityLevelNormal},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseActivityLevel(tt.input))
		})
	}
}

func TestNewActivityLogger(t *testing.T) {
	var buf bytes.Buffer
	cfg := ActivityLoggerConfig{
		Level:            ActivityLevelVerbose,
		MaxContentLength: 100,
		Output:           &buf,
		BufferSize:       1000,
		MissionID:        "test-mission",
		AgentName:        "test-agent",
	}

	logger, err := NewActivityLogger(cfg)
	require.NoError(t, err)
	require.NotNil(t, logger)

	assert.Equal(t, ActivityLevelVerbose, logger.Level())
	assert.Equal(t, "test-mission", logger.missionID)
	assert.Equal(t, "test-agent", logger.agentName)

	// Clean up
	err = logger.Close()
	assert.NoError(t, err)
}

func TestActivityLogger_LevelFiltering(t *testing.T) {
	tests := []struct {
		name       string
		level      ActivityLevel
		eventType  ActivityEventType
		shouldLog  bool
	}{
		// Quiet level - only errors and findings
		{"quiet/error", ActivityLevelQuiet, EventError, true},
		{"quiet/finding", ActivityLevelQuiet, EventFinding, true},
		{"quiet/agent_start", ActivityLevelQuiet, EventAgentStart, false},
		{"quiet/llm_prompt", ActivityLevelQuiet, EventLLMPrompt, false},
		{"quiet/decision", ActivityLevelQuiet, EventDecision, false},

		// Normal level - agent lifecycle, findings, errors, decisions
		{"normal/agent_start", ActivityLevelNormal, EventAgentStart, true},
		{"normal/agent_end", ActivityLevelNormal, EventAgentEnd, true},
		{"normal/finding", ActivityLevelNormal, EventFinding, true},
		{"normal/error", ActivityLevelNormal, EventError, true},
		{"normal/decision", ActivityLevelNormal, EventDecision, true},
		{"normal/llm_prompt", ActivityLevelNormal, EventLLMPrompt, false},
		{"normal/tool_call", ActivityLevelNormal, EventToolCall, false},

		// Verbose level - all events
		{"verbose/llm_prompt", ActivityLevelVerbose, EventLLMPrompt, true},
		{"verbose/tool_call", ActivityLevelVerbose, EventToolCall, true},
		{"verbose/memory_store", ActivityLevelVerbose, EventMemoryStore, true},

		// Debug level - all events
		{"debug/all", ActivityLevelDebug, EventGraphRAGStore, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cfg := ActivityLoggerConfig{
				Level:      tt.level,
				Output:     &buf,
				BufferSize: 10,
			}

			logger, err := NewActivityLogger(cfg)
			require.NoError(t, err)
			defer logger.Close()

			// Emit event
			event := ActivityEvent{
				EventType: tt.eventType,
				Payload:   map[string]interface{}{"test": "data"},
			}

			logger.Emit(context.Background(), event)

			// Give async writer time to process
			time.Sleep(50 * time.Millisecond)

			if tt.shouldLog {
				assert.Greater(t, buf.Len(), 0, "expected event to be logged")
			} else {
				assert.Equal(t, 0, buf.Len(), "expected event to be filtered")
			}
		})
	}
}

func TestActivityLogger_ContentTruncation(t *testing.T) {
	longContent := strings.Repeat("a", 1000)

	tests := []struct {
		name       string
		level      ActivityLevel
		maxLen     int
		expectTrunc bool
	}{
		{"verbose/truncate", ActivityLevelVerbose, 100, true},
		{"debug/no_truncate", ActivityLevelDebug, 100, false},
		{"short/no_truncate", ActivityLevelVerbose, 2000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cfg := ActivityLoggerConfig{
				Level:            tt.level,
				MaxContentLength: tt.maxLen,
				Output:           &buf,
			}

			logger, err := NewActivityLogger(cfg)
			require.NoError(t, err)
			defer logger.Close()

			// Emit LLM prompt with long content
			messages := []llm.Message{
				{Role: llm.RoleUser, Content: longContent},
			}

			logger.EmitLLMPrompt(context.Background(), "default", messages)

			// Give async writer time to process
			time.Sleep(50 * time.Millisecond)

			// Parse output
			var event ActivityEvent
			err = json.NewDecoder(&buf).Decode(&event)
			require.NoError(t, err)

			content, ok := event.Payload["content"].(string)
			require.True(t, ok)

			truncated, ok := event.Payload["content_truncated"].(bool)
			require.True(t, ok)

			if tt.expectTrunc {
				assert.True(t, truncated, "expected content to be truncated")
				assert.Less(t, len(content), len(longContent), "truncated content should be shorter")
			} else {
				assert.False(t, truncated, "expected content not to be truncated")
				assert.Equal(t, longContent, content, "content should be unchanged")
			}
		})
	}
}

func TestActivityLogger_EventEnrichment(t *testing.T) {
	var buf bytes.Buffer
	cfg := ActivityLoggerConfig{
		Level:           ActivityLevelVerbose,
		Output:          &buf,
		MissionID:       "mission-123",
		AgentName:       "test-agent",
		LangfuseTraceID: "langfuse-456",
	}

	logger, err := NewActivityLogger(cfg)
	require.NoError(t, err)
	defer logger.Close()

	// Emit event with basic context (no trace)
	event := ActivityEvent{
		EventType: EventToolCall,
		Payload:   map[string]interface{}{"tool": "test"},
	}

	logger.Emit(context.Background(), event)

	// Give async writer time to process
	time.Sleep(50 * time.Millisecond)

	// Parse output
	var logged ActivityEvent
	err = json.NewDecoder(&buf).Decode(&logged)
	require.NoError(t, err)

	// Check enrichment from logger config
	assert.Equal(t, "mission-123", logged.MissionID)
	assert.Equal(t, "test-agent", logged.AgentName)
	assert.Equal(t, "langfuse-456", logged.LangfuseTraceID)
	assert.NotZero(t, logged.Timestamp)

	// TraceID and SpanID may be empty without a real tracer
	// In production, OpenTelemetry will be configured and will populate these
}

func TestActivityLogger_BufferOverflow(t *testing.T) {
	var buf bytes.Buffer
	cfg := ActivityLoggerConfig{
		Level:      ActivityLevelVerbose,
		Output:     &buf,
		BufferSize: 5, // Small buffer to trigger overflow
	}

	logger, err := NewActivityLogger(cfg)
	require.NoError(t, err)

	// Fill buffer beyond capacity
	for i := 0; i < 20; i++ {
		event := ActivityEvent{
			EventType: EventToolCall,
			Payload:   map[string]interface{}{"index": i},
		}
		logger.Emit(context.Background(), event)
	}

	// Check that some events were dropped
	dropped := logger.eventsDropped.Load()
	assert.Greater(t, dropped, int64(0), "expected some events to be dropped")

	// Clean up
	logger.Close()
}

func TestActivityLogger_JSONSerialization(t *testing.T) {
	tests := []struct {
		name      string
		eventType ActivityEventType
		emitFunc  func(logger ActivityLogger, ctx context.Context)
	}{
		{
			name:      "agent_start",
			eventType: EventAgentStart,
			emitFunc: func(logger ActivityLogger, ctx context.Context) {
				logger.EmitAgentStart(ctx, "test-agent", "test task")
			},
		},
		{
			name:      "agent_end",
			eventType: EventAgentEnd,
			emitFunc: func(logger ActivityLogger, ctx context.Context) {
				logger.EmitAgentEnd(ctx, "test-agent", "completed", 1000)
			},
		},
		{
			name:      "llm_prompt",
			eventType: EventLLMPrompt,
			emitFunc: func(logger ActivityLogger, ctx context.Context) {
				messages := []llm.Message{
					{Role: llm.RoleUser, Content: "test prompt"},
				}
				logger.EmitLLMPrompt(ctx, "default", messages)
			},
		},
		{
			name:      "llm_response",
			eventType: EventLLMResponse,
			emitFunc: func(logger ActivityLogger, ctx context.Context) {
				resp := &llm.CompletionResponse{
					Model:        "claude-3",
					Message:      llm.Message{Role: llm.RoleAssistant, Content: "test response"},
					FinishReason: llm.FinishReasonStop,
					Usage: llm.CompletionTokenUsage{
						PromptTokens:     10,
						CompletionTokens: 20,
						TotalTokens:      30,
					},
				}
				logger.EmitLLMResponse(ctx, "default", resp)
			},
		},
		{
			name:      "tool_call",
			eventType: EventToolCall,
			emitFunc: func(logger ActivityLogger, ctx context.Context) {
				logger.EmitToolCall(ctx, "nmap", map[string]string{"target": "example.com"})
			},
		},
		{
			name:      "tool_result",
			eventType: EventToolResult,
			emitFunc: func(logger ActivityLogger, ctx context.Context) {
				logger.EmitToolResult(ctx, "nmap", map[string]string{"result": "success"}, 500, nil)
			},
		},
		{
			name:      "finding",
			eventType: EventFinding,
			emitFunc: func(logger ActivityLogger, ctx context.Context) {
				finding := &agent.Finding{
					ID:          types.NewID(),
					Title:       "Test Finding",
					Severity:    agent.SeverityHigh,
					Confidence:  0.9,
					Category:    "test",
					CWE:         []string{"CWE-79"},
				}
				logger.EmitFinding(ctx, finding)
			},
		},
		{
			name:      "decision",
			eventType: EventDecision,
			emitFunc: func(logger ActivityLogger, ctx context.Context) {
				logger.EmitDecision(ctx, "execute_agent", "node-1", "ready to execute", 0.95)
			},
		},
		{
			name:      "error",
			eventType: EventError,
			emitFunc: func(logger ActivityLogger, ctx context.Context) {
				logger.EmitError(ctx, "test_operation", errors.New("test error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cfg := ActivityLoggerConfig{
				Level:  ActivityLevelVerbose,
				Output: &buf,
			}

			logger, err := NewActivityLogger(cfg)
			require.NoError(t, err)
			defer logger.Close()

			// Emit event
			ctx := context.Background()
			tt.emitFunc(logger, ctx)

			// Give async writer time to process
			time.Sleep(50 * time.Millisecond)

			// Parse output - should be valid JSON
			var event ActivityEvent
			err = json.NewDecoder(&buf).Decode(&event)
			require.NoError(t, err, "event should be valid JSON")

			// Verify event type
			assert.Equal(t, tt.eventType, event.EventType)
			assert.NotNil(t, event.Payload)
		})
	}
}

func TestActivityLogger_GracefulShutdown(t *testing.T) {
	var buf bytes.Buffer
	cfg := ActivityLoggerConfig{
		Level:      ActivityLevelVerbose,
		Output:     &buf,
		BufferSize: 100,
	}

	logger, err := NewActivityLogger(cfg)
	require.NoError(t, err)

	// Emit multiple events
	for i := 0; i < 10; i++ {
		event := ActivityEvent{
			EventType: EventToolCall,
			Payload:   map[string]interface{}{"index": i},
		}
		logger.Emit(context.Background(), event)
	}

	// Close should flush remaining events
	err = logger.Close()
	assert.NoError(t, err)

	// Count events in output
	lines := bytes.Count(buf.Bytes(), []byte("\n"))
	assert.Equal(t, 10, lines, "all events should be flushed on close")

	// Second close should be idempotent
	err = logger.Close()
	assert.NoError(t, err)
}

func TestActivityLogger_SetLevel(t *testing.T) {
	var buf bytes.Buffer
	cfg := ActivityLoggerConfig{
		Level:  ActivityLevelQuiet,
		Output: &buf,
	}

	logger, err := NewActivityLogger(cfg)
	require.NoError(t, err)
	defer logger.Close()

	// Initially quiet - tool calls should not log
	logger.EmitToolCall(context.Background(), "test", nil)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, buf.Len(), "quiet level should not log tool calls")

	// Change to verbose
	logger.SetLevel(ActivityLevelVerbose)
	assert.Equal(t, ActivityLevelVerbose, logger.Level())

	// Now tool calls should log
	logger.EmitToolCall(context.Background(), "test", nil)
	time.Sleep(50 * time.Millisecond)
	assert.Greater(t, buf.Len(), 0, "verbose level should log tool calls")
}

func TestNoopActivityLogger(t *testing.T) {
	logger := NewNoopActivityLogger()
	require.NotNil(t, logger)

	ctx := context.Background()

	// All methods should be safe to call
	logger.Emit(ctx, ActivityEvent{})
	logger.EmitAgentStart(ctx, "test", "test")
	logger.EmitAgentEnd(ctx, "test", "completed", 100)
	logger.EmitLLMPrompt(ctx, "default", nil)
	logger.EmitLLMResponse(ctx, "default", nil)
	logger.EmitToolCall(ctx, "test", nil)
	logger.EmitToolResult(ctx, "test", nil, 100, nil)
	logger.EmitFinding(ctx, nil)
	logger.EmitDecision(ctx, "test", "target", "reason", 0.9)
	logger.EmitError(ctx, "test", errors.New("test"))

	// Level operations
	assert.Equal(t, ActivityLevelQuiet, logger.Level())
	logger.SetLevel(ActivityLevelVerbose)

	// Cleanup operations
	err := logger.Flush()
	assert.NoError(t, err)
	err = logger.Close()
	assert.NoError(t, err)
}

func TestActivityLogger_LLMPromptMultipleMessages(t *testing.T) {
	var buf bytes.Buffer
	cfg := ActivityLoggerConfig{
		Level:  ActivityLevelVerbose,
		Output: &buf,
	}

	logger, err := NewActivityLogger(cfg)
	require.NoError(t, err)
	defer logger.Close()

	// Emit multiple messages
	messages := []llm.Message{
		{Role: llm.RoleSystem, Content: "system prompt"},
		{Role: llm.RoleUser, Content: "user message 1"},
		{Role: llm.RoleAssistant, Content: "assistant response"},
		{Role: llm.RoleUser, Content: "user message 2"},
	}

	logger.EmitLLMPrompt(context.Background(), "default", messages)

	// Give async writer time to process
	time.Sleep(100 * time.Millisecond)

	// Should have emitted 4 events (one per message)
	lines := bytes.Split(buf.Bytes(), []byte("\n"))
	validEvents := 0
	for _, line := range lines {
		if len(line) > 0 {
			var event ActivityEvent
			if err := json.Unmarshal(line, &event); err == nil {
				validEvents++
				// Check message index and count
				assert.Equal(t, EventLLMPrompt, event.EventType)
				messageCount, ok := event.Payload["message_count"].(float64)
				assert.True(t, ok)
				assert.Equal(t, float64(4), messageCount)
			}
		}
	}

	assert.Equal(t, 4, validEvents, "should emit one event per message")
}

func TestActivityLogger_ToolResultWithError(t *testing.T) {
	var buf bytes.Buffer
	cfg := ActivityLoggerConfig{
		Level:  ActivityLevelVerbose,
		Output: &buf,
	}

	logger, err := NewActivityLogger(cfg)
	require.NoError(t, err)
	defer logger.Close()

	// Emit tool result with error
	testErr := errors.New("connection timeout")
	logger.EmitToolResult(context.Background(), "nmap", nil, 1000, testErr)

	// Give async writer time to process
	time.Sleep(50 * time.Millisecond)

	// Parse output
	var event ActivityEvent
	err = json.NewDecoder(&buf).Decode(&event)
	require.NoError(t, err)

	// Check payload
	success, ok := event.Payload["success"].(bool)
	require.True(t, ok)
	assert.False(t, success)

	errorMsg, ok := event.Payload["error"].(string)
	require.True(t, ok)
	assert.Equal(t, "connection timeout", errorMsg)

	latency, ok := event.Payload["latency_ms"].(float64)
	require.True(t, ok)
	assert.Equal(t, float64(1000), latency)
}
