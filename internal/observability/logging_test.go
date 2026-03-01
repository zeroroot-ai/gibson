package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/embedded"
)

// mockTraceID and mockSpanID for testing
var (
	mockTraceID = trace.TraceID{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	mockSpanID  = trace.SpanID{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
)

// mockSpan implements trace.Span for testing
type mockSpan struct {
	embedded.Span
	traceID trace.TraceID
	spanID  trace.SpanID
}

func (m *mockSpan) SpanContext() trace.SpanContext {
	return trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    m.traceID,
		SpanID:     m.spanID,
		TraceFlags: trace.FlagsSampled,
	})
}

func (m *mockSpan) IsRecording() bool {
	return true
}

func (m *mockSpan) SetStatus(code codes.Code, description string) {}

func (m *mockSpan) SetAttributes(attributes ...attribute.KeyValue) {}

func (m *mockSpan) End(options ...trace.SpanEndOption) {}

func (m *mockSpan) RecordError(err error, options ...trace.EventOption) {}

func (m *mockSpan) AddEvent(name string, options ...trace.EventOption) {}

func (m *mockSpan) SetName(name string) {}

func (m *mockSpan) TracerProvider() trace.TracerProvider {
	return nil
}

func (m *mockSpan) AddLink(link trace.Link) {}

// createMockSpanContext creates a context with a mock trace span
func createMockSpanContext() context.Context {
	span := &mockSpan{
		traceID: mockTraceID,
		spanID:  mockSpanID,
	}
	return trace.ContextWithSpan(context.Background(), span)
}

func TestNewTracedLogger(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelInfo)

	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	require.NotNil(t, logger)
	assert.Equal(t, "mission-123", logger.missionID)
	assert.Equal(t, "test-agent", logger.agentName)
	assert.True(t, logger.config.RedactSensitive)
}

func TestTracedLogger_Debug(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelDebug)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	ctx := context.Background()
	logger.Debug(ctx, "debug message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "debug message")
	assert.Contains(t, output, "mission-123")
	assert.Contains(t, output, "test-agent")
	assert.Contains(t, output, "DEBUG")
}

func TestTracedLogger_Info(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelInfo)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	ctx := context.Background()
	logger.Info(ctx, "info message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "info message")
	assert.Contains(t, output, "mission-123")
	assert.Contains(t, output, "test-agent")
	assert.Contains(t, output, "INFO")
}

func TestTracedLogger_Warn(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelWarn)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	ctx := context.Background()
	logger.Warn(ctx, "warning message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "warning message")
	assert.Contains(t, output, "mission-123")
	assert.Contains(t, output, "test-agent")
	assert.Contains(t, output, "WARN")
}

func TestTracedLogger_Error(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelError)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	ctx := context.Background()
	logger.Error(ctx, "error message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "error message")
	assert.Contains(t, output, "mission-123")
	assert.Contains(t, output, "test-agent")
	assert.Contains(t, output, "ERROR")
}

func TestTracedLogger_WithContext_TraceCorrelation(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelInfo)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	// Create context with mock trace span
	ctx := createMockSpanContext()

	logger.Info(ctx, "test message with trace")

	output := buf.String()

	// Verify trace correlation fields are present
	assert.Contains(t, output, "trace_id")
	assert.Contains(t, output, "span_id")
	assert.Contains(t, output, mockTraceID.String())
	assert.Contains(t, output, mockSpanID.String())

	// Verify mission context fields
	assert.Contains(t, output, "mission_id")
	assert.Contains(t, output, "mission-123")
	assert.Contains(t, output, "agent_name")
	assert.Contains(t, output, "test-agent")
}

func TestTracedLogger_WithContext_NoTrace(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelInfo)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	// Use background context without trace
	ctx := context.Background()

	logger.Info(ctx, "test message without trace")

	output := buf.String()

	// Verify mission context fields are present
	assert.Contains(t, output, "mission_id")
	assert.Contains(t, output, "mission-123")
	assert.Contains(t, output, "agent_name")
	assert.Contains(t, output, "test-agent")

	// Trace fields should not be present
	assert.NotContains(t, output, "trace_id")
	assert.NotContains(t, output, "span_id")
}

func TestNewJSONHandler(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelInfo)

	require.NotNil(t, handler)

	logger := slog.New(handler)
	logger.Info("test message", "key", "value")

	output := buf.String()

	// Verify JSON format
	var logEntry map[string]interface{}
	err := json.Unmarshal([]byte(output), &logEntry)
	require.NoError(t, err)

	assert.Equal(t, "INFO", logEntry["level"])
	assert.Equal(t, "test message", logEntry["msg"])
	assert.Equal(t, "value", logEntry["key"])
}

func TestNewTextHandler(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewTextHandler(buf, slog.LevelInfo)

	require.NotNil(t, handler)

	logger := slog.New(handler)
	logger.Info("test message", "key", "value")

	output := buf.String()

	// Verify text format contains expected components
	assert.Contains(t, output, "INFO")
	assert.Contains(t, output, "test message")
	assert.Contains(t, output, "key=value")
}

func TestRedactSensitiveData_Prompt(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelInfo)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	ctx := context.Background()
	logger.Info(ctx, "llm call", "prompt", "secret prompt data", "response", "public data")

	output := buf.String()

	assert.Contains(t, output, "[REDACTED]")
	assert.NotContains(t, output, "secret prompt data")
	assert.Contains(t, output, "public data")
}

func TestRedactSensitiveData_APIKey(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelInfo)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	ctx := context.Background()
	logger.Info(ctx, "api call", "api_key", "sk-1234567890", "endpoint", "/api/v1/test")

	output := buf.String()

	assert.Contains(t, output, "[REDACTED]")
	assert.NotContains(t, output, "sk-1234567890")
	assert.Contains(t, output, "/api/v1/test")
}

func TestRedactSensitiveData_Secret(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelInfo)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	ctx := context.Background()
	logger.Info(ctx, "config loaded", "secret", "my-secret-value", "name", "config")

	output := buf.String()

	assert.Contains(t, output, "[REDACTED]")
	assert.NotContains(t, output, "my-secret-value")
	assert.Contains(t, output, "config")
}

func TestRedactSensitiveData_Password(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelInfo)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	ctx := context.Background()
	logger.Info(ctx, "auth attempt", "password", "P@ssw0rd123", "username", "admin")

	output := buf.String()

	assert.Contains(t, output, "[REDACTED]")
	assert.NotContains(t, output, "P@ssw0rd123")
	assert.Contains(t, output, "admin")
}

func TestRedactSensitiveData_Token(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelInfo)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	ctx := context.Background()
	logger.Info(ctx, "token refresh", "token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "user_id", "user-123")

	output := buf.String()

	assert.Contains(t, output, "[REDACTED]")
	assert.NotContains(t, output, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
	assert.Contains(t, output, "user-123")
}

func TestRedactSensitiveData_Credential(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelInfo)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	ctx := context.Background()
	logger.Info(ctx, "creds loaded", "credential", "secret-cred", "service", "database")

	output := buf.String()

	assert.Contains(t, output, "[REDACTED]")
	assert.NotContains(t, output, "secret-cred")
	assert.Contains(t, output, "database")
}

func TestRedactSensitiveData_MultipleSensitiveFields(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelInfo)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	ctx := context.Background()
	logger.Info(ctx, "auth flow",
		"api_key", "key-123",
		"password", "pass-456",
		"token", "token-789",
		"user", "john.doe",
	)

	output := buf.String()

	// All sensitive fields should be redacted
	assert.NotContains(t, output, "key-123")
	assert.NotContains(t, output, "pass-456")
	assert.NotContains(t, output, "token-789")

	// Non-sensitive fields should remain
	assert.Contains(t, output, "john.doe")

	// Should contain redacted markers
	assert.Contains(t, output, "[REDACTED]")
}

func TestRedactSensitiveData_DebugLevel_NoRedaction(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelDebug)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	ctx := context.Background()
	logger.Debug(ctx, "debug info", "prompt", "sensitive prompt", "api_key", "sk-12345")

	output := buf.String()

	// Debug level should not redact (for debugging purposes)
	assert.Contains(t, output, "sensitive prompt")
	assert.Contains(t, output, "sk-12345")
	assert.NotContains(t, output, "[REDACTED]")
}

func TestRedactSensitiveData_CaseInsensitive(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelInfo)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	ctx := context.Background()

	// Test various case variations
	testCases := []struct {
		key   string
		value string
	}{
		{"API_KEY", "key1"},
		{"Api_Key", "key2"},
		{"api_key", "key3"},
		{"PROMPT", "prompt1"},
		{"Prompt", "prompt2"},
		{"SECRET", "secret1"},
		{"Password", "pass1"},
	}

	for _, tc := range testCases {
		buf.Reset()
		logger.Info(ctx, "test", tc.key, tc.value, "public", "data")
		output := buf.String()

		assert.Contains(t, output, "[REDACTED]", "Failed for key: %s", tc.key)
		assert.NotContains(t, output, tc.value, "Failed to redact value for key: %s", tc.key)
	}
}

func TestRedactSensitiveData_OddNumberOfArgs(t *testing.T) {
	// Test that odd number of args doesn't crash
	args := []any{"key1", "value1", "key2"}
	result := redactSensitiveData(args)

	// Should return args unchanged
	assert.Equal(t, args, result)
}

func TestRedactSensitiveData_EmptyArgs(t *testing.T) {
	args := []any{}
	result := redactSensitiveData(args)

	assert.Empty(t, result)
}

func TestRedactSensitiveData_NonStringKeys(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelInfo)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	ctx := context.Background()

	// Test with non-string key (should not panic)
	logger.Info(ctx, "test", 123, "value", "normal_key", "normal_value")

	output := buf.String()

	// Should not crash and should log normally
	assert.Contains(t, output, "normal_value")
}

func TestTracedLogger_AllLevelsWithTraceContext(t *testing.T) {
	ctx := createMockSpanContext()

	tests := []struct {
		name     string
		level    slog.Level
		logFunc  func(*TracedLogger, context.Context, string, ...any)
		levelStr string
	}{
		{
			name:  "debug",
			level: slog.LevelDebug,
			logFunc: func(l *TracedLogger, ctx context.Context, msg string, args ...any) {
				l.Debug(ctx, msg, args...)
			},
			levelStr: "DEBUG",
		},
		{
			name:  "info",
			level: slog.LevelInfo,
			logFunc: func(l *TracedLogger, ctx context.Context, msg string, args ...any) {
				l.Info(ctx, msg, args...)
			},
			levelStr: "INFO",
		},
		{
			name:  "warn",
			level: slog.LevelWarn,
			logFunc: func(l *TracedLogger, ctx context.Context, msg string, args ...any) {
				l.Warn(ctx, msg, args...)
			},
			levelStr: "WARN",
		},
		{
			name:  "error",
			level: slog.LevelError,
			logFunc: func(l *TracedLogger, ctx context.Context, msg string, args ...any) {
				l.Error(ctx, msg, args...)
			},
			levelStr: "ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			handler := NewJSONHandler(buf, tt.level)
			logger := NewTracedLogger(handler, "mission-456", "trace-agent")

			tt.logFunc(logger, ctx, "trace test", "key", "value")

			output := buf.String()

			// Verify log level
			assert.Contains(t, output, tt.levelStr)

			// Verify trace correlation
			assert.Contains(t, output, "trace_id")
			assert.Contains(t, output, "span_id")
			assert.Contains(t, output, mockTraceID.String())
			assert.Contains(t, output, mockSpanID.String())

			// Verify mission context
			assert.Contains(t, output, "mission-456")
			assert.Contains(t, output, "trace-agent")
		})
	}
}

func TestJSONHandler_OutputFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelInfo)
	logger := slog.New(handler)

	logger.Info("structured log",
		slog.String("string_field", "value"),
		slog.Int("int_field", 42),
		slog.Bool("bool_field", true),
	)

	output := buf.String()

	var logEntry map[string]interface{}
	err := json.Unmarshal([]byte(output), &logEntry)
	require.NoError(t, err, "Output should be valid JSON")

	assert.Equal(t, "INFO", logEntry["level"])
	assert.Equal(t, "structured log", logEntry["msg"])
	assert.Equal(t, "value", logEntry["string_field"])
	assert.Equal(t, float64(42), logEntry["int_field"])
	assert.Equal(t, true, logEntry["bool_field"])
	assert.NotEmpty(t, logEntry["time"])
}

func TestTextHandler_OutputFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewTextHandler(buf, slog.LevelInfo)
	logger := slog.New(handler)

	logger.Info("text log", "key1", "value1", "key2", 123)

	output := buf.String()

	// Text format should contain key=value pairs
	assert.Contains(t, output, "INFO")
	assert.Contains(t, output, "text log")
	assert.Contains(t, output, "key1=value1")
	assert.Contains(t, output, "key2=123")
}

func TestRedactSensitiveData_UnderscoreVariations(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelInfo)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	ctx := context.Background()

	testCases := []struct {
		key   string
		value string
	}{
		{"api_key", "key1"},
		{"apikey", "key2"},
		{"apiKey", "key3"},
		{"secret_key", "secret1"},
		{"secretkey", "secret2"},
		{"secretKey", "secret3"},
	}

	for _, tc := range testCases {
		buf.Reset()
		logger.Info(ctx, "test", tc.key, tc.value)
		output := buf.String()

		assert.Contains(t, output, "[REDACTED]", "Failed for key: %s", tc.key)
		assert.NotContains(t, output, tc.value, "Failed to redact value for key: %s", tc.key)
	}
}

func TestTracedLogger_PromptsFieldRedaction(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONHandler(buf, slog.LevelInfo)
	logger := NewTracedLogger(handler, "mission-123", "test-agent")

	ctx := context.Background()
	logger.Info(ctx, "multi prompt", "prompts", []string{"prompt1", "prompt2"}, "count", 2)

	output := buf.String()

	assert.Contains(t, output, "[REDACTED]")
	assert.NotContains(t, output, "prompt1")
	assert.NotContains(t, output, "prompt2")
	assert.Contains(t, output, "\"count\":2")
}
