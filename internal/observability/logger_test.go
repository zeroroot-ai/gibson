package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/trace"
)

// TestNewLogger verifies that NewLogger creates a logger with the correct configuration
func TestNewLogger(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		wantLevel slog.Level
		wantComp  string
	}{
		{
			name: "default config",
			config: Config{
				Level:     slog.LevelInfo,
				Output:    &bytes.Buffer{},
				Component: "test-component",
			},
			wantLevel: slog.LevelInfo,
			wantComp:  "test-component",
		},
		{
			name: "debug level",
			config: Config{
				Level:     slog.LevelDebug,
				Output:    &bytes.Buffer{},
				Component: "debug-test",
			},
			wantLevel: slog.LevelDebug,
			wantComp:  "debug-test",
		},
		{
			name: "error level with redaction",
			config: Config{
				Level:           slog.LevelError,
				Output:          &bytes.Buffer{},
				Component:       "secure-component",
				RedactSensitive: true,
			},
			wantLevel: slog.LevelError,
			wantComp:  "secure-component",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.config)

			require.NotNil(t, logger)
			assert.NotNil(t, logger.slog)
			assert.Equal(t, tt.config, logger.config)
			assert.Equal(t, tt.wantComp, logger.component)
		})
	}
}

// TestLoggerDebug verifies Debug method emits correct JSON with all fields
func TestLoggerDebug(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:     slog.LevelDebug,
		Output:    &buf,
		Component: "test",
	}
	logger := NewLogger(cfg)

	ctx := context.Background()
	logger.Debug(ctx, "test debug message", "key1", "value1", "key2", 42)

	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "failed to parse log JSON")

	assert.Equal(t, "DEBUG", entry["level"])
	assert.Equal(t, "test debug message", entry["msg"])
	assert.Equal(t, "test", entry["component"])
	assert.Equal(t, "value1", entry["key1"])
	assert.Equal(t, float64(42), entry["key2"]) // JSON numbers are float64
	assert.NotEmpty(t, entry["time"])
}

// TestLoggerInfo verifies Info method emits correct JSON
func TestLoggerInfo(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:     slog.LevelInfo,
		Output:    &buf,
		Component: "test",
	}
	logger := NewLogger(cfg)

	ctx := context.Background()
	logger.Info(ctx, "test info message", "status", "running")

	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "failed to parse log JSON")

	assert.Equal(t, "INFO", entry["level"])
	assert.Equal(t, "test info message", entry["msg"])
	assert.Equal(t, "test", entry["component"])
	assert.Equal(t, "running", entry["status"])
	assert.NotEmpty(t, entry["time"])
}

// TestLoggerWarn verifies Warn method emits correct JSON
func TestLoggerWarn(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:     slog.LevelWarn,
		Output:    &buf,
		Component: "test",
	}
	logger := NewLogger(cfg)

	ctx := context.Background()
	logger.Warn(ctx, "test warning", "rate", 95)

	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "failed to parse log JSON")

	assert.Equal(t, "WARN", entry["level"])
	assert.Equal(t, "test warning", entry["msg"])
	assert.Equal(t, "test", entry["component"])
	assert.Equal(t, float64(95), entry["rate"])
	assert.NotEmpty(t, entry["time"])
}

// TestLoggerError verifies Error method emits correct JSON
func TestLoggerError(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:     slog.LevelError,
		Output:    &buf,
		Component: "test",
	}
	logger := NewLogger(cfg)

	ctx := context.Background()
	logger.Error(ctx, "test error", "error", "something failed")

	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "failed to parse log JSON")

	assert.Equal(t, "ERROR", entry["level"])
	assert.Equal(t, "test error", entry["msg"])
	assert.Equal(t, "test", entry["component"])
	assert.Equal(t, "something failed", entry["error"])
	assert.NotEmpty(t, entry["time"])
}

// TestLoggerEvent verifies Event method includes event_type and event_data
func TestLoggerEvent(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:     slog.LevelInfo,
		Output:    &buf,
		Component: "test",
	}
	logger := NewLogger(cfg)

	ctx := context.Background()
	eventData := LLMResponseEventData{
		Model:            "claude-3-opus-20240229",
		PromptTokens:     1024,
		CompletionTokens: 512,
		TotalTokens:      1536,
		LatencyMs:        250,
	}

	logger.Event(ctx, string(EventTypeLLMResponse), "LLM call completed", eventData)

	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "failed to parse log JSON")

	assert.Equal(t, "INFO", entry["level"])
	assert.Equal(t, "LLM call completed", entry["msg"])
	assert.Equal(t, "test", entry["component"])
	assert.Equal(t, string(string(EventTypeLLMResponse)), entry["event_type"])

	// Verify event_data structure
	eventDataMap, ok := entry["event_data"].(map[string]any)
	require.True(t, ok, "event_data should be a map")
	assert.Equal(t, "claude-3-opus-20240229", eventDataMap["model"])
	assert.Equal(t, float64(1024), eventDataMap["prompt_tokens"])
	assert.Equal(t, float64(512), eventDataMap["completion_tokens"])
	assert.Equal(t, float64(1536), eventDataMap["total_tokens"])
	assert.Equal(t, float64(250), eventDataMap["latency_ms"])
}

// TestLoggerWithComponent verifies context enrichment adds component field
func TestLoggerWithComponent(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:     slog.LevelInfo,
		Output:    &buf,
		Component: "original",
	}
	logger := NewLogger(cfg)

	// Create new logger with different component
	componentLogger := logger.WithComponent("orchestrator")

	ctx := context.Background()
	componentLogger.Info(ctx, "test message")

	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "failed to parse log JSON")

	assert.Equal(t, "orchestrator", entry["component"])

	// Original logger should be unchanged
	assert.Equal(t, "original", logger.component)
}

// TestLoggerWithMission verifies context enrichment adds mission fields
func TestLoggerWithMission(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:     slog.LevelInfo,
		Output:    &buf,
		Component: "test",
	}
	logger := NewLogger(cfg)

	missionLogger := logger.WithMission("mission-123", "network-scan")

	ctx := context.Background()
	missionLogger.Info(ctx, "mission started")

	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "failed to parse log JSON")

	assert.Equal(t, "mission-123", entry["mission_id"])
	assert.Equal(t, "network-scan", entry["mission_name"])
}

// TestLoggerWithAgent verifies context enrichment adds agent_name field
func TestLoggerWithAgent(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:     slog.LevelInfo,
		Output:    &buf,
		Component: "test",
	}
	logger := NewLogger(cfg)

	agentLogger := logger.WithAgent("network-recon")

	ctx := context.Background()
	agentLogger.Info(ctx, "agent executing")

	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "failed to parse log JSON")

	assert.Equal(t, "network-recon", entry["agent_name"])
}

// TestLoggerWithNode verifies context enrichment adds node_id field
func TestLoggerWithNode(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:     slog.LevelInfo,
		Output:    &buf,
		Component: "test",
	}
	logger := NewLogger(cfg)

	nodeLogger := logger.WithNode("recon-1")

	ctx := context.Background()
	nodeLogger.Info(ctx, "node executing")

	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "failed to parse log JSON")

	assert.Equal(t, "recon-1", entry["node_id"])
}

// TestLoggerChainedContext verifies multiple context methods can be chained
func TestLoggerChainedContext(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:     slog.LevelInfo,
		Output:    &buf,
		Component: "test",
	}
	logger := NewLogger(cfg)

	// Chain multiple context enrichment methods
	enrichedLogger := logger.
		WithComponent("orchestrator").
		WithMission("m-123", "recon").
		WithAgent("network-recon").
		WithNode("node-1")

	ctx := context.Background()
	enrichedLogger.Info(ctx, "fully enriched log")

	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "failed to parse log JSON")

	assert.Equal(t, "orchestrator", entry["component"])
	assert.Equal(t, "m-123", entry["mission_id"])
	assert.Equal(t, "recon", entry["mission_name"])
	assert.Equal(t, "network-recon", entry["agent_name"])
	assert.Equal(t, "node-1", entry["node_id"])
}

// TestLoggerTraceCorrelation verifies trace_id and span_id extraction from OpenTelemetry context
func TestLoggerTraceCorrelation(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:     slog.LevelInfo,
		Output:    &buf,
		Component: "test",
	}
	logger := NewLogger(cfg)

	// Create a tracer provider and tracer
	tp := trace.NewTracerProvider()
	otel.SetTracerProvider(tp)
	tracer := tp.Tracer("test-tracer")

	// Start a span
	ctx, span := tracer.Start(context.Background(), "test-operation")
	defer span.End()

	logger.Info(ctx, "message with trace")

	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "failed to parse log JSON")

	// Verify trace_id and span_id are present
	assert.NotEmpty(t, entry["trace_id"], "trace_id should be present")
	assert.NotEmpty(t, entry["span_id"], "span_id should be present")

	// Verify they are valid hex strings
	traceID, ok := entry["trace_id"].(string)
	require.True(t, ok)
	assert.Len(t, traceID, 32, "trace_id should be 32 hex characters")

	spanID, ok := entry["span_id"].(string)
	require.True(t, ok)
	assert.Len(t, spanID, 16, "span_id should be 16 hex characters")
}

// TestLoggerNoTraceContext verifies logs work without OpenTelemetry context
func TestLoggerNoTraceContext(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:     slog.LevelInfo,
		Output:    &buf,
		Component: "test",
	}
	logger := NewLogger(cfg)

	// Use plain context without any span
	ctx := context.Background()
	logger.Info(ctx, "message without trace")

	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "failed to parse log JSON")

	// trace_id and span_id should not be present
	assert.Nil(t, entry["trace_id"], "trace_id should not be present without span")
	assert.Nil(t, entry["span_id"], "span_id should not be present without span")
}

// TestLoggerRedactionEnabled verifies sensitive fields are redacted when RedactSensitive=true
func TestLoggerRedactionEnabled(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:           slog.LevelInfo,
		Output:          &buf,
		Component:       "test",
		RedactSensitive: true,
	}
	logger := NewLogger(cfg)

	ctx := context.Background()
	logger.Info(ctx, "sensitive data", "username", "alice", "password", "secret123", "api_key", "sk_live_abc123")

	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "failed to parse log JSON")

	// username should not be redacted (not sensitive)
	assert.Equal(t, "alice", entry["username"])

	// password and api_key should be redacted
	assert.Equal(t, "[REDACTED]", entry["password"])
	assert.Equal(t, "[REDACTED]", entry["api_key"])
}

// TestLoggerRedactionDisabled verifies sensitive fields are NOT redacted when RedactSensitive=false
func TestLoggerRedactionDisabled(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:           slog.LevelInfo,
		Output:          &buf,
		Component:       "test",
		RedactSensitive: false,
	}
	logger := NewLogger(cfg)

	ctx := context.Background()
	logger.Info(ctx, "sensitive data", "password", "secret123", "api_key", "sk_live_abc123")

	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "failed to parse log JSON")

	// Values should NOT be redacted when redaction is disabled
	assert.Equal(t, "secret123", entry["password"])
	assert.Equal(t, "sk_live_abc123", entry["api_key"])
}

// TestLoggerDebugNoRedaction verifies Debug logs are never redacted (even with RedactSensitive=true)
func TestLoggerDebugNoRedaction(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:           slog.LevelDebug,
		Output:          &buf,
		Component:       "test",
		RedactSensitive: true,
	}
	logger := NewLogger(cfg)

	ctx := context.Background()
	logger.Debug(ctx, "debug with sensitive", "password", "secret123")

	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "failed to parse log JSON")

	// Debug logs should NOT redact (for debugging purposes)
	assert.Equal(t, "secret123", entry["password"])
}

// TestLoggerLevelFiltering verifies logs below configured level are not emitted
func TestLoggerLevelFiltering(t *testing.T) {
	tests := []struct {
		name       string
		level      slog.Level
		logFunc    func(*Logger, context.Context)
		shouldEmit bool
	}{
		{
			name:  "debug filtered at info level",
			level: slog.LevelInfo,
			logFunc: func(l *Logger, ctx context.Context) {
				l.Debug(ctx, "debug message")
			},
			shouldEmit: false,
		},
		{
			name:  "info allowed at info level",
			level: slog.LevelInfo,
			logFunc: func(l *Logger, ctx context.Context) {
				l.Info(ctx, "info message")
			},
			shouldEmit: true,
		},
		{
			name:  "warn allowed at info level",
			level: slog.LevelInfo,
			logFunc: func(l *Logger, ctx context.Context) {
				l.Warn(ctx, "warn message")
			},
			shouldEmit: true,
		},
		{
			name:  "error allowed at info level",
			level: slog.LevelInfo,
			logFunc: func(l *Logger, ctx context.Context) {
				l.Error(ctx, "error message")
			},
			shouldEmit: true,
		},
		{
			name:  "info filtered at warn level",
			level: slog.LevelWarn,
			logFunc: func(l *Logger, ctx context.Context) {
				l.Info(ctx, "info message")
			},
			shouldEmit: false,
		},
		{
			name:  "warn allowed at warn level",
			level: slog.LevelWarn,
			logFunc: func(l *Logger, ctx context.Context) {
				l.Warn(ctx, "warn message")
			},
			shouldEmit: true,
		},
		{
			name:  "debug allowed at debug level",
			level: slog.LevelDebug,
			logFunc: func(l *Logger, ctx context.Context) {
				l.Debug(ctx, "debug message")
			},
			shouldEmit: true,
		},
		{
			name:  "warn filtered at error level",
			level: slog.LevelError,
			logFunc: func(l *Logger, ctx context.Context) {
				l.Warn(ctx, "warn message")
			},
			shouldEmit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cfg := Config{
				Level:     tt.level,
				Output:    &buf,
				Component: "test",
			}
			logger := NewLogger(cfg)

			ctx := context.Background()
			tt.logFunc(logger, ctx)

			if tt.shouldEmit {
				assert.NotEmpty(t, buf.String(), "log should be emitted")
			} else {
				assert.Empty(t, buf.String(), "log should be filtered")
			}
		})
	}
}

// TestLoggerEventFiltering verifies Event method respects log level (events are Info level)
func TestLoggerEventFiltering(t *testing.T) {
	// Event should be emitted at Info level
	t.Run("event emitted at info level", func(t *testing.T) {
		var buf bytes.Buffer
		cfg := Config{
			Level:     slog.LevelInfo,
			Output:    &buf,
			Component: "test",
		}
		logger := NewLogger(cfg)

		ctx := context.Background()
		logger.Event(ctx, string(EventTypeMissionStart), "mission started", MissionEventData{
			MissionID:   "m-123",
			MissionName: "test-mission",
		})

		assert.NotEmpty(t, buf.String(), "event should be emitted at info level")
	})

	// Event should be filtered at Warn level
	t.Run("event filtered at warn level", func(t *testing.T) {
		var buf bytes.Buffer
		cfg := Config{
			Level:     slog.LevelWarn,
			Output:    &buf,
			Component: "test",
		}
		logger := NewLogger(cfg)

		ctx := context.Background()
		logger.Event(ctx, string(EventTypeMissionStart), "mission started", MissionEventData{
			MissionID:   "m-123",
			MissionName: "test-mission",
		})

		assert.Empty(t, buf.String(), "event should be filtered at warn level")
	})
}

// TestLoggerSlog verifies Slog() returns the underlying slog.Logger
func TestLoggerSlog(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:     slog.LevelInfo,
		Output:    &buf,
		Component: "test",
	}
	logger := NewLogger(cfg)

	slogger := logger.Slog()
	require.NotNil(t, slogger)

	// Verify we can use the underlying slog directly
	slogger.Info("direct slog message")

	assert.Contains(t, buf.String(), "direct slog message")
}

// TestLoggerImmutability verifies that With* methods return new instances
func TestLoggerImmutability(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:     slog.LevelInfo,
		Output:    &buf,
		Component: "original",
	}
	original := NewLogger(cfg)

	// Create modified loggers
	withComp := original.WithComponent("modified")
	withMission := original.WithMission("m-123", "test")
	withAgent := original.WithAgent("test-agent")
	withNode := original.WithNode("node-1")

	// Verify original is unchanged
	assert.Equal(t, "original", original.component)
	assert.Empty(t, original.missionID)
	assert.Empty(t, original.missionName)
	assert.Empty(t, original.agentName)
	assert.Empty(t, original.nodeID)

	// Verify new loggers have the modified values
	assert.Equal(t, "modified", withComp.component)
	assert.Equal(t, "m-123", withMission.missionID)
	assert.Equal(t, "test", withMission.missionName)
	assert.Equal(t, "test-agent", withAgent.agentName)
	assert.Equal(t, "node-1", withNode.nodeID)
}

// TestLoggerMultipleLogs verifies multiple log calls work correctly
func TestLoggerMultipleLogs(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:     slog.LevelInfo,
		Output:    &buf,
		Component: "test",
	}
	logger := NewLogger(cfg)

	ctx := context.Background()
	logger.Info(ctx, "first message")
	logger.Info(ctx, "second message")
	logger.Warn(ctx, "third message")

	// Parse each line as separate JSON
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, 3, "should have 3 log entries")

	var first, second, third map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &first))
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &second))
	require.NoError(t, json.Unmarshal([]byte(lines[2]), &third))

	assert.Equal(t, "first message", first["msg"])
	assert.Equal(t, "second message", second["msg"])
	assert.Equal(t, "third message", third["msg"])
	assert.Equal(t, "WARN", third["level"])
}

// TestLoggerEmptyContext verifies empty context fields are omitted
func TestLoggerEmptyContext(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:  slog.LevelInfo,
		Output: &buf,
		// No Component set
	}
	logger := NewLogger(cfg)

	ctx := context.Background()
	logger.Info(ctx, "minimal log")

	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "failed to parse log JSON")

	// Empty component should not be in the log
	_, hasComponent := entry["component"]
	assert.False(t, hasComponent, "empty component should not be in log")
}

// TestLoggerWithComponentEmptyString verifies empty component string is not logged
func TestLoggerWithComponentEmptyString(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:     slog.LevelInfo,
		Output:    &buf,
		Component: "test",
	}
	logger := NewLogger(cfg).WithComponent("")

	ctx := context.Background()
	logger.Info(ctx, "test message")

	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "failed to parse log JSON")

	// Empty component should not be in the log
	_, hasComponent := entry["component"]
	assert.False(t, hasComponent, "empty component should not be in log")
}

// TestLoggerJSONHandler verifies NewJSONHandler creates a valid handler
func TestLoggerJSONHandler(t *testing.T) {
	var buf bytes.Buffer
	handler := NewJSONHandler(&buf, slog.LevelInfo)
	require.NotNil(t, handler)

	// Create a logger with the handler and verify it works
	logger := slog.New(handler)
	logger.Info("test message")

	assert.Contains(t, buf.String(), "test message")
	assert.Contains(t, buf.String(), `"level":"INFO"`)
}

// TestLoggerTextHandler verifies NewTextHandler creates a valid handler
func TestLoggerTextHandler(t *testing.T) {
	var buf bytes.Buffer
	handler := NewTextHandler(&buf, slog.LevelInfo)
	require.NotNil(t, handler)

	// Create a logger with the handler and verify it works
	logger := slog.New(handler)
	logger.Info("test message")

	assert.Contains(t, buf.String(), "test message")
	assert.Contains(t, buf.String(), "level=INFO")
}
