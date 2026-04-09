package observability

import (
	"context"
	"io"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

// Logger is the single unified logging interface for all Gibson components.
// All logging in Gibson MUST go through this type.
//
// Logger provides structured logging with automatic trace correlation, context enrichment,
// and sensitive data redaction. It wraps slog.Logger and adds Gibson-specific context
// like mission IDs, agent names, and node IDs.
//
// Example usage:
//
//	logger := NewLogger(DefaultConfig())
//	logger = logger.WithMission("mission-123", "network-scan")
//	logger = logger.WithAgent("network-recon")
//	logger.Info(ctx, "scanning network", "target", "10.0.0.0/24")
//
// All log methods accept context for OpenTelemetry trace correlation. The logger
// automatically extracts trace_id and span_id from the context and includes them
// in every log entry.
type Logger struct {
	slog        *slog.Logger
	config      Config
	component   string
	missionID   string
	missionName string
	agentName   string
	nodeID      string
}

// NewLogger creates a new Logger with the given configuration.
// The logger is configured with a JSON handler writing to config.Output
// at the specified log level.
//
// Parameters:
//   - config: Configuration for the logger (level, output, redaction, etc.)
//
// Returns:
//   - *Logger: A configured logger ready for use
//
// Example:
//
//	cfg := DefaultConfig()
//	cfg.Level = slog.LevelDebug
//	logger := NewLogger(cfg)
func NewLogger(config Config) *Logger {
	// Create slog.Logger with JSON handler
	handler := slog.NewJSONHandler(config.Output, &slog.HandlerOptions{
		Level: config.Level,
	})

	return &Logger{
		slog:      slog.New(handler),
		config:    config,
		component: config.Component,
	}
}

// Debug logs a debug-level message with automatic trace correlation.
// Debug logs include all fields without redaction.
//
// Parameters:
//   - ctx: Context containing OpenTelemetry span for trace correlation
//   - msg: The log message
//   - args: Optional key-value pairs for structured logging (must be even number)
//
// Example:
//
//	logger.Debug(ctx, "processing workflow node", "node_id", "recon-1", "status", "running")
func (l *Logger) Debug(ctx context.Context, msg string, args ...any) {
	// Add context fields and log at debug level
	logger := l.withContextFields(ctx)
	logger.Debug(msg, args...)
}

// Info logs an info-level message with automatic trace correlation.
// Sensitive data in args is redacted if config.RedactSensitive is enabled.
//
// Parameters:
//   - ctx: Context containing OpenTelemetry span for trace correlation
//   - msg: The log message
//   - args: Optional key-value pairs for structured logging (must be even number)
//
// Example:
//
//	logger.Info(ctx, "mission started", "target", "example.com")
func (l *Logger) Info(ctx context.Context, msg string, args ...any) {
	// Redact sensitive fields if configured
	if l.config.RedactSensitive {
		args = Redact(args)
	}

	// Add context fields and log at info level
	logger := l.withContextFields(ctx)
	logger.Info(msg, args...)
}

// Warn logs a warning-level message with automatic trace correlation.
// Sensitive data in args is redacted if config.RedactSensitive is enabled.
//
// Parameters:
//   - ctx: Context containing OpenTelemetry span for trace correlation
//   - msg: The log message
//   - args: Optional key-value pairs for structured logging (must be even number)
//
// Example:
//
//	logger.Warn(ctx, "rate limit approaching", "current", 90, "limit", 100)
func (l *Logger) Warn(ctx context.Context, msg string, args ...any) {
	// Redact sensitive fields if configured
	if l.config.RedactSensitive {
		args = Redact(args)
	}

	// Add context fields and log at warn level
	logger := l.withContextFields(ctx)
	logger.Warn(msg, args...)
}

// Error logs an error-level message with automatic trace correlation.
// Sensitive data in args is redacted if config.RedactSensitive is enabled.
//
// Parameters:
//   - ctx: Context containing OpenTelemetry span for trace correlation
//   - msg: The log message
//   - args: Optional key-value pairs for structured logging (must be even number)
//
// Example:
//
//	logger.Error(ctx, "tool execution failed", "tool", "nmap", "error", err.Error())
func (l *Logger) Error(ctx context.Context, msg string, args ...any) {
	// Redact sensitive fields if configured
	if l.config.RedactSensitive {
		args = Redact(args)
	}

	// Add context fields and log at error level
	logger := l.withContextFields(ctx)
	logger.Error(msg, args...)
}

// Event logs a structured event with type and data.
// Events are logged at Info level and include event_type and event_data fields.
// The data parameter is automatically marshaled to JSON by slog.
//
// Parameters:
//   - ctx: Context containing OpenTelemetry span for trace correlation
//   - eventType: The type of event (e.g., EventTypeMissionStart)
//   - msg: Human-readable description of the event
//   - data: Event-specific data structure (will be JSON marshaled)
//
// Example:
//
//	logger.Event(ctx, EventTypeLLMResponse, "LLM call completed",
//	    LLMResponseEventData{
//	        Model: "claude-3-opus-20240229",
//	        PromptTokens: 1024,
//	        CompletionTokens: 512,
//	    })
func (l *Logger) Event(ctx context.Context, eventType string, msg string, data any) {
	// Add context fields
	logger := l.withContextFields(ctx)

	// Log event with type and data
	logger.Info(msg,
		"event_type", eventType,
		"event_data", data,
	)
}

// WithComponent returns a new Logger with the component field set.
// This method returns a new Logger instance; it does not modify the original.
//
// Parameters:
//   - component: The component name (e.g., "orchestrator", "harness", "daemon")
//
// Returns:
//   - *Logger: A new logger with the component field set
//
// Example:
//
//	orchestratorLogger := logger.WithComponent("orchestrator")
func (l *Logger) WithComponent(component string) *Logger {
	clone := *l
	clone.component = component
	return &clone
}

// WithMission returns a new Logger with mission context fields set.
// This method returns a new Logger instance; it does not modify the original.
//
// Parameters:
//   - missionID: The unique mission identifier
//   - missionName: The human-readable mission name
//
// Returns:
//   - *Logger: A new logger with mission context fields set
//
// Example:
//
//	missionLogger := logger.WithMission("m-abc123", "network-recon")
func (l *Logger) WithMission(missionID, missionName string) *Logger {
	clone := *l
	clone.missionID = missionID
	clone.missionName = missionName
	return &clone
}

// WithAgent returns a new Logger with the agent name field set.
// This method returns a new Logger instance; it does not modify the original.
//
// Parameters:
//   - agentName: The name of the agent
//
// Returns:
//   - *Logger: A new logger with the agent_name field set
//
// Example:
//
//	agentLogger := logger.WithAgent("network-recon")
func (l *Logger) WithAgent(agentName string) *Logger {
	clone := *l
	clone.agentName = agentName
	return &clone
}

// WithNode returns a new Logger with the node ID field set.
// This method returns a new Logger instance; it does not modify the original.
//
// Parameters:
//   - nodeID: The workflow node identifier
//
// Returns:
//   - *Logger: A new logger with the node_id field set
//
// Example:
//
//	nodeLogger := logger.WithNode("recon-1")
func (l *Logger) WithNode(nodeID string) *Logger {
	clone := *l
	clone.nodeID = nodeID
	return &clone
}

// Slog returns the underlying slog.Logger for advanced usage.
// Use this when you need direct access to slog features not exposed by Logger.
//
// Returns:
//   - *slog.Logger: The underlying slog.Logger instance
//
// Example:
//
//	// Use slog's With() method directly
//	customLogger := logger.Slog().With("custom_field", "value")
func (l *Logger) Slog() *slog.Logger {
	return l.slog
}

// withContextFields creates a new slog.Logger with context fields added.
// This includes component, mission_id, mission_name, agent_name, node_id (if set),
// and OpenTelemetry trace correlation fields (trace_id, span_id).
//
// Parameters:
//   - ctx: Context containing OpenTelemetry span for trace correlation
//
// Returns:
//   - *slog.Logger: A logger with all context fields added
func (l *Logger) withContextFields(ctx context.Context) *slog.Logger {
	logger := l.slog

	// Add component field
	if l.component != "" {
		logger = logger.With(slog.String("component", l.component))
	}

	// Add mission context fields
	if l.missionID != "" {
		logger = logger.With(slog.String("mission_id", l.missionID))
	}
	if l.missionName != "" {
		logger = logger.With(slog.String("mission_name", l.missionName))
	}

	// Add agent context field
	if l.agentName != "" {
		logger = logger.With(slog.String("agent_name", l.agentName))
	}

	// Add node context field
	if l.nodeID != "" {
		logger = logger.With(slog.String("node_id", l.nodeID))
	}

	// Extract trace context from OpenTelemetry
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		spanCtx := span.SpanContext()
		logger = logger.With(
			slog.String("trace_id", spanCtx.TraceID().String()),
			slog.String("span_id", spanCtx.SpanID().String()),
		)
	}

	return logger
}

// NewJSONHandler creates a new JSON log handler with the specified output and level.
// JSON format is ideal for structured logging in production environments.
//
// Parameters:
//   - w: The writer to output logs to (e.g., os.Stdout, file)
//   - level: The minimum log level to output
//
// Returns:
//   - slog.Handler: A configured JSON handler
func NewJSONHandler(w io.Writer, level slog.Level) slog.Handler {
	return slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
	})
}

// NewTextHandler creates a new text log handler with the specified output and level.
// Text format is human-readable and useful for development and debugging.
//
// Parameters:
//   - w: The writer to output logs to (e.g., os.Stdout, file)
//   - level: The minimum log level to output
//
// Returns:
//   - slog.Handler: A configured text handler
func NewTextHandler(w io.Writer, level slog.Level) slog.Handler {
	return slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: level,
	})
}

