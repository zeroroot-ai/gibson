package observability

import (
	"context"
	"io"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/llm"
)

// ActivityEventType defines the type of activity event.
type ActivityEventType string

const (
	EventAgentStart    ActivityEventType = "AGENT_START"
	EventAgentEnd      ActivityEventType = "AGENT_END"
	EventLLMPrompt     ActivityEventType = "LLM_PROMPT"
	EventLLMResponse   ActivityEventType = "LLM_RESPONSE"
	EventToolCall      ActivityEventType = "TOOL_CALL"
	EventToolResult    ActivityEventType = "TOOL_RESULT"
	EventFinding       ActivityEventType = "FINDING"
	EventDecision      ActivityEventType = "DECISION"
	EventError         ActivityEventType = "ERROR"
	EventMemoryStore   ActivityEventType = "MEMORY_STORE"
	EventMemoryRecall  ActivityEventType = "MEMORY_RECALL"
	EventGraphRAGStore ActivityEventType = "GRAPHRAG_STORE"
	EventDelegation    ActivityEventType = "DELEGATION"
)

// String returns the string representation of ActivityEventType
func (a ActivityEventType) String() string {
	return string(a)
}

// ActivityLevel defines the verbosity level for activity logging.
type ActivityLevel int

const (
	// ActivityLevelQuiet logs only errors and findings
	ActivityLevelQuiet ActivityLevel = iota
	// ActivityLevelNormal logs agent lifecycle, findings, errors, and decisions
	ActivityLevelNormal
	// ActivityLevelVerbose logs all events including LLM content (truncated)
	ActivityLevelVerbose
	// ActivityLevelDebug logs full content with no truncation
	ActivityLevelDebug
)

// String returns the string representation of ActivityLevel
func (a ActivityLevel) String() string {
	switch a {
	case ActivityLevelQuiet:
		return "quiet"
	case ActivityLevelNormal:
		return "normal"
	case ActivityLevelVerbose:
		return "verbose"
	case ActivityLevelDebug:
		return "debug"
	default:
		return "unknown"
	}
}

// ParseActivityLevel parses a string into an ActivityLevel
func ParseActivityLevel(s string) ActivityLevel {
	switch s {
	case "quiet":
		return ActivityLevelQuiet
	case "normal":
		return ActivityLevelNormal
	case "verbose":
		return ActivityLevelVerbose
	case "debug":
		return ActivityLevelDebug
	default:
		return ActivityLevelNormal
	}
}

// ActivityEvent represents a structured activity event for logging.
type ActivityEvent struct {
	Timestamp       time.Time              `json:"timestamp"`
	Level           string                 `json:"level"`
	EventType       ActivityEventType      `json:"event_type"`
	MissionID       string                 `json:"mission_id,omitempty"`
	AgentName       string                 `json:"agent_name,omitempty"`
	TraceID         string                 `json:"trace_id,omitempty"`
	SpanID          string                 `json:"span_id,omitempty"`
	LangfuseTraceID string                 `json:"langfuse_trace_id,omitempty"`
	Payload         map[string]interface{} `json:"payload"`
}

// ActivityLoggerConfig configures the activity logger.
type ActivityLoggerConfig struct {
	// Level sets the verbosity level
	Level ActivityLevel

	// MaxContentLength is the maximum characters for content fields before truncation
	MaxContentLength int

	// Output is the writer for activity events
	Output io.Writer

	// BufferSize is the event buffer size for async writes
	BufferSize int

	// MissionID is the mission context (optional)
	MissionID string

	// AgentName is the agent context (optional)
	AgentName string

	// LangfuseTraceID is the Langfuse trace ID for correlation (optional)
	LangfuseTraceID string

	// Metrics is the Prometheus metrics recorder (optional)
	Metrics *ActivityMetrics
}

// ActivityLogger emits structured activity events.
type ActivityLogger interface {
	// Emit logs an activity event at the appropriate level.
	Emit(ctx context.Context, event ActivityEvent)

	// EmitAgentStart logs an agent starting execution.
	EmitAgentStart(ctx context.Context, agentName string, taskDescription string)

	// EmitAgentEnd logs an agent completing execution.
	EmitAgentEnd(ctx context.Context, agentName string, status string, durationMs int64)

	// EmitLLMPrompt logs messages sent to an LLM.
	EmitLLMPrompt(ctx context.Context, slot string, messages []llm.Message)

	// EmitLLMResponse logs an LLM response.
	EmitLLMResponse(ctx context.Context, slot string, response *llm.CompletionResponse)

	// EmitToolCall logs a tool invocation.
	EmitToolCall(ctx context.Context, toolName string, params interface{})

	// EmitToolResult logs a tool execution result.
	EmitToolResult(ctx context.Context, toolName string, result interface{}, durationMs int64, err error)

	// EmitFinding logs a security finding discovery.
	EmitFinding(ctx context.Context, finding *agent.Finding)

	// EmitDecision logs an orchestrator decision.
	EmitDecision(ctx context.Context, action string, target string, reasoning string, confidence float64)

	// EmitError logs an error event.
	EmitError(ctx context.Context, operation string, err error)

	// Level returns the current activity logging level.
	Level() ActivityLevel

	// SetLevel changes the activity logging level.
	SetLevel(level ActivityLevel)

	// Flush ensures all buffered events are written.
	Flush() error

	// Close shuts down the logger gracefully.
	Close() error
}
