package daemon

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// GraphEvent represents an execution event that should be processed by the taxonomy graph engine.
// It captures the event type, trace context, timestamp, and event-specific data.
type GraphEvent struct {
	// Type is the event type (e.g., "mission.started", "agent.started", "tool.call.started")
	Type string

	// TraceID is the OpenTelemetry trace ID for this event
	TraceID string

	// SpanID is the OpenTelemetry span ID for this event
	SpanID string

	// ParentSpanID is the parent span ID (for creating PART_OF relationships)
	ParentSpanID string

	// Timestamp is when the event occurred
	Timestamp time.Time

	// Data contains event-specific fields that will be used for node/relationship property mappings
	Data map[string]any
}

// Event type constants matching execution_events.yaml
const (
	// Mission events
	EventTypeMissionStarted   = "mission.started"
	EventTypeMissionCompleted = "mission.completed"
	EventTypeMissionFailed    = "mission.failed"

	// Agent events
	EventTypeAgentStarted   = "agent.started"
	EventTypeAgentCompleted = "agent.completed"
	EventTypeAgentFailed    = "agent.failed"
	EventTypeAgentDelegated = "agent.delegated"

	// LLM events
	EventTypeLLMRequestStarted   = "llm.request.started"
	EventTypeLLMRequestCompleted = "llm.request.completed"
	EventTypeLLMRequestFailed    = "llm.request.failed"
	EventTypeLLMStreamStarted    = "llm.stream.started"
	EventTypeLLMStreamCompleted  = "llm.stream.completed"

	// Tool events
	EventTypeToolCallStarted   = "tool.call.started"
	EventTypeToolCallCompleted = "tool.call.completed"
	EventTypeToolCallFailed    = "tool.call.failed"

	// Plugin events
	EventTypePluginQueryStarted   = "plugin.query.started"
	EventTypePluginQueryCompleted = "plugin.query.completed"
	EventTypePluginQueryFailed    = "plugin.query.failed"

	// Finding events
	EventTypeFindingDiscovered     = "finding.discovered"
	EventTypeAgentFindingSubmitted = "agent.finding_submitted"
)

// ExtractTraceContext extracts trace context (trace ID, span ID, parent span ID) from a context.
// Returns empty strings if no trace context is found.
func ExtractTraceContext(ctx context.Context) (traceID, spanID, parentSpanID string) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return "", "", ""
	}

	spanCtx := span.SpanContext()
	if !spanCtx.IsValid() {
		return "", "", ""
	}

	traceID = spanCtx.TraceID().String()
	spanID = spanCtx.SpanID().String()

	// Extract parent span ID if available
	// Note: OpenTelemetry doesn't provide direct access to parent span ID from span context
	// The parent span ID will need to be passed explicitly in event data when creating relationships
	// For now, we leave it empty and expect it to be provided in event data

	return traceID, spanID, ""
}

// NewGraphEvent creates a new GraphEvent with trace context extracted from the provided context.
func NewGraphEvent(ctx context.Context, eventType string, data map[string]any) *GraphEvent {
	traceID, spanID, parentSpanID := ExtractTraceContext(ctx)

	return &GraphEvent{
		Type:         eventType,
		TraceID:      traceID,
		SpanID:       spanID,
		ParentSpanID: parentSpanID,
		Timestamp:    time.Now(),
		Data:         data,
	}
}
