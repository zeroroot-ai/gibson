package observability

import (
	"context"

	"go.opentelemetry.io/otel/trace"
)

// ExtractParentSpanID gets the parent span ID from the context.
// This is used to populate parent_span_id in events for relationship creation.
//
// Returns:
//   - string: The parent span ID in hex format, or empty string if no valid span context
//
// Example:
//
//	parentSpanID := observability.ExtractParentSpanID(ctx)
//	event := LLMRequestStartedEvent{
//	    TraceID:      traceID,
//	    SpanID:       spanID,
//	    ParentSpanID: parentSpanID,  // Now populated
//	}
func ExtractParentSpanID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return ""
	}
	return span.SpanContext().SpanID().String()
}

// ExtractSpanContext extracts trace ID, span ID, and parent span ID from context.
// This is a convenience function for extracting all span context information at once.
//
// Returns:
//   - traceID: The trace ID in hex format
//   - spanID: The current span ID in hex format
//   - parentSpanID: The parent span ID in hex format (from ExtractParentSpanID)
//
// Example:
//
//	traceID, spanID, parentSpanID := observability.ExtractSpanContext(ctx)
//	event := ToolCallEvent{
//	    TraceID:      traceID,
//	    SpanID:       spanID,
//	    ParentSpanID: parentSpanID,
//	}
func ExtractSpanContext(ctx context.Context) (traceID, spanID, parentSpanID string) {
	span := trace.SpanFromContext(ctx)
	sc := span.SpanContext()
	if sc.IsValid() {
		traceID = sc.TraceID().String()
		spanID = sc.SpanID().String()
	}

	// Parent span ID needs to be extracted before creating a new span
	// If this is called within a span, it returns the current span's ID
	// which would be the parent for any child spans created next
	parentSpanID = ExtractParentSpanID(ctx)

	return
}

// ExtractTraceID extracts just the trace ID from the context.
// This is useful when only the trace ID is needed without span information.
//
// Returns:
//   - string: The trace ID in hex format, or empty string if no valid span context
func ExtractTraceID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return ""
	}
	return span.SpanContext().TraceID().String()
}

// ExtractSpanID extracts just the current span ID from the context.
// This is useful when only the span ID is needed without trace information.
//
// Returns:
//   - string: The span ID in hex format, or empty string if no valid span context
func ExtractSpanID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return ""
	}
	return span.SpanContext().SpanID().String()
}
