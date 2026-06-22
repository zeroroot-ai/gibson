// Package observability provides shared OTel + slog initialisation for
// internal platform services. It is NOT customer-facing; do not import it
// from any package under opensource/.
package observability

// Structured-log and span-attribute field name constants.
// Use these instead of inline strings so grep-ability is guaranteed across
// all platform-clients consumers.
const (
	// TraceIDField is the slog/span attribute key for the OpenTelemetry trace ID.
	TraceIDField = "trace_id"

	// SpanIDField is the slog/span attribute key for the OpenTelemetry span ID.
	SpanIDField = "span_id"

	// TenantIDField is the slog/span attribute key for the platform tenant identifier.
	TenantIDField = "tenant_id"

	// RequestIDField is the slog/span attribute key for the per-request correlation ID.
	RequestIDField = "request_id"

	// UserIDField is the slog/span attribute key for the authenticated user identifier.
	UserIDField = "user_id"
)
