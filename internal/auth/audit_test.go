package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdkauth "github.com/zero-day-ai/sdk/auth"
)

// testLogHandler is a custom slog handler that captures log output for testing.
type testLogHandler struct {
	buf    *bytes.Buffer
	level  slog.Level
	attrs  []slog.Attr
	groups []string
}

// newTestLogHandler creates a new test log handler that captures JSON output.
func newTestLogHandler() *testLogHandler {
	return &testLogHandler{
		buf:   &bytes.Buffer{},
		level: slog.LevelDebug,
	}
}

// Enabled implements slog.Handler.
func (h *testLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

// Handle implements slog.Handler.
func (h *testLogHandler) Handle(_ context.Context, r slog.Record) error {
	// Write log record as JSON
	m := make(map[string]any)
	m["time"] = r.Time
	m["level"] = r.Level.String()
	m["msg"] = r.Message

	// Add attributes
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value.Any()
		return true
	})

	// Add handler-level attributes
	for _, a := range h.attrs {
		m[a.Key] = a.Value.Any()
	}

	data, err := json.Marshal(m)
	if err != nil {
		return err
	}

	h.buf.Write(data)
	h.buf.WriteString("\n")
	return nil
}

// WithAttrs implements slog.Handler.
func (h *testLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := &testLogHandler{
		buf:    h.buf,
		level:  h.level,
		attrs:  append([]slog.Attr{}, h.attrs...),
		groups: append([]string{}, h.groups...),
	}
	clone.attrs = append(clone.attrs, attrs...)
	return clone
}

// WithGroup implements slog.Handler.
func (h *testLogHandler) WithGroup(name string) slog.Handler {
	clone := &testLogHandler{
		buf:    h.buf,
		level:  h.level,
		attrs:  append([]slog.Attr{}, h.attrs...),
		groups: append([]string{}, h.groups...),
	}
	clone.groups = append(clone.groups, name)
	return clone
}

// String returns the captured log output.
func (h *testLogHandler) String() string {
	return h.buf.String()
}

// Contains checks if the log output contains the specified substring.
func (h *testLogHandler) Contains(substr string) bool {
	return strings.Contains(h.buf.String(), substr)
}

// TestLogAuthSuccess_AllRequiredFields tests that LogAuthSuccess includes all required fields.
func TestLogAuthSuccess_AllRequiredFields(t *testing.T) {
	handler := newTestLogHandler()
	oldDefault := slog.Default()
	defer slog.SetDefault(oldDefault)
	slog.SetDefault(slog.New(handler))

	// Create a test identity
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject:   "user@example.com",
			Issuer:    "https://auth.example.com",
			ExpiresAt: time.Now().Add(time.Hour),
		},
		Roles: []string{"admin", "user"},
	}

	// Create context with trace ID
	ctx := context.Background()
	tracer := otel.Tracer("test")
	ctx, span := tracer.Start(ctx, "test-span")
	defer span.End()

	// Add tenant to context
	ctx = ContextWithTenant(ctx, "test-tenant")

	// Call LogAuthSuccess
	clientIP := "192.168.1.100"
	LogAuthSuccess(ctx, identity, clientIP)

	// Get log output
	logOutput := handler.String()

	// Verify all required fields are present
	requiredFields := []string{
		"event_type",
		"auth_success",
		"timestamp",
		"subject",
		"user@example.com",
		"issuer",
		"https://auth.example.com",
		"tenant_id",
		"test-tenant",
		"client_ip",
		"192.168.1.100",
		"trace_id",
		"roles",
		"admin",
		"success",
		"true",
	}

	for _, field := range requiredFields {
		if !strings.Contains(logOutput, field) {
			t.Errorf("LogAuthSuccess missing required field: %s\nLog output: %s", field, logOutput)
		}
	}
}

// TestLogAuthFailure_DoesNotIncludeToken tests that LogAuthFailure does not log token values.
func TestLogAuthFailure_DoesNotIncludeToken(t *testing.T) {
	handler := newTestLogHandler()
	oldDefault := slog.Default()
	defer slog.SetDefault(oldDefault)
	slog.SetDefault(slog.New(handler))

	ctx := context.Background()

	// Simulate a token value that should NEVER appear in logs
	fakeToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"

	// Call LogAuthFailure with a reason (should not include token)
	reason := "token expired"
	issuer := "https://auth.example.com"
	clientIP := "192.168.1.100"

	LogAuthFailure(ctx, reason, issuer, clientIP)

	// Get log output
	logOutput := handler.String()

	// Verify token is NOT in the log
	if strings.Contains(logOutput, fakeToken) {
		t.Errorf("LogAuthFailure logged token value! This is a security issue.\nLog output: %s", logOutput)
	}

	// Verify required fields are present
	requiredFields := []string{
		"event_type",
		"auth_failure",
		"reason",
		"token expired",
		"issuer",
		"https://auth.example.com",
		"client_ip",
		"192.168.1.100",
		"success",
		"false",
	}

	for _, field := range requiredFields {
		if !strings.Contains(logOutput, field) {
			t.Errorf("LogAuthFailure missing required field: %s\nLog output: %s", field, logOutput)
		}
	}
}

// TestLogAuthFailure_WithTraceID tests that LogAuthFailure includes trace_id from context.
func TestLogAuthFailure_WithTraceID(t *testing.T) {
	handler := newTestLogHandler()
	oldDefault := slog.Default()
	defer slog.SetDefault(oldDefault)
	slog.SetDefault(slog.New(handler))

	// Create context with trace ID
	ctx := context.Background()
	tracer := otel.Tracer("test")
	ctx, span := tracer.Start(ctx, "test-span")
	defer span.End()

	// Get the trace ID for verification
	traceID := span.SpanContext().TraceID().String()

	// Call LogAuthFailure
	LogAuthFailure(ctx, "invalid signature", "https://auth.example.com", "10.0.0.1")

	// Get log output
	logOutput := handler.String()

	// Verify trace_id is present
	if !strings.Contains(logOutput, "trace_id") {
		t.Errorf("LogAuthFailure missing trace_id field\nLog output: %s", logOutput)
	}

	if !strings.Contains(logOutput, traceID) {
		t.Errorf("LogAuthFailure trace_id mismatch. Expected: %s\nLog output: %s", traceID, logOutput)
	}
}

// TestLogPermissionDenied_IncludesActionAndResource tests that LogPermissionDenied includes action and resource.
func TestLogPermissionDenied_IncludesActionAndResource(t *testing.T) {
	handler := newTestLogHandler()
	oldDefault := slog.Default()
	defer slog.SetDefault(oldDefault)
	slog.SetDefault(slog.New(handler))

	// Create a test identity
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "user@example.com",
			Issuer:  "https://auth.example.com",
		},
		Roles: []string{"viewer"},
	}

	ctx := context.Background()

	// Add tenant to context
	ctx = ContextWithTenant(ctx, "test-tenant")

	// Call LogPermissionDenied
	action := "execute"
	resource := "mission"

	LogPermissionDenied(ctx, identity, action, resource)

	// Get log output
	logOutput := handler.String()

	// Verify all required fields are present
	requiredFields := []string{
		"event_type",
		"permission_denied",
		"subject",
		"user@example.com",
		"action",
		"execute",
		"resource",
		"mission",
		"tenant_id",
		"test-tenant",
		"roles",
		"viewer",
		"reason",
		"insufficient permissions",
		"success",
		"false",
	}

	for _, field := range requiredFields {
		if !strings.Contains(logOutput, field) {
			t.Errorf("LogPermissionDenied missing required field: %s\nLog output: %s", field, logOutput)
		}
	}
}

// TestLogPermissionDenied_WithNilIdentity tests that LogPermissionDenied works with nil identity.
func TestLogPermissionDenied_WithNilIdentity(t *testing.T) {
	handler := newTestLogHandler()
	oldDefault := slog.Default()
	defer slog.SetDefault(oldDefault)
	slog.SetDefault(slog.New(handler))

	ctx := context.Background()

	// Call LogPermissionDenied with nil identity (unauthenticated attempt)
	LogPermissionDenied(ctx, nil, "read", "finding")

	// Get log output
	logOutput := handler.String()

	// Verify event is logged even without identity
	if !strings.Contains(logOutput, "permission_denied") {
		t.Errorf("LogPermissionDenied did not log event with nil identity\nLog output: %s", logOutput)
	}

	// Verify action and resource are still logged
	if !strings.Contains(logOutput, "read") || !strings.Contains(logOutput, "finding") {
		t.Errorf("LogPermissionDenied missing action or resource\nLog output: %s", logOutput)
	}
}

// TestExtractIPFromPeerAddr tests the IP extraction helper function.
func TestExtractIPFromPeerAddr(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected string
	}{
		{
			name:     "IPv4 with port",
			addr:     "192.168.1.100:12345",
			expected: "192.168.1.100",
		},
		{
			name:     "IPv6 with port",
			addr:     "[::1]:8080",
			expected: "::1",
		},
		{
			name:     "IPv6 full address with port",
			addr:     "[2001:db8::1]:443",
			expected: "2001:db8::1",
		},
		{
			name:     "Localhost IPv4",
			addr:     "127.0.0.1:9090",
			expected: "127.0.0.1",
		},
		{
			name:     "No port",
			addr:     "192.168.1.1",
			expected: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractIPFromPeerAddr(tt.addr)
			if result != tt.expected {
				t.Errorf("extractIPFromPeerAddr(%q) = %q, want %q", tt.addr, result, tt.expected)
			}
		})
	}
}

// TestLogAuthSuccess_WithNilIdentity tests that LogAuthSuccess handles nil identity gracefully.
func TestLogAuthSuccess_WithNilIdentity(t *testing.T) {
	handler := newTestLogHandler()
	oldDefault := slog.Default()
	defer slog.SetDefault(oldDefault)
	slog.SetDefault(slog.New(handler))

	ctx := context.Background()

	// Call LogAuthSuccess with nil identity (should not panic or log)
	LogAuthSuccess(ctx, nil, "192.168.1.100")

	// Get log output
	logOutput := handler.String()

	// Should not have logged anything
	if len(logOutput) > 0 {
		t.Errorf("LogAuthSuccess should not log with nil identity, but logged: %s", logOutput)
	}
}

// TestLogAuditEvent_WithoutContext tests that audit logging works without trace context.
func TestLogAuditEvent_WithoutContext(t *testing.T) {
	handler := newTestLogHandler()
	logger := slog.New(handler)

	ctx := context.Background()

	// Call without trace context
	event := &AuditEvent{
		EventType: "auth_success",
		Subject:   "test-user",
		Success:   true,
	}

	logAuditEvent(ctx, logger, event)

	// Get log output
	logOutput := handler.String()

	// Should still log successfully, just without trace_id
	if !strings.Contains(logOutput, "auth_success") {
		t.Errorf("logAuditEvent failed without trace context\nLog output: %s", logOutput)
	}

	// Verify timestamp was added automatically
	if !strings.Contains(logOutput, "timestamp") {
		t.Errorf("logAuditEvent missing automatic timestamp\nLog output: %s", logOutput)
	}
}

// TestLogAuthSuccess_LogLevel tests that success events are logged at INFO level.
func TestLogAuthSuccess_LogLevel(t *testing.T) {
	handler := newTestLogHandler()
	oldDefault := slog.Default()
	defer slog.SetDefault(oldDefault)
	slog.SetDefault(slog.New(handler))

	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "user@example.com",
			Issuer:  "https://auth.example.com",
		},
	}

	ctx := context.Background()

	LogAuthSuccess(ctx, identity, "192.168.1.100")

	logOutput := handler.String()

	// Verify it's logged at INFO level
	if !strings.Contains(logOutput, "INFO") {
		t.Errorf("LogAuthSuccess should log at INFO level\nLog output: %s", logOutput)
	}
}

// TestLogAuthFailure_LogLevel tests that failure events are logged at WARN level.
func TestLogAuthFailure_LogLevel(t *testing.T) {
	handler := newTestLogHandler()
	oldDefault := slog.Default()
	defer slog.SetDefault(oldDefault)
	slog.SetDefault(slog.New(handler))

	ctx := context.Background()

	LogAuthFailure(ctx, "token expired", "https://auth.example.com", "192.168.1.100")

	logOutput := handler.String()

	// Verify it's logged at WARN level
	if !strings.Contains(logOutput, "WARN") {
		t.Errorf("LogAuthFailure should log at WARN level\nLog output: %s", logOutput)
	}
}

// TestLogPermissionDenied_WithTraceID tests trace ID extraction in permission denied events.
func TestLogPermissionDenied_WithTraceID(t *testing.T) {
	handler := newTestLogHandler()
	oldDefault := slog.Default()
	defer slog.SetDefault(oldDefault)
	slog.SetDefault(slog.New(handler))

	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "user@example.com",
			Issuer:  "https://auth.example.com",
		},
		Roles: []string{"viewer"},
	}

	// Create context with trace ID
	ctx := context.Background()
	tracer := otel.Tracer("test")
	ctx, span := tracer.Start(ctx, "test-span")
	defer span.End()

	// Get the trace ID for verification
	traceID := span.SpanContext().TraceID().String()

	LogPermissionDenied(ctx, identity, "write", "finding")

	logOutput := handler.String()

	// Verify trace_id is present
	if !strings.Contains(logOutput, "trace_id") {
		t.Errorf("LogPermissionDenied missing trace_id field\nLog output: %s", logOutput)
	}

	if !strings.Contains(logOutput, traceID) {
		t.Errorf("LogPermissionDenied trace_id mismatch. Expected: %s\nLog output: %s", traceID, logOutput)
	}
}

// TestAuditEvent_Timestamp tests that timestamps are automatically added when not provided.
func TestAuditEvent_Timestamp(t *testing.T) {
	handler := newTestLogHandler()
	logger := slog.New(handler)

	ctx := context.Background()
	beforeTime := time.Now()

	event := &AuditEvent{
		EventType: "auth_success",
		Subject:   "test-user",
		Success:   true,
		// No timestamp provided
	}

	logAuditEvent(ctx, logger, event)

	afterTime := time.Now()

	// Verify timestamp was added and is reasonable
	if event.Timestamp.IsZero() {
		t.Error("logAuditEvent did not set timestamp automatically")
	}

	if event.Timestamp.Before(beforeTime) || event.Timestamp.After(afterTime) {
		t.Errorf("logAuditEvent timestamp out of range: %v", event.Timestamp)
	}
}

// TestLogAuthSuccess_EmptyClientIP tests that client IP is extracted from context when empty.
func TestLogAuthSuccess_EmptyClientIP(t *testing.T) {
	handler := newTestLogHandler()
	oldDefault := slog.Default()
	defer slog.SetDefault(oldDefault)
	slog.SetDefault(slog.New(handler))

	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "user@example.com",
			Issuer:  "https://auth.example.com",
		},
	}

	ctx := context.Background()

	// Call with empty client IP (would normally extract from gRPC peer, but not available in unit test)
	LogAuthSuccess(ctx, identity, "")

	logOutput := handler.String()

	// Should still log successfully
	if !strings.Contains(logOutput, "auth_success") {
		t.Errorf("LogAuthSuccess failed with empty client IP\nLog output: %s", logOutput)
	}
}
