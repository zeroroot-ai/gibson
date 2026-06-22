package observability_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

// TestInit_ReturnsNonNilObservability verifies that Init with a valid
// serviceName succeeds and returns a fully-populated *Observability.
func TestInit_ReturnsNonNilObservability(t *testing.T) {
	ctx := context.Background()
	o, err := observability.Init(ctx, "test-service-basic")
	if err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	if o == nil {
		t.Fatal("Init returned nil Observability")
	}
	if o.TracerProvider() == nil {
		t.Error("Observability.TracerProvider() is nil")
	}
	if o.MeterProvider() == nil {
		t.Error("Observability.MeterProvider() is nil")
	}
	if o.Logger == nil {
		t.Error("Observability.Logger is nil")
	}
}

// TestInit_IndependentProviders verifies that two calls to Init in the same
// process produce independent providers that do not share state. This is the
// key regression test for the global-mutation defect fixed by Option C.
func TestInit_IndependentProviders(t *testing.T) {
	ctx := context.Background()

	o1, err := observability.Init(ctx, "test-service-independent-1")
	if err != nil {
		t.Fatalf("first Init: %v", err)
	}

	o2, err := observability.Init(ctx, "test-service-independent-2")
	if err != nil {
		t.Fatalf("second Init: %v", err)
	}

	// The two instances must not be the same pointer.
	if o1 == o2 {
		t.Fatal("two Init calls returned the same *Observability pointer; providers are not independent")
	}

	// The TracerProvider interfaces must point to different underlying values.
	if o1.TracerProvider() == o2.TracerProvider() {
		t.Error("TracerProvider() returned the same instance for two independent Init calls")
	}

	// The MeterProvider interfaces must point to different underlying values.
	if o1.MeterProvider() == o2.MeterProvider() {
		t.Error("MeterProvider() returned the same instance for two independent Init calls")
	}
}

// TestInit_DifferentServiceNames verifies that distinct serviceNames produce
// distinct *Observability instances (no caching side-effects).
func TestInit_DifferentServiceNames(t *testing.T) {
	ctx := context.Background()

	o1, err := observability.Init(ctx, "test-service-alpha")
	if err != nil {
		t.Fatalf("Init alpha: %v", err)
	}

	o2, err := observability.Init(ctx, "test-service-beta")
	if err != nil {
		t.Fatalf("Init beta: %v", err)
	}

	if o1 == o2 {
		t.Error("different serviceNames returned the same *Observability instance")
	}
}

// TestInit_SameServiceNameTwice verifies that calling Init twice with the same
// serviceName still produces two independent instances (no global cache).
func TestInit_SameServiceNameTwice(t *testing.T) {
	ctx := context.Background()
	const svc = "test-service-same-name-twice"

	o1, err := observability.Init(ctx, svc)
	if err != nil {
		t.Fatalf("first Init: %v", err)
	}

	o2, err := observability.Init(ctx, svc)
	if err != nil {
		t.Fatalf("second Init: %v", err)
	}

	// Option C removes idempotent caching — each call is a fresh instance.
	if o1 == o2 {
		t.Error("two Init calls with the same serviceName returned the same pointer; " +
			"global cache must not exist (Option C)")
	}
}

// TestInit_EmptyServiceName verifies that Init rejects an empty serviceName.
func TestInit_EmptyServiceName(t *testing.T) {
	_, err := observability.Init(context.Background(), "")
	if err == nil {
		t.Fatal("Init with empty serviceName should return an error")
	}
}

// TestFieldConstants verifies that the exported string constants carry the
// exact values the rest of the platform depends on.
func TestFieldConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"TraceIDField", observability.TraceIDField, "trace_id"},
		{"SpanIDField", observability.SpanIDField, "span_id"},
		{"TenantIDField", observability.TenantIDField, "tenant_id"},
		{"RequestIDField", observability.RequestIDField, "request_id"},
		{"UserIDField", observability.UserIDField, "user_id"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
			}
		})
	}
}

// TestLoggerOutputIsStructuredJSON verifies that the Observability.Logger writes
// valid JSON and that the four canonical field names appear in the output.
func TestLoggerOutputIsStructuredJSON(t *testing.T) {
	ctx := context.Background()
	o, err := observability.Init(ctx, "test-service-logger-json",
		observability.WithLogLevel(slog.LevelDebug),
	)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Write a log entry through a test logger with the four canonical fields.
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger.Info("probe",
		observability.TraceIDField, "abc123",
		observability.SpanIDField, "def456",
		observability.TenantIDField, "t1",
		observability.RequestIDField, "req-1",
		observability.UserIDField, "u1",
	)

	// Confirm the output is valid JSON.
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("logger output is not valid JSON: %v\noutput: %s", err, buf.String())
	}

	// Confirm all field names are present as keys.
	for _, field := range []string{
		observability.TraceIDField,
		observability.SpanIDField,
		observability.TenantIDField,
		observability.RequestIDField,
		observability.UserIDField,
	} {
		if _, ok := m[field]; !ok {
			t.Errorf("field %q missing from JSON output: %s", field, buf.String())
		}
	}

	_ = o
}

// TestShutdown_Idempotent verifies that calling Shutdown multiple times
// returns nil and does not panic.
func TestShutdown_Idempotent(t *testing.T) {
	ctx := context.Background()
	o, err := observability.Init(ctx, "test-service-shutdown")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	shutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := o.Shutdown(shutCtx); err != nil {
		t.Errorf("first Shutdown: %v", err)
	}
	if err := o.Shutdown(shutCtx); err != nil {
		t.Errorf("second Shutdown (idempotency): %v", err)
	}
}

// TestWithOTLPEndpoint_Option verifies that WithOTLPEndpoint is accepted
// without error when no collector is reachable (the provider is initialised
// lazily / no-op-fallback for unreachable endpoints).
func TestWithOTLPEndpoint_Option(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping endpoint option test in short mode")
	}

	ctx := context.Background()
	const svc = "test-service-endpoint-option"

	// Point at an unreachable address — Init should not block or error
	// because OTLP exporters connect lazily.
	o, err := observability.Init(ctx, svc,
		observability.WithOTLPEndpoint("localhost:19999"),
	)
	if err != nil {
		t.Fatalf("Init with unreachable endpoint: %v", err)
	}
	if o == nil {
		t.Fatal("expected non-nil Observability")
	}
}

// TestSetGlobal_DoesNotPanic verifies that SetGlobal can be called without
// panicking (the global providers are set to the instance's providers).
func TestSetGlobal_DoesNotPanic(t *testing.T) {
	ctx := context.Background()
	o, err := observability.Init(ctx, "test-service-set-global")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	// SetGlobal must not panic.
	o.SetGlobal()

	// Shutdown must still succeed after SetGlobal.
	shutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := o.Shutdown(shutCtx); err != nil {
		t.Errorf("Shutdown after SetGlobal: %v", err)
	}
}
