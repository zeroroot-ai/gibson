package observability

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// TestSetAuthzAttributes_AllFieldsSet verifies the helper emits every
// canonical attribute when populated on an allow decision.
func TestSetAuthzAttributes_AllFieldsSet(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "TestRPC")

	SetAuthzAttributes(
		ctx,
		"/gibson.daemon.admin.v1.DaemonAdminService/ProvisionTenant",
		"alice",
		"tenant-a",
		"tenants:provision",
		true,
		"",
	)
	span.End()

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	attrs := spans[0].Attributes
	got := map[string]attribute.Value{}
	for _, a := range attrs {
		got[string(a.Key)] = a.Value
	}

	if v, ok := got[GibsonAuthzMethod]; !ok || v.AsString() != "/gibson.daemon.admin.v1.DaemonAdminService/ProvisionTenant" {
		t.Errorf("method attr wrong: %v", got[GibsonAuthzMethod])
	}
	if v, ok := got[GibsonAuthzSubject]; !ok || v.AsString() != "alice" {
		t.Errorf("subject attr wrong: %v", got[GibsonAuthzSubject])
	}
	if v, ok := got[GibsonAuthzTenant]; !ok || v.AsString() != "tenant-a" {
		t.Errorf("tenant attr wrong: %v", got[GibsonAuthzTenant])
	}
	if v, ok := got[GibsonAuthzPermissionRequired]; !ok || v.AsString() != "tenants:provision" {
		t.Errorf("permission attr wrong: %v", got[GibsonAuthzPermissionRequired])
	}
	if v, ok := got[GibsonAuthzAllowed]; !ok || !v.AsBool() {
		t.Errorf("allowed attr wrong: %v", got[GibsonAuthzAllowed])
	}
	// Reason should be absent on allow.
	if _, ok := got[GibsonAuthzReason]; ok {
		t.Errorf("reason attr should be absent on allow, got: %v", got[GibsonAuthzReason])
	}
}

// TestSetAuthzAttributes_DenyIncludesReason verifies the reason attribute
// is emitted on deny.
func TestSetAuthzAttributes_DenyIncludesReason(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "TestRPC")

	SetAuthzAttributes(
		ctx,
		"/gibson.daemon.admin.v1.DaemonAdminService/ListTenants",
		"bob",
		"*",
		"tenants:list-all",
		false,
		"missing_permission: tenants:list-all",
	)
	span.End()

	spans := exporter.GetSpans()
	attrs := spans[0].Attributes
	got := map[string]attribute.Value{}
	for _, a := range attrs {
		got[string(a.Key)] = a.Value
	}

	if v, ok := got[GibsonAuthzAllowed]; !ok || v.AsBool() {
		t.Errorf("allowed should be false on deny, got: %v", got[GibsonAuthzAllowed])
	}
	if v, ok := got[GibsonAuthzReason]; !ok || v.AsString() != "missing_permission: tenants:list-all" {
		t.Errorf("reason attr wrong on deny: %v", got[GibsonAuthzReason])
	}
}

// TestSetAuthzAttributes_NoActiveSpanIsNoop verifies the helper does not
// panic and does not leak attributes when there is no active span.
func TestSetAuthzAttributes_NoActiveSpanIsNoop(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SetAuthzAttributes with no span should not panic, got: %v", r)
		}
	}()

	// Background context has no span.
	SetAuthzAttributes(context.Background(), "method", "alice", "tenant", "perm", true, "")
}

// TestSetAuthzAttributes_UnauthenticatedRPC verifies the helper handles
// unauthenticated RPCs (empty subject, empty permission) gracefully.
func TestSetAuthzAttributes_UnauthenticatedRPC(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "TestRPC")

	SetAuthzAttributes(ctx, "/gibson.test.v1/Open", "", "*", "", true, "")
	span.End()

	spans := exporter.GetSpans()
	attrs := spans[0].Attributes
	got := map[string]attribute.Value{}
	for _, a := range attrs {
		got[string(a.Key)] = a.Value
	}

	// Method and allowed should be set.
	if _, ok := got[GibsonAuthzMethod]; !ok {
		t.Error("method attr should be set")
	}
	if _, ok := got[GibsonAuthzAllowed]; !ok {
		t.Error("allowed attr should be set")
	}
	// Subject and permission should be absent (they were empty).
	if _, ok := got[GibsonAuthzSubject]; ok {
		t.Error("subject attr should be absent when empty")
	}
	if _, ok := got[GibsonAuthzPermissionRequired]; ok {
		t.Error("permission attr should be absent when empty")
	}
}

var _ = trace.NewNoopTracerProvider // silence unused import if span creation changes
