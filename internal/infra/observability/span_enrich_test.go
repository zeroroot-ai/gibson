package observability

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/zeroroot-ai/gibson/internal/infra/contextkeys"
	"github.com/zeroroot-ai/sdk/auth"
)

// captureAttrs runs EnrichSpan against a fresh in-memory tracer and returns
// the attributes recorded on the span. Shared by every test case below so
// individual tests stay focused on the ctx/attr relationship.
func captureAttrs(t *testing.T, ctx context.Context, spanName string) map[string]attribute.Value {
	t.Helper()
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	tracer := tp.Tracer("test")
	_, span := tracer.Start(ctx, spanName)
	EnrichSpan(ctx, span)
	span.End()

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	got := map[string]attribute.Value{}
	for _, a := range spans[0].Attributes {
		got[string(a.Key)] = a.Value
	}
	return got
}

// TestEnrichSpan_EmptyContext_FallsBack asserts that a bare context produces
// tenant_id=auth.SystemTenantString (the "_system" sentinel returned by
// TenantFromContext when nothing else is resolvable) and user_id="unknown".
// The hardcoded "default" fallback in EnrichSpan is effectively dead code
// because TenantFromContext never returns "" — matches the existing
// otel_mission_tracer.go behavior.
func TestEnrichSpan_EmptyContext_FallsBack(t *testing.T) {
	got := captureAttrs(t, context.Background(), "TestSpan")

	if v, ok := got[AttrTenantID]; !ok || v.AsString() != auth.SystemTenantString {
		t.Errorf("tenant_id = %v, want %q", got[AttrTenantID], auth.SystemTenantString)
	}
	if v, ok := got[AttrUserID]; !ok || v.AsString() != unknownUserSentinel {
		t.Errorf("user_id = %v, want %q", got[AttrUserID], unknownUserSentinel)
	}
	if _, ok := got[AttrInitiatorUserID]; ok {
		t.Error("initiator_user_id should not be present on empty ctx")
	}
	if _, ok := got[AttrExecutorUserID]; ok {
		t.Error("executor_user_id should not be present on empty ctx")
	}
}

// TestEnrichSpan_TenantOnly asserts tenant_id is taken from context.
func TestEnrichSpan_TenantOnly(t *testing.T) {
	ctx := auth.ContextWithTenantString(context.Background(), "acme-corp")
	got := captureAttrs(t, ctx, "TestSpan")

	if v := got[AttrTenantID].AsString(); v != "acme-corp" {
		t.Errorf("tenant_id = %q, want acme-corp", v)
	}
	if v := got[AttrUserID].AsString(); v != unknownUserSentinel {
		t.Errorf("user_id = %q, want %q", v, unknownUserSentinel)
	}
}

// TestEnrichSpan_ActingUser asserts ActingUser populates user_id.
func TestEnrichSpan_ActingUser(t *testing.T) {
	ctx := auth.ContextWithActingUser(context.Background(), "user-alice")
	got := captureAttrs(t, ctx, "TestSpan")

	if v := got[AttrUserID].AsString(); v != "user-alice" {
		t.Errorf("user_id = %q, want user-alice", v)
	}
}

// TestEnrichSpan_InitiatorOnly_UserIDFallsBack asserts InitiatorUser is the
// user_id when no ActingUser is set, and that initiator_user_id is also
// written as its own attribute.
func TestEnrichSpan_InitiatorOnly_UserIDFallsBack(t *testing.T) {
	ctx := auth.ContextWithInitiatorUser(context.Background(), "user-initiator")
	got := captureAttrs(t, ctx, "TestSpan")

	if v := got[AttrUserID].AsString(); v != "user-initiator" {
		t.Errorf("user_id = %q, want user-initiator", v)
	}
	if v := got[AttrInitiatorUserID].AsString(); v != "user-initiator" {
		t.Errorf("initiator_user_id = %q, want user-initiator", v)
	}
}

// TestEnrichSpan_ActingAndInitiator_ActingWins asserts precedence: when both
// are set, user_id takes ActingUser but initiator_user_id is still present
// so downstream aggregation can distinguish them.
func TestEnrichSpan_ActingAndInitiator_ActingWins(t *testing.T) {
	ctx := auth.ContextWithActingUser(context.Background(), "user-acting")
	ctx = auth.ContextWithInitiatorUser(ctx, "user-initiator")
	got := captureAttrs(t, ctx, "TestSpan")

	if v := got[AttrUserID].AsString(); v != "user-acting" {
		t.Errorf("user_id = %q, want user-acting (acting wins)", v)
	}
	if v := got[AttrInitiatorUserID].AsString(); v != "user-initiator" {
		t.Errorf("initiator_user_id = %q, want user-initiator", v)
	}
}

// TestEnrichSpan_ExecutorSet asserts executor_user_id is written when set.
func TestEnrichSpan_ExecutorSet(t *testing.T) {
	ctx := auth.ContextWithInitiatorUser(context.Background(), "user-alice")
	ctx = auth.ContextWithExecutorUser(ctx, "user-bob")
	got := captureAttrs(t, ctx, "TestSpan")

	if v := got[AttrInitiatorUserID].AsString(); v != "user-alice" {
		t.Errorf("initiator_user_id = %q, want user-alice", v)
	}
	if v := got[AttrExecutorUserID].AsString(); v != "user-bob" {
		t.Errorf("executor_user_id = %q, want user-bob", v)
	}
}

// TestEnrichSpan_ComponentScopeSet asserts component_scope is written.
func TestEnrichSpan_ComponentScopeSet(t *testing.T) {
	ctx := auth.ContextWithComponentScope(context.Background(), "agent_principal:agent-xyz")
	got := captureAttrs(t, ctx, "TestSpan")

	if v := got[AttrComponentScope].AsString(); v != "agent_principal:agent-xyz" {
		t.Errorf("component_scope = %q, want agent_principal:agent-xyz", v)
	}
}

// TestEnrichSpan_MissionContextKeys asserts mission_id / run_id / agent_id /
// agent_run_id all flow from contextkeys into attributes.
func TestEnrichSpan_MissionContextKeys(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, contextkeys.MissionID, "mission-1")
	ctx = contextkeys.WithMissionRunID(ctx, "run-1")
	ctx = context.WithValue(ctx, contextkeys.AgentName, "nmap-agent")
	ctx = contextkeys.WithAgentRunID(ctx, "agentrun-1")

	got := captureAttrs(t, ctx, "TestSpan")

	if v := got[AttrMissionID].AsString(); v != "mission-1" {
		t.Errorf("mission_id = %q, want mission-1", v)
	}
	if v := got[AttrRunID].AsString(); v != "run-1" {
		t.Errorf("run_id = %q, want run-1", v)
	}
	if v := got[AttrAgentID].AsString(); v != "nmap-agent" {
		t.Errorf("agent_id = %q, want nmap-agent", v)
	}
	if v := got[AttrAgentRunID].AsString(); v != "agentrun-1" {
		t.Errorf("agent_run_id = %q, want agentrun-1", v)
	}
}

// TestEnrichSpan_SlotName asserts slot_name flows through ContextWithSlotName.
func TestEnrichSpan_SlotName(t *testing.T) {
	ctx := ContextWithSlotName(context.Background(), "reasoner")
	got := captureAttrs(t, ctx, "TestSpan")

	if v := got[AttrSlotName].AsString(); v != "reasoner" {
		t.Errorf("slot_name = %q, want reasoner", v)
	}
}

// TestEnrichSpan_SlotName_EmptyIsIgnored asserts that ContextWithSlotName("")
// does not populate the attribute.
func TestEnrichSpan_SlotName_EmptyIsIgnored(t *testing.T) {
	ctx := ContextWithSlotName(context.Background(), "")
	got := captureAttrs(t, ctx, "TestSpan")

	if _, ok := got[AttrSlotName]; ok {
		t.Error("empty slot name should not be written as attribute")
	}
}

// TestEnrichSpan_NilSpanIsNoop asserts calling with a nil span does not panic.
func TestEnrichSpan_NilSpanIsNoop(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked on nil span: %v", r)
		}
	}()
	EnrichSpan(context.Background(), nil)
}

// TestEnrichSpan_NilContextIsNoop asserts calling with a nil context does
// not panic. Go's context.Value will panic on nil; EnrichSpan must guard.
func TestEnrichSpan_NilContextIsNoop(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	_, span := tp.Tracer("test").Start(context.Background(), "TestSpan")
	defer span.End()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked on nil ctx: %v", r)
		}
	}()
	//nolint:staticcheck // nil ctx is the branch under test
	EnrichSpan(nil, span)
}

// TestEnrichSpan_UnknownUserIncrementsCounter asserts the Prometheus
// counter increments when user identity is unresolvable.
func TestEnrichSpan_UnknownUserIncrementsCounter(t *testing.T) {
	// Force counter registration before measuring so the first test run
	// and subsequent runs see a stable baseline.
	initUnknownUserCounter()

	before := testutil.ToFloat64(unknownUserCounter.WithLabelValues("UnknownSpan1"))
	captureAttrs(t, context.Background(), "UnknownSpan1")
	after := testutil.ToFloat64(unknownUserCounter.WithLabelValues("UnknownSpan1"))

	if after-before != 1 {
		t.Errorf("counter delta = %v, want 1", after-before)
	}
}

// TestEnrichSpan_KnownUserDoesNotIncrementCounter asserts the counter is
// silent when user identity IS resolvable.
func TestEnrichSpan_KnownUserDoesNotIncrementCounter(t *testing.T) {
	initUnknownUserCounter()

	ctx := auth.ContextWithActingUser(context.Background(), "user-known")
	before := testutil.ToFloat64(unknownUserCounter.WithLabelValues("KnownSpan"))
	captureAttrs(t, ctx, "KnownSpan")
	after := testutil.ToFloat64(unknownUserCounter.WithLabelValues("KnownSpan"))

	if after-before != 0 {
		t.Errorf("counter delta = %v, want 0", after-before)
	}
}
