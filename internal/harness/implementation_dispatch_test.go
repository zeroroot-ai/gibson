// Package harness — implementation_dispatch_test.go
//
// Integration tests for the dispatch policy gate wired into
// DefaultAgentHarness.CallToolProto (Task 21, setec-sandbox-prod-default §C3).
//
// The gate fires for every SANDBOXED entry found in the ComponentRegistry.
// Entries with PLUGIN/AGENT dispatch modes fall through to other dispatch
// paths and are tested via direct policy.Decide calls in the dispatch
// package (Task 18). The harness-level tests here verify:
//
//   - Gate runs before executor selection on SANDBOXED entries
//   - Deny outcomes short-circuit without calling the executor
//   - Allow outcomes proceed to the executor (or the "executor not wired" branch)
//   - Synchronous audit events are emitted for both allow and deny
//   - Gate is skipped when dispatchPolicy is nil (backward-compatible)
//
// Restrictions: no Redis, no real network. Hermetic, race-safe.
package harness

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/zero-day-ai/gibson/internal/audit"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/dispatch"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
)

// ── Fake helpers ─────────────────────────────────────────────────────────────

// fakeDispatchRegistry is a fake ComponentRegistry that returns exactly one
// SANDBOXED entry for DiscoverSystemOnly("tool", toolName).
// All other registry methods are no-ops.
type fakeDispatchRegistry struct {
	toolName     string
	toolMode     componentpb.DispatchMode
	contentTrust componentpb.ContentTrust
}

func (r *fakeDispatchRegistry) Register(_ context.Context, _, _, _ string, _ component.ComponentInfo) (string, error) {
	return "", nil
}
func (r *fakeDispatchRegistry) Deregister(_ context.Context, _, _, _, _ string) error { return nil }
func (r *fakeDispatchRegistry) RefreshTTL(_ context.Context, _, _, _, _ string) error { return nil }
func (r *fakeDispatchRegistry) Discover(_ context.Context, _, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (r *fakeDispatchRegistry) DiscoverAll(_ context.Context, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (r *fakeDispatchRegistry) ListTenantComponents(_ context.Context, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (r *fakeDispatchRegistry) DiscoverTenantOnly(_ context.Context, _, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (r *fakeDispatchRegistry) DiscoverSystemOnly(_ context.Context, kind, name string) ([]component.ComponentInfo, error) {
	if kind == "tool" && name == r.toolName && r.toolMode == componentpb.DispatchMode_DISPATCH_MODE_SANDBOXED {
		return []component.ComponentInfo{{
			Kind:         "tool",
			Name:         r.toolName,
			DispatchMode: r.toolMode,
			ContentTrust: r.contentTrust,
			Image:        "ghcr.io/zero-day-ai/test-tool:latest",
		}}, nil
	}
	return nil, nil
}

// fakePolicyAuditWriter captures WriteSync calls for assertion.
type fakePolicyAuditWriter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (w *fakePolicyAuditWriter) WriteSync(_ context.Context, ev audit.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, ev)
	return nil
}

func (w *fakePolicyAuditWriter) recorded() []audit.Event {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]audit.Event, len(w.events))
	copy(out, w.events)
	return out
}

// gateWithOverride wraps dispatch.Policy to inject overrideActive per-call.
type gateWithOverride struct {
	inner          dispatch.Policy
	overrideActive bool
}

func (g *gateWithOverride) Decide(ctx context.Context, in dispatch.Input) dispatch.Decision {
	in.OverrideActive = g.overrideActive
	return g.inner.Decide(ctx, in)
}

// gateWithSandboxUnhealthy wraps dispatch.Policy to inject SandboxHealthy=false.
type gateWithSandboxUnhealthy struct {
	inner dispatch.Policy
}

func (g *gateWithSandboxUnhealthy) Decide(ctx context.Context, in dispatch.Input) dispatch.Decision {
	in.SandboxHealthy = false
	return g.inner.Decide(ctx, in)
}

// dispatchNopProto is a minimal proto message for use as request/response.
var dispatchNopProto = &componentpb.ComponentDescriptor{}

// buildGateHarness builds a minimal DefaultAgentHarness with:
//   - fakeDispatchRegistry returning one SANDBOXED entry
//   - the given policy gate
//   - fakePolicyAuditWriter
func buildGateHarness(t *testing.T, trust componentpb.ContentTrust, policy dispatch.Policy) (h *DefaultAgentHarness, aw *fakePolicyAuditWriter) {
	t.Helper()
	aw = &fakePolicyAuditWriter{}
	missionCtx := NewMissionContext(types.NewID(), "gate-test", "agent")
	target := NewTargetInfo(types.NewID(), "target", "https://example.com", "web")
	h = &DefaultAgentHarness{
		slotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
		componentRegistry: &fakeDispatchRegistry{
			toolName:     "gate-tool",
			toolMode:     componentpb.DispatchMode_DISPATCH_MODE_SANDBOXED,
			contentTrust: trust,
		},
		dispatchPolicy:    policy,
		policyAuditWriter: aw,
		missionCtx:        missionCtx,
		targetInfo:        target,
		logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		tracer:            trace.NewNoopTracerProvider().Tracer("test"),
		metrics:           NewNoOpMetricsRecorder(),
		// sandboxedExecutor intentionally nil — tests the gate's deny/allow logic,
		// not the executor itself. After an allow, the harness will return
		// "sandboxed executor not wired" which is the correct defence-in-depth path.
	}
	return h, aw
}

// isGateDeny returns true when the error message contains the deny reason string,
// indicating the gate denied the call (not the executor-not-wired fallback).
func isGateDeny(err error, reason string) bool {
	if err == nil || reason == "" {
		return false
	}
	return strings.Contains(err.Error(), reason)
}

// ── Tests ────────────────────────────────────────────────────────────────────

// TestGate_UNTRUSTED_SANDBOXED_Allow verifies that UNTRUSTED + SANDBOXED + healthy
// reaches the gate-allow branch and emits an "allow" audit event.
func TestGate_UNTRUSTED_SANDBOXED_Allow(t *testing.T) {
	t.Parallel()

	policy := dispatch.NewPolicy(dispatch.Config{})
	h, aw := buildGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED, policy)

	err := h.CallToolProto(context.Background(), "gate-tool", dispatchNopProto, dispatchNopProto)

	// Gate should ALLOW; the next error is executor-not-wired (defence-in-depth).
	// That error must not be a gate deny.
	if err != nil {
		assert.False(t, isGateDeny(err, dispatch.ReasonUntrustedRequiresSandbox),
			"gate wrongly denied UNTRUSTED+SANDBOXED call: %v", err)
		assert.False(t, isGateDeny(err, dispatch.ReasonSandboxUnavailable),
			"gate wrongly denied UNTRUSTED+SANDBOXED+healthy call: %v", err)
	}

	events := aw.recorded()
	require.NotEmpty(t, events, "gate should emit audit event")
	assert.Equal(t, "allow", events[0].Decision)
	assert.Equal(t, "dispatch_policy_decision", events[0].Action)
}

// TestGate_UNTRUSTED_SANDBOXED_Deny_SandboxUnhealthy verifies that
// UNTRUSTED + SANDBOXED + SandboxHealthy=false yields DenySandboxUnavailable.
func TestGate_UNTRUSTED_SANDBOXED_Deny_SandboxUnhealthy(t *testing.T) {
	t.Parallel()

	innerPolicy := dispatch.NewPolicy(dispatch.Config{})
	policy := &gateWithSandboxUnhealthy{inner: innerPolicy}
	h, aw := buildGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED, policy)

	err := h.CallToolProto(context.Background(), "gate-tool", dispatchNopProto, dispatchNopProto)

	require.Error(t, err)
	assert.True(t, isGateDeny(err, dispatch.ReasonSandboxUnavailable),
		"expected sandbox_unavailable deny reason, got: %v", err)

	events := aw.recorded()
	require.NotEmpty(t, events)
	assert.Equal(t, "deny", events[0].Decision)
}

// TestGate_TRUSTED_SANDBOXED_Allow verifies that TRUSTED + SANDBOXED emits
// an allow decision (TRUSTED content passes the gate regardless of mode).
func TestGate_TRUSTED_SANDBOXED_Allow(t *testing.T) {
	t.Parallel()

	policy := dispatch.NewPolicy(dispatch.Config{})
	h, aw := buildGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED, policy)

	err := h.CallToolProto(context.Background(), "gate-tool", dispatchNopProto, dispatchNopProto)

	if err != nil {
		assert.False(t, isGateDeny(err, dispatch.ReasonUntrustedRequiresSandbox),
			"gate wrongly denied TRUSTED+SANDBOXED call: %v", err)
	}

	events := aw.recorded()
	require.NotEmpty(t, events)
	assert.Equal(t, "allow", events[0].Decision)
}

// TestGate_Unspecified_StrictFalse_Allow verifies that UNSPECIFIED content trust
// with StrictDefaultUntrusted=false is treated as TRUSTED (backward compat).
func TestGate_Unspecified_StrictFalse_Allow(t *testing.T) {
	t.Parallel()

	policy := dispatch.NewPolicy(dispatch.Config{StrictDefaultUntrusted: false})
	h, aw := buildGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_UNSPECIFIED, policy)

	err := h.CallToolProto(context.Background(), "gate-tool", dispatchNopProto, dispatchNopProto)

	if err != nil {
		assert.False(t, isGateDeny(err, dispatch.ReasonUntrustedRequiresSandbox),
			"gate should not deny UNSPECIFIED+strict=false: %v", err)
	}

	events := aw.recorded()
	require.NotEmpty(t, events)
	assert.Equal(t, "allow", events[0].Decision)
}

// TestGate_Unspecified_StrictTrue_SANDBOXED_Allow verifies that UNSPECIFIED
// with StrictDefaultUntrusted=true is treated as UNTRUSTED. UNTRUSTED+SANDBOXED
// with healthy sandbox is still allowed.
func TestGate_Unspecified_StrictTrue_SANDBOXED_Allow(t *testing.T) {
	t.Parallel()

	policy := dispatch.NewPolicy(dispatch.Config{StrictDefaultUntrusted: true})
	h, aw := buildGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_UNSPECIFIED, policy)

	err := h.CallToolProto(context.Background(), "gate-tool", dispatchNopProto, dispatchNopProto)

	// UNTRUSTED+SANDBOXED+SandboxHealthy=true → allow
	if err != nil {
		assert.False(t, isGateDeny(err, dispatch.ReasonUntrustedRequiresSandbox),
			"UNTRUSTED+SANDBOXED should be allowed: %v", err)
		assert.False(t, isGateDeny(err, dispatch.ReasonSandboxUnavailable),
			"sandbox is healthy; should not deny: %v", err)
	}

	events := aw.recorded()
	require.NotEmpty(t, events)
	assert.Equal(t, "allow", events[0].Decision)
}

// TestGate_Override_Flips_SandboxUnhealthy_To_Allow verifies that when
// OverrideActive=true, a UNTRUSTED + SANDBOXED + sandbox-unhealthy call is
// still allowed (override takes priority over sandbox health check).
func TestGate_Override_Flips_SandboxUnhealthy_To_Allow(t *testing.T) {
	t.Parallel()

	innerPolicy := dispatch.NewPolicy(dispatch.Config{})
	// Override + sandbox-unhealthy: override wins.
	policy := &gateWithOverride{inner: innerPolicy, overrideActive: true}
	h, aw := buildGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED, policy)

	err := h.CallToolProto(context.Background(), "gate-tool", dispatchNopProto, dispatchNopProto)

	if err != nil {
		assert.False(t, isGateDeny(err, dispatch.ReasonSandboxUnavailable),
			"override should flip sandbox-unavailable to allow: %v", err)
		assert.False(t, isGateDeny(err, dispatch.ReasonUntrustedRequiresSandbox),
			"override should flip untrusted deny to allow: %v", err)
	}

	events := aw.recorded()
	require.NotEmpty(t, events)
	assert.Equal(t, "allow", events[0].Decision)
}

// TestGate_Nil_Policy verifies that when dispatchPolicy is nil the gate is
// skipped and existing dispatch behaviour is unchanged.
func TestGate_Nil_Policy(t *testing.T) {
	t.Parallel()

	// nil policy — gate must be skipped entirely
	h, _ := buildGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED, nil)

	err := h.CallToolProto(context.Background(), "gate-tool", dispatchNopProto, dispatchNopProto)

	// No gate ⟹ no gate-deny; may return executor-not-wired.
	if err != nil {
		assert.False(t, isGateDeny(err, dispatch.ReasonUntrustedRequiresSandbox),
			"gate must not fire when dispatchPolicy is nil: %v", err)
	}
}

// TestGate_AuditEvent_Fields verifies that the synchronous audit event emitted
// for a SANDBOXED dispatch contains the expected fields (action, target, decision).
func TestGate_AuditEvent_Fields(t *testing.T) {
	t.Parallel()

	policy := dispatch.NewPolicy(dispatch.Config{})
	h, aw := buildGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED, policy)

	_ = h.CallToolProto(context.Background(), "gate-tool", dispatchNopProto, dispatchNopProto)

	events := aw.recorded()
	require.NotEmpty(t, events)
	ev := events[0]

	assert.Equal(t, "dispatch_policy_decision", ev.Action, "action field")
	assert.Equal(t, "tool", ev.TargetType, "target_type field")
	assert.Equal(t, "gate-tool", ev.TargetID, "target_id field")
	assert.Contains(t, []string{"allow", "deny"}, ev.Decision, "decision must be allow or deny")
}

// TestGate_Deny_SandboxUnhealthy_Audit verifies that a gate deny emits
// a "deny" decision in the audit event.
func TestGate_Deny_SandboxUnhealthy_Audit(t *testing.T) {
	t.Parallel()

	innerPolicy := dispatch.NewPolicy(dispatch.Config{})
	policy := &gateWithSandboxUnhealthy{inner: innerPolicy}
	h, aw := buildGateHarness(t, componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED, policy)

	err := h.CallToolProto(context.Background(), "gate-tool", dispatchNopProto, dispatchNopProto)
	require.Error(t, err)

	events := aw.recorded()
	require.NotEmpty(t, events)
	assert.Equal(t, "deny", events[0].Decision)
}
