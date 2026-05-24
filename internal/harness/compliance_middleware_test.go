package harness

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/contextkeys"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/types"
	sdkagent "github.com/zero-day-ai/sdk/agent"
	taxonomypb "github.com/zero-day-ai/sdk/api/gen/taxonomy/v1"
	"github.com/zero-day-ai/sdk/auth"
	"github.com/zero-day-ai/sdk/codegen/workspace"
	sdktypes "github.com/zero-day-ai/sdk/types"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
)

// fakeSink captures emitted signals for assertion.
type fakeSink struct {
	mu      sync.Mutex
	signals []*taxonomypb.ComplianceSignal
	err     error
	panic   bool
}

func (s *fakeSink) Emit(ctx context.Context, sig *taxonomypb.ComplianceSignal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.panic {
		panic("fakeSink: simulated panic")
	}
	s.signals = append(s.signals, sig)
	return s.err
}

func (s *fakeSink) Signals() []*taxonomypb.ComplianceSignal {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*taxonomypb.ComplianceSignal, len(s.signals))
	copy(out, s.signals)
	return out
}

// minimalMiddleware builds a ComplianceMiddleware with a fake sink and no
// inner harness — suitable for tests that only exercise the beginSignal /
// completeSignal / emit pipeline directly.
func minimalMiddleware(t *testing.T, sink *fakeSink) *ComplianceMiddleware {
	t.Helper()
	m, err := NewComplianceMiddleware(ComplianceMiddlewareConfig{
		Inner: &noopInnerHarness{},
		Sink:  sink,
	})
	if err != nil {
		t.Fatalf("NewComplianceMiddleware: %v", err)
	}
	return m
}

// noopInnerHarness is a minimal stub of AgentHarness for middleware tests
// that only exercise the beginSignal/completeSignal/emit pipeline directly
// without actually calling through the middleware's method wrappers.
// Every method returns zero values.
type noopInnerHarness struct{}

var _ AgentHarness = (*noopInnerHarness)(nil)

func (*noopInnerHarness) Complete(context.Context, string, []llm.Message, ...CompletionOption) (*llm.CompletionResponse, error) {
	return nil, nil
}
func (*noopInnerHarness) CompleteWithTools(context.Context, string, []llm.Message, []llm.ToolDef, ...CompletionOption) (*llm.CompletionResponse, error) {
	return nil, nil
}
func (*noopInnerHarness) Stream(context.Context, string, []llm.Message, ...CompletionOption) (<-chan llm.StreamChunk, error) {
	return nil, nil
}
func (*noopInnerHarness) CompleteStructuredAny(context.Context, string, []llm.Message, any, ...CompletionOption) (any, error) {
	return nil, nil
}
func (*noopInnerHarness) CompleteStructuredAnyWithUsage(context.Context, string, []llm.Message, any, ...CompletionOption) (*StructuredCompletionResult, error) {
	return nil, nil
}
func (*noopInnerHarness) CallToolProto(context.Context, string, proto.Message, proto.Message) error {
	return nil
}
func (*noopInnerHarness) CallToolProtoStream(context.Context, string, proto.Message, proto.Message, sdkagent.ToolStreamCallback) error {
	return nil
}
func (*noopInnerHarness) ListTools() []ToolDescriptor { return nil }
func (*noopInnerHarness) GetToolDescriptor(context.Context, string) (*ToolDescriptor, error) {
	return nil, nil
}
func (*noopInnerHarness) GetToolCapabilities(context.Context, string) (*sdktypes.Capabilities, error) {
	return nil, nil
}
func (*noopInnerHarness) GetAllToolCapabilities(context.Context) (map[string]*sdktypes.Capabilities, error) {
	return nil, nil
}
func (*noopInnerHarness) QueryPlugin(context.Context, string, string, map[string]any) (any, error) {
	return nil, nil
}
func (*noopInnerHarness) ListPlugins() []PluginDescriptor { return nil }
func (*noopInnerHarness) DelegateToAgent(context.Context, string, agent.Task) (agent.Result, error) {
	return agent.Result{}, nil
}
func (*noopInnerHarness) ListAgents() []AgentDescriptor { return nil }
func (*noopInnerHarness) SubmitFinding(context.Context, agent.Finding) error {
	return nil
}
func (*noopInnerHarness) GetFindings(context.Context, FindingFilter) ([]agent.Finding, error) {
	return nil, nil
}
func (*noopInnerHarness) Memory() memory.MemoryStore { return nil }
func (*noopInnerHarness) MissionID() types.ID        { return "" }
func (*noopInnerHarness) Mission() MissionContext    { return MissionContext{} }
func (*noopInnerHarness) MissionExecutionContext() MissionExecutionContextSDK {
	return MissionExecutionContextSDK{}
}
func (*noopInnerHarness) GetMissionRunHistory(context.Context) ([]MissionRunSummarySDK, error) {
	return nil, nil
}
func (*noopInnerHarness) GetPreviousRunFindings(context.Context, FindingFilter) ([]agent.Finding, error) {
	return nil, nil
}
func (*noopInnerHarness) GetAllRunFindings(context.Context, FindingFilter) ([]agent.Finding, error) {
	return nil, nil
}
func (*noopInnerHarness) Target() TargetInfo            { return TargetInfo{} }
func (*noopInnerHarness) Checkpoint() CheckpointAccess  { return nil }
func (*noopInnerHarness) Tracer() trace.Tracer          { return nil }
func (*noopInnerHarness) Logger() *slog.Logger          { return slog.Default() }
func (*noopInnerHarness) Metrics() MetricsRecorder      { return nil }
func (*noopInnerHarness) TokenUsage() *llm.TokenTracker { return nil }
func (*noopInnerHarness) Workspace() workspace.Workspace {
	return nil
}
func (*noopInnerHarness) Workspaces() map[string]workspace.Workspace {
	return map[string]workspace.Workspace{}
}

func TestComplianceMiddleware_IdentityStamping_Full(t *testing.T) {
	sink := &fakeSink{}
	m := minimalMiddleware(t, sink)

	id := auth.Identity{
		Subject:        "user-123",
		Issuer:         "zitadel",
		CredentialType: "oidc",
		Tenant:         auth.MustNewTenantID("tenant-a"),
	}
	// Use WithIdentity directly; ContextWithTenantString calls WithTenant which
	// replaces the whole Identity (losing Subject), so only WithIdentity is correct here.
	ctx := auth.WithIdentity(context.Background(), id)

	sip := m.beginSignal(ctx, MethodComplete, LLMTarget{Slot: "primary"})
	m.completeSignal(ctx, sip, nil)
	m.emit(ctx, sip)

	sigs := sink.Signals()
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(sigs))
	}
	got := sigs[0]
	if got.ActorId != "user-123" {
		t.Errorf("ActorId = %q; want user-123", got.ActorId)
	}
	if got.ActorTenantId != "tenant-a" {
		t.Errorf("ActorTenantId = %q; want tenant-a", got.ActorTenantId)
	}
	// Roles are no longer carried in the daemon identity (FGA handles authz);
	// RolesSnapshot is always empty in the new model.
	if len(got.RolesSnapshot) != 0 {
		t.Errorf("RolesSnapshot = %v; want empty (roles removed from daemon identity)", got.RolesSnapshot)
	}
	if got.Decision != DecisionNotChecked {
		t.Errorf("Decision = %q; want not_checked (no authz in context)", got.Decision)
	}
}

func TestComplianceMiddleware_IdentityStamping_SystemSentinel(t *testing.T) {
	sink := &fakeSink{}
	m := minimalMiddleware(t, sink)
	ctx := context.Background()

	sip := m.beginSignal(ctx, MethodComplete, LLMTarget{Slot: "primary"})
	m.completeSignal(ctx, sip, nil)
	m.emit(ctx, sip)

	sigs := sink.Signals()
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(sigs))
	}
	got := sigs[0]
	if got.ActorId != systemSentinel {
		t.Errorf("ActorId = %q; want %q", got.ActorId, systemSentinel)
	}
	if got.ActorTenantId != systemSentinel {
		t.Errorf("ActorTenantId = %q; want %q", got.ActorTenantId, systemSentinel)
	}
	if !got.SystemOwned {
		t.Errorf("SystemOwned should be true when identity is missing")
	}
}

func TestComplianceMiddleware_AuthzDecisionCapture(t *testing.T) {
	sink := &fakeSink{}
	m := minimalMiddleware(t, sink)

	ctx := contextkeys.WithAuthzDecision(context.Background(), contextkeys.AuthzDecisionValue{
		Decision: DecisionAllow,
		PolicyID: "tools.execute",
		Reason:   "fga policy allow",
	})

	sip := m.beginSignal(ctx, MethodCallToolProto, ToolCallTarget{Name: "nmap"})
	m.completeSignal(ctx, sip, nil)
	m.emit(ctx, sip)

	sigs := sink.Signals()
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(sigs))
	}
	got := sigs[0]
	if got.Decision != DecisionAllow {
		t.Errorf("Decision = %q; want allow", got.Decision)
	}
	if got.PolicyId == nil || *got.PolicyId != "tools.execute" {
		t.Errorf("PolicyId = %v; want tools.execute", got.PolicyId)
	}
}

func TestComplianceMiddleware_OutcomeCapture_Success(t *testing.T) {
	sink := &fakeSink{}
	m := minimalMiddleware(t, sink)
	ctx := context.Background()

	sip := m.beginSignal(ctx, MethodComplete, LLMTarget{Slot: "primary"})
	m.completeSignal(ctx, sip, nil)
	m.emit(ctx, sip)

	sigs := sink.Signals()
	if !sigs[0].Success {
		t.Errorf("Success should be true on nil error")
	}
	if sigs[0].ErrorCode != nil {
		t.Errorf("ErrorCode should be nil on success")
	}
}

func TestComplianceMiddleware_OutcomeCapture_Error(t *testing.T) {
	sink := &fakeSink{}
	m := minimalMiddleware(t, sink)
	ctx := context.Background()

	sip := m.beginSignal(ctx, MethodComplete, LLMTarget{Slot: "primary"})
	m.completeSignal(ctx, sip, errors.New("context deadline exceeded"))
	m.emit(ctx, sip)

	sigs := sink.Signals()
	if sigs[0].Success {
		t.Errorf("Success should be false on error")
	}
	if sigs[0].ErrorCode == nil || *sigs[0].ErrorCode != "timeout" {
		t.Errorf("ErrorCode = %v; want 'timeout'", sigs[0].ErrorCode)
	}
}

func TestComplianceMiddleware_FailureIsolation_SinkError(t *testing.T) {
	sink := &fakeSink{err: errors.New("neo4j unavailable")}
	m := minimalMiddleware(t, sink)
	ctx := context.Background()

	sip := m.beginSignal(ctx, MethodComplete, LLMTarget{Slot: "primary"})
	m.completeSignal(ctx, sip, nil)
	m.emit(ctx, sip) // must not panic or block

	if m.BufferLen() != 1 {
		t.Errorf("BufferLen = %d; want 1 (failed signal should be buffered)", m.BufferLen())
	}
}

func TestComplianceMiddleware_FailureIsolation_SinkPanic(t *testing.T) {
	sink := &fakeSink{panic: true}
	m := minimalMiddleware(t, sink)
	ctx := context.Background()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("emit should have recovered panic, instead got: %v", r)
		}
	}()

	sip := m.beginSignal(ctx, MethodComplete, LLMTarget{Slot: "primary"})
	m.completeSignal(ctx, sip, nil)
	m.emit(ctx, sip)
}

func TestComplianceMiddleware_BufferOverflow(t *testing.T) {
	sink := &fakeSink{err: errors.New("neo4j unavailable")}
	m, err := NewComplianceMiddleware(ComplianceMiddlewareConfig{
		Inner:         &noopInnerHarness{},
		Sink:          sink,
		FailBufferCap: 3, // tiny cap for test
	})
	if err != nil {
		t.Fatalf("NewComplianceMiddleware: %v", err)
	}
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		sip := m.beginSignal(ctx, MethodComplete, LLMTarget{Slot: "primary"})
		m.completeSignal(ctx, sip, nil)
		m.emit(ctx, sip)
	}

	if m.BufferLen() != 3 {
		t.Errorf("BufferLen = %d; want 3 (cap)", m.BufferLen())
	}
	// 5 failed signals, buffer cap 3 → 2 dropped.
	if got := counterValue(t, m.metrics.SignalsDropped); got != 2 {
		t.Errorf("SignalsDropped = %v; want 2", got)
	}
}

func TestComplianceMiddleware_DisabledIsNoOp(t *testing.T) {
	sink := &fakeSink{}
	m := minimalMiddleware(t, sink)
	m.SetDisabled(true)
	ctx := context.Background()

	sip := m.beginSignal(ctx, MethodComplete, LLMTarget{Slot: "primary"})
	m.completeSignal(ctx, sip, nil)
	m.emit(ctx, sip)

	if len(sink.Signals()) != 0 {
		t.Errorf("disabled middleware should not emit; got %d", len(sink.Signals()))
	}
}

func TestComplianceMiddleware_CoveredMethodCount(t *testing.T) {
	sink := &fakeSink{}
	m := minimalMiddleware(t, sink)
	count := m.CoveredMethodCount()
	if count < 10 {
		// Sanity: at least ten methods should emit signals.
		t.Errorf("CoveredMethodCount = %d; want >= 10", count)
	}
}

func TestComplianceHealthCheck_Thresholds(t *testing.T) {
	sink := &fakeSink{err: errors.New("boom")}
	m, err := NewComplianceMiddleware(ComplianceMiddlewareConfig{
		Inner:         &noopInnerHarness{},
		Sink:          sink,
		FailBufferCap: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	hc := NewComplianceHealthCheck(m)

	// Empty buffer → healthy.
	if hc.Health(context.Background()).State.String() != "healthy" {
		t.Errorf("empty buffer should be healthy")
	}

	// Fill to 80% → degraded.
	for i := 0; i < 8; i++ {
		sip := m.beginSignal(context.Background(), MethodComplete, LLMTarget{Slot: "s"})
		m.completeSignal(context.Background(), sip, nil)
		m.emit(context.Background(), sip)
	}
	state := hc.Health(context.Background()).State.String()
	if state != "degraded" {
		t.Errorf("80%% buffer should be degraded, got %q", state)
	}

	// Fill to 100% → unhealthy.
	for i := 0; i < 3; i++ {
		sip := m.beginSignal(context.Background(), MethodComplete, LLMTarget{Slot: "s"})
		m.completeSignal(context.Background(), sip, nil)
		m.emit(context.Background(), sip)
	}
	state = hc.Health(context.Background()).State.String()
	if state != "unhealthy" {
		t.Errorf("full buffer should be unhealthy, got %q", state)
	}
}
