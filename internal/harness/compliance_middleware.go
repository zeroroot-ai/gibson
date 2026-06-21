package harness

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/zeroroot-ai/gibson/internal/contextkeys"
	taxonomypb "github.com/zeroroot-ai/sdk/api/gen/taxonomy/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"go.opentelemetry.io/otel/trace"
)

// ComplianceRuleEvaluator is the narrow interface the middleware uses to
// run compliance rules against a signal before emission. This lives as an
// interface so the rules-catalog spec can wire in a real evaluator
// without the middleware having to import the catalog package at build
// time (avoiding a cycle with the SDK taxonomy package in test code).
type ComplianceRuleEvaluator interface {
	// Evaluate returns the matched control IDs for the given signal.
	// The tenant id is passed so the implementation can load tenant
	// overlays on top of system rules.
	Evaluate(sig *taxonomypb.ComplianceSignal, tenantID string) []string
}

// SignalSink is the persistence abstraction for compliance signals. Production
// uses a sink that packs signals into DiscoveryResult and hands them to the
// existing DiscoveryProcessor; tests substitute fakes.
type SignalSink interface {
	Emit(ctx context.Context, sig *taxonomypb.ComplianceSignal) error
}

// Clock is the minimal time abstraction used by the middleware so tests can
// substitute deterministic clocks. Production uses realClock{}.
type Clock interface {
	Now() time.Time
}

// realClock wraps time.Now.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// RealClock returns a Clock backed by time.Now, suitable for production.
func RealClock() Clock { return realClock{} }

// systemSentinel is the actor/tenant value stamped when the middleware runs
// in an internal daemon job with no inbound identity (Requirement 2.4).
const systemSentinel = "_system"

// ComplianceMiddleware wraps an AgentHarness and synthesizes a compliance
// signal for every method call. This file contains the struct, constructor,
// and the shared beginSignal / completeSignal / emit helpers used by the
// per-method interceptors in compliance_middleware_methods.go.
//
// Per Requirement 1.1, ComplianceMiddleware implements AgentHarness and is
// composed into the harness chain BEFORE the OTel wrapper so OTel spans
// capture emit overhead. Authorization decisions arrive on context from the
// gRPC FGA interceptor — see stampAuthzDecision below.
type ComplianceMiddleware struct {
	inner AgentHarness

	graphReader GraphReader
	sink        SignalSink
	resolver    *ResourceResolver
	merger      *TagMerger
	actionTable ActionTable
	clock       Clock
	logger      *slog.Logger
	metrics     *ComplianceMetrics

	// Rule evaluator from audit-compliance-rules-catalog. Optional —
	// nil = no rule evaluation, signals emit without control_ids stamped.
	ruleEvaluator ComplianceRuleEvaluator

	// Emergency disable flag (Requirement 12.2). When true, the middleware
	// becomes a pass-through: no signals are constructed or emitted. The
	// inner harness is still called normally.
	disabled bool
	disMu    sync.RWMutex

	// Bounded failure buffer for signals whose persistence failed. Ring
	// behavior: push-oldest-out. Consumed by the /readyz health check.
	failBuffer    []*taxonomypb.ComplianceSignal
	failBufferCap int
	failBufferMu  sync.Mutex
}

// ComplianceMiddlewareConfig groups the construction parameters so the
// constructor signature does not balloon as new dependencies are added.
type ComplianceMiddlewareConfig struct {
	Inner         AgentHarness
	GraphReader   GraphReader
	Sink          SignalSink
	Resolver      *ResourceResolver       // optional; constructed from GraphReader if nil
	Merger        *TagMerger              // optional; constructed from defaults if nil
	ActionTable   ActionTable             // optional; DefaultActionTable if nil
	Clock         Clock                   // optional; RealClock if nil
	Logger        *slog.Logger            // optional; slog.Default if nil
	Metrics       *ComplianceMetrics      // optional; NewComplianceMetrics if nil
	FailBufferCap int                     // 0 → DefaultFailBufferCap
	RuleEvaluator ComplianceRuleEvaluator // optional; no control_ids if nil
}

// DefaultFailBufferCap is the default size of the bounded failure buffer
// (Requirement 10.3).
const DefaultFailBufferCap = 10_000

// NewComplianceMiddleware constructs a ComplianceMiddleware with the given
// config. All required fields (Inner, GraphReader, Sink) must be non-nil;
// optional fields are defaulted.
func NewComplianceMiddleware(cfg ComplianceMiddlewareConfig) (*ComplianceMiddleware, error) {
	if cfg.Inner == nil {
		return nil, errors.New("compliance middleware: Inner harness is required")
	}
	if cfg.Sink == nil {
		return nil, errors.New("compliance middleware: Sink is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "compliance_middleware")

	metrics := cfg.Metrics
	if metrics == nil {
		metrics = NewComplianceMetrics()
	}

	resolver := cfg.Resolver
	if resolver == nil {
		resolver = NewResourceResolver(cfg.GraphReader, logger)
	}

	merger := cfg.Merger
	if merger == nil {
		merger = NewTagMerger(logger, metrics)
	}

	table := cfg.ActionTable
	if table == nil {
		table = DefaultActionTable()
	}

	clk := cfg.Clock
	if clk == nil {
		clk = RealClock()
	}

	bufCap := cfg.FailBufferCap
	if bufCap <= 0 {
		bufCap = DefaultFailBufferCap
	}

	return &ComplianceMiddleware{
		inner:         cfg.Inner,
		graphReader:   cfg.GraphReader,
		sink:          cfg.Sink,
		resolver:      resolver,
		merger:        merger,
		actionTable:   table,
		clock:         clk,
		logger:        logger,
		metrics:       metrics,
		failBufferCap: bufCap,
		ruleEvaluator: cfg.RuleEvaluator,
	}, nil
}

// SetDisabled toggles the emergency no-op flag. See Requirement 12.2.
// Thread-safe; can be called at any time.
func (m *ComplianceMiddleware) SetDisabled(disabled bool) {
	m.disMu.Lock()
	defer m.disMu.Unlock()
	m.disabled = disabled
	m.metrics.SetDisabled(disabled)
}

// isDisabled reads the current emergency-disable flag.
func (m *ComplianceMiddleware) isDisabled() bool {
	m.disMu.RLock()
	defer m.disMu.RUnlock()
	return m.disabled
}

// CoveredMethodCount returns the number of harness methods the middleware is
// configured to emit signals for. Used by daemon startup logging
// (Requirement 1.5).
func (m *ComplianceMiddleware) CoveredMethodCount() int {
	n := 0
	for _, e := range m.actionTable {
		if e.Emit {
			n++
		}
	}
	return n
}

// ────────────────────────────────────────────────────────────────────────────
// Signal construction pipeline
// ────────────────────────────────────────────────────────────────────────────

// beginSignal captures the state the middleware can see BEFORE the inner
// harness call — identity, tenant, action, resource, occurred_at, trace_id.
// The returned signal is completed by completeSignal after the inner call
// returns.
func (m *ComplianceMiddleware) beginSignal(
	ctx context.Context,
	method HarnessMethod,
	request any,
) *signalInProgress {
	start := m.clock.Now()

	entry, ok := m.actionTable.Lookup(method)
	if !ok {
		// Defensive fallback — the action table coverage test should make
		// this unreachable in practice.
		entry = ActionEntry{
			Action:        string(method),
			DefaultEffect: EffectNone,
			Emit:          false,
		}
	}

	sig := &taxonomypb.ComplianceSignal{
		SignalId:   uuid.New().String(),
		Action:     entry.Action,
		Effect:     entry.DefaultEffect,
		OccurredAt: start.UnixMilli(),
		Success:    true, // default; completeSignal flips on error
	}

	m.stampIdentity(ctx, sig)
	m.stampChain(ctx, sig)
	m.stampTraceID(ctx, sig)
	m.stampAuthzDecision(ctx, sig)

	// Pre-call resource resolution (for tool / LLM / memory / plugin / etc).
	res := m.resolver.Resolve(ctx, method, request)
	sig.ResourceType = res.ResourceType
	if res.ResourceNodeID != "" {
		id := res.ResourceNodeID
		sig.ResourceNodeId = &id
	}
	if res.ResourceURI != "" {
		uri := res.ResourceURI
		sig.ResourceUri = &uri
	}

	return &signalInProgress{
		signal:  sig,
		entry:   entry,
		method:  method,
		request: request,
		start:   start,
	}
}

// signalInProgress carries the in-flight signal plus the per-call bookkeeping
// that completeSignal needs to populate the outcome fields.
type signalInProgress struct {
	signal  *taxonomypb.ComplianceSignal
	entry   ActionEntry
	method  HarnessMethod
	request any
	start   time.Time
}

// completeSignal stamps outcome fields (latency, success, error_code) after
// the inner harness call returns. Callers pass the error they got back from
// the inner call (nil if the call succeeded).
func (m *ComplianceMiddleware) completeSignal(
	ctx context.Context,
	sip *signalInProgress,
	err error,
) {
	end := m.clock.Now()
	sip.signal.LatencyMs = end.Sub(sip.start).Milliseconds()

	if err != nil {
		sip.signal.Success = false
		code := classifyErrorCode(err)
		sip.signal.ErrorCode = &code
	}
}

// emit routes a completed signal through the persistence pipeline. Failure
// isolation (task 9) wraps this method in defer/recover and handles the
// bounded fail buffer.
func (m *ComplianceMiddleware) emit(ctx context.Context, sip *signalInProgress) {
	if m.isDisabled() {
		return
	}
	if !sip.entry.Emit {
		return
	}

	defer func() {
		if r := recover(); r != nil {
			m.logger.ErrorContext(ctx, "panic during compliance signal emission",
				slog.Any("panic", r),
				slog.String("method", string(sip.method)),
			)
			m.metrics.RecordPersistFailure("panic")
		}
	}()

	// Run the rule evaluator (if wired) BEFORE persistence so matched
	// control IDs land on the stored signal. Evaluator panics are
	// isolated so a broken rule cannot kill emission.
	if m.ruleEvaluator != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					m.logger.WarnContext(ctx, "panic during compliance rule evaluation",
						slog.Any("panic", r),
						slog.String("method", string(sip.method)),
					)
				}
			}()
			controlIDs := m.ruleEvaluator.Evaluate(sip.signal, sip.signal.ActorTenantId)
			if len(controlIDs) > 0 {
				sip.signal.ControlIds = controlIDs
			}
		}()
	}

	emitStart := m.clock.Now()
	err := m.sink.Emit(ctx, sip.signal)
	m.metrics.EmitLatency.Observe(m.clock.Now().Sub(emitStart).Seconds())

	if err != nil {
		m.metrics.RecordPersistFailure(classifySinkError(err))
		m.pushFailBuffer(sip.signal)
		m.logger.WarnContext(ctx, "compliance signal emission failed",
			slog.String("method", string(sip.method)),
			slog.String("action", sip.signal.Action),
			slog.String("error", err.Error()),
		)
		m.metrics.RecordEmitted(sip.signal.Action, sip.signal.Effect, false)
		return
	}
	m.metrics.RecordEmitted(sip.signal.Action, sip.signal.Effect, true)
}

// pushFailBuffer appends a failed signal to the bounded ring buffer, dropping
// the oldest entry on overflow and incrementing the drop counter.
func (m *ComplianceMiddleware) pushFailBuffer(sig *taxonomypb.ComplianceSignal) {
	m.failBufferMu.Lock()
	defer m.failBufferMu.Unlock()

	if len(m.failBuffer) >= m.failBufferCap {
		// drop oldest
		m.failBuffer = m.failBuffer[1:]
		m.metrics.SignalsDropped.Inc()
	}
	m.failBuffer = append(m.failBuffer, sig)
	m.metrics.SetBuffered(len(m.failBuffer))
}

// BufferLen returns the current depth of the fail buffer — used by the
// health check registered in task 14.
func (m *ComplianceMiddleware) BufferLen() int {
	m.failBufferMu.Lock()
	defer m.failBufferMu.Unlock()
	return len(m.failBuffer)
}

// BufferCap returns the maximum buffer depth.
func (m *ComplianceMiddleware) BufferCap() int {
	return m.failBufferCap
}

// ────────────────────────────────────────────────────────────────────────────
// Identity, chain, and authz stamping
// ────────────────────────────────────────────────────────────────────────────

// stampIdentity reads the caller identity and tenant from context and stamps
// actor_id, actor_tenant_id, api_key_id, roles_snapshot. Missing fields fall
// back to the system sentinel per Requirement 2.4.
func (m *ComplianceMiddleware) stampIdentity(ctx context.Context, sig *taxonomypb.ComplianceSignal) {
	id, err := auth.IdentityFromContext(ctx)
	if err != nil {
		sig.ActorId = systemSentinel
		sig.ActorTenantId = systemSentinel
		sig.SystemOwned = true
		return
	}

	sig.ActorId = id.Subject
	if sig.ActorId == "" {
		sig.ActorId = systemSentinel
	}

	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		tenant = systemSentinel
	}
	sig.ActorTenantId = tenant

	// For API key callers, Subject is the key ID; expose it for audit trails.
	if id.CredentialType == "apikey" && id.Subject != "" {
		subj := id.Subject
		sig.ApiKeyId = &subj
	}
	// Roles are no longer carried in the daemon identity (FGA handles authz);
	// RolesSnapshot is left empty.
}

// stampChain reads the delegation-chain context keys landed by the foundation
// spec and stamps the chain fields on the signal (Requirement 2.6).
func (m *ComplianceMiddleware) stampChain(ctx context.Context, sig *taxonomypb.ComplianceSignal) {
	if v := contextkeys.GetAgentRunID(ctx); v != "" {
		sig.AgentRunId = &v
	}
	if v := contextkeys.GetMissionRunID(ctx); v != "" {
		sig.MissionRunId = &v
	}
	if v, ok := ctx.Value(contextkeys.MissionID).(string); ok && v != "" {
		sig.MissionId = &v
	}
	if v, ok := contextkeys.GetParentAgentRunID(ctx); ok && v != "" {
		sig.ParentAgentRunId = &v
	}
	if chain, ok := contextkeys.GetCallerChain(ctx); ok && len(chain) > 0 {
		sig.CallerChain = append([]string{}, chain...)
	}
	if v, ok := contextkeys.GetCallerComponent(ctx); ok && v != "" {
		sig.CallerComponent = v
	}
	if v, ok := contextkeys.GetCallerComponentVersion(ctx); ok && v != "" {
		sig.CallerComponentVersion = v
	}
}

// stampTraceID copies the active OTel trace ID onto the signal so forensic
// replay via Loki/traces can join on a single field (Requirement 8.7).
func (m *ComplianceMiddleware) stampTraceID(ctx context.Context, sig *taxonomypb.ComplianceSignal) {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return
	}
	tid := span.SpanContext().TraceID().String()
	sig.TraceId = &tid
}

// stampAuthzDecision reads the decision the FGA gRPC interceptor stamped onto
// context and copies it onto the signal.
// Per Requirement 7.3, missing decisions default to "not_checked".
func (m *ComplianceMiddleware) stampAuthzDecision(ctx context.Context, sig *taxonomypb.ComplianceSignal) {
	dec, ok := contextkeys.GetAuthzDecision(ctx)
	if !ok {
		sig.Decision = DecisionNotChecked
		return
	}
	sig.Decision = dec.Decision
	if dec.PolicyID != "" {
		pid := dec.PolicyID
		sig.PolicyId = &pid
	}
	if dec.Reason != "" {
		r := dec.Reason
		sig.DecisionReason = &r
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Error classification helpers
// ────────────────────────────────────────────────────────────────────────────

// classifyErrorCode maps an arbitrary Go error to a stable error-code string
// drawn from a fixed allow-list. Raw error messages are NEVER used
// (Requirement 8.2) because they may contain customer data or secrets.
func classifyErrorCode(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case contains(msg, "context canceled"):
		return "canceled"
	case contains(msg, "deadline exceeded"):
		return "timeout"
	case contains(msg, "permission denied"), contains(msg, "PermissionDenied"):
		return "authorization_denied"
	case contains(msg, "unavailable"), contains(msg, "Unavailable"):
		return "backend_unavailable"
	case contains(msg, "quota"), contains(msg, "rate limit"):
		return "quota_exceeded"
	case contains(msg, "not found"), contains(msg, "NotFound"):
		return "not_found"
	case contains(msg, "invalid"), contains(msg, "validation"):
		return "invalid_argument"
	default:
		return "internal_error"
	}
}

// classifySinkError collapses a persistence error into a stable metric label.
func classifySinkError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case contains(msg, "neo4j"), contains(msg, "connection refused"), contains(msg, "unavailable"):
		return "neo4j_unavailable"
	case contains(msg, "validation"):
		return "validation_error"
	case contains(msg, "marshal"), contains(msg, "serialize"):
		return "serialization_error"
	default:
		return "internal_error"
	}
}

// contains is a case-insensitive substring check used for error
// classification. Lifted here to avoid an import of strings just for the
// ToLower + Contains pair.
func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	// Manual lower-case scan — short strings only.
	for i := 0; i+len(substr) <= len(s); i++ {
		if eqFold(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func eqFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
