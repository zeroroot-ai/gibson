// Package observability — span_enrich.go
//
// EnrichSpan is the single helper that applies Gibson's canonical identity +
// mission attribute set to an OpenTelemetry span. It is the contract between
// the spec `llm-user-attribution-governance` and every span-creation site in
// this package (mission, decision, agent, tool spans).
//
// Why it's a free function, not a method on the tracer: any caller that has
// (ctx, span) should be able to enrich uniformly without holding a tracer
// reference, and keeping it pure lets callers instrument custom span paths
// (e.g., future budget.Enforcer spans, modelgate.Filter spans) without a
// dependency on OTelMissionTracer.
//
// Unknown-user fallback: when no user identity is resolvable, the `user_id`
// attribute is set to "unknown" and the `gibson_span_unknown_user_total`
// Prometheus counter is incremented (registered in metrics.go). This is a
// deliberate visibility signal — operators can detect unattributed LLM
// traffic without the call itself failing.

package observability

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/zeroroot-ai/gibson/internal/contextkeys"
	"github.com/zeroroot-ai/sdk/auth"
)

// Attribute keys applied by EnrichSpan. Flat (no "gibson." prefix) so they
// map cleanly into the trace metadata surface, which treats
// dotted OTel semantic-convention keys specially. These are deliberately
// separate from the gibson.* attributes defined in attributes.go — the
// gibson.* set is the internal-dashboard attribute vocabulary; these are
// the cross-observability-vendor identity vocabulary.
const (
	// AttrTenantID carries the tenant ID on every span.
	AttrTenantID = "tenant_id"

	// AttrUserID carries the effective user ID — the ActingUser when present
	// (synchronous RPC caller), else the InitiatorUser (mission originator),
	// else the literal "unknown".
	AttrUserID = "user_id"

	// AttrInitiatorUserID carries the mission-initiator user ID — stable
	// across sub-agent delegation, checkpoint/resume, and retries.
	AttrInitiatorUserID = "initiator_user_id"

	// AttrExecutorUserID carries the currently executing agent's owner user
	// ID. Differs from initiator when a parent agent delegates to a
	// sub-agent owned by a different user.
	AttrExecutorUserID = "executor_user_id"

	// AttrMissionID carries the mission ID (flat key, complements the
	// dotted gibson.mission.id attribute set by the tracer).
	AttrMissionID = "mission_id"

	// AttrRunID carries the mission run ID.
	AttrRunID = "run_id"

	// AttrAgentID carries the currently executing agent's name.
	AttrAgentID = "agent_id"

	// AttrAgentRunID carries the current agent's run ID (delegation-scoped).
	AttrAgentRunID = "agent_run_id"

	// AttrComponentScope carries the agent-principal component scope when the
	// request was authenticated via a capability grant.
	AttrComponentScope = "component_scope"

	// AttrSlotName carries the LLM slot name the agent requested.
	AttrSlotName = "slot_name"

	// unknownUserSentinel is the value emitted when user identity cannot
	// be resolved from any context key. Paired with a counter increment.
	unknownUserSentinel = "unknown"

	// tenantFallback is the value emitted when no tenant is resolvable.
	// Uses the system-tenant sentinel so that un-attributed spans are
	// visibly owned by the platform operator, not a phantom "default" tenant.
	tenantFallback = auth.SystemTenantString
)

// EnrichSpan applies Gibson's canonical identity + mission attribute set
// to span from the values present in ctx. Safe to call with a nil span or
// a nil context; both become no-ops.
//
// Attribute rules:
//   - tenant_id is always set (falls back to "_system" when absent).
//   - user_id is always set (falls back to "unknown" when absent; the
//     fallback also increments gibson_span_unknown_user_total).
//   - Every other attribute is set only when its source is present in ctx.
//
// Call this at the end of every span-creation site AFTER writing the
// span-specific attributes. Attribute writes are idempotent so calling
// EnrichSpan twice on the same span is safe; the second call just
// overwrites with the same values.
func EnrichSpan(ctx context.Context, span trace.Span) {
	if span == nil || ctx == nil {
		return
	}

	// Tenant — always set; falls back to auth.SystemTenantString ("_system")
	// when no identity is present so un-attributed spans are auditable.
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		tenantID = tenantFallback
	}

	// Effective user: ActingUser first (synchronous RPC caller), then
	// InitiatorUser (mission-stable), then fall back to the unknown sentinel
	// and bump the metric so operators can triage the gap.
	var effectiveUser string
	if v, ok := auth.ActingUserFromContext(ctx); ok {
		effectiveUser = v
	} else if v, ok := auth.InitiatorUserFromContext(ctx); ok {
		effectiveUser = v
	} else {
		effectiveUser = unknownUserSentinel
		recordUnknownUserSpan(ctx, span)
	}

	attrs := make([]attribute.KeyValue, 0, 12)
	attrs = append(attrs,
		attribute.String(AttrTenantID, tenantID),
		attribute.String(AttrUserID, effectiveUser),
	)

	// Initiator / Executor — set only when present so filters don't see ""
	// or "unknown" noise for spans that legitimately have no initiator
	// (e.g., health probes).
	if v, ok := auth.InitiatorUserFromContext(ctx); ok {
		attrs = append(attrs, attribute.String(AttrInitiatorUserID, v))
	}
	if v, ok := auth.ExecutorUserFromContext(ctx); ok {
		attrs = append(attrs, attribute.String(AttrExecutorUserID, v))
	}

	// Component scope — present when the RPC arrived via a capability grant.
	if v := auth.ComponentScopeFromContext(ctx); v != "" {
		attrs = append(attrs, attribute.String(AttrComponentScope, v))
	}

	// Mission / Run / Agent — read from the shared contextkeys package
	// (populated by the mission and harness layers). Each is optional.
	if v := contextkeys.GetMissionRunID(ctx); v != "" {
		attrs = append(attrs, attribute.String(AttrRunID, v))
	}
	if v, ok := ctx.Value(contextkeys.MissionID).(string); ok && v != "" {
		attrs = append(attrs, attribute.String(AttrMissionID, v))
	}
	if v, ok := ctx.Value(contextkeys.AgentName).(string); ok && v != "" {
		attrs = append(attrs, attribute.String(AttrAgentID, v))
	}
	if v := contextkeys.GetAgentRunID(ctx); v != "" {
		attrs = append(attrs, attribute.String(AttrAgentRunID, v))
	}
	if v, ok := slotNameFromContext(ctx); ok {
		attrs = append(attrs, attribute.String(AttrSlotName, v))
	}

	span.SetAttributes(attrs...)
}

// slotNameContextKey is the context key used to thread the current LLM slot
// name through to EnrichSpan. Set by the daemon's ExecuteLLM handler when
// it knows the slot, read here to attribute the resulting span.
type slotNameContextKey struct{}

// ContextWithSlotName stores the LLM slot name in ctx for span attribution.
// Callers set this immediately before dispatching an LLM call so the child
// span (and any span created between now and dispatch) carries the slot.
func ContextWithSlotName(ctx context.Context, slot string) context.Context {
	if slot == "" {
		return ctx
	}
	return context.WithValue(ctx, slotNameContextKey{}, slot)
}

// slotNameFromContext returns the slot name previously stored by
// ContextWithSlotName, and true if present.
func slotNameFromContext(ctx context.Context) (string, bool) {
	if v, ok := ctx.Value(slotNameContextKey{}).(string); ok && v != "" {
		return v, true
	}
	return "", false
}
