package api

// server_entitlements_audit.go — classification helpers + emission shims
// used by the entitlements admin RPCs (WriteAccessTuples,
// UpsertTenantQuota, EmitAuditEvent) and the tenant-operator's
// reconciliation summary path.
//
// Classification logic is intentionally pure (no I/O, no logger) so it is
// easy to unit-test.
//
// Spec: access-matrix-finish task 17, R6.

import (
	"context"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson/internal/auth"
)

// classifyActorSource derives the "actor_source" audit field from the
// identity already attached to ctx by the auth interceptors.
//
// Mapping (R6 AC 2):
//   - apikey issuer         → "tenant_admin" (keys are tenant-scoped admin
//     surfaces; dashboard users issue them explicitly for automation)
//   - better-auth issuer    → "user"
//   - agent-auth issuer     → "user" (agent acting on behalf of its owner)
//   - spiffe + "/platform/" → "platform"
//   - spiffe (other)        → "operator"
//   - internal              → "system"
//   - http(s) issuer URL    → "user" (OIDC)
//   - everything else       → "unknown"
func classifyActorSource(ctx context.Context) string {
	ident, _ := auth.GibsonIdentityFromContext(ctx)
	if ident == nil {
		return "system"
	}
	switch ident.Issuer {
	case "apikey":
		return "tenant_admin"
	case "better-auth":
		return "user"
	case "agent-auth":
		return "user"
	case "internal":
		return "system"
	}
	if ident.Issuer == "spiffe" || strings.HasPrefix(ident.Subject, "spiffe://") {
		if strings.Contains(ident.Subject, "/platform/") {
			return "platform"
		}
		return "operator"
	}
	if strings.HasPrefix(ident.Issuer, "http://") || strings.HasPrefix(ident.Issuer, "https://") {
		return "user"
	}
	return "unknown"
}

// classifyRelationAction maps an FGA relation name onto the "action_class"
// audit field. Returns "" for non-catalog relations so audit consumers can
// filter cleanly.
//
// Mapping (R6 AC 3):
//   - can_read / *_read_disabled / component_read_enabled        → "read"
//   - can_configure / *_write_disabled / component_write_enabled → "write"
//   - can_execute / *_execute_disabled / component_execute_enabled → "execute"
func classifyRelationAction(relation string) string {
	switch {
	case relation == "can_read",
		strings.HasSuffix(relation, "_read_disabled"),
		relation == "component_read_enabled":
		return "read"
	case relation == "can_configure",
		strings.HasSuffix(relation, "_write_disabled"),
		relation == "component_write_enabled":
		return "write"
	case relation == "can_execute",
		strings.HasSuffix(relation, "_execute_disabled"),
		relation == "component_execute_enabled":
		return "execute"
	}
	return ""
}

// classifyScopeType derives the "scope_type" field from the tuple's USER
// side. `has_*` relations are feature tuples; anything component-scoped
// falls into the "component" bucket regardless of the user-side prefix.
func classifyScopeType(user string) string {
	switch {
	case strings.HasPrefix(user, "tenant:"):
		return "tenant"
	case strings.HasPrefix(user, "team:"):
		return "team"
	case strings.HasPrefix(user, "user:"):
		return "user"
	case strings.HasPrefix(user, "agent_principal:"):
		return "component"
	case strings.HasPrefix(user, "component:"):
		return "component"
	}
	return ""
}

// formatTuple renders an FGA tuple as the audit event's `tuple` field.
func formatTuple(user, relation, object string) string {
	return user + "#" + relation + "@" + object
}

// auditEmitter is the narrow sink used by emitAccessTupleChange /
// emitReconcileSummary. Satisfied by *audit.AuditLogger; tests inject an
// in-memory recorder.
type auditEmitter interface {
	Log(ctx context.Context, action, resource, resourceID string, details map[string]any) error
}

// emitAccessTupleChange records one FGA-tuple-write (or delete) as an audit
// event. `op` is "write" or "delete". Returns quickly — the AuditLogger's
// write is append-only to Redis Streams and non-blocking on caller-side.
func emitAccessTupleChange(
	ctx context.Context,
	em auditEmitter,
	actorSource string,
	tuple struct{ User, Relation, Object string },
	op string,
	reason string,
) {
	if em == nil {
		return
	}
	details := map[string]any{
		"tuple":        formatTuple(tuple.User, tuple.Relation, tuple.Object),
		"tuple_user":   tuple.User,
		"tuple_relation": tuple.Relation,
		"tuple_object": tuple.Object,
		"action_class": classifyRelationAction(tuple.Relation),
		"scope_type":   classifyScopeType(tuple.User),
		"operation":    op,
		"reason":       reason,
		"actor_source": actorSource,
		"timestamp":    time.Now().UTC().Format(time.RFC3339Nano),
	}
	_ = em.Log(ctx, "access_tuple_change", "component", tuple.Object, details)
}

// ReconcileSummaryFields carries the trigger + deltas a tenant-operator
// reconcile pass emits at the end of each loop.
type ReconcileSummaryFields struct {
	Plan                 string
	AddedFeatureTuples   int
	RemovedFeatureTuples int
	QuotaDelta           int
	DurationMs           int64
	Trigger              string // "cr_change" | "background" | "stripe_webhook"
}

// emitReconcileSummary records one entitlements-reconcile summary audit
// event. Intended to be called by the tenant-operator via EmitAuditEvent.
func emitReconcileSummary(
	ctx context.Context,
	em auditEmitter,
	tenantID string,
	actorSource string,
	f ReconcileSummaryFields,
) {
	if em == nil {
		return
	}
	details := map[string]any{
		"plan":                   f.Plan,
		"added_feature_tuples":   f.AddedFeatureTuples,
		"removed_feature_tuples": f.RemovedFeatureTuples,
		"quota_delta":            f.QuotaDelta,
		"duration_ms":            f.DurationMs,
		"trigger":                f.Trigger,
		"actor_source":           actorSource,
		"timestamp":              time.Now().UTC().Format(time.RFC3339Nano),
	}
	_ = em.Log(ctx, "entitlements_reconcile", "tenant", tenantID, details)
}
