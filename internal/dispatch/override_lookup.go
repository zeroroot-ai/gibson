// Package dispatch — override_lookup.go
//
// OverrideLookup is the narrow interface the harness uses to populate
// Input.OverrideActive before calling Policy.Decide. The concrete
// implementation reads from the DispatchOverrideServer's in-memory cache
// (with Redis fallback) — that detail is in the daemon package to avoid
// an import cycle. The harness only imports this interface.
//
// Why a separate interface rather than importing daemon.DispatchOverrideServer
// directly? The harness (internal/harness) imports the dispatch package
// (internal/dispatch), and the daemon package (internal/daemon) imports the
// harness package. Importing daemon from dispatch would create a cycle:
//   dispatch → daemon → harness → dispatch
//
// The interface breaks the cycle: daemon provides a concrete implementation
// that satisfies OverrideLookup; the harness accepts the interface.
//
// Spec: setec-sandbox-prod-default §C3/§C4 (R3.4, Task 30).
package dispatch

import "context"

// OverrideLookup is the narrow interface the harness calls to check whether
// a platform-operator override is active for a given tenant before evaluating
// the dispatch policy gate.
//
// Implementations are expected to be O(1) in the common case (in-memory
// cache hit). A Redis fallback may incur a single network round-trip on a
// cache miss (e.g. after a daemon restart). The lookup must not block the
// dispatch hot path for more than a few milliseconds; callers should apply
// a short context deadline if necessary.
//
// The returned OverrideState carries both the active flag and the
// audit_event_id from the override that authorised it. The gate stamps
// the audit_event_id as parent_event_id on allow-decision audit events so
// auditors can pivot from a dispatch event to the override that authorised it.
type OverrideLookup interface {
	// LookupTenantOverride returns the active override state for the given
	// tenant. Returns a zero OverrideState (Active=false) when no active
	// override exists.
	LookupTenantOverride(ctx context.Context, tenantID string) OverrideState
}

// OverrideState captures the result of an override lookup.
//
// When Active is false all other fields are zero — the gate treats the
// tenant as having no override. When Active is true, AuditEventID holds the
// identifier of the audit event that recorded the override installation, so
// the gate can stamp it as parent_event_id on any allow-decision audit event
// it emits for this tenant.
type OverrideState struct {
	// Active is true when a non-expired operator override is in effect.
	Active bool

	// AuditEventID is the identifier of the audit.Event emitted when the
	// override was installed. Non-empty only when Active is true.
	// Used by the harness to populate parent_event_id on allow-decision
	// audit events per design §C3.
	AuditEventID string
}

// NoopOverrideLookup is a production-safe no-op implementation of OverrideLookup
// that always returns an inactive state. Used when the override service is not
// wired (e.g. in tests that do not require override functionality, or in
// deployments that have not yet provisioned a DispatchOverrideServer).
type NoopOverrideLookup struct{}

// LookupTenantOverride always returns an inactive override state.
func (NoopOverrideLookup) LookupTenantOverride(_ context.Context, _ string) OverrideState {
	return OverrideState{}
}

// Compile-time assertion that NoopOverrideLookup satisfies OverrideLookup.
var _ OverrideLookup = NoopOverrideLookup{}
