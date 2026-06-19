package harness

import "context"

// DelegationObserved is a run-provenance fact: a parent agent run delegated work to
// a child agent run. The daemon wires a DelegationSink to fold this into the tenant
// World (as AgentRunObserved events) so the graph projector — the sole writer of
// the projected graph (ADR-0007) — materializes the :AgentRun nodes and the
// DELEGATED_TO edge. Kept as a plain struct + callback so the harness stays
// decoupled from the brain package.
type DelegationObserved struct {
	Tenant      string
	Scope       string
	ParentRunID string
	ParentAgent string
	ChildRunID  string
	ChildAgent  string
}

// DelegationSink folds a DelegationObserved into the World. Optional; when nil the
// harness records no run-provenance.
type DelegationSink func(ctx context.Context, d DelegationObserved)
