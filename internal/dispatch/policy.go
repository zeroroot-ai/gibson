// Package dispatch implements the daemon's dispatch policy gate.
//
// The gate enforces the security invariant
//
//	content_trust == UNTRUSTED  ⇒  dispatch_mode == SANDBOXED
//
// for every harness call. Direct PLUGIN/AGENT execution against UNTRUSTED
// data is denied unless a platform-operator override (R3.4) is active for
// the affected tenant. The gate is purposely a pure function — Decide takes
// an Input and returns a Decision; it performs no I/O, no audit emission,
// no Redis lookups. Callers (the harness) layer audit emission and override
// state on top.
//
// Spec: setec-sandbox-prod-default §C3 (R3.1, R3.3).
package dispatch

import (
	"context"

	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
)

// Reason values for deny outcomes. These strings are stable wire-format
// identifiers — they appear in audit events, mission-step error messages
// (Scenario 2: "untrusted_content_requires_sandbox"), and Prometheus
// metric labels. Changing them is a breaking change to the dashboard's
// error-string rendering and to operator runbooks.
const (
	// ReasonUntrustedRequiresSandbox is emitted when an UNTRUSTED component
	// is asked to dispatch via PLUGIN or AGENT and no override is active.
	// User-facing mission-step error per design Scenario 2.
	ReasonUntrustedRequiresSandbox = "untrusted_content_requires_sandbox"

	// ReasonSandboxUnavailable is emitted when an UNTRUSTED+SANDBOXED call
	// is denied because the sandbox health probe / breaker reports the
	// sandbox is not reachable.
	ReasonSandboxUnavailable = "sandbox_unavailable"

	// ReasonDispatchModeUnspecified is emitted when a descriptor's dispatch
	// mode is the proto zero value (UNSPECIFIED). The gate refuses to guess.
	ReasonDispatchModeUnspecified = "dispatch_mode_unspecified"

	// ReasonExecutorNotWired is emitted when a SANDBOXED dispatch is
	// requested but the daemon was built without `setec_integration`. In
	// production (GIBSON_MODE=saas) the startup self-check prevents this
	// from ever firing; in dev it surfaces as a clean deny instead of a
	// nil-pointer panic.
	ReasonExecutorNotWired = "executor_not_wired"

	// ReasonQuotaExceeded is emitted by the executor entry point when the
	// per-tenant concurrent-detonation cap is hit. It is layered on top
	// of the gate (the gate itself does not consult quota state) but the
	// constant lives here so audit / metric labels share one source of
	// truth. Spec design §"Resource quotas" Scenario 5.
	ReasonQuotaExceeded = "quota_exceeded"
)

// Input is the call-site bundle the gate evaluates.
//
// Tenant / Mission / Step / Tool are tagging fields used by audit and
// tracing; the gate does not branch on them. ToolMode and ContentTrust
// come from the registered ComponentDescriptor. SandboxHealthy and
// OverrideActive are populated by the harness from the breaker state and
// the Redis-backed override record respectively, before calling Decide.
type Input struct {
	Tenant       string
	Mission      string
	Step         string
	Tool         string
	ToolMode     componentpb.DispatchMode  // tool's declared mode
	ContentTrust componentpb.ContentTrust  // call-site classification
	SandboxHealthy bool
	OverrideActive bool                    // R3.4 in effect for tenant
}

// Decision is the gate's verdict.
//
// Allowed=true means the harness should proceed to the executor matching
// ChosenMode. Allowed=false means the harness MUST short-circuit with a
// structured error carrying Reason; the executor MUST NOT be invoked.
type Decision struct {
	Allowed    bool
	ChosenMode componentpb.DispatchMode
	Reason     string                     // structured deny reason; empty on allow
}

// Policy is the gate interface. Decide is a pure function: same Input
// always yields the same Decision; no I/O, no clock, no goroutines.
type Policy interface {
	Decide(ctx context.Context, in Input) Decision
}

// Config tunes gate behavior. The zero value is the production-default
// configuration (StrictDefaultUntrusted=false): an UNSPECIFIED ContentTrust
// is treated as TRUSTED at gate-eval time for backward compatibility with
// descriptors registered before the SDK shipped the field. Operators can
// set StrictDefaultUntrusted=true via the daemon's config to invert that
// default during a phased rollout (the gate then refuses dispatch unless
// the descriptor explicitly declares CONTENT_TRUST_TRUSTED).
type Config struct {
	StrictDefaultUntrusted bool
}

// NewPolicy constructs a Policy with the given configuration.
func NewPolicy(cfg Config) Policy {
	return &policy{cfg: cfg}
}

// policy is the production Policy implementation. The struct itself is
// stateless; storing Config keeps the StrictDefaultUntrusted flag on the
// gate without re-reading it on every call.
type policy struct {
	cfg Config
}

// Decide implements the dispatch policy state diagram from design
// §"Dispatch policy state diagram". Every state-diagram transition has
// a corresponding code branch; the function never returns a zero-value
// Decision (Allowed=false, Reason="") — every code path terminates in
// exactly one named outcome.
//
// Decision tree (in evaluation order):
//
//  1. ToolMode == UNSPECIFIED                   ⇒ DenyUnknownMode
//  2. ContentTrust resolves to UNTRUSTED:
//       a. OverrideActive=true                  ⇒ Allowed (override path)
//       b. ToolMode == SANDBOXED:
//            - SandboxHealthy=true              ⇒ Allowed
//            - SandboxHealthy=false             ⇒ DenySandboxUnavailable
//       c. ToolMode in {PLUGIN, AGENT}          ⇒ DenyUntrustedNotSandboxed
//  3. ContentTrust resolves to TRUSTED:
//       a. ToolMode in {SANDBOXED, PLUGIN, AGENT} ⇒ Allowed
//
// `ContentTrust` resolution: when the descriptor's value is
// CONTENT_TRUST_UNSPECIFIED, the gate treats it as TRUSTED unless
// `Config.StrictDefaultUntrusted=true`, in which case it treats it as
// UNTRUSTED (operator-controlled phased-rollout flag).
//
// The DenyExecutorMissing terminal from the state diagram is enforced
// upstream by the harness (the harness checks for a nil sandboxedExecutor
// when ChosenMode=SANDBOXED before dispatching) — keeping the gate pure
// means it cannot consult an executor pointer. Callers must handle the
// "executor missing" case post-Decide; if they don't, the
// startup_refused self-check (R1.4) prevents production from ever
// reaching this branch.
func (p *policy) Decide(_ context.Context, in Input) Decision {
	// 1. Unknown mode is always a clean deny — the gate refuses to guess.
	if in.ToolMode == componentpb.DispatchMode_DISPATCH_MODE_UNSPECIFIED {
		return Decision{
			Allowed:    false,
			ChosenMode: in.ToolMode,
			Reason:     ReasonDispatchModeUnspecified,
		}
	}

	// 2. Resolve content trust: UNSPECIFIED maps to TRUSTED unless the
	// strict-default-untrusted flag is on (phased rollout).
	trust := in.ContentTrust
	if trust == componentpb.ContentTrust_CONTENT_TRUST_UNSPECIFIED {
		if p.cfg.StrictDefaultUntrusted {
			trust = componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED
		} else {
			trust = componentpb.ContentTrust_CONTENT_TRUST_TRUSTED
		}
	}

	if trust == componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED {
		// 2a. Operator override flips the deny to allow for UNTRUSTED.
		// Note: the override does NOT promote an UNSPECIFIED dispatch
		// mode (handled in step 1 above) — only an explicit ToolMode
		// can be allowed via the escape hatch.
		if in.OverrideActive {
			return Decision{
				Allowed:    true,
				ChosenMode: in.ToolMode,
			}
		}

		// 2b. UNTRUSTED + SANDBOXED requires the sandbox to be reachable.
		if in.ToolMode == componentpb.DispatchMode_DISPATCH_MODE_SANDBOXED {
			if in.SandboxHealthy {
				return Decision{
					Allowed:    true,
					ChosenMode: componentpb.DispatchMode_DISPATCH_MODE_SANDBOXED,
				}
			}
			return Decision{
				Allowed:    false,
				ChosenMode: in.ToolMode,
				Reason:     ReasonSandboxUnavailable,
			}
		}

		// 2c. UNTRUSTED + PLUGIN/AGENT (no override) is the canonical deny.
		return Decision{
			Allowed:    false,
			ChosenMode: in.ToolMode,
			Reason:     ReasonUntrustedRequiresSandbox,
		}
	}

	// 3. TRUSTED content runs in any explicit mode.
	return Decision{
		Allowed:    true,
		ChosenMode: in.ToolMode,
	}
}
