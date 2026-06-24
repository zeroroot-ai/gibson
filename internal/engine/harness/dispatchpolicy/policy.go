// Package dispatchpolicy is the single fail-closed gate that decides whether a
// component may execute and how, given its content-trust classification, the
// availability of a sandboxed dispatch, and the daemon's deployment shape.
//
// It exists so that no execution path in the harness can run untrusted code
// outside a setec sandbox in the hosted deployment. See ADR-0010
// (docs/adr/0010-untrusted-execution-isolation-boundary.md) and gibson#994.
package dispatchpolicy

import componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"

// DeploymentShape is how the daemon is deployed, which determines the isolation
// policy for untrusted execution. Sourced from GIBSON_UNTRUSTED_EXEC and
// fail-closed to ShapeSetecOnly. The zero value is ShapeSetecOnly so an
// unwired harness fails closed.
type DeploymentShape int

const (
	// ShapeSetecOnly is the hosted (multi-tenant, our-infrastructure)
	// deployment: untrusted execution is setec-or-denied. Fail-closed default.
	ShapeSetecOnly DeploymentShape = iota

	// ShapeCustomerIsolation is a customer-operated (on-prem / self-hosted)
	// deployment where the customer owns the isolation boundary.
	ShapeCustomerIsolation
)

// Config values for GIBSON_UNTRUSTED_EXEC.
const (
	ModeSetecOnly         = "setec-only"
	ModeCustomerIsolation = "customer-isolation"
)

// ParseShape resolves a GIBSON_UNTRUSTED_EXEC value to a DeploymentShape.
// "customer-isolation" selects ShapeCustomerIsolation; "setec-only" and the
// empty string select ShapeSetecOnly. It never errs — any unrecognised value
// fail-closes to ShapeSetecOnly. The config loader is responsible for rejecting
// invalid values loudly (see config.loadUntrustedExec); this function stays
// total so callers downstream of a validated config can never panic.
func ParseShape(raw string) DeploymentShape {
	if raw == ModeCustomerIsolation {
		return ShapeCustomerIsolation
	}
	return ShapeSetecOnly
}

// Decision is the gate's verdict for a single execution.
type Decision int

const (
	// Deny: the component must not execute under this policy.
	Deny Decision = iota

	// RequireSetec: the component must execute via the setec sandbox.
	RequireSetec

	// AllowInProcess: the component may take the in-process / direct-gRPC path.
	AllowInProcess
)

// Decide is the gate. It is pure and total.
//
//   - When a sandboxed dispatch is available it is always honoured
//     (RequireSetec) — the safe choice for both trust levels and both shapes.
//   - An UNTRUSTED component under ShapeSetecOnly with no sandboxed dispatch is
//     Deny — untrusted code never runs in our address space in the hosted
//     deployment, and there is no in-process fallback.
//   - Everything else is AllowInProcess: TRUSTED components (and, for
//     backward-compat with descriptors registered before the field shipped,
//     CONTENT_TRUST_UNSPECIFIED, which is treated as TRUSTED), and — under
//     ShapeCustomerIsolation, where the customer owns isolation — untrusted
//     components with no sandbox.
func Decide(trust componentpb.ContentTrust, hasSandboxedDispatch bool, shape DeploymentShape) Decision {
	if hasSandboxedDispatch {
		return RequireSetec
	}

	untrusted := trust == componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED
	if untrusted && shape == ShapeSetecOnly {
		return Deny
	}
	return AllowInProcess
}
