// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package dispatchpolicy is the single fail-closed gate that decides whether a
// component may execute and how, given its content-trust classification, the
// availability of a sandboxed dispatch, and the daemon's deployment shape.
//
// It exists so that no execution path in the harness can run untrusted code
// outside a setec sandbox in the hosted deployment. See ADR-0110
// and gibson#994.
package dispatchpolicy

import (
	capabilitypb "github.com/zeroroot-ai/sdk/api/gen/gibson/capability/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
)

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

// Placement is where a component's code runs. It comes from how the
// component enrolled, a fact the daemon records, never from what the
// component says about itself.
type Placement int

const (
	// PlacementCluster is a workload the platform attests: it enrolled with a
	// SPIRE identity and runs in the platform's cluster. The zero value, so a
	// caller that does not know the placement gets the strict rule.
	PlacementCluster Placement = iota

	// PlacementOutside is a component that enrolled with a bootstrap token
	// and runs on the tenant's own machine. It gets work through the work
	// queue. The platform runs none of its code, so the sandbox rule does not
	// cover it. Its output is untrusted data like any other tool output.
	PlacementOutside
)

// Decide is the gate. It is pure and total.
//
//   - When a sandboxed dispatch is available it is always honoured
//     (RequireSetec), for every placement, trust level and shape.
//   - Under ShapeCustomerIsolation the customer owns isolation, so everything
//     else is AllowInProcess.
//   - Under ShapeSetecOnly a PlacementOutside component is AllowInProcess: its
//     code runs on the tenant's machine, and the daemon only queues work for
//     it.
//   - Under ShapeSetecOnly a PlacementCluster component is AllowInProcess only
//     when its trust is TRUSTED. UNTRUSTED and CONTENT_TRUST_UNSPECIFIED are
//     both Deny: code in the platform's cluster that nothing states as
//     trusted runs in a sandbox or not at all.
func Decide(placement Placement, trust componentpb.ContentTrust, hasSandboxedDispatch bool, shape DeploymentShape) Decision {
	if hasSandboxedDispatch {
		return RequireSetec
	}
	if shape != ShapeSetecOnly || placement == PlacementOutside {
		return AllowInProcess
	}
	if trust == componentpb.ContentTrust_CONTENT_TRUST_TRUSTED {
		return AllowInProcess
	}
	return Deny
}

// IsolationAllowed reports whether a capability grant's isolation mode is
// permitted under the deployment shape (ADR-0110 / gibson#998). It is the
// fail-closed gate for WHERE untrusted execution may be isolated:
//
//   - ShapeSetecOnly (hosted SaaS): only ISOLATION_MODE_HOSTED_SANDBOX is
//     permitted — untrusted execution must run in the platform-operated setec
//     fleet. ISOLATION_MODE_UNSPECIFIED is treated as HOSTED_SANDBOX (back-compat
//     for grants minted before the field shipped), so it is also permitted.
//     Every customer-operated mode is rejected.
//   - ShapeCustomerIsolation (on-prem / self-hosted): the customer owns the
//     isolation boundary, so every mode is permitted. ON_PREM_SANDBOX_ENDPOINT
//     additionally requires a configured customer-pointed setec endpoint, which
//     the caller resolves separately.
//
// It is pure and total: an unrecognised mode under ShapeSetecOnly is rejected
// (fail-closed), and any mode under ShapeCustomerIsolation is allowed.
func IsolationAllowed(isolation capabilitypb.IsolationMode, shape DeploymentShape) bool {
	if shape == ShapeCustomerIsolation {
		return true
	}
	switch isolation {
	case capabilitypb.IsolationMode_ISOLATION_MODE_UNSPECIFIED,
		capabilitypb.IsolationMode_ISOLATION_MODE_HOSTED_SANDBOX:
		return true
	default:
		return false
	}
}
