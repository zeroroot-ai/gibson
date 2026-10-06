// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package dispatchpolicy is the single fail-closed gate that decides whether a
// component may execute and how. Its inputs are where the component runs,
// the trust the catalog states for it, and whether a sandboxed dispatch
// exists.
//
// The platform starts mission code only in a setec sandbox. No config value
// and no grant selects a different place. See ADR-0110.
package dispatchpolicy

import (
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
)

// Decision is the gate's verdict for a single execution.
type Decision int

const (
	// Deny means that the component must not execute.
	Deny Decision = iota

	// RequireSetec means that the platform starts the code, and it starts it
	// in a setec sandbox.
	RequireSetec

	// AllowWorkQueue means that the platform does not start the code. The
	// component runs already, and it pulls its work from the work queue.
	AllowWorkQueue
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
//   - When a sandboxed dispatch is available it is always used
//     (RequireSetec), for every placement and trust level.
//   - A PlacementOutside component is AllowWorkQueue: its code runs on the
//     tenant's machine, and the daemon only queues work for it.
//   - A PlacementCluster component is AllowWorkQueue only when the catalog
//     states that it is TRUSTED. Such a component runs as a platform pod and
//     pulls its work. UNTRUSTED and CONTENT_TRUST_UNSPECIFIED are both Deny:
//     code in the platform's cluster that nothing states as trusted runs in
//     a sandbox or not at all.
func Decide(placement Placement, trust componentpb.ContentTrust, hasSandboxedDispatch bool) Decision {
	if hasSandboxedDispatch {
		return RequireSetec
	}
	if placement == PlacementOutside {
		return AllowWorkQueue
	}
	if trust == componentpb.ContentTrust_CONTENT_TRUST_TRUSTED {
		return AllowWorkQueue
	}
	return Deny
}
