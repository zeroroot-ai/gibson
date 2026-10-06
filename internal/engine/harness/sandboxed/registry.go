// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package sandboxed implements the Gibson harness's sandboxed tool execution
// backend: per-call Setec microVM dispatch via gRPC with mTLS.
//
// Scope:
//   - No Setec-specific gRPC client type leaks out of this package.
//   - All public types are plain structs that the daemon's startup wiring
//     populates from configuration.
//   - The Executor consumes a minimal SandboxClient interface so unit tests
//     can mock the gRPC surface without importing the Setec module.
//
// Dispatch is driven by the embedded kind:tool catalog manifests (ADR-0117):
// harness.CallToolProto resolves a ToolSpec per call from componentcatalog,
// gated per tenant by can_execute, before handing off to
// Executor.ExecuteWithSpec.
//
// It was not always so, and the difference is a security boundary rather than
// a refactor. A runtime catalog refresher used to write tool metadata to
// ComponentRegistry entries under the _system tenant, and dispatch resolved
// from those — which carried no per-tenant check at all, so any tenant could
// run any discovered tool. That refresher is deleted, not disabled
// (ADR-0117/ADR-0027); do not reintroduce a registry-sourced dispatch path.
package sandboxed

// ToolSpec is the resolved launch spec for one sandboxed tool call. Fields
// are populated per-call from the tool's kind:tool catalog manifest and
// passed to Executor.ExecuteWithSpec.
type ToolSpec struct {
	Image   string
	Command []string
	Env     map[string]string
	VCPU    int32
	Memory  string

	// Egress, when non-empty, confines the tool sandbox to exactly these
	// targets — the dispatching agent's egressAllow ceiling (ADR-0136). Empty
	// means the sandbox takes the defaultNetworkMode of its SandboxClass.
	// Sandbox isolation is unconditional; this only bounds egress breadth.
	Egress []EgressRule

	// NetworkMode, when set, is the network mode of the launch. It carries
	// the network scope of the mission node that starts the tool (gibson#865).
	NetworkMode string

	// Live carries the per-call scope the running-sandbox console keys by.
	// Like Egress it is dispatch-time scope, not catalog data: the caller
	// fills it from the request it is serving. Its Tenant also names the
	// setec namespace of the launch, so a call with an empty Tenant does not
	// launch (ADR-0142).
	Live LiveScope
}

// LiveScope is the identity a sandbox run is enumerated under by the
// read-only running-sandbox console (ADR-0116 S11).
type LiveScope struct {
	// Tenant is the CUSTOMER tenant that owns the run. setec gets it on each
	// request (ADR-0142).
	Tenant string
	// MissionID and MissionRunID scope the run to its mission, so the console
	// can link back. Empty for a call outside a mission.
	MissionID    string
	MissionRunID string
}
