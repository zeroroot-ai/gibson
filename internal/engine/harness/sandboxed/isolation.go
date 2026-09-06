// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sandboxed

import "fmt"

// Isolation verification for sandbox launches (ADR-0052).
//
// The sandbox boundary is where untrusted code runs, so gibson must both ASK
// for a specific isolation posture and CHECK that it got it. Asking without
// checking is not a control: a cluster whose default SandboxClass resolves to
// `runc`, or whose class carries a fallback chain ending in `runc`, would run
// tool code with no kernel boundary and gibson would never notice.
//
// Two halves, both enforced by VerifyIsolation:
//
//  1. gibson names an explicit SandboxClass on every launch. setec's Sandbox
//     admission webhook rejects a create whose sandboxClassName does not
//     resolve ("SandboxClass %q not found"), so naming a class is
//     server-validated: a launch against a cluster that lacks the class fails
//     rather than silently landing on the cluster default.
//
//  2. gibson compares the isolation setec reports back against what it asked
//     for, and refuses the sandbox on a mismatch or on a runtime backend that
//     carries no isolation boundary.
//
// The setec.v1 gRPC ABI does not yet echo the resolved class or the chosen
// runtime backend — LaunchResponse carries only sandbox_id/name/namespace,
// and WaitResponse only phase/exit_code/reason. The Sandbox CR does record
// the truth (spec.sandboxClassName and status.runtime.chosen, the latter one
// of kata-fc, kata-qemu, gvisor, runc), it is simply not on the wire, and
// gibson holds no Kubernetes client (ADR-0023) so it cannot read the CR.
// LaunchResponse.SandboxClass / LaunchResponse.Runtime are the fields the
// adapter fills once setec reports them; until then half (2) can only fire on
// what an adapter does report. Tracked upstream — see the PR description.

// isolatedRuntimes is the set of setec runtime backends that put a kernel or
// user-space-kernel boundary between the sandboxed workload and the node.
// `runc` is deliberately absent: it is setec's development backend and shares
// the host kernel, which is exactly the posture ADR-0052 forbids for
// untrusted code.
var isolatedRuntimes = map[string]struct{}{
	"kata-fc":   {},
	"kata-qemu": {},
	"gvisor":    {},
}

// VerifyIsolation reports whether a Launch round-trip actually produced the
// isolation that was requested. It returns a non-nil error — meaning DENY the
// sandbox, do not use it — when:
//
//   - no SandboxClass was requested, so the launch would inherit whatever the
//     cluster happens to default to;
//   - setec bound the sandbox to a different class than the one requested;
//   - setec resolved the class to a runtime backend with no isolation
//     boundary.
//
// A caller that gets an error must treat the sandbox as unusable and kill it;
// the workload inside it has not been proven to be contained.
func VerifyIsolation(requestedClass string, resp LaunchResponse) error {
	if requestedClass == "" {
		return fmt.Errorf(
			"isolation unverified: no sandbox class requested, so the launch inherits the cluster default")
	}
	if resp.SandboxClass != "" && resp.SandboxClass != requestedClass {
		return fmt.Errorf(
			"isolation unverified: requested sandbox class %q but setec bound %q",
			requestedClass, resp.SandboxClass)
	}
	if resp.Runtime != "" {
		if _, ok := isolatedRuntimes[resp.Runtime]; !ok {
			return fmt.Errorf(
				"isolation unverified: sandbox class %q resolved to runtime %q, which provides no isolation boundary",
				requestedClass, resp.Runtime)
		}
	}
	return nil
}
