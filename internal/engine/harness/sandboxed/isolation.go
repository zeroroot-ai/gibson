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
// The setec.v1 LaunchResponse reports the class that setec bound
// (sandbox_class) and the runtime backend of that class (runtime). The
// adapter copies both. A response that reports either one empty is refused:
// a launch whose isolation is not reported is not proven contained.

// IsolatedRuntime is the one setec runtime backend: a Firecracker machine in
// a launcher pod (ADR-0116, ADR-0141, ADR-0166, setec#198). It puts a kernel
// boundary between the sandboxed workload and the node. Each other value is
// refused, including the backends that left setec (kata-fc, kata-qemu,
// gvisor) and `runc`, which shares the host kernel.
const IsolatedRuntime = "launcher"

// VerifyIsolation reports whether a Launch round-trip actually produced the
// isolation that was requested. It returns a non-nil error — meaning DENY the
// sandbox, do not use it — when:
//
//   - no SandboxClass was requested, so the launch would inherit whatever the
//     cluster happens to default to;
//   - setec reported no class or no runtime, so the isolation is unproven;
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
	if resp.SandboxClass == "" || resp.Runtime == "" {
		return fmt.Errorf(
			"isolation unverified: setec reported class %q and runtime %q for a launch of class %q; both are required",
			resp.SandboxClass, resp.Runtime, requestedClass)
	}
	if resp.SandboxClass != requestedClass {
		return fmt.Errorf(
			"isolation unverified: requested sandbox class %q but setec bound %q",
			requestedClass, resp.SandboxClass)
	}
	if resp.Runtime != IsolatedRuntime {
		return fmt.Errorf(
			"isolation unverified: sandbox class %q resolved to runtime %q, not the %s backend of setec",
			requestedClass, resp.Runtime, IsolatedRuntime)
	}
	return nil
}
