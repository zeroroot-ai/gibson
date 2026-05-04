// Package saga provides the unified saga step abstraction shared by the
// Gibson tenant-operator's reconcile loop and any other CRD orchestrator
// that needs ordered, idempotent, retry-aware steps with structured
// condition tracking.
//
// # Design
//
// A Saga is a directed acyclic graph of Steps. Each Step is an interface
// implementation that declares:
//
//   - its Name (stable identifier used in logs/metrics/conditions),
//   - the K8s condition type it owns,
//   - the steps it depends on (Requires) — used to compute topological
//     execution order,
//   - the client capabilities it needs (RequiredClients) — checked at
//     runner construction so a misconfigured operator pod fails fast at
//     startup instead of silently logging "step success" while skipping
//     work,
//   - Provision (do the work) and Deprovision (undo it) methods.
//
// The Runner iterates the topologically-sorted Steps, records outcomes
// as typed conditions on the reconciled object's status, emits Kubernetes
// Events, and requeues on transient failures with exponential backoff.
// Permanent errors trigger compensating Deprovision calls in reverse
// order.
//
// All steps MUST be idempotent — re-running a completed step is a no-op.
// The Runner never proceeds past a step that returns done=false or err.
//
// # Why this lives in gibson, not the operator
//
// The operator was the original home of this orchestration code. Moving
// it to gibson/pkg/platform/saga/ allows the daemon (or any future
// gibson-resident reconciler) to use the same primitive without copying
// it. See spec tenant-provisioning-unification.
//
// # Capability gating
//
// Each Step declares the client capabilities it needs. The Runner's
// ValidateAtStartup call verifies that every required capability is
// present in Deps; if any are missing in production mode (devMode=false),
// the function returns an aggregated error naming each unsatisfied
// capability and the steps that require it. Running with --dev-mode=true
// allows missing capabilities to be replaced by stub clients (the caller
// is responsible for installing them in Deps).
package saga
