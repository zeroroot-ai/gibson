package saga

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Step is the unified saga step contract. Every reconcile step
// (data-plane provisioner, identity provisioner, billing step) implements
// this interface; the Runner orchestrates them via a topologically-sorted
// DAG.
//
// All steps MUST be idempotent — re-running a completed step is a no-op.
// Provision returns done=true when the step is complete. Returning
// done=false + nil err requests a requeue. Returning any err triggers
// retry-with-backoff (transient) or compensating teardown (permanent,
// see ClassifyError).
type Step interface {
	// Name is a short, stable identifier used in logs, events, and metrics.
	Name() string

	// Condition returns the K8s condition type this step writes (e.g.,
	// "PostgresProvisioned"). The Runner sets the condition True on success,
	// False with a Reason on failure.
	Condition() string

	// Requires returns the names of steps that must complete successfully
	// before this step can run. The Runner topologically sorts the step
	// graph from these declarations and refuses to construct a Saga
	// containing cycles or references to unknown step names.
	Requires() []string

	// RequiredClients returns the client capabilities this step needs. The
	// Runner's ValidateAtStartup checks every step's RequiredClients
	// against the provided Deps; missing capabilities cause startup
	// failure in production mode.
	RequiredClients() []ClientCapability

	// Provision performs the step's work. obj is the reconciled CRD
	// (Tenant, TenantMember, etc.) — steps that need typed access
	// type-assert on the concrete CRD type. deps is the bag of clients
	// (guaranteed non-nil for every capability listed in
	// RequiredClients() if the runner's startup gate passed).
	Provision(ctx context.Context, obj ConditionedObject, deps *Deps) (done bool, err error)

	// Deprovision undoes Provision. Called by the Runner during
	// compensating rollback (after a permanent error in a downstream
	// step) and during teardown when the CRD is being deleted. Must be
	// idempotent and tolerant of partial-prior-Provision state.
	Deprovision(ctx context.Context, obj ConditionedObject, deps *Deps) error

	// Skip, if it returns true, causes the Runner to mark the step's
	// condition True with Reason=Skipped without calling Provision.
	// Used for tier-dependent steps (e.g., Stripe creation on free tier).
	// Default implementations return false.
	Skip(obj ConditionedObject) bool
}

// ConditionedObject is implemented by any K8s object whose status carries
// a Conditions slice and an ObservedGeneration. Every Gibson CRD satisfies
// this via its generated Status type plus a small accessor shim. The
// shim is implemented in the operator alongside the CRD type definitions
// (this package cannot reference operator types).
type ConditionedObject interface {
	metav1.Object
	runtime.Object
	GetConditions() *[]metav1.Condition
	GetPhase() string
	SetPhase(string)
	GetObservedGeneration() int64
	SetObservedGeneration(int64)
}

// ErrorClassification categorizes step errors for the Runner. Permanent
// errors trigger compensating teardown; transient errors trigger
// retry-with-backoff up to a per-step max-attempts cap.
type ErrorClassification int

const (
	// ErrorTransient: the step may succeed on retry. Network blips,
	// timeouts, 5xx from upstream services. Runner requeues with
	// exponential backoff.
	ErrorTransient ErrorClassification = iota

	// ErrorPermanent: the step will never succeed without operator
	// intervention. Bad input, schema violation, 4xx from upstream.
	// Runner runs Deprovision on previously-completed steps in reverse
	// topological order, then marks the CRD as Failed.
	ErrorPermanent
)

// ClassifyError maps an error to its ErrorClassification. The default
// implementation treats nil-safe wrapped errors via errors.Is checks
// against a small sentinel set; steps may override by implementing the
// optional ErrorClassifier interface.
//
// Step authors should use clients.WrapPermanent (in the operator's
// internal/clients package) to mark errors that should NOT be retried.
type ErrorClassifier interface {
	ClassifyError(err error) ErrorClassification
}
