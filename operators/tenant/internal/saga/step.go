// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package saga provides a reusable reconcile-step orchestration primitive
// used by every Gibson CRD controller.
//
// Phase 4 of spec tenant-provisioning-unification-phase2 collapsed the
// operator's local Step/Runner onto the unified gibson/pkg/platform/saga
// (psaga) interface. This file is now a thin re-export shim:
//
//   - saga.Step is an alias for psaga.Step (the interface).
//   - saga.ConditionedObject is an alias for psaga.ConditionedObject.
//   - saga.StepBase is a small embeddable type that supplies safe defaults
//     for Requires / RequiredClients / Skip / Deprovision so each concrete
//     step only has to override Provision (and Skip / Deprovision when
//     it has interesting behaviour).
//
// All steps MUST be idempotent — re-running a completed step is a no-op.
package saga

import (
	"context"
	"time"

	psaga "github.com/zeroroot-ai/gibson/pkg/platform/saga"
)

// Step is the unified saga step contract. Re-exported so existing operator
// code keeps importing `saga.Step`.
type Step = psaga.Step

// ConditionedObject is implemented by any K8s object whose status carries
// a Conditions slice and an ObservedGeneration. Re-exported.
type ConditionedObject = psaga.ConditionedObject

// ClientCapability is re-exported so flows can declare RequiredClients()
// without importing psaga directly.
type ClientCapability = psaga.ClientCapability

// Re-exported capability constants — flows reference these from their
// RequiredClients() implementations.
const (
	CapabilityPostgresAdmin = psaga.CapabilityPostgresAdmin
	CapabilityVaultAdmin    = psaga.CapabilityVaultAdmin
	CapabilityVaultTransit  = psaga.CapabilityVaultTransit
	CapabilityKubernetes    = psaga.CapabilityKubernetes
	CapabilityZitadelAdmin  = psaga.CapabilityZitadelAdmin
	CapabilityFGA           = psaga.CapabilityFGA
	CapabilityRedisAdmin    = psaga.CapabilityRedisAdmin
	CapabilityQdrantAdmin   = psaga.CapabilityQdrantAdmin
	CapabilityStripe        = psaga.CapabilityStripe
	CapabilityDaemonGRPC    = psaga.CapabilityDaemonGRPC
	CapabilitySMTP          = psaga.CapabilitySMTP
)

// Deps is re-exported so cmd/main.go can build the unified bag without
// importing psaga directly.
type Deps = psaga.Deps

// StepBase supplies safe defaults for every Step interface method except
// Provision. Concrete steps embed it and override Provision (always) plus
// Skip / Deprovision when they need non-default behaviour.
//
// Usage:
//
//	type myStep struct {
//	    saga.StepBase
//	    deps SomeDeps
//	}
//
//	func newMyStep(d SomeDeps) *myStep {
//	    return &myStep{
//	        StepBase: saga.StepBase{
//	            N:     "MyStep",
//	            C:     "MyCondition",
//	            Req:   []string{"UpstreamStep"},
//	            Caps:  []saga.ClientCapability{saga.CapabilityKubernetes},
//	            Owner: "tenant-operator",
//	            P99:   30 * time.Second,
//	        },
//	        deps: d,
//	    }
//	}
//
//	func (s *myStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
//	    // …
//	}
//
// StepBase deliberately lives in the operator's saga package rather than
// in psaga so the platform package keeps its zero-dependency policy.
//
// The Owner + P99 fields are operator-private metadata (NOT part of the
// psaga.Step interface — the SDK contract stays stable). They are
// consumed by contract tests and future observability surfaces; see
// tenant-operator#83.
type StepBase struct {
	// N is the step's short, stable identifier — visible in logs, events,
	// and status conditions.
	N string

	// C is the K8s condition type the step writes (e.g. "PostgresProvisioned").
	C string

	// Req lists the names of steps that must complete before this one.
	// Empty means "no upstream dependencies". The runner topologically
	// sorts the step graph from these declarations.
	Req []string

	// Caps lists the capabilities the step needs at runtime. Used by
	// psaga.ValidateAtStartup to gate boot in production mode.
	Caps []ClientCapability

	// Owner identifies the team / subsystem responsible for the step's
	// failure mode. Used by the contract test to refuse unowned steps
	// and (in the future) to route alerts. Required for every step.
	// Examples: "tenant-operator", "platform-postgres", "dashboard",
	// "zitadel-integration", "stripe-billing", "platform-vault".
	Owner string

	// P99 is the expected p99 duration of a successful Provision call,
	// used by alerting to flag steps that have drifted slow. Zero means
	// "no expected SLA" (some steps block on external controllers — e.g.
	// RemoveZitadelOrg waits on TenantMember CRDs being cleaned up).
	P99 time.Duration
}

// Name implements psaga.Step.
func (b StepBase) Name() string { return b.N }

// Condition implements psaga.Step.
func (b StepBase) Condition() string { return b.C }

// Requires implements psaga.Step.
func (b StepBase) Requires() []string { return b.Req }

// RequiredClients implements psaga.Step.
func (b StepBase) RequiredClients() []ClientCapability { return b.Caps }

// GetOwner returns the step's owner. Operator-private — not part of
// the psaga.Step interface. The contract test calls this via a type
// assertion to OwnerProvider; steps that don't embed StepBase MUST
// implement the interface themselves.
func (b StepBase) GetOwner() string { return b.Owner }

// GetP99 returns the step's expected p99 duration. Operator-private,
// same pattern as GetOwner.
func (b StepBase) GetP99() time.Duration { return b.P99 }

// Skip implements psaga.Step. Default: never skip.
func (b StepBase) Skip(_ ConditionedObject) bool { return false }

// Deprovision implements psaga.Step. Default: no-op (the parent CRD's
// owned resources are reclaimed by K8s GC). Steps with side effects
// outside the CRD's ownership graph (Vault, Stripe, Zitadel, etc.) MUST
// override this.
func (b StepBase) Deprovision(_ context.Context, _ ConditionedObject, _ *Deps) error {
	return nil
}
