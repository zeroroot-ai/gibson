package saga

import (
	"context"
)

// StepFn is the function-form step signature used by the operator's
// pre-Phase-2 saga code. Adapter helpers in this file let callers wrap
// a StepFn into a Step interface implementation, easing incremental
// migration. New steps should implement Step directly.
type StepFn func(ctx context.Context, obj ConditionedObject) (done bool, err error)

// AdaptOption configures FromStepFn.
type AdaptOption func(*adaptedStep)

// WithRequires sets the step's Requires() return value.
func WithRequires(names ...string) AdaptOption {
	return func(a *adaptedStep) { a.requires = append(a.requires[:0], names...) }
}

// WithRequiredClients sets the step's RequiredClients() return value.
func WithRequiredClients(caps ...ClientCapability) AdaptOption {
	return func(a *adaptedStep) { a.caps = append(a.caps[:0], caps...) }
}

// WithSkipFn sets a Skip predicate. Default returns false.
func WithSkipFn(fn func(ConditionedObject) bool) AdaptOption {
	return func(a *adaptedStep) { a.skipFn = fn }
}

// WithDeprovisionFn sets a Deprovision callback. Default is a no-op
// (returns nil) — appropriate for steps whose work is fully reversible
// by deleting the parent CRD's owned resources via K8s GC.
func WithDeprovisionFn(fn func(context.Context, ConditionedObject, *Deps) error) AdaptOption {
	return func(a *adaptedStep) { a.deprovisionFn = fn }
}

// FromStepFn wraps a function-form step into a Step interface
// implementation. Use during incremental saga migrations: a flow file
// can wrap its existing closure today and convert to a struct
// implementation later without changing the runner-side construction.
//
// The provisionFn argument is required; passing a nil receiver panics.
// All other behaviors (Requires, RequiredClients, Skip, Deprovision)
// have safe defaults if no AdaptOption sets them.
func FromStepFn(name, condition string, provisionFn StepFn, opts ...AdaptOption) Step {
	if provisionFn == nil {
		panic("saga.FromStepFn: provisionFn must not be nil")
	}
	a := &adaptedStep{
		name:        name,
		condition:   condition,
		provisionFn: provisionFn,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

type adaptedStep struct {
	name          string
	condition     string
	requires      []string
	caps          []ClientCapability
	provisionFn   StepFn
	skipFn        func(ConditionedObject) bool
	deprovisionFn func(context.Context, ConditionedObject, *Deps) error
}

func (a *adaptedStep) Name() string                        { return a.name }
func (a *adaptedStep) Condition() string                   { return a.condition }
func (a *adaptedStep) Requires() []string                  { return a.requires }
func (a *adaptedStep) RequiredClients() []ClientCapability { return a.caps }

func (a *adaptedStep) Skip(obj ConditionedObject) bool {
	if a.skipFn != nil {
		return a.skipFn(obj)
	}
	return false
}

func (a *adaptedStep) Provision(ctx context.Context, obj ConditionedObject, _ *Deps) (done bool, err error) {
	// adaptedStep targets the legacy StepFn signature, which does not
	// receive Deps — wrappers can capture the Deps they need via
	// closure. Future direct-Step implementations get the Deps argument
	// directly.
	return a.provisionFn(ctx, obj)
}

func (a *adaptedStep) Deprovision(ctx context.Context, obj ConditionedObject, deps *Deps) error {
	if a.deprovisionFn != nil {
		return a.deprovisionFn(ctx, obj, deps)
	}
	return nil
}
