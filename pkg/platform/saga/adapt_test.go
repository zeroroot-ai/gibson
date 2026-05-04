package saga_test

import (
	"context"
	"errors"
	"testing"

	"github.com/zero-day-ai/gibson/pkg/platform/saga"
)

func TestFromStepFn_Defaults(t *testing.T) {
	step := saga.FromStepFn("Test", "TestReady",
		func(_ context.Context, _ saga.ConditionedObject) (bool, error) { return true, nil },
	)

	if step.Name() != "Test" {
		t.Errorf("Name() = %q, want Test", step.Name())
	}
	if step.Condition() != "TestReady" {
		t.Errorf("Condition() = %q, want TestReady", step.Condition())
	}
	if len(step.Requires()) != 0 {
		t.Errorf("default Requires() = %v, want empty", step.Requires())
	}
	if len(step.RequiredClients()) != 0 {
		t.Errorf("default RequiredClients() = %v, want empty", step.RequiredClients())
	}
	if step.Skip(nil) {
		t.Error("default Skip() = true, want false")
	}
	if err := step.Deprovision(context.Background(), nil, nil); err != nil {
		t.Errorf("default Deprovision() = %v, want nil", err)
	}
}

func TestFromStepFn_Options(t *testing.T) {
	deprovisionCalled := false
	skipCalled := false

	step := saga.FromStepFn("WithOpts", "OptsReady",
		func(_ context.Context, _ saga.ConditionedObject) (bool, error) { return true, nil },
		saga.WithRequires("DepA", "DepB"),
		saga.WithRequiredClients(saga.CapabilityVaultAdmin, saga.CapabilityFGA),
		saga.WithSkipFn(func(_ saga.ConditionedObject) bool { skipCalled = true; return true }),
		saga.WithDeprovisionFn(func(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) error {
			deprovisionCalled = true
			return errors.New("deprovision oops")
		}),
	)

	if got := step.Requires(); len(got) != 2 || got[0] != "DepA" || got[1] != "DepB" {
		t.Errorf("Requires() = %v, want [DepA DepB]", got)
	}
	if got := step.RequiredClients(); len(got) != 2 ||
		got[0] != saga.CapabilityVaultAdmin || got[1] != saga.CapabilityFGA {
		t.Errorf("RequiredClients() = %v, want [vault-admin fga]", got)
	}
	if !step.Skip(nil) {
		t.Error("WithSkipFn returning true was not applied")
	}
	if !skipCalled {
		t.Error("Skip predicate was not invoked")
	}
	if err := step.Deprovision(context.Background(), nil, nil); err == nil || err.Error() != "deprovision oops" {
		t.Errorf("Deprovision returned %v, want 'deprovision oops'", err)
	}
	if !deprovisionCalled {
		t.Error("Deprovision callback was not invoked")
	}
}

func TestFromStepFn_NilFnPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("FromStepFn with nil provisionFn did not panic")
		}
	}()
	_ = saga.FromStepFn("T", "TR", nil)
}

// Compile-time guard.
var _ saga.Step = saga.FromStepFn("compile", "compile",
	func(_ context.Context, _ saga.ConditionedObject) (bool, error) { return true, nil })
