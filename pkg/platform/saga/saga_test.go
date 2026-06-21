package saga_test

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/pkg/platform/saga"
)

// stubStep is a minimal Step implementation used to verify that the
// interface is reachable and that the Runner's expected callees compile.
// This satisfies the "Existing operator step impls can be made to satisfy
// this interface with mechanical changes only (verified by stub
// implementation in test)" success criterion for Phase 1.4.
type stubStep struct {
	name      string
	condition string
	requires  []saga.ClientCapability
}

func (s *stubStep) Name() string                             { return s.name }
func (s *stubStep) Condition() string                        { return s.condition }
func (s *stubStep) Requires() []string                       { return nil }
func (s *stubStep) RequiredClients() []saga.ClientCapability { return s.requires }
func (s *stubStep) Skip(_ saga.ConditionedObject) bool       { return false }
func (s *stubStep) Deprovision(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) error {
	return nil
}
func (s *stubStep) Provision(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	return true, nil
}

// Compile-time interface assertion.
var _ saga.Step = (*stubStep)(nil)

func TestStubStep_SatisfiesInterface(t *testing.T) {
	var _ saga.Step = &stubStep{name: "TestStep", condition: "Tested"}
}

func TestDeps_Has(t *testing.T) {
	// Empty Deps satisfies no capabilities.
	var d saga.Deps
	for _, c := range saga.AllCapabilities() {
		if d.Has(c) {
			t.Errorf("empty Deps reports Has(%s) = true; want false", c)
		}
	}

	// Deps with K8s populated reports K8s but nothing else.
	d.K8s = &fakeK8s{}
	if !d.Has(saga.CapabilityKubernetes) {
		t.Error("Deps with K8s set reports Has(Kubernetes) = false")
	}
	if d.Has(saga.CapabilityVaultAdmin) {
		t.Error("Deps with only K8s reports Has(VaultAdmin) = true")
	}
}

func TestDeps_HasNilReceiver(t *testing.T) {
	var d *saga.Deps // nil
	if d.Has(saga.CapabilityKubernetes) {
		t.Error("nil Deps reports Has() = true")
	}
}

func TestAllCapabilities_NoDuplicates(t *testing.T) {
	seen := map[saga.ClientCapability]bool{}
	for _, c := range saga.AllCapabilities() {
		if seen[c] {
			t.Errorf("AllCapabilities() contains duplicate %s", c)
		}
		seen[c] = true
	}
	// Sanity: at least 11 capabilities listed (Langfuse retired, gibson#755).
	if got := len(saga.AllCapabilities()); got < 11 {
		t.Errorf("AllCapabilities() returned %d entries, want >= 11", got)
	}
}

// Compile-only test — exercises every method on the Step interface so a
// future signature change is immediately visible at compile time.
func TestStep_AllMethodsCallable(t *testing.T) {
	step := &stubStep{name: "TestStep", condition: "Tested"}
	_ = step.Name()
	_ = step.Condition()
	_ = step.Requires()
	_ = step.RequiredClients()
	_ = step.Skip(nil)
	_ = step.Deprovision(context.Background(), nil, nil)
	_, _ = step.Provision(context.Background(), nil, nil)
}

// fakeK8s is an empty placeholder satisfying the KubernetesClient
// interface (which is `any` at this layer).
type fakeK8s struct{}
