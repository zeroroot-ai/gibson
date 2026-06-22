package flows

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// TestComponentGrantTuplesCanonicalForm pins the FGA tuple shape the
// enrollment saga writes for component grants (gibson#694):
//
//	(<kind>_principal:enrollment-<uid>, direct_execute, component:<name>)
//
// Two historical regressions this guards against:
//   - object "component:<kind>-<name>" — a kind-qualified-dash form no
//     checker derives, so the grant could never match;
//   - relation "can_execute" — a computed relation in model.fga, which
//     OpenFGA rejects tuple writes against.
func TestComponentGrantTuplesCanonicalForm(t *testing.T) {
	ae := makeEnrollmentForKind("uid-canon-1", "tenant-canon", gibsonv1alpha1.PrincipalKindAgent)

	tuples := componentGrantTuples(ae)
	if len(tuples) != 1 {
		t.Fatalf("expected 1 tuple, got %d", len(tuples))
	}
	tu := tuples[0]
	if tu.User != "agent_principal:enrollment-uid-canon-1" {
		t.Errorf("user = %q, want agent_principal:enrollment-uid-canon-1", tu.User)
	}
	if tu.Relation != "direct_execute" {
		t.Errorf("relation = %q, want direct_execute (can_execute is computed and unwritable)", tu.Relation)
	}
	if tu.Object != "component:noop" {
		t.Errorf("object = %q, want canonical bare component:noop", tu.Object)
	}
}

// TestWriteComponentGrantsStepWritesCanonicalTuples runs the actual saga step
// end-to-end against the recording fake and asserts the written tuples carry
// the canonical form, so the step body cannot drift from the helper.
func TestWriteComponentGrantsStepWritesCanonicalTuples(t *testing.T) {
	fakeFGA := &recordingFGA{}
	ae := makeEnrollmentForKind(types.UID("uid-canon-2"), "tenant-canon", gibsonv1alpha1.PrincipalKindTool)

	step := newWriteAgentGrantsStep(EnrollmentDeps{FGA: fakeFGA})
	done, err := step.Provision(context.Background(), ae, nil)
	if err != nil || !done {
		t.Fatalf("Provision = (%v, %v), want (true, nil)", done, err)
	}

	var found bool
	for _, tu := range fakeFGA.snapshot() {
		if tu.Relation == "direct_execute" && tu.Object == "component:noop" &&
			tu.User == "tool_principal:enrollment-uid-canon-2" {
			found = true
		}
		if tu.Object == "component:tool-noop" || tu.Relation == "can_execute" {
			t.Errorf("legacy tuple shape written: %+v", tu)
		}
	}
	if !found {
		t.Fatalf("canonical grant tuple not written; got %+v", fakeFGA.snapshot())
	}
	if got := ae.Status.GrantsAppliedCount; got != 1 {
		t.Errorf("GrantsAppliedCount = %d, want 1", got)
	}
}
