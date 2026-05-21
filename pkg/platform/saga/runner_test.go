package saga_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/zero-day-ai/gibson/pkg/platform/saga"
)

// --- Test helpers ---

type testStep struct {
	name        string
	condition   string
	requires    []string
	caps        []saga.ClientCapability
	skipFn      func(saga.ConditionedObject) bool
	provisionFn func(context.Context, saga.ConditionedObject, *saga.Deps) (bool, error)
}

func (s *testStep) Name() string                             { return s.name }
func (s *testStep) Condition() string                        { return s.condition }
func (s *testStep) Requires() []string                       { return s.requires }
func (s *testStep) RequiredClients() []saga.ClientCapability { return s.caps }
func (s *testStep) Skip(o saga.ConditionedObject) bool {
	if s.skipFn != nil {
		return s.skipFn(o)
	}
	return false
}
func (s *testStep) Deprovision(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) error {
	return nil
}
func (s *testStep) Provision(ctx context.Context, o saga.ConditionedObject, d *saga.Deps) (bool, error) {
	if s.provisionFn != nil {
		return s.provisionFn(ctx, o, d)
	}
	return true, nil
}

func newStep(name, cond string) *testStep {
	return &testStep{name: name, condition: cond}
}

// fakeObj implements saga.ConditionedObject for tests.
type fakeObj struct {
	metav1.ObjectMeta
	conditions []metav1.Condition
	phase      string
}

func (f *fakeObj) GetObjectKind() schema.ObjectKind { return &gvkProvider{kind: "FakeObj"} }
func (f *fakeObj) DeepCopyObject() runtime.Object {
	cp := *f
	cp.conditions = append([]metav1.Condition(nil), f.conditions...)
	return &cp
}
func (f *fakeObj) GetConditions() *[]metav1.Condition { return &f.conditions }
func (f *fakeObj) GetPhase() string                   { return f.phase }
func (f *fakeObj) SetPhase(p string)                  { f.phase = p }
func (f *fakeObj) GetObservedGeneration() int64       { return 0 }
func (f *fakeObj) SetObservedGeneration(_ int64)      {}

type gvkProvider struct {
	kind string
}

func (g *gvkProvider) GroupVersionKind() schema.GroupVersionKind {
	return schema.GroupVersionKind{Kind: g.kind}
}
func (g *gvkProvider) SetGroupVersionKind(gvk schema.GroupVersionKind) { g.kind = gvk.Kind }

// --- TopoSort tests ---

func TestTopoSort_LinearChain(t *testing.T) {
	a := &testStep{name: "A", condition: "A"}
	b := &testStep{name: "B", condition: "B", requires: []string{"A"}}
	c := &testStep{name: "C", condition: "C", requires: []string{"B"}}
	got, err := saga.TopoSort([]saga.Step{c, b, a})
	if err != nil {
		t.Fatalf("TopoSort: %v", err)
	}
	if got[0].Name() != "A" || got[1].Name() != "B" || got[2].Name() != "C" {
		t.Errorf("order = %s, %s, %s; want A, B, C",
			got[0].Name(), got[1].Name(), got[2].Name())
	}
}

func TestTopoSort_StableForIndependent(t *testing.T) {
	a := &testStep{name: "A", condition: "A"}
	b := &testStep{name: "B", condition: "B"}
	c := &testStep{name: "C", condition: "C"}
	got, _ := saga.TopoSort([]saga.Step{a, b, c})
	if got[0].Name() != "A" || got[1].Name() != "B" || got[2].Name() != "C" {
		t.Errorf("stable order broken: got %s, %s, %s", got[0].Name(), got[1].Name(), got[2].Name())
	}
}

func TestTopoSort_Cycle(t *testing.T) {
	a := &testStep{name: "A", condition: "A", requires: []string{"B"}}
	b := &testStep{name: "B", condition: "B", requires: []string{"A"}}
	_, err := saga.TopoSort([]saga.Step{a, b})
	if err == nil {
		t.Fatal("TopoSort accepted cycle A→B→A")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("error = %q; want mention of cycle", err)
	}
}

func TestTopoSort_UnknownReference(t *testing.T) {
	a := &testStep{name: "A", condition: "A", requires: []string{"Nope"}}
	_, err := saga.TopoSort([]saga.Step{a})
	if err == nil {
		t.Fatal("TopoSort accepted unknown ref")
	}
	if !strings.Contains(err.Error(), "Nope") {
		t.Errorf("error = %q; want mention of unknown step", err)
	}
}

func TestTopoSort_DuplicateNames(t *testing.T) {
	a1 := &testStep{name: "A", condition: "A"}
	a2 := &testStep{name: "A", condition: "A2"}
	_, err := saga.TopoSort([]saga.Step{a1, a2})
	if err == nil {
		t.Fatal("TopoSort accepted duplicate names")
	}
}

func TestTopoSort_EmptyName(t *testing.T) {
	_, err := saga.TopoSort([]saga.Step{&testStep{name: ""}})
	if err == nil {
		t.Fatal("TopoSort accepted empty name")
	}
}

// --- ValidateAtStartup tests ---

func TestValidateAtStartup_AllSatisfied(t *testing.T) {
	s := &testStep{name: "S", condition: "S", caps: []saga.ClientCapability{saga.CapabilityKubernetes}}
	deps := &saga.Deps{K8s: struct{}{}}
	if err := saga.ValidateAtStartup([]saga.Step{s}, deps); err != nil {
		t.Errorf("ValidateAtStartup: %v", err)
	}
}

func TestValidateAtStartup_MissingCapabilities_Aggregated(t *testing.T) {
	s1 := &testStep{name: "S1", condition: "S1", caps: []saga.ClientCapability{saga.CapabilityVaultAdmin, saga.CapabilityFGA}}
	s2 := &testStep{name: "S2", condition: "S2", requires: []string{"S1"}, caps: []saga.ClientCapability{saga.CapabilityVaultAdmin}}
	deps := &saga.Deps{} // empty
	err := saga.ValidateAtStartup([]saga.Step{s1, s2}, deps)
	if err == nil {
		t.Fatal("ValidateAtStartup accepted empty deps")
	}
	var ve *saga.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error type = %T; want *saga.ValidationError", err)
	}
	if len(ve.Missing) != 2 {
		t.Errorf("Missing has %d entries; want 2 (vault-admin, fga)", len(ve.Missing))
	}
	// vault-admin should be required by both S1 and S2 in the aggregation.
	if got := ve.Missing[saga.CapabilityVaultAdmin]; len(got) != 2 {
		t.Errorf("Missing[vault-admin] has %d steps; want 2 (S1, S2)", len(got))
	}
}

// TestValidateAtStartup_TopologyErrorAlwaysReported asserts that a cyclic
// step graph is reported as a startup error regardless of capability
// satisfaction. After the one-code-path epic (deploy#205) removed the
// devMode bypass, this is the only remaining "is the graph structurally
// valid?" check.
func TestValidateAtStartup_TopologyErrorAlwaysReported(t *testing.T) {
	a := &testStep{name: "A", condition: "A", requires: []string{"B"}}
	b := &testStep{name: "B", condition: "B", requires: []string{"A"}}
	if err := saga.ValidateAtStartup([]saga.Step{a, b}, &saga.Deps{}); err == nil {
		t.Error("ValidateAtStartup accepted cycle")
	}
}

// --- Runner tests ---

func TestRunner_Run_AllComplete(t *testing.T) {
	a := newStep("A", "ACond")
	b := newStep("B", "BCond")
	b.requires = []string{"A"}
	r := &saga.Runner{Deps: &saga.Deps{}}
	obj := &fakeObj{ObjectMeta: metav1.ObjectMeta{Name: "test", Generation: 1}}
	res := r.Run(context.Background(), obj, []saga.Step{a, b}, "Ready")
	if !res.AllComplete {
		t.Errorf("AllComplete = false; want true (err=%v)", res.Err)
	}
	if obj.GetPhase() != "Ready" {
		t.Errorf("Phase = %q; want Ready", obj.GetPhase())
	}
}

func TestRunner_Run_TransientErrorRequeues(t *testing.T) {
	a := newStep("A", "ACond")
	a.provisionFn = func(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) (bool, error) {
		return false, errors.New("transient blip")
	}
	r := &saga.Runner{
		Deps:           &saga.Deps{},
		InitialBackoff: 100 * time.Millisecond,
	}
	obj := &fakeObj{ObjectMeta: metav1.ObjectMeta{Name: "test", Generation: 1}}
	res := r.Run(context.Background(), obj, []saga.Step{a}, "Ready")
	if res.Blocked {
		t.Error("transient error caused Blocked=true")
	}
	if res.RequeueAfter <= 0 {
		t.Error("transient error had no RequeueAfter")
	}
	if res.AllComplete {
		t.Error("AllComplete=true on error")
	}
}

func TestRunner_Run_PermanentErrorBlocks(t *testing.T) {
	permanent := &saga.ValidationError{Missing: map[saga.ClientCapability][]string{saga.CapabilityKubernetes: {"S"}}}
	a := newStep("A", "ACond")
	a.provisionFn = func(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) (bool, error) {
		return false, permanent
	}
	r := &saga.Runner{Deps: &saga.Deps{}}
	obj := &fakeObj{ObjectMeta: metav1.ObjectMeta{Name: "test", Generation: 1}}
	res := r.Run(context.Background(), obj, []saga.Step{a}, "Ready")
	if !res.Blocked {
		t.Error("permanent error did not Block")
	}
	if res.AllComplete {
		t.Error("AllComplete=true on permanent error")
	}
	// Tenant should have a Blocked condition.
	c := saga.FindCondition(*obj.GetConditions(), "Blocked")
	if c == nil || c.Status != metav1.ConditionTrue {
		t.Error("Blocked condition not set True")
	}
}

func TestRunner_Run_SkipPredicateMarksTrue(t *testing.T) {
	a := newStep("A", "ACond")
	a.skipFn = func(saga.ConditionedObject) bool { return true }
	a.provisionFn = func(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) (bool, error) {
		t.Error("Provision called even though Skip returned true")
		return true, nil
	}
	r := &saga.Runner{Deps: &saga.Deps{}}
	obj := &fakeObj{ObjectMeta: metav1.ObjectMeta{Name: "test", Generation: 1}}
	res := r.Run(context.Background(), obj, []saga.Step{a}, "Ready")
	if !res.AllComplete {
		t.Errorf("AllComplete = false (err=%v)", res.Err)
	}
	c := saga.FindCondition(*obj.GetConditions(), "ACond")
	if c == nil || c.Reason != saga.ReasonSkipped {
		t.Errorf("Skipped condition not set; got %+v", c)
	}
}

func TestRunner_Run_TopoErrorBlocks(t *testing.T) {
	a := newStep("A", "ACond")
	a.requires = []string{"B"}
	b := newStep("B", "BCond")
	b.requires = []string{"A"}
	r := &saga.Runner{Deps: &saga.Deps{}}
	obj := &fakeObj{ObjectMeta: metav1.ObjectMeta{Name: "test", Generation: 1}}
	res := r.Run(context.Background(), obj, []saga.Step{a, b}, "Ready")
	if !res.Blocked {
		t.Error("Run did not block on topology error")
	}
}

func TestRunner_Backoff_ExponentialCappedAtMax(t *testing.T) {
	// Use a fixed clock so we can control "elapsed time since last
	// transition" deterministically. We set the condition's
	// LastTransitionTime to a known past, then call backoffForStep
	// indirectly by triggering a transient error from a step.
	now := time.Now()
	a := newStep("A", "ACond")
	a.provisionFn = func(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) (bool, error) {
		return false, errors.New("transient")
	}
	clock := func() time.Time { return now }
	r := &saga.Runner{
		Deps:           &saga.Deps{},
		Clock:          clock,
		InitialBackoff: 1 * time.Second,
		MaxBackoff:     10 * time.Second,
	}
	obj := &fakeObj{ObjectMeta: metav1.ObjectMeta{Name: "test", Generation: 1}}
	// First run: condition does not exist yet, backoff should be InitialBackoff.
	res := r.Run(context.Background(), obj, []saga.Step{a}, "Ready")
	if res.RequeueAfter < 1*time.Second || res.RequeueAfter > 1100*time.Millisecond {
		t.Errorf("first transient backoff = %s; want ~1s", res.RequeueAfter)
	}

	// Simulate "5s elapsed since condition first set False" by rewinding
	// LastTransitionTime. With InitialBackoff=1s, that's 5 attempts (well
	// under StepMaxAttempts default 20, so transient handling kicks in
	// rather than Blocked). 2^5=32s, capped at MaxBackoff=10s.
	c := saga.FindCondition(*obj.GetConditions(), "ACond")
	if c == nil {
		t.Fatal("ACond not set after transient error")
	}
	c.LastTransitionTime = metav1.NewTime(now.Add(-5 * time.Second))
	saga.SetCondition(obj.GetConditions(), *c)

	res = r.Run(context.Background(), obj, []saga.Step{a}, "Ready")
	if res.Blocked {
		t.Fatalf("expected transient retry, got Blocked=true")
	}
	if res.RequeueAfter != 10*time.Second {
		t.Errorf("after 5s elapsed (5 attempts, 2^5=32s > Max=10s), backoff = %s; want capped at 10s", res.RequeueAfter)
	}
}

func TestValidateAtStartupVerbose_Summary(t *testing.T) {
	s := &testStep{name: "S", condition: "S", caps: []saga.ClientCapability{saga.CapabilityKubernetes}}
	deps := &saga.Deps{K8s: struct{}{}}
	summary, err := saga.ValidateAtStartupVerbose([]saga.Step{s}, deps)
	if err != nil {
		t.Fatalf("ValidateAtStartupVerbose: %v", err)
	}
	if !strings.Contains(summary, "validated 1 step") {
		t.Errorf("summary missing step count: %q", summary)
	}
	if !strings.Contains(summary, "1 capabilit") {
		t.Errorf("summary missing capability count: %q", summary)
	}
}

func TestValidateAtStartupVerbose_FailureReturnsEmptySummary(t *testing.T) {
	s := &testStep{name: "S", condition: "S", caps: []saga.ClientCapability{saga.CapabilityVaultAdmin}}
	summary, err := saga.ValidateAtStartupVerbose([]saga.Step{s}, &saga.Deps{})
	if err == nil {
		t.Fatal("expected error with missing cap")
	}
	if summary != "" {
		t.Errorf("expected empty summary on failure, got %q", summary)
	}
}

// Sanity that error messages from ValidationError are useful.
func TestValidationError_ErrorMessageMentionsCapabilityAndSteps(t *testing.T) {
	ve := &saga.ValidationError{
		Missing: map[saga.ClientCapability][]string{
			saga.CapabilityVaultAdmin: {"ProvisionPostgres", "ProvisionNeo4j"},
		},
	}
	msg := ve.Error()
	if !strings.Contains(msg, "vault-admin") {
		t.Errorf("error msg %q missing capability name", msg)
	}
	if !strings.Contains(msg, "ProvisionPostgres") {
		t.Errorf("error msg %q missing step name", msg)
	}
	// After deploy#205 the --dev-mode bypass hint is gone — one binary,
	// every environment, capability misses always fail-fast.
	if strings.Contains(msg, "--dev-mode") {
		t.Errorf("error msg %q must no longer reference --dev-mode (deleted in deploy#205)", msg)
	}
}

// TestRunner_Run_ContinueOnBlocked_IteratesPastPermanentFail locks in
// the teardown-saga step-isolation contract (tenant-operator#184): a
// permanent fail on step B must NOT bypass step C. Step B's Blocked
// condition is still set; step C still runs; at end-of-loop the
// outcome is Blocked with the first blocked step's error, but step C
// observed its own success.
func TestRunner_Run_ContinueOnBlocked_IteratesPastPermanentFail(t *testing.T) {
	permanent := &saga.ValidationError{Missing: map[saga.ClientCapability][]string{saga.CapabilityKubernetes: {"B"}}}

	aRan, bRan, cRan := false, false, false
	a := newStep("A", "ACond")
	a.provisionFn = func(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) (bool, error) {
		aRan = true
		return true, nil
	}
	b := newStep("B", "BCond")
	b.requires = []string{"A"}
	b.provisionFn = func(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) (bool, error) {
		bRan = true
		return false, permanent
	}
	c := newStep("C", "CCond")
	c.requires = []string{"B"}
	c.provisionFn = func(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) (bool, error) {
		cRan = true
		return true, nil
	}

	r := &saga.Runner{
		Deps:              &saga.Deps{},
		ContinueOnBlocked: true,
	}
	obj := &fakeObj{ObjectMeta: metav1.ObjectMeta{Name: "test", Generation: 1}}
	res := r.Run(context.Background(), obj, []saga.Step{a, b, c}, "Deleted")

	if !aRan {
		t.Error("A did not run")
	}
	if !bRan {
		t.Error("B did not run")
	}
	if !cRan {
		t.Error("C did not run — step-isolation regression (tenant-operator#184)")
	}
	if !res.Blocked {
		t.Error("expected RunResult.Blocked=true at end of run (first-blocked carryover)")
	}
	if res.AllComplete {
		t.Error("AllComplete=true despite a permanent fail")
	}
	if res.Err == nil || !errors.Is(res.Err, permanent) {
		t.Errorf("Err = %v; want permanent (first-blocked carryover)", res.Err)
	}

	// Step B condition is False; step C condition is True.
	if c := saga.FindCondition(*obj.GetConditions(), "BCond"); c == nil || c.Status != metav1.ConditionFalse {
		t.Errorf("BCond = %+v; want ConditionFalse", c)
	}
	if c := saga.FindCondition(*obj.GetConditions(), "CCond"); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("CCond = %+v; want ConditionTrue", c)
	}
	// Object-level Blocked condition set True (continues to record).
	if c := saga.FindCondition(*obj.GetConditions(), "Blocked"); c == nil || c.Status != metav1.ConditionTrue {
		t.Error("expected object-level Blocked condition True")
	}
	// finalPhase NOT set when any step blocked.
	if obj.GetPhase() == "Deleted" {
		t.Error("finalPhase set despite a blocked step (would falsely advertise teardown complete)")
	}
}

// TestRunner_Run_ContinueOnBlocked_OffByDefault locks in the existing
// halt-on-permanent behavior when ContinueOnBlocked is unset. Provision
// sagas must not regress.
func TestRunner_Run_ContinueOnBlocked_OffByDefault(t *testing.T) {
	permanent := &saga.ValidationError{Missing: map[saga.ClientCapability][]string{saga.CapabilityKubernetes: {"B"}}}
	bRan, cRan := false, false
	b := newStep("B", "BCond")
	b.provisionFn = func(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) (bool, error) {
		bRan = true
		return false, permanent
	}
	c := newStep("C", "CCond")
	c.requires = []string{"B"}
	c.provisionFn = func(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) (bool, error) {
		cRan = true
		return true, nil
	}
	r := &saga.Runner{Deps: &saga.Deps{}}
	obj := &fakeObj{ObjectMeta: metav1.ObjectMeta{Name: "test", Generation: 1}}
	res := r.Run(context.Background(), obj, []saga.Step{b, c}, "Ready")

	if !bRan {
		t.Error("B did not run")
	}
	if cRan {
		t.Error("C ran despite ContinueOnBlocked=false (provision semantics regression)")
	}
	if !res.Blocked {
		t.Error("Blocked=false on permanent fail in default-mode")
	}
}

// Compile-time check that fakeObj satisfies ConditionedObject.
var _ saga.ConditionedObject = (*fakeObj)(nil)

// Sanity check that we have access to time.Time helpers we expect.
var _ = fmt.Sprintf // keep import
