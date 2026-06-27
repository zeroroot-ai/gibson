// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package saga_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/testr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// passingStep returns done=true on first call. Used as a minimal step that
// exercises the adapter's happy-path.
type passingStep struct {
	saga.StepBase
	called *int
}

func (s *passingStep) Provision(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	*s.called++
	return true, nil
}

// transientFailingStep always returns a transient error. Verifies the
// adapter requeues with backoff (not Blocked).
type transientFailingStep struct {
	saga.StepBase
}

func (s *transientFailingStep) Provision(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	return false, errors.New("network blip")
}

// permanentFailingStep returns a clients.ErrPermanent-wrapped error so the
// adapter's classifier marks it permanent → Blocked.
type permanentFailingStep struct {
	saga.StepBase
}

func (s *permanentFailingStep) Provision(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	return false, clients.WrapPermanent(errors.New("bad config"))
}

func newTestTenant() *gibsonv1alpha1.Tenant {
	const name = "acme"
	return &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Generation: 1,
			UID:        "test-uid",
		},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: name,
			Owner:       "owner@example.com",
			Tier:        gibsonv1alpha1.TenantPlanTeam,
		},
	}
}

func newTestRunner(t *testing.T) *saga.Runner {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = gibsonv1alpha1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := saga.NewRunner(c, events.NewFakeRecorder(100), testr.New(t))
	r.InitialBackoff = 5 * time.Millisecond
	r.MaxBackoff = 50 * time.Millisecond
	r.RequeueInterval = time.Millisecond
	return r
}

func TestRunner_HappyPath_AllStepsComplete(t *testing.T) {
	r := newTestRunner(t)
	tenant := newTestTenant()

	calledOne, calledTwo := 0, 0
	steps := []saga.Step{
		&passingStep{StepBase: saga.StepBase{N: "One", C: "OneReady"}, called: &calledOne},
		&passingStep{StepBase: saga.StepBase{N: "Two", C: "TwoReady"}, called: &calledTwo},
	}

	result, err := r.Run(context.Background(), tenant, steps, string(gibsonv1alpha1.TenantPhaseReady))
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue, got %v", result.RequeueAfter)
	}
	if calledOne != 1 || calledTwo != 1 {
		t.Errorf("each step expected called once, got one=%d two=%d", calledOne, calledTwo)
	}
	if tenant.Status.Phase != gibsonv1alpha1.TenantPhaseReady {
		t.Errorf("expected Ready phase, got %q", tenant.Status.Phase)
	}
	if !saga.IsConditionTrue(tenant.Status.Conditions, "Ready") {
		t.Errorf("expected Ready=True")
	}
	if !saga.IsConditionTrue(tenant.Status.Conditions, "OneReady") {
		t.Errorf("expected OneReady=True")
	}
	if tenant.Status.ObservedGeneration != 1 {
		t.Errorf("expected observedGeneration=1, got %d", tenant.Status.ObservedGeneration)
	}
}

func TestRunner_TransientError_RequeuesWithoutBlocking(t *testing.T) {
	r := newTestRunner(t)
	tenant := newTestTenant()

	steps := []saga.Step{&transientFailingStep{StepBase: saga.StepBase{N: "Flaky", C: "FlakyReady"}}}
	result, err := r.Run(context.Background(), tenant, steps, string(gibsonv1alpha1.TenantPhaseReady))
	if err == nil {
		t.Fatal("expected non-nil err on transient failure")
	}
	if result.RequeueAfter == 0 {
		t.Errorf("expected RequeueAfter>0 for transient retry, got 0")
	}
	if saga.IsConditionTrue(tenant.Status.Conditions, "Blocked") {
		t.Errorf("transient error must NOT set Blocked")
	}
}

func TestRunner_PermanentError_SetsBlocked(t *testing.T) {
	r := newTestRunner(t)
	tenant := newTestTenant()

	steps := []saga.Step{&permanentFailingStep{StepBase: saga.StepBase{N: "BadConfig", C: "BadConfigReady"}}}
	result, err := r.Run(context.Background(), tenant, steps, string(gibsonv1alpha1.TenantPhaseReady))
	if err != nil {
		// Adapter swallows the err on Blocked outcomes — controller-runtime
		// must NOT requeue, and returning a non-nil err triggers an immediate
		// requeue.
		t.Fatalf("expected nil err on Blocked outcome (controller must not requeue), got %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("Blocked outcome must not requeue, got RequeueAfter=%v", result.RequeueAfter)
	}
	if !saga.IsConditionTrue(tenant.Status.Conditions, "Blocked") {
		t.Errorf("expected Blocked=True after permanent error")
	}
}

// TestRunner_HonorRetryAnnotation_ClearsBlockedAndRemovesAnnotation verifies
// the happy path of the saga-retry-from annotation: a Tenant carrying
// Blocked=SagaFailed AND the annotation gets cleared on the next reconcile
// without operator intervention.
func TestRunner_HonorRetryAnnotation_ClearsBlockedAndRemovesAnnotation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = gibsonv1alpha1.AddToScheme(scheme)
	tenant := newTestTenant()
	tenant.Annotations = map[string]string{
		saga.AnnotationSagaRetryFrom: "WriteInitialFGA",
	}
	tenant.Status.Conditions = []metav1.Condition{
		{
			Type:               "Blocked",
			Status:             metav1.ConditionTrue,
			Reason:             "SagaFailed",
			LastTransitionTime: metav1.NewTime(time.Now()),
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.Tenant{}).
		WithObjects(tenant).
		Build()
	rec := events.NewFakeRecorder(10)
	r := saga.NewRunner(c, rec, testr.New(t))

	honored, err := r.HonorRetryAnnotation(context.Background(), tenant)
	if err != nil {
		t.Fatalf("HonorRetryAnnotation: %v", err)
	}
	if !honored {
		t.Fatal("expected honored=true when annotation is present")
	}
	if _, ok := tenant.Annotations[saga.AnnotationSagaRetryFrom]; ok {
		t.Errorf("annotation must be removed after honoring")
	}
	if saga.IsConditionTrue(tenant.Status.Conditions, "Blocked") {
		t.Errorf("Blocked must be cleared after honoring")
	}
	select {
	case e := <-rec.Events:
		if !strings.Contains(e, "SagaRetryRequested") {
			t.Errorf("event missing SagaRetryRequested: %q", e)
		}
	default:
		t.Errorf("expected an event to be recorded")
	}
}

// TestRunner_HonorRetryAnnotation_NoAnnotationIsNoop verifies that a Tenant
// without the annotation passes through unchanged.
func TestRunner_HonorRetryAnnotation_NoAnnotationIsNoop(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = gibsonv1alpha1.AddToScheme(scheme)
	tenant := newTestTenant()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := saga.NewRunner(c, events.NewFakeRecorder(10), testr.New(t))

	honored, err := r.HonorRetryAnnotation(context.Background(), tenant)
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if honored {
		t.Errorf("expected honored=false when annotation absent")
	}
}

// TestRunner_HonorRetryAnnotation_PreservesNonSagaBlocked verifies that
// Blocked conditions with Reason != SagaFailed are NOT cleared. Spec-level
// permanent failures (SlugCollision, InvalidSpec) must require human
// intervention; the saga-retry-from annotation is for transient upstream
// causes only.
func TestRunner_HonorRetryAnnotation_PreservesNonSagaBlocked(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = gibsonv1alpha1.AddToScheme(scheme)
	tenant := newTestTenant()
	tenant.Annotations = map[string]string{
		saga.AnnotationSagaRetryFrom: "WriteInitialFGA",
	}
	tenant.Status.Conditions = []metav1.Condition{
		{
			Type:               "Blocked",
			Status:             metav1.ConditionTrue,
			Reason:             "SlugCollision",
			LastTransitionTime: metav1.NewTime(time.Now()),
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.Tenant{}).
		WithObjects(tenant).
		Build()
	r := saga.NewRunner(c, events.NewFakeRecorder(10), testr.New(t))

	honored, err := r.HonorRetryAnnotation(context.Background(), tenant)
	if err != nil {
		t.Fatalf("HonorRetryAnnotation: %v", err)
	}
	if !honored {
		t.Fatal("expected honored=true when annotation is present")
	}
	if _, ok := tenant.Annotations[saga.AnnotationSagaRetryFrom]; ok {
		t.Errorf("annotation must be removed even when no SagaFailed condition existed")
	}
	if !saga.IsConditionTrue(tenant.Status.Conditions, "Blocked") {
		t.Errorf("non-SagaFailed Blocked condition must survive — operator must fix the spec")
	}
}

// TestRunner_Run_HonorsRetryAnnotationBeforeSagaRuns verifies that
// Runner.Run automatically honors the annotation before delegating to the
// platform runner, so a tenant that was previously Blocked can re-attempt
// the saga in the same reconcile.
func TestRunner_Run_HonorsRetryAnnotationBeforeSagaRuns(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = gibsonv1alpha1.AddToScheme(scheme)
	tenant := newTestTenant()
	tenant.Annotations = map[string]string{
		saga.AnnotationSagaRetryFrom: "WriteInitialFGA",
	}
	tenant.Status.Conditions = []metav1.Condition{
		{
			Type:               "Blocked",
			Status:             metav1.ConditionTrue,
			Reason:             "SagaFailed",
			LastTransitionTime: metav1.NewTime(time.Now()),
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.Tenant{}).
		WithObjects(tenant).
		Build()
	r := saga.NewRunner(c, events.NewFakeRecorder(10), testr.New(t))
	r.InitialBackoff = time.Millisecond
	r.MaxBackoff = 10 * time.Millisecond
	r.RequeueInterval = time.Millisecond

	called := 0
	steps := []saga.Step{
		&passingStep{StepBase: saga.StepBase{N: "One", C: "OneReady"}, called: &called},
	}

	result, err := r.Run(context.Background(), tenant, steps, string(gibsonv1alpha1.TenantPhaseReady))
	if err != nil {
		t.Fatalf("expected nil err after annotation-driven retry, got %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue (all steps complete), got %v", result.RequeueAfter)
	}
	if called != 1 {
		t.Errorf("expected step to run once after annotation clear, got called=%d", called)
	}
	if _, ok := tenant.Annotations[saga.AnnotationSagaRetryFrom]; ok {
		t.Errorf("annotation must be cleared by Runner.Run")
	}
	if saga.IsConditionTrue(tenant.Status.Conditions, "Blocked") {
		t.Errorf("Blocked must be cleared after successful retry")
	}
}

// ---------------------------------------------------------------------------
// RunForDeletion tests — #157 contract.
// ---------------------------------------------------------------------------

func TestRunForDeletion_AllStepsComplete_ReturnsAllComplete(t *testing.T) {
	r := newTestRunner(t)
	tenant := newTestTenant()
	called := 0
	steps := []saga.Step{
		&passingStep{StepBase: saga.StepBase{N: "Teardown", C: "TeardownReady"}, called: &called},
	}
	outcome := r.RunForDeletion(context.Background(), tenant, steps, string(gibsonv1alpha1.TenantPhaseTerminated))
	if !outcome.AllComplete {
		t.Errorf("expected AllComplete=true, got %+v", outcome)
	}
	if outcome.Blocked {
		t.Errorf("expected Blocked=false, got %+v", outcome)
	}
	if outcome.Err != nil {
		t.Errorf("expected nil err, got %v", outcome.Err)
	}
	if outcome.Result.RequeueAfter != 0 {
		t.Errorf("expected no requeue, got %v", outcome.Result.RequeueAfter)
	}
}

func TestRunForDeletion_PermanentFailure_CompletesViaBestEffort(t *testing.T) {
	// Issue #184: a permanent failure in a SINGLE teardown step no longer
	// halts the saga. The bestEffortStep wrapper catches the classified-
	// permanent error, logs it, and returns success so subsequent steps
	// still get a chance to run. With a 1-step saga, the outcome is
	// therefore AllComplete=true (the only step "completed" via the
	// leak path). The #157 contract (caller proceeds to finalizer
	// removal — no infinite Terminating) still holds, by a different
	// route: the saga is reported as complete rather than blocked.
	r := newTestRunner(t)
	tenant := newTestTenant()
	steps := []saga.Step{
		&permanentFailingStep{StepBase: saga.StepBase{N: "Broken", C: "BrokenReady"}},
	}
	outcome := r.RunForDeletion(context.Background(), tenant, steps, string(gibsonv1alpha1.TenantPhaseTerminated))
	if !outcome.AllComplete {
		t.Errorf("expected AllComplete=true (bestEffort swallows permanent), got %+v", outcome)
	}
	if outcome.Blocked {
		t.Errorf("expected Blocked=false (wrapper converts permanent to leak+continue), got %+v", outcome)
	}
	if outcome.Result.RequeueAfter != 0 {
		t.Errorf("must NOT requeue (caller proceeds to finalizer removal); got RequeueAfter=%v",
			outcome.Result.RequeueAfter)
	}
}

func TestRunForDeletion_PermanentFailureInMiddle_RunsAllSiblings(t *testing.T) {
	// Issue #184 core invariant: a permanent fail on step N does NOT
	// bypass steps N+1..end. Live regression source — before this fix,
	// a step-level UNAUTHORIZED in the middle of the teardown
	// chain triggered the #157 escape hatch and silently skipped
	// DeleteVaultNamespace, RemoveZitadelOrg, DeleteFGATuples,
	// DeleteTenantName, DeleteRedisKeyspace — leaving the K8s ns,
	// OpenBao ns, broker_config row, Zitadel org, and FGA tuples
	// orphaned for every kubectl delete tenant.
	r := newTestRunner(t)
	tenant := newTestTenant()
	aCalls, cCalls := 0, 0
	steps := []saga.Step{
		&passingStep{StepBase: saga.StepBase{N: "A", C: "ACond"}, called: &aCalls},
		&permanentFailingStep{StepBase: saga.StepBase{N: "B", C: "BCond", Req: []string{"A"}}},
		&passingStep{StepBase: saga.StepBase{N: "C", C: "CCond", Req: []string{"B"}}, called: &cCalls},
	}
	outcome := r.RunForDeletion(context.Background(), tenant, steps, string(gibsonv1alpha1.TenantPhaseTerminated))

	if aCalls != 1 {
		t.Errorf("step A ran %d times; want 1", aCalls)
	}
	if cCalls != 1 {
		t.Errorf("step C ran %d times; want 1 — step-isolation regression (tenant-operator#184)", cCalls)
	}
	if outcome.Blocked {
		t.Errorf("expected Blocked=false (wrapper leaks B, A+C succeed), got %+v", outcome)
	}
	if !outcome.AllComplete {
		t.Errorf("expected AllComplete=true; got %+v", outcome)
	}
}

func TestRunForDeletion_TransientError_RequeuesWithoutFinalizing(t *testing.T) {
	// Transient failure during teardown must NOT remove the finalizer.
	// The caller (reconcileDelete) keys off outcome.Result.RequeueAfter > 0
	// to keep the CR alive and retry later.
	r := newTestRunner(t)
	tenant := newTestTenant()
	steps := []saga.Step{
		&transientFailingStep{StepBase: saga.StepBase{N: "Flaky", C: "FlakyReady"}},
	}
	outcome := r.RunForDeletion(context.Background(), tenant, steps, string(gibsonv1alpha1.TenantPhaseTerminated))
	if outcome.Blocked {
		t.Errorf("transient error must NOT mark Blocked, got %+v", outcome)
	}
	if outcome.AllComplete {
		t.Errorf("transient error must NOT mark AllComplete, got %+v", outcome)
	}
	if outcome.Result.RequeueAfter == 0 {
		t.Errorf("transient error must requeue with backoff (so finalizer stays); got 0")
	}
	if outcome.Err == nil {
		t.Errorf("expected non-nil transient err")
	}
}

// TestRunner_SuccessClears_Blocked verifies tenant-operator#141: a tenant that
// previously had a permanent saga failure (Blocked=True) and then has its
// misconfiguration fixed will have the Blocked condition cleared when the saga
// runs to completion successfully.
func TestRunner_SuccessClears_Blocked(t *testing.T) {
	r := newTestRunner(t)
	tenant := newTestTenant()
	// Seed a pre-existing Blocked=True condition (as if a prior reconcile
	// permanently failed and set it).
	tenant.Status.Conditions = []metav1.Condition{
		{
			Type:               "Blocked",
			Status:             metav1.ConditionTrue,
			Reason:             "SagaFailed",
			LastTransitionTime: metav1.NewTime(time.Now()),
		},
	}

	called := 0
	steps := []saga.Step{
		&passingStep{StepBase: saga.StepBase{N: "Fix", C: "FixReady"}, called: &called},
	}
	result, err := r.Run(context.Background(), tenant, steps, string(gibsonv1alpha1.TenantPhaseReady))
	if err != nil {
		t.Fatalf("expected nil err on successful run, got %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue after success, got %v", result.RequeueAfter)
	}
	if saga.IsConditionTrue(tenant.Status.Conditions, "Blocked") {
		t.Errorf("Blocked=True must be cleared after a successful saga run (tenant-operator#141)")
	}
}

func TestRunner_ClearStaleBlocked_DropsAgedSagaFailed(t *testing.T) {
	r := newTestRunner(t)
	conds := []metav1.Condition{
		{
			Type:               "Blocked",
			Status:             metav1.ConditionTrue,
			Reason:             "SagaFailed",
			LastTransitionTime: metav1.NewTime(time.Now().Add(-2 * time.Hour)),
		},
		{
			Type:               "Blocked",
			Status:             metav1.ConditionTrue,
			Reason:             "SlugCollision",
			LastTransitionTime: metav1.NewTime(time.Now().Add(-2 * time.Hour)),
		},
	}
	r.ClearStaleBlocked(&conds)
	if len(conds) != 1 {
		t.Fatalf("expected SagaFailed to be cleared and SlugCollision to remain, got %d conds", len(conds))
	}
	if conds[0].Reason != "SlugCollision" {
		t.Errorf("expected SlugCollision to survive, got reason=%q", conds[0].Reason)
	}
}
