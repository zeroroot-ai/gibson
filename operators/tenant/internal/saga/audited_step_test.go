// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package saga_test

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr/testr"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// loggingStep appends "change:<name>" to log each time it runs, and returns
// err when err is set.
type loggingStep struct {
	saga.StepBase
	log *[]string
	err error
}

func (s *loggingStep) Provision(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	*s.log = append(*s.log, "change:"+s.N)
	if s.err != nil {
		return false, s.err
	}
	return true, nil
}

// auditedRunner is a runner whose audit records go to sink. Each accepted
// record appends "record:<step>" to log.
func auditedRunner(t *testing.T, log *[]string, sink *audittest.Sink) *saga.Runner {
	t.Helper()
	sink.OnEmit = func(ev audit.Event) {
		*log = append(*log, "record:"+ev.Fields["step"]+":"+ev.Result)
	}
	scheme := runtime.NewScheme()
	_ = gibsonv1alpha1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := saga.NewRunner(c, events.NewFakeRecorder(100), testr.New(t), sink.Emitter(t))
	r.RequeueInterval = 0
	return r
}

func twoSteps(log *[]string) []saga.Step {
	return []saga.Step{
		&loggingStep{StepBase: saga.StepBase{N: "One", C: "OneReady"}, log: log},
		&loggingStep{StepBase: saga.StepBase{N: "Two", C: "TwoReady", Req: []string{"One"}}, log: log},
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Each step writes its audit record before it changes state, with the
// tenant, the target and the step (gibson#583).
func TestAuditedStep_RecordsBeforeEachChange(t *testing.T) {
	var log []string
	sink := &audittest.Sink{}
	r := auditedRunner(t, &log, sink)
	if _, err := r.Run(context.Background(), newTestTenant(), twoSteps(&log), string(gibsonv1alpha1.TenantPhaseReady)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []string{"record:One:", "change:One", "record:Two:", "change:Two"}
	if !equal(log, want) {
		t.Fatalf("order = %v, want %v", log, want)
	}
	for _, ev := range sink.Events() {
		if ev.Action != audit.ActionSagaStep || ev.TenantID != "acme" || ev.TargetType != "tenant" ||
			ev.TargetID != "acme" || ev.Fields["final_phase"] != string(gibsonv1alpha1.TenantPhaseReady) {
			t.Errorf("record = %+v", ev)
		}
	}
}

// A step whose audit record cannot be written does not run, and the saga
// does not go on to the next step.
func TestAuditedStep_FailedRecordStopsTheStep(t *testing.T) {
	var log []string
	sink := &audittest.Sink{Err: errors.New("daemon down")}
	r := auditedRunner(t, &log, sink)
	tenant := newTestTenant()
	_, err := r.Run(context.Background(), tenant, twoSteps(&log), string(gibsonv1alpha1.TenantPhaseReady))
	if err == nil {
		t.Fatal("Run returned no error with no audit record")
	}
	if len(log) != 0 {
		t.Fatalf("steps ran with no audit record: %v", log)
	}
	if meta.IsStatusConditionTrue(tenant.Status.Conditions, "OneReady") {
		t.Fatal("the step is marked done with no audit record")
	}
}

// A step that fails after its record gets a second record with the result
// "failure" and the reason.
func TestAuditedStep_FailedChangeIsRecorded(t *testing.T) {
	var log []string
	sink := &audittest.Sink{}
	r := auditedRunner(t, &log, sink)
	steps := []saga.Step{&loggingStep{StepBase: saga.StepBase{N: "One", C: "OneReady"}, log: &log, err: errors.New("redis down")}}
	if _, err := r.Run(context.Background(), newTestTenant(), steps, string(gibsonv1alpha1.TenantPhaseReady)); err == nil {
		t.Fatal("Run returned no error for a failed step")
	}
	want := []string{"record:One:", "change:One", "record:One:failure"}
	if !equal(log, want) {
		t.Fatalf("order = %v, want %v", log, want)
	}
	if got := sink.Events()[1].Reason; got != "redis down" {
		t.Errorf("reason = %q, want %q", got, "redis down")
	}
}

// A step that already holds at this generation runs its idempotent re-check
// with no new record. A new generation gets a new record.
func TestAuditedStep_SettledStepWritesNoRecord(t *testing.T) {
	var log []string
	sink := &audittest.Sink{}
	r := auditedRunner(t, &log, sink)
	tenant := newTestTenant()
	steps := twoSteps(&log)
	for range 2 {
		if _, err := r.Run(context.Background(), tenant, steps, string(gibsonv1alpha1.TenantPhaseReady)); err != nil {
			t.Fatalf("Run: %v", err)
		}
	}
	if n := len(sink.Events()); n != 2 {
		t.Fatalf("records after two passes = %d, want 2", n)
	}
	tenant.Generation++
	if _, err := r.Run(context.Background(), tenant, steps, string(gibsonv1alpha1.TenantPhaseReady)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := len(sink.Events()); n != 4 {
		t.Fatalf("records after a new generation = %d, want 4", n)
	}
}

// A runner with no audit emitter runs no step, in both flows.
func TestRunner_NoAuditRunsNothing(t *testing.T) {
	var log []string
	scheme := runtime.NewScheme()
	_ = gibsonv1alpha1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := saga.NewRunner(c, events.NewFakeRecorder(10), testr.New(t), nil)
	if _, err := r.Run(context.Background(), newTestTenant(), twoSteps(&log), "Ready"); !errors.Is(err, saga.ErrNoAudit) {
		t.Fatalf("Run = %v, want ErrNoAudit", err)
	}
	out := r.RunForDeletion(context.Background(), newTestTenant(), twoSteps(&log), "Terminated")
	if !errors.Is(out.Err, saga.ErrNoAudit) || out.AllComplete || out.Blocked {
		t.Fatalf("RunForDeletion = %+v, want ErrNoAudit and not finished", out)
	}
	if len(log) != 0 {
		t.Fatalf("steps ran with no audit emitter: %v", log)
	}
}

// The record of a namespaced object belongs to the tenant of its namespace.
func TestAuditedStep_EnrollmentRecordNamesItsTenant(t *testing.T) {
	var log []string
	sink := &audittest.Sink{}
	r := auditedRunner(t, &log, sink)
	ae := &gibsonv1alpha1.AgentEnrollment{ObjectMeta: metav1.ObjectMeta{Name: "agent-1", Namespace: "tenant-acme", Generation: 1}}
	steps := []saga.Step{&loggingStep{StepBase: saga.StepBase{N: "One", C: "OneReady"}, log: &log}}
	if _, err := r.Run(context.Background(), ae, steps, string(gibsonv1alpha1.AgentEnrollmentPhaseActive)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	ev := sink.Events()[0]
	if ev.TenantID != "acme" || ev.TargetType != "agentenrollment" || ev.TargetID != "tenant-acme/agent-1" {
		t.Fatalf("record = %+v", ev)
	}
}
