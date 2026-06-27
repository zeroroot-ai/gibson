// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
)

// stubGrantsProvisioner is a fake grants.Provisioner that records the tuples it
// was asked to provision/deprovision and can be configured to fail.
type stubGrantsProvisioner struct {
	provisionErr   error
	deprovisionErr error
	provisioned    [][]fga.Tuple
	deprovisioned  [][]fga.Tuple
}

func (s *stubGrantsProvisioner) Provision(_ context.Context, tuples []fga.Tuple) error {
	s.provisioned = append(s.provisioned, tuples)
	return s.provisionErr
}

func (s *stubGrantsProvisioner) Deprovision(_ context.Context, tuples []fga.Tuple) error {
	s.deprovisioned = append(s.deprovisioned, tuples)
	return s.deprovisionErr
}

func newTenantGrants(name, tenantID string) *gibsonv1alpha1.TenantGrants {
	return &gibsonv1alpha1.TenantGrants{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tenant-acme"},
		Spec: gibsonv1alpha1.TenantGrantsSpec{
			TenantID:             tenantID,
			PlatformRegistration: true,
		},
	}
}

func reconcileTG(t *testing.T, r *TenantGrantsReconciler, name string) (ctrl.Result, error) {
	t.Helper()
	return r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "tenant-acme", Name: name},
	})
}

// First reconcile adds the finalizer; second provisions the canonical
// registration tuple and marks Ready.
func TestTenantGrants_ProvisionsAndMarksReady(t *testing.T) {
	scheme := setupScheme(t)
	tg := newTenantGrants("acme-grants", "acme")
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantGrants{}).
		WithObjects(tg).
		Build()

	stub := &stubGrantsProvisioner{}
	r := &TenantGrantsReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	// Pass 1: finalizer added, requeue, no provision yet.
	if _, err := reconcileTG(t, r, "acme-grants"); err != nil {
		t.Fatalf("reconcile pass 1: %v", err)
	}
	var afterFinalizer gibsonv1alpha1.TenantGrants
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-grants"}, &afterFinalizer); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !controllerutil.ContainsFinalizer(&afterFinalizer, gibsonv1alpha1.TenantGrantsFinalizer) {
		t.Fatalf("expected finalizer added on pass 1")
	}
	if len(stub.provisioned) != 0 {
		t.Fatalf("provision must not run before finalizer is set, got %v", stub.provisioned)
	}

	// Pass 2: provision runs, status becomes Ready.
	if _, err := reconcileTG(t, r, "acme-grants"); err != nil {
		t.Fatalf("reconcile pass 2: %v", err)
	}
	if len(stub.provisioned) != 1 || len(stub.provisioned[0]) != 1 {
		t.Fatalf("want one Provision of one tuple, got %v", stub.provisioned)
	}
	want := fga.Tuple{User: "tenant:acme", Relation: "parent", Object: "system_tenant:_system"}
	if stub.provisioned[0][0] != want {
		t.Fatalf("want canonical registration tuple, got %+v", stub.provisioned[0][0])
	}

	var got gibsonv1alpha1.TenantGrants
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-grants"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.Status.Ready {
		t.Fatalf("want Ready=true, got %+v", got.Status)
	}
	if got.Status.Phase != gibsonv1alpha1.TenantGrantsPhaseReady {
		t.Fatalf("want phase Ready, got %q", got.Status.Phase)
	}
	if got.Status.AppliedTuples != 1 {
		t.Fatalf("want AppliedTuples=1, got %d", got.Status.AppliedTuples)
	}
	if len(got.Status.Components) != 1 || got.Status.Components[0].Name != "platform-registration" {
		t.Fatalf("want 1 platform-registration component, got %+v", got.Status.Components)
	}
	cond := findCond(got.Status.Conditions, gibsonv1alpha1.ConditionTenantGrantsReady)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("want Ready condition True, got %+v", cond)
	}
}

// ExtraTuples participate alongside the registration tuple, and the extra-tuples
// component is reported.
func TestTenantGrants_ExtraTuplesReconciled(t *testing.T) {
	scheme := setupScheme(t)
	tg := newTenantGrants("acme-grants", "acme")
	tg.Spec.ExtraTuples = []gibsonv1alpha1.TenantGrantTuple{
		{User: "tenant:acme", Relation: "member", Object: "team:acme"},
	}
	controllerutil.AddFinalizer(tg, gibsonv1alpha1.TenantGrantsFinalizer)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantGrants{}).
		WithObjects(tg).
		Build()

	stub := &stubGrantsProvisioner{}
	r := &TenantGrantsReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	if _, err := reconcileTG(t, r, "acme-grants"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(stub.provisioned) != 1 || len(stub.provisioned[0]) != 2 {
		t.Fatalf("want one Provision of two tuples (registration + extra), got %v", stub.provisioned)
	}
	var got gibsonv1alpha1.TenantGrants
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-grants"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status.AppliedTuples != 2 {
		t.Fatalf("want AppliedTuples=2, got %d", got.Status.AppliedTuples)
	}
	if len(got.Status.Components) != 2 {
		t.Fatalf("want platform-registration + extra-tuples components, got %+v", got.Status.Components)
	}
}

// A provision failure surfaces an error (so controller-runtime backs off) and
// records Failed status without mutating spec.
func TestTenantGrants_ProvisionFailureSetsFailed(t *testing.T) {
	scheme := setupScheme(t)
	tg := newTenantGrants("acme-grants", "acme")
	controllerutil.AddFinalizer(tg, gibsonv1alpha1.TenantGrantsFinalizer)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantGrants{}).
		WithObjects(tg).
		Build()

	stub := &stubGrantsProvisioner{provisionErr: errors.New("fga write failed")}
	r := &TenantGrantsReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	_, err := reconcileTG(t, r, "acme-grants")
	if err == nil {
		t.Fatalf("want error from failed provision so controller-runtime requeues")
	}

	var got gibsonv1alpha1.TenantGrants
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-grants"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status.Phase != gibsonv1alpha1.TenantGrantsPhaseFailed {
		t.Fatalf("want phase Failed, got %q", got.Status.Phase)
	}
	if got.Status.Ready {
		t.Fatalf("want Ready=false on failure")
	}
	if got.Status.LastError == "" {
		t.Fatalf("want LastError populated on failure")
	}
}

// Deletion runs the idempotent Deprovision (passing the desired tuples) and
// drops the finalizer.
func TestTenantGrants_FinalizerTeardown(t *testing.T) {
	scheme := setupScheme(t)
	tg := newTenantGrants("acme-grants", "acme")
	controllerutil.AddFinalizer(tg, gibsonv1alpha1.TenantGrantsFinalizer)
	now := metav1.Now()
	tg.DeletionTimestamp = &now
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantGrants{}).
		WithObjects(tg).
		Build()

	stub := &stubGrantsProvisioner{}
	r := &TenantGrantsReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	if _, err := reconcileTG(t, r, "acme-grants"); err != nil {
		t.Fatalf("reconcile delete: %v", err)
	}
	if len(stub.deprovisioned) != 1 || len(stub.deprovisioned[0]) != 1 {
		t.Fatalf("want Deprovision of the registration tuple, got %v", stub.deprovisioned)
	}
	// After finalizer removal the fake client GCs the object.
	var got gibsonv1alpha1.TenantGrants
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-grants"}, &got); err == nil {
		t.Fatalf("want object gone after finalizer removal, still present: %+v", got)
	}
}

// A NotFound from Deprovision (tuples already gone) is treated as success.
func TestTenantGrants_TeardownNotFoundIsSuccess(t *testing.T) {
	scheme := setupScheme(t)
	tg := newTenantGrants("acme-grants", "acme")
	controllerutil.AddFinalizer(tg, gibsonv1alpha1.TenantGrantsFinalizer)
	now := metav1.Now()
	tg.DeletionTimestamp = &now
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantGrants{}).
		WithObjects(tg).
		Build()

	stub := &stubGrantsProvisioner{deprovisionErr: clients.ErrNotFound}
	r := &TenantGrantsReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	if _, err := reconcileTG(t, r, "acme-grants"); err != nil {
		t.Fatalf("NotFound from deprovision must not error: %v", err)
	}
	var got gibsonv1alpha1.TenantGrants
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-grants"}, &got); err == nil {
		t.Fatalf("want object gone after teardown, still present: %+v", got)
	}
}

// A nil provisioner fails loud in status without mutating spec.
func TestTenantGrants_NilProvisionerFailsLoud(t *testing.T) {
	scheme := setupScheme(t)
	tg := newTenantGrants("acme-grants", "acme")
	controllerutil.AddFinalizer(tg, gibsonv1alpha1.TenantGrantsFinalizer)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantGrants{}).
		WithObjects(tg).
		Build()

	r := &TenantGrantsReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: nil}

	if _, err := reconcileTG(t, r, "acme-grants"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var got gibsonv1alpha1.TenantGrants
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-grants"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status.Phase != gibsonv1alpha1.TenantGrantsPhaseFailed || got.Status.LastError == "" {
		t.Fatalf("want Failed phase + LastError on nil provisioner, got %+v", got.Status)
	}
}
