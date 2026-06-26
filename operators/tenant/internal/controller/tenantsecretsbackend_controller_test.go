// Copyright 2026 Zero Day AI, Inc.
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
)

// stubSecretsProvisioner is a fake secrets.Provisioner that records the tenant
// ids it was asked to provision/deprovision and can be configured to fail.
type stubSecretsProvisioner struct {
	provisionErr   error
	deprovisionErr error
	provisioned    []string
	deprovisioned  []string
}

func (s *stubSecretsProvisioner) Provision(_ context.Context, tenantID string) error {
	s.provisioned = append(s.provisioned, tenantID)
	return s.provisionErr
}

func (s *stubSecretsProvisioner) Deprovision(_ context.Context, tenantID string) error {
	s.deprovisioned = append(s.deprovisioned, tenantID)
	return s.deprovisionErr
}

func newTenantSecretsBackend(name, tenantID string) *gibsonv1alpha1.TenantSecretsBackend {
	return &gibsonv1alpha1.TenantSecretsBackend{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tenant-acme"},
		Spec: gibsonv1alpha1.TenantSecretsBackendSpec{
			TenantID: tenantID,
		},
	}
}

func reconcileTSB(t *testing.T, r *TenantSecretsBackendReconciler, name string) (ctrl.Result, error) {
	t.Helper()
	return r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "tenant-acme", Name: name},
	})
}

// First reconcile adds the finalizer; second provisions and marks Ready.
func TestTenantSecretsBackend_ProvisionsAndMarksReady(t *testing.T) {
	scheme := setupScheme(t)
	tsb := newTenantSecretsBackend("acme-secrets", "acme")
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantSecretsBackend{}).
		WithObjects(tsb).
		Build()

	stub := &stubSecretsProvisioner{}
	r := &TenantSecretsBackendReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	// Pass 1: finalizer added, requeue.
	if _, err := reconcileTSB(t, r, "acme-secrets"); err != nil {
		t.Fatalf("reconcile pass 1: %v", err)
	}
	var afterFinalizer gibsonv1alpha1.TenantSecretsBackend
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-secrets"}, &afterFinalizer); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !controllerutil.ContainsFinalizer(&afterFinalizer, gibsonv1alpha1.TenantSecretsBackendFinalizer) {
		t.Fatalf("expected finalizer added on pass 1")
	}
	if len(stub.provisioned) != 0 {
		t.Fatalf("provision must not run before finalizer is set, got %v", stub.provisioned)
	}

	// Pass 2: provision runs, status becomes Ready.
	if _, err := reconcileTSB(t, r, "acme-secrets"); err != nil {
		t.Fatalf("reconcile pass 2: %v", err)
	}
	if len(stub.provisioned) != 1 || stub.provisioned[0] != "acme" {
		t.Fatalf("want Provision(acme) once, got %v", stub.provisioned)
	}

	var got gibsonv1alpha1.TenantSecretsBackend
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-secrets"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.Status.Ready {
		t.Fatalf("want Ready=true, got %+v", got.Status)
	}
	if got.Status.Phase != gibsonv1alpha1.TenantSecretsBackendPhaseReady {
		t.Fatalf("want phase Ready, got %q", got.Status.Phase)
	}
	// vault-namespace, jwt-auth, broker-config
	if len(got.Status.Components) != 3 {
		t.Fatalf("want 3 component conditions, got %d: %+v", len(got.Status.Components), got.Status.Components)
	}
	cond := findCond(got.Status.Conditions, gibsonv1alpha1.ConditionSecretsBackendCRReady)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("want Ready condition True, got %+v", cond)
	}
}

// A provision failure surfaces an error (so controller-runtime backs off) and
// records Failed status without mutating spec.
func TestTenantSecretsBackend_ProvisionFailureSetsFailed(t *testing.T) {
	scheme := setupScheme(t)
	tsb := newTenantSecretsBackend("acme-secrets", "acme")
	controllerutil.AddFinalizer(tsb, gibsonv1alpha1.TenantSecretsBackendFinalizer)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantSecretsBackend{}).
		WithObjects(tsb).
		Build()

	stub := &stubSecretsProvisioner{provisionErr: errors.New("vault namespace create failed")}
	r := &TenantSecretsBackendReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	_, err := reconcileTSB(t, r, "acme-secrets")
	if err == nil {
		t.Fatalf("want error from failed provision so controller-runtime requeues")
	}

	var got gibsonv1alpha1.TenantSecretsBackend
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-secrets"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status.Phase != gibsonv1alpha1.TenantSecretsBackendPhaseFailed {
		t.Fatalf("want phase Failed, got %q", got.Status.Phase)
	}
	if got.Status.Ready {
		t.Fatalf("want Ready=false on failure")
	}
	if got.Status.LastError == "" {
		t.Fatalf("want LastError populated on failure")
	}
}

// Deletion runs the idempotent Deprovision and drops the finalizer.
func TestTenantSecretsBackend_FinalizerTeardown(t *testing.T) {
	scheme := setupScheme(t)
	tsb := newTenantSecretsBackend("acme-secrets", "acme")
	controllerutil.AddFinalizer(tsb, gibsonv1alpha1.TenantSecretsBackendFinalizer)
	now := metav1.Now()
	tsb.DeletionTimestamp = &now
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantSecretsBackend{}).
		WithObjects(tsb).
		Build()

	stub := &stubSecretsProvisioner{}
	r := &TenantSecretsBackendReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	if _, err := reconcileTSB(t, r, "acme-secrets"); err != nil {
		t.Fatalf("reconcile delete: %v", err)
	}
	if len(stub.deprovisioned) != 1 || stub.deprovisioned[0] != "acme" {
		t.Fatalf("want Deprovision(acme), got %v", stub.deprovisioned)
	}
	// After finalizer removal the fake client GCs the object.
	var got gibsonv1alpha1.TenantSecretsBackend
	err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-secrets"}, &got)
	if err == nil {
		t.Fatalf("want object gone after finalizer removal, still present: %+v", got)
	}
}

// A NotFound from Deprovision (backend already gone) is treated as success.
func TestTenantSecretsBackend_TeardownNotFoundIsSuccess(t *testing.T) {
	scheme := setupScheme(t)
	tsb := newTenantSecretsBackend("acme-secrets", "acme")
	controllerutil.AddFinalizer(tsb, gibsonv1alpha1.TenantSecretsBackendFinalizer)
	now := metav1.Now()
	tsb.DeletionTimestamp = &now
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantSecretsBackend{}).
		WithObjects(tsb).
		Build()

	stub := &stubSecretsProvisioner{deprovisionErr: clients.ErrNotFound}
	r := &TenantSecretsBackendReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	if _, err := reconcileTSB(t, r, "acme-secrets"); err != nil {
		t.Fatalf("NotFound from deprovision must not error: %v", err)
	}
	var got gibsonv1alpha1.TenantSecretsBackend
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-secrets"}, &got); err == nil {
		t.Fatalf("want object gone after teardown, still present: %+v", got)
	}
}
