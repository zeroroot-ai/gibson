// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"testing"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// stubFinalBackup is the FinalBackupTaker of a test. It returns the values of
// its fields and counts its calls.
type stubFinalBackup struct {
	done  bool
	err   error
	calls int
}

func (s *stubFinalBackup) Ensure(context.Context, *gibsonv1alpha1.Tenant) (bool, error) {
	s.calls++
	return s.done, s.err
}

// provisionedTenantInDeletion provisions the four children of the tenant
// "acme", gives each a finalizer, and deletes the Tenant. It returns the
// reconciler with the given backup gate.
func provisionedTenantInDeletion(t *testing.T, gate *stubFinalBackup) (*TenantReconciler, client.Client) {
	t.Helper()
	r, c := newChildOrchestrationReconciler(t, childOrchestrationTenant())
	r.FinalBackup = gate

	reconcileTenant(t, r)
	reconcileTenant(t, r)
	markIdentityReadyFlag(t, c)
	reconcileTenant(t, r)
	markSecretsReadyFlag(t, c)
	reconcileTenant(t, r)
	markGrantsReadyFlag(t, c)
	reconcileTenant(t, r)
	markDataPlaneReadyFlag(t, c)
	reconcileTenant(t, r)

	addChildFinalizer(t, c, &gibsonv1alpha1.TenantIdentity{}, gibsonv1alpha1.TenantIdentityFinalizer)
	addChildFinalizer(t, c, &gibsonv1alpha1.TenantSecretsBackend{}, gibsonv1alpha1.TenantSecretsBackendFinalizer)
	addChildFinalizer(t, c, &gibsonv1alpha1.TenantGrants{}, gibsonv1alpha1.TenantGrantsFinalizer)
	addChildFinalizer(t, c, &gibsonv1alpha1.TenantDataPlane{}, gibsonv1alpha1.TenantDataPlaneFinalizer)

	var tn gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), types.NamespacedName{Name: "acme"}, &tn); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(context.Background(), &tn); err != nil {
		t.Fatalf("delete tenant: %v", err)
	}
	if gate.calls != 0 {
		t.Fatalf("the backup gate ran %d times before the delete", gate.calls)
	}
	return r, c
}

// assertNothingRemoved fails when the delete flow touched a child or the
// finalizer of the Tenant.
func assertNothingRemoved(t *testing.T, c client.Client) {
	t.Helper()
	for _, child := range []client.Object{
		&gibsonv1alpha1.TenantDataPlane{},
		&gibsonv1alpha1.TenantGrants{},
		&gibsonv1alpha1.TenantSecretsBackend{},
		&gibsonv1alpha1.TenantIdentity{},
	} {
		if !childExists(t, c, child) {
			t.Errorf("%T is gone although the last backup did not complete", child)
		}
		if childDeleting(t, c, child) {
			t.Errorf("%T is in deletion although the last backup did not complete", child)
		}
	}
	var tn gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), types.NamespacedName{Name: "acme"}, &tn); err != nil {
		t.Fatalf("the Tenant is gone although the last backup did not complete: %v", err)
	}
	found := false
	for _, f := range tn.Finalizers {
		if f == gibsonv1alpha1.TenantFinalizer {
			found = true
		}
	}
	if !found {
		t.Error("the Tenant lost its finalizer although the last backup did not complete")
	}
}

// A failed backup stops the delete flow, and the flow removes nothing
// (ADR-0075).
func TestReconcileDelete_FailedBackupRemovesNothing(t *testing.T) {
	backupErr := errors.New("the backup failed")
	gate := &stubFinalBackup{err: backupErr}
	r, c := provisionedTenantInDeletion(t, gate)

	for i := 0; i < 3; i++ {
		_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "acme"}})
		if !errors.Is(err, backupErr) {
			t.Fatalf("pass %d: err = %v, want the backup error", i, err)
		}
	}
	if gate.calls != 3 {
		t.Errorf("the backup gate ran %d times in three passes, want 3", gate.calls)
	}
	assertNothingRemoved(t, c)
}

// While the backup runs, the delete flow waits and removes nothing.
func TestReconcileDelete_UnfinishedBackupRemovesNothing(t *testing.T) {
	gate := &stubFinalBackup{}
	r, c := provisionedTenantInDeletion(t, gate)

	res, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "acme"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != finalBackupRequeueInterval {
		t.Errorf("RequeueAfter = %v, want %v", res.RequeueAfter, finalBackupRequeueInterval)
	}
	assertNothingRemoved(t, c)

	// The control: when the backup completes, the same flow starts to delete
	// the last child. So the assertions above can fail.
	gate.done = true
	reconcileTenant(t, r)
	if !childDeleting(t, c, &gibsonv1alpha1.TenantDataPlane{}) {
		t.Fatal("after the backup completed, the delete flow did not start")
	}
}

// A reconciler with no backup gate deletes nothing.
func TestReconcileDelete_NoBackupGateIsAnError(t *testing.T) {
	gate := &stubFinalBackup{done: true}
	r, c := provisionedTenantInDeletion(t, gate)
	r.FinalBackup = nil

	_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "acme"}})
	if !errors.Is(err, errNoFinalBackupTaker) {
		t.Fatalf("err = %v, want errNoFinalBackupTaker", err)
	}
	assertNothingRemoved(t, c)
}
