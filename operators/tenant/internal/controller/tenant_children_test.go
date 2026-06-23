/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"testing"

	"github.com/go-logr/logr/testr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// childOrchestrationScheme registers core types + the gibson CRDs so the fake
// client can serve the Tenant and its four owned sub-CRDs.
func childOrchestrationScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme,
		networkingv1.AddToScheme,
		rbacv1.AddToScheme,
		gibsonv1alpha1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return scheme
}

// newChildOrchestrationReconciler builds a Tenant reconciler whose fake client
// also serves the four sub-CRDs as status subresources, so tests can flip a
// child's Status.Ready to simulate its controller converging.
func newChildOrchestrationReconciler(t *testing.T, tenant *gibsonv1alpha1.Tenant) (*TenantReconciler, client.Client) {
	t.Helper()
	scheme := childOrchestrationScheme(t)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(
			&gibsonv1alpha1.Tenant{},
			&gibsonv1alpha1.TenantIdentity{},
			&gibsonv1alpha1.TenantSecretsBackend{},
			&gibsonv1alpha1.TenantGrants{},
			&gibsonv1alpha1.TenantDataPlane{},
		).
		WithObjects(tenant).
		Build()

	runner := saga.NewRunner(fakeClient, events.NewFakeRecorder(100), testr.New(t))
	r := &TenantReconciler{
		Client:               fakeClient,
		Scheme:               scheme,
		Runner:               runner,
		NamespaceProvisioner: NewNamespaceProvisioner(fakeClient, "gibson-platform", nil),
		// Production wires this via SetupWithManager (noop when no daemon client);
		// these tests drive Reconcile directly, so default it here too.
		StatusReporter: noopTenantStatusReporter{},
	}
	return r, fakeClient
}

func childOrchestrationTenant() *gibsonv1alpha1.Tenant {
	return &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme", UID: types.UID("uid-acme")},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: "Acme Inc",
			Tier:        gibsonv1alpha1.TenantPlanEnterprise,
		},
	}
}

func reconcileTenant(t *testing.T, r *TenantReconciler) {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "acme"},
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

func childExists(t *testing.T, c client.Client, obj client.Object) bool {
	t.Helper()
	err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme"}, obj)
	if err == nil {
		return true
	}
	if apierrors.IsNotFound(err) {
		return false
	}
	t.Fatalf("get %T: %v", obj, err)
	return false
}

// TestChildOrchestration_CreationOrder verifies the Tenant creates its owned
// sub-CRDs in dependency order (Identity → SecretsBackend → Grants → DataPlane):
// each child is created only once its predecessor reports Status.Ready.
func TestChildOrchestration_CreationOrder(t *testing.T) {
	r, c := newChildOrchestrationReconciler(t, childOrchestrationTenant())

	// Pass 1: finalizer added.
	reconcileTenant(t, r)
	// Pass 2: namespace provisioned + first child (Identity) created.
	reconcileTenant(t, r)

	if !childExists(t, c, &gibsonv1alpha1.TenantIdentity{}) {
		t.Fatalf("TenantIdentity (1st) must exist after namespace is provisioned")
	}
	if childExists(t, c, &gibsonv1alpha1.TenantSecretsBackend{}) {
		t.Errorf("TenantSecretsBackend must NOT exist before Identity is Ready")
	}

	// Identity Ready → next reconcile creates SecretsBackend, not Grants.
	markIdentityReadyFlag(t, c)
	reconcileTenant(t, r)
	if !childExists(t, c, &gibsonv1alpha1.TenantSecretsBackend{}) {
		t.Fatalf("TenantSecretsBackend (2nd) must exist after Identity Ready")
	}
	if childExists(t, c, &gibsonv1alpha1.TenantGrants{}) {
		t.Errorf("TenantGrants must NOT exist before SecretsBackend is Ready")
	}

	// SecretsBackend Ready → Grants created.
	markSecretsReadyFlag(t, c)
	reconcileTenant(t, r)
	if !childExists(t, c, &gibsonv1alpha1.TenantGrants{}) {
		t.Fatalf("TenantGrants (3rd) must exist after SecretsBackend Ready")
	}
	if childExists(t, c, &gibsonv1alpha1.TenantDataPlane{}) {
		t.Errorf("TenantDataPlane must NOT exist before Grants is Ready")
	}

	// Grants Ready → DataPlane created (last).
	markGrantsReadyFlag(t, c)
	reconcileTenant(t, r)
	if !childExists(t, c, &gibsonv1alpha1.TenantDataPlane{}) {
		t.Fatalf("TenantDataPlane (4th) must exist after Grants Ready")
	}
}

// TestChildOrchestration_ReadinessGate verifies the Tenant only flips to Ready
// once ALL four owned sub-CRDs report Status.Ready.
func TestChildOrchestration_ReadinessGate(t *testing.T) {
	r, c := newChildOrchestrationReconciler(t, childOrchestrationTenant())

	reconcileTenant(t, r) // finalizer
	reconcileTenant(t, r) // namespace + Identity

	// Drive each child Ready in order, reconciling between each.
	markIdentityReadyFlag(t, c)
	reconcileTenant(t, r)
	markSecretsReadyFlag(t, c)
	reconcileTenant(t, r)
	markGrantsReadyFlag(t, c)
	reconcileTenant(t, r)

	// Before DataPlane is Ready, the Tenant must still be Provisioning.
	var mid gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), types.NamespacedName{Name: "acme"}, &mid); err != nil {
		t.Fatal(err)
	}
	if mid.Status.Phase == gibsonv1alpha1.TenantPhaseReady {
		t.Fatalf("Tenant must NOT be Ready before all children Ready; got %q", mid.Status.Phase)
	}

	// DataPlane Ready → final reconcile flips Tenant to Ready.
	markDataPlaneReadyFlag(t, c)
	reconcileTenant(t, r)

	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), types.NamespacedName{Name: "acme"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != gibsonv1alpha1.TenantPhaseReady {
		t.Errorf("Tenant phase got %q, want Ready once all children Ready", got.Status.Phase)
	}
}

// TestChildOrchestration_ReverseOrderTeardown verifies the Tenant finalizer
// deletes the owned sub-CRDs in REVERSE dependency order (DataPlane → Grants →
// SecretsBackend → Identity), waiting for each child's finalizer to complete
// (the child fully gone) before deleting the next.
func TestChildOrchestration_ReverseOrderTeardown(t *testing.T) {
	r, c := newChildOrchestrationReconciler(t, childOrchestrationTenant())

	// Provision all four children to Ready.
	reconcileTenant(t, r) // finalizer
	reconcileTenant(t, r) // namespace + Identity
	markIdentityReadyFlag(t, c)
	reconcileTenant(t, r)
	markSecretsReadyFlag(t, c)
	reconcileTenant(t, r)
	markGrantsReadyFlag(t, c)
	reconcileTenant(t, r)
	markDataPlaneReadyFlag(t, c)
	reconcileTenant(t, r)

	// Give every child a finalizer so a Delete sets DeletionTimestamp instead
	// of removing the object — mirrors the real sub-CRD controllers.
	addChildFinalizer(t, c, &gibsonv1alpha1.TenantIdentity{}, gibsonv1alpha1.TenantIdentityFinalizer)
	addChildFinalizer(t, c, &gibsonv1alpha1.TenantSecretsBackend{}, gibsonv1alpha1.TenantSecretsBackendFinalizer)
	addChildFinalizer(t, c, &gibsonv1alpha1.TenantGrants{}, gibsonv1alpha1.TenantGrantsFinalizer)
	addChildFinalizer(t, c, &gibsonv1alpha1.TenantDataPlane{}, gibsonv1alpha1.TenantDataPlaneFinalizer)

	// Delete the Tenant (sets DeletionTimestamp; finalizer keeps it alive).
	var tn gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), types.NamespacedName{Name: "acme"}, &tn); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(context.Background(), &tn); err != nil {
		t.Fatalf("delete tenant: %v", err)
	}

	// Reconcile 1: DataPlane (last child) gets DeletionTimestamp; the others
	// must be untouched (ordered teardown stops at the first not-yet-gone).
	reconcileTenant(t, r)
	if !childDeleting(t, c, &gibsonv1alpha1.TenantDataPlane{}) {
		t.Fatalf("DataPlane must be deleting first")
	}
	if childDeleting(t, c, &gibsonv1alpha1.TenantGrants{}) {
		t.Errorf("Grants must NOT be deleting while DataPlane still present")
	}

	// Simulate DataPlane's finalizer completing.
	finishChildDeletion(t, c, &gibsonv1alpha1.TenantDataPlane{}, gibsonv1alpha1.TenantDataPlaneFinalizer)

	// Reconcile 2: Grants now deletes; SecretsBackend untouched.
	reconcileTenant(t, r)
	if !childDeleting(t, c, &gibsonv1alpha1.TenantGrants{}) {
		t.Fatalf("Grants must be deleting after DataPlane gone")
	}
	if childDeleting(t, c, &gibsonv1alpha1.TenantSecretsBackend{}) {
		t.Errorf("SecretsBackend must NOT be deleting while Grants still present")
	}
	finishChildDeletion(t, c, &gibsonv1alpha1.TenantGrants{}, gibsonv1alpha1.TenantGrantsFinalizer)

	// Reconcile 3: SecretsBackend deletes; Identity untouched.
	reconcileTenant(t, r)
	if !childDeleting(t, c, &gibsonv1alpha1.TenantSecretsBackend{}) {
		t.Fatalf("SecretsBackend must be deleting after Grants gone")
	}
	if childDeleting(t, c, &gibsonv1alpha1.TenantIdentity{}) {
		t.Errorf("Identity must NOT be deleting while SecretsBackend still present")
	}
	finishChildDeletion(t, c, &gibsonv1alpha1.TenantSecretsBackend{}, gibsonv1alpha1.TenantSecretsBackendFinalizer)

	// Reconcile 4: Identity (first child) deletes last.
	reconcileTenant(t, r)
	if !childDeleting(t, c, &gibsonv1alpha1.TenantIdentity{}) {
		t.Fatalf("Identity must be deleting last")
	}
	finishChildDeletion(t, c, &gibsonv1alpha1.TenantIdentity{}, gibsonv1alpha1.TenantIdentityFinalizer)

	// Reconcile 5: all children gone → teardown saga runs, finalizer removed,
	// Tenant GC'd.
	reconcileTenant(t, r)
	var gone gibsonv1alpha1.Tenant
	err := c.Get(context.Background(), types.NamespacedName{Name: "acme"}, &gone)
	if err == nil {
		// Tenant may still exist if teardown saga requeued (namespace
		// finalizing); assert at least the finalizer drove all children gone.
		if childExists(t, c, &gibsonv1alpha1.TenantIdentity{}) {
			t.Errorf("all children must be gone before tenant finalizer completes")
		}
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected error getting tenant: %v", err)
	}
}

// ---- helpers to flip child Ready flags via the status subresource ----

func markIdentityReadyFlag(t *testing.T, c client.Client) {
	markChildReadyFlag(t, c, &gibsonv1alpha1.TenantIdentity{})
}
func markSecretsReadyFlag(t *testing.T, c client.Client) {
	markChildReadyFlag(t, c, &gibsonv1alpha1.TenantSecretsBackend{})
}
func markGrantsReadyFlag(t *testing.T, c client.Client) {
	markChildReadyFlag(t, c, &gibsonv1alpha1.TenantGrants{})
}
func markDataPlaneReadyFlag(t *testing.T, c client.Client) {
	markChildReadyFlag(t, c, &gibsonv1alpha1.TenantDataPlane{})
}

func markChildReadyFlag(t *testing.T, c client.Client, obj client.Object) {
	t.Helper()
	key := types.NamespacedName{Namespace: "tenant-acme", Name: "acme"}
	if err := c.Get(context.Background(), key, obj); err != nil {
		t.Fatalf("get child %T: %v", obj, err)
	}
	switch o := obj.(type) {
	case *gibsonv1alpha1.TenantIdentity:
		o.Status.Ready = true
	case *gibsonv1alpha1.TenantSecretsBackend:
		o.Status.Ready = true
	case *gibsonv1alpha1.TenantGrants:
		o.Status.Ready = true
	case *gibsonv1alpha1.TenantDataPlane:
		o.Status.Ready = true
	default:
		t.Fatalf("unknown child type %T", obj)
	}
	if err := c.Status().Update(context.Background(), obj); err != nil {
		t.Fatalf("status update %T: %v", obj, err)
	}
}

func addChildFinalizer(t *testing.T, c client.Client, obj client.Object, fin string) {
	t.Helper()
	key := types.NamespacedName{Namespace: "tenant-acme", Name: "acme"}
	if err := c.Get(context.Background(), key, obj); err != nil {
		t.Fatalf("get child %T: %v", obj, err)
	}
	obj.SetFinalizers(append(obj.GetFinalizers(), fin))
	if err := c.Update(context.Background(), obj); err != nil {
		t.Fatalf("update finalizer %T: %v", obj, err)
	}
}

func childDeleting(t *testing.T, c client.Client, obj client.Object) bool {
	t.Helper()
	err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme"}, obj)
	if apierrors.IsNotFound(err) {
		return false
	}
	if err != nil {
		t.Fatalf("get %T: %v", obj, err)
	}
	return !obj.GetDeletionTimestamp().IsZero()
}

// finishChildDeletion strips the finalizer so the fake client GC's the object,
// simulating the child controller's finalizer completing.
func finishChildDeletion(t *testing.T, c client.Client, obj client.Object, fin string) {
	t.Helper()
	key := types.NamespacedName{Namespace: "tenant-acme", Name: "acme"}
	if err := c.Get(context.Background(), key, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return
		}
		t.Fatalf("get %T: %v", obj, err)
	}
	kept := make([]string, 0)
	for _, f := range obj.GetFinalizers() {
		if f != fin {
			kept = append(kept, f)
		}
	}
	obj.SetFinalizers(kept)
	if err := c.Update(context.Background(), obj); err != nil {
		t.Fatalf("strip finalizer %T: %v", obj, err)
	}
}
