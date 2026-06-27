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
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/identity"
)

// stubIdentityProvisioner is a fake identity.Provisioner that records the
// requests it was asked to provision/deprovision and can be configured to fail.
type stubIdentityProvisioner struct {
	provisionErr   error
	deprovisionErr error
	result         identity.Result
	provisioned    []identity.Request
	deprovisioned  []string
}

func (s *stubIdentityProvisioner) Provision(_ context.Context, req identity.Request) (identity.Result, error) {
	s.provisioned = append(s.provisioned, req)
	if s.provisionErr != nil {
		return identity.Result{}, s.provisionErr
	}
	return s.result, nil
}

func (s *stubIdentityProvisioner) Deprovision(_ context.Context, orgID string) error {
	s.deprovisioned = append(s.deprovisioned, orgID)
	return s.deprovisionErr
}

func newTenantIdentity(name, tenantID string) *gibsonv1alpha1.TenantIdentity {
	return &gibsonv1alpha1.TenantIdentity{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tenant-acme"},
		Spec: gibsonv1alpha1.TenantIdentitySpec{
			TenantID:    tenantID,
			DisplayName: "Acme Corp",
		},
	}
}

func reconcileTI(t *testing.T, r *TenantIdentityReconciler, name string) (ctrl.Result, error) {
	t.Helper()
	return r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "tenant-acme", Name: name},
	})
}

// First reconcile adds the finalizer; second provisions and marks Ready,
// recording the org id/slug returned by the provisioner.
func TestTenantIdentity_ProvisionsAndMarksReady(t *testing.T) {
	scheme := setupScheme(t)
	ti := newTenantIdentity("acme-identity", "acme")
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantIdentity{}).
		WithObjects(ti).
		Build()

	stub := &stubIdentityProvisioner{result: identity.Result{OrgID: "org-123", Slug: "acme"}}
	r := &TenantIdentityReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	// Pass 1: finalizer added, requeue.
	if _, err := reconcileTI(t, r, "acme-identity"); err != nil {
		t.Fatalf("reconcile pass 1: %v", err)
	}
	var afterFinalizer gibsonv1alpha1.TenantIdentity
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-identity"}, &afterFinalizer); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !controllerutil.ContainsFinalizer(&afterFinalizer, gibsonv1alpha1.TenantIdentityFinalizer) {
		t.Fatalf("expected finalizer added on pass 1")
	}
	if len(stub.provisioned) != 0 {
		t.Fatalf("provision must not run before finalizer is set, got %v", stub.provisioned)
	}

	// Pass 2: provision runs, status becomes Ready.
	if _, err := reconcileTI(t, r, "acme-identity"); err != nil {
		t.Fatalf("reconcile pass 2: %v", err)
	}
	if len(stub.provisioned) != 1 || stub.provisioned[0].TenantID != "acme" {
		t.Fatalf("want Provision(acme) once, got %v", stub.provisioned)
	}
	if stub.provisioned[0].DisplayName != "Acme Corp" {
		t.Fatalf("want DisplayName passed through, got %q", stub.provisioned[0].DisplayName)
	}

	var got gibsonv1alpha1.TenantIdentity
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-identity"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.Status.Ready {
		t.Fatalf("want Ready=true, got %+v", got.Status)
	}
	if got.Status.Phase != gibsonv1alpha1.TenantIdentityPhaseReady {
		t.Fatalf("want phase Ready, got %q", got.Status.Phase)
	}
	if got.Status.ZitadelOrgID != "org-123" || got.Status.ZitadelOrgSlug != "acme" {
		t.Fatalf("want org id/slug recorded on status, got id=%q slug=%q", got.Status.ZitadelOrgID, got.Status.ZitadelOrgSlug)
	}
	// zitadel-org only (no OIDC clients requested).
	if len(got.Status.Components) != 1 || got.Status.Components[0].Name != "zitadel-org" {
		t.Fatalf("want 1 zitadel-org component, got %+v", got.Status.Components)
	}
	cond := findCond(got.Status.Conditions, gibsonv1alpha1.ConditionTenantIdentityReady)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("want Ready condition True, got %+v", cond)
	}
}

// When the spec requests an OIDC client, the oidc-client component participates.
func TestTenantIdentity_OIDCClientComponentReported(t *testing.T) {
	scheme := setupScheme(t)
	ti := newTenantIdentity("acme-identity", "acme")
	ti.Spec.OIDCClients = []gibsonv1alpha1.TenantIdentityOIDCClient{{Name: "dashboard"}}
	controllerutil.AddFinalizer(ti, gibsonv1alpha1.TenantIdentityFinalizer)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantIdentity{}).
		WithObjects(ti).
		Build()

	stub := &stubIdentityProvisioner{result: identity.Result{OrgID: "org-123", Slug: "acme"}}
	r := &TenantIdentityReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	if _, err := reconcileTI(t, r, "acme-identity"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var got gibsonv1alpha1.TenantIdentity
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-identity"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Status.Components) != 2 {
		t.Fatalf("want zitadel-org + oidc-client components, got %+v", got.Status.Components)
	}
}

// A provision failure surfaces an error (so controller-runtime backs off) and
// records Failed status without mutating spec.
func TestTenantIdentity_ProvisionFailureSetsFailed(t *testing.T) {
	scheme := setupScheme(t)
	ti := newTenantIdentity("acme-identity", "acme")
	controllerutil.AddFinalizer(ti, gibsonv1alpha1.TenantIdentityFinalizer)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantIdentity{}).
		WithObjects(ti).
		Build()

	stub := &stubIdentityProvisioner{provisionErr: errors.New("zitadel create org failed")}
	r := &TenantIdentityReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	_, err := reconcileTI(t, r, "acme-identity")
	if err == nil {
		t.Fatalf("want error from failed provision so controller-runtime requeues")
	}

	var got gibsonv1alpha1.TenantIdentity
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-identity"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status.Phase != gibsonv1alpha1.TenantIdentityPhaseFailed {
		t.Fatalf("want phase Failed, got %q", got.Status.Phase)
	}
	if got.Status.Ready {
		t.Fatalf("want Ready=false on failure")
	}
	if got.Status.LastError == "" {
		t.Fatalf("want LastError populated on failure")
	}
}

// Deletion runs the idempotent Deprovision (passing the recorded org id) and
// drops the finalizer.
func TestTenantIdentity_FinalizerTeardown(t *testing.T) {
	scheme := setupScheme(t)
	ti := newTenantIdentity("acme-identity", "acme")
	ti.Status.ZitadelOrgID = "org-123"
	controllerutil.AddFinalizer(ti, gibsonv1alpha1.TenantIdentityFinalizer)
	now := metav1.Now()
	ti.DeletionTimestamp = &now
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantIdentity{}).
		WithObjects(ti).
		Build()

	stub := &stubIdentityProvisioner{}
	r := &TenantIdentityReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	if _, err := reconcileTI(t, r, "acme-identity"); err != nil {
		t.Fatalf("reconcile delete: %v", err)
	}
	if len(stub.deprovisioned) != 1 || stub.deprovisioned[0] != "org-123" {
		t.Fatalf("want Deprovision(org-123), got %v", stub.deprovisioned)
	}
	// After finalizer removal the fake client GCs the object.
	var got gibsonv1alpha1.TenantIdentity
	err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-identity"}, &got)
	if err == nil {
		t.Fatalf("want object gone after finalizer removal, still present: %+v", got)
	}
}

// A NotFound from Deprovision (org already gone) is treated as success.
func TestTenantIdentity_TeardownNotFoundIsSuccess(t *testing.T) {
	scheme := setupScheme(t)
	ti := newTenantIdentity("acme-identity", "acme")
	ti.Status.ZitadelOrgID = "org-123"
	controllerutil.AddFinalizer(ti, gibsonv1alpha1.TenantIdentityFinalizer)
	now := metav1.Now()
	ti.DeletionTimestamp = &now
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantIdentity{}).
		WithObjects(ti).
		Build()

	stub := &stubIdentityProvisioner{deprovisionErr: clients.ErrNotFound}
	r := &TenantIdentityReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	if _, err := reconcileTI(t, r, "acme-identity"); err != nil {
		t.Fatalf("NotFound from deprovision must not error: %v", err)
	}
	var got gibsonv1alpha1.TenantIdentity
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-identity"}, &got); err == nil {
		t.Fatalf("want object gone after teardown, still present: %+v", got)
	}
}
