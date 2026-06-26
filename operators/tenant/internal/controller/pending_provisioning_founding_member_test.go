// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// pending_provisioning_founding_member_test.go — the founding-owner TenantMember
// creation the pending-provisioning reconcile performs alongside the Tenant CR
// (dashboard#855). Lets the dashboard drop its applyTenantMember signup write.
package controller

import (
	"context"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

// TestSlugifyEmail_MatchesDashboard pins the member-name derivation to the
// dashboard's slugify (app/actions/signup.ts) so the operator-created member is
// byte-identical to the one the dashboard used to write.
func TestSlugifyEmail_MatchesDashboard(t *testing.T) {
	cases := map[string]string{
		"anthony@zero-day.ai": "anthony-zero-day-ai",
		"OWNER@Acme.test":     "owner-acme-test",
		"a..b@c":              "a-b-c",
		"--lead@trail--":      "lead-trail",
	}
	for in, want := range cases {
		if got := slugifyEmail(in); got != want {
			t.Errorf("slugifyEmail(%q) = %q, want %q", in, got, want)
		}
	}
	if got := foundingMemberName("anthony@zero-day.ai"); got != "anthony-zero-day-ai-owner" {
		t.Errorf("foundingMemberName: got %q", got)
	}
	if got := tenantNamespace("acme"); got != "tenant-acme" {
		t.Errorf("tenantNamespace: got %q", got)
	}
}

// TestDrain_CreatesFoundingOwnerMember asserts the reconcile creates the
// founding-owner TenantMember byte-identically to the dashboard's signup write,
// then acks.
func TestDrain_CreatesFoundingOwnerMember(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	d := &stubDaemon{pending: []provision.PendingTenant{{
		TenantID:      "acme",
		OwnerUserID:   "zitadel-user-9",
		OwnerEmail:    "owner@acme.test",
		WorkspaceName: "Acme Inc",
		Tier:          "team",
	}}}

	if err := newRunnable(t, c, d).drain(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	var m gibsonv1alpha1.TenantMember
	key := client.ObjectKey{Namespace: "tenant-acme", Name: "owner-acme-test-owner"}
	if err := c.Get(context.Background(), key, &m); err != nil {
		t.Fatalf("expected founding TenantMember created: %v", err)
	}
	if m.Spec.Email != "owner@acme.test" {
		t.Errorf("email: got %q", m.Spec.Email)
	}
	if m.Spec.Role != gibsonv1alpha1.MemberRoleOwner {
		t.Errorf("role: got %q, want owner", m.Spec.Role)
	}
	if m.Spec.TenantRef.Name != "acme" {
		t.Errorf("tenantRef: got %q", m.Spec.TenantRef.Name)
	}
	if m.Spec.AcceptedByUserID != "zitadel-user-9" {
		t.Errorf("acceptedByUserId: got %q (must pre-accept the founding owner)", m.Spec.AcceptedByUserID)
	}
	if m.Spec.InvitedByEmail != "" {
		t.Errorf("invitedByEmail must be empty for the founding owner, got %q", m.Spec.InvitedByEmail)
	}
	if len(d.acked) != 1 || d.acked[0] != "acme" {
		t.Errorf("expected acme acked, got %v", d.acked)
	}
}

// TestEnsureFoundingMember_Idempotent: an existing member CR (by name) is left
// untouched (existence-check), so a re-drain does not error or mutate it.
func TestEnsureFoundingMember_Idempotent(t *testing.T) {
	scheme := setupScheme(t)
	existing := &gibsonv1alpha1.TenantMember{}
	existing.Name = "owner-acme-test-owner"
	existing.Namespace = "tenant-acme"
	existing.Spec = gibsonv1alpha1.TenantMemberSpec{
		Email: "owner@acme.test",
		Role:  gibsonv1alpha1.MemberRoleOwner,
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()

	r := newRunnable(t, c, &stubDaemon{})
	err := r.ensureFoundingMember(context.Background(), provision.PendingTenant{
		TenantID:    "acme",
		OwnerUserID: "zitadel-user-9",
		OwnerEmail:  "owner@acme.test",
	})
	if err != nil {
		t.Fatalf("ensureFoundingMember idempotent: %v", err)
	}
}

// TestReconcileOne_MemberCreateNamespaceMissing_NoAck: when the per-tenant
// namespace does not exist yet (the Tenant reconcile has not created it), the
// founding-member create fails and reconcileOne skips the ack so the record
// stays pending and retries on the next drain.
func TestReconcileOne_MemberCreateNamespaceMissing_NoAck(t *testing.T) {
	scheme := setupScheme(t)
	// Intercept TenantMember Create to return NotFound (namespace not yet
	// provisioned), the way the real API server rejects a create into a missing
	// namespace.
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*gibsonv1alpha1.TenantMember); ok {
					return apierrors.NewNotFound(
						schema.GroupResource{Group: "", Resource: "namespaces"}, "tenant-acme")
				}
				return cl.Create(ctx, obj, opts...)
			},
		}).Build()

	d := &stubDaemon{}
	err := newRunnable(t, c, d).reconcileOne(context.Background(), provision.PendingTenant{
		TenantID:      "acme",
		OwnerUserID:   "zitadel-user-9",
		OwnerEmail:    "owner@acme.test",
		WorkspaceName: "Acme Inc",
		Tier:          "team",
	})
	if err == nil {
		t.Fatalf("expected reconcileOne to error when founding-member create fails")
	}
	// Tenant CR was created (so the re-drain no-ops it) but the record must NOT
	// be acked — it stays pending until the namespace appears.
	var got gibsonv1alpha1.Tenant
	if getErr := c.Get(context.Background(), client.ObjectKey{Name: "acme"}, &got); getErr != nil {
		t.Errorf("expected Tenant CR created even though member create failed: %v", getErr)
	}
	if d.ackCalls != 0 {
		t.Errorf("expected NO ack when founding-member create fails, got %d", d.ackCalls)
	}
}

// TestEnsureFoundingMember_EmptyOwnerEmail_NoOp: a record without an owner email
// cannot build the member; ensureFoundingMember is a no-op (no error) so the
// tenant still gets acked.
func TestEnsureFoundingMember_EmptyOwnerEmail_NoOp(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := newRunnable(t, c, &stubDaemon{})
	if err := r.ensureFoundingMember(context.Background(), provision.PendingTenant{TenantID: "acme"}); err != nil {
		t.Fatalf("expected no-op for empty owner email, got %v", err)
	}
}
