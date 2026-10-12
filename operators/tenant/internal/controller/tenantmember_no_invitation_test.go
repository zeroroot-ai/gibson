// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// The daemon owns every invitation and every onboarding email (gibson#626,
// gibson#520, gibson#987). The tenant operator issues no invitation of its
// own: no token Secret and no mail.
//
// The operator used to do all three for each TenantMember in phase "". Its
// plain-text mail read "a Gibson admin has invited you to join <slug> on
// Gibson", and its accept link carried a token that the daemon had never
// stored, so the link could not work. The founding owner of every signup got
// that mail beside the onboarding email of the daemon.

// invitationTokenSecrets lists the Secrets that the old invitation path wrote.
func invitationTokenSecrets(t *testing.T, c client.Client) []corev1.Secret {
	t.Helper()
	var list corev1.SecretList
	if err := c.List(context.Background(), &list,
		client.MatchingLabels{"gibson.zeroroot.ai/kind": "invitation-token"}); err != nil {
		t.Fatalf("list secrets: %v", err)
	}
	return list.Items
}

// TestFoundingMember_ActivatesWithNoInvitation reconciles the founding member
// exactly as ensureFoundingMember and bootstrap-tenant-owner write it: the
// account exists, so spec.acceptedByUserId is set. One pass makes it Active.
func TestFoundingMember_ActivatesWithNoInvitation(t *testing.T) {
	fz := &fakeZitadelClient{}
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "founder",
			Namespace:  "default",
			Finalizers: []string{gibsonv1alpha1.TenantMemberFinalizer},
		},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:            "founder@acme.com",
			Role:             gibsonv1alpha1.MemberRoleOwner,
			TenantRef:        localRef(),
			AcceptedByUserID: "user-1",
		},
	}
	r, fc := buildMemberReconciler(t, fz, tenantWithOrgID(), member)

	doReconcile(t, r, "founder")

	if s := invitationTokenSecrets(t, fc); len(s) != 0 {
		t.Fatalf("the operator wrote %d invitation token Secret(s); the daemon owns invitations", len(s))
	}
	var got gibsonv1alpha1.TenantMember
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "founder"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != gibsonv1alpha1.TenantMemberPhaseActive {
		t.Fatalf("phase = %q, want Active after one pass", got.Status.Phase)
	}
	if got.Status.UserID != "user-1" {
		t.Errorf("status.userId = %q, want user-1", got.Status.UserID)
	}
}
