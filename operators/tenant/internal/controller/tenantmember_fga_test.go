// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	fgaclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
)

// fakeFGAClient is a minimal fga.Client test double that records
// WriteConditional calls and can be configured to return an error.
type fakeFGAClient struct {
	mu sync.Mutex

	writeConditionalCalls []fgaclient.ConditionalTuple
	writeConditionalErr   error
	writeCalls            int
	writeErr              error
}

func (f *fakeFGAClient) Write(_ context.Context, _ []fgaclient.Tuple) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writeCalls++
	return f.writeErr
}

func (f *fakeFGAClient) WriteConditional(_ context.Context, t fgaclient.ConditionalTuple) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writeConditionalCalls = append(f.writeConditionalCalls, t)
	return f.writeConditionalErr
}

func (f *fakeFGAClient) Delete(_ context.Context, _ []fgaclient.Tuple) error { return nil }
func (f *fakeFGAClient) Read(_ context.Context, _ fgaclient.Tuple) ([]fgaclient.Tuple, error) {
	return nil, nil
}
func (f *fakeFGAClient) Check(_ context.Context, _, _, _ string) (bool, error) { return false, nil }
func (f *fakeFGAClient) Ping(_ context.Context) error                          { return nil }

// buildMemberReconcilerWithFGA builds a TenantMemberReconciler with the given
// fake FGA client, no Zitadel client (Zitadel == nil skips syncZitadel), and
// a fake k8s client seeded with the tenant and member objects.
func buildMemberReconcilerWithFGA(
	t *testing.T,
	fga *fakeFGAClient,
	tenant *gibsonv1alpha1.Tenant,
	member *gibsonv1alpha1.TenantMember,
) *TenantMemberReconciler {
	t.Helper()
	s := newMemberTestScheme(t)
	objs := []interface{}{tenant, member}
	_ = objs
	fc := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&gibsonv1alpha1.Tenant{}, &gibsonv1alpha1.TenantMember{}).
		WithObjects(tenant, member).
		Build()
	if err := fc.Status().Update(context.Background(), tenant); err != nil {
		t.Fatalf("seed tenant status: %v", err)
	}
	return &TenantMemberReconciler{
		Client:   fc,
		Scheme:   s,
		Recorder: events.NewFakeRecorder(20),
		FGA:      fga,
		// Zitadel deliberately nil — syncZitadel returns (Result{}, nil) immediately.
	}
}

// invitedMemberFixture returns a TenantMember in Invited phase with
// AcceptedByUserID set, ready for acceptInvitation to run.
func invitedMemberFixture(name, userID string) *gibsonv1alpha1.TenantMember {
	return &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  "default",
			Finalizers: []string{gibsonv1alpha1.TenantMemberFinalizer},
		},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:            userID + "@acme.com",
			Role:             gibsonv1alpha1.MemberRoleMember,
			TenantRef:        corev1.LocalObjectReference{Name: "acme"},
			AcceptedByUserID: userID,
		},
		Status: gibsonv1alpha1.TenantMemberStatus{
			Phase: gibsonv1alpha1.TenantMemberPhaseInvited,
		},
	}
}

// TestAcceptInvitation_WriteConditional_HappyPath verifies that when
// acceptInvitation runs with FGA set, WriteConditional is called with the
// correct active_session/token_not_revoked tuple (epoch revoked_at), and the
// TM transitions to Active phase.
func TestAcceptInvitation_WriteConditional_HappyPath(t *testing.T) {
	fga := &fakeFGAClient{}
	member := invitedMemberFixture("alice", "user-alice-123")
	r := buildMemberReconcilerWithFGA(t, fga, tenantWithOrgID(), member)

	doReconcile(t, r, "alice")

	fga.mu.Lock()
	calls := append([]fgaclient.ConditionalTuple(nil), fga.writeConditionalCalls...)
	fga.mu.Unlock()

	// gibson#1244: acceptInvitation now writes TWO active_session tuples — the
	// per-tenant tuple (object tenant:acme) and the user-scoped tuple (object
	// user:<id>) that gates tenant-less requests.
	if len(calls) != 2 {
		t.Fatalf("expected 2 WriteConditional calls (per-tenant + user-scoped), got %d", len(calls))
	}
	byObject := map[string]fgaclient.ConditionalTuple{}
	for _, c := range calls {
		byObject[c.Object] = c
	}
	const epoch = "1970-01-01T00:00:00Z"

	got, ok := byObject["tenant:acme"]
	if !ok {
		t.Fatalf("missing per-tenant WriteConditional on tenant:acme; calls=%+v", calls)
	}
	if want := "user:user-alice-123"; got.User != want {
		t.Errorf("WriteConditional User = %q, want %q", got.User, want)
	}
	if want := "active_session"; got.Relation != want {
		t.Errorf("WriteConditional Relation = %q, want %q", got.Relation, want)
	}
	if want := "token_not_revoked"; got.ConditionName != want {
		t.Errorf("WriteConditional ConditionName = %q, want %q", got.ConditionName, want)
	}
	if v, ok := got.ConditionContext["revoked_at"]; !ok || v != epoch {
		t.Errorf("WriteConditional ConditionContext[revoked_at] = %v, want %q", v, epoch)
	}

	// The user-scoped tuple is self-referential and closes gibson#1244.
	userGot, ok := byObject["user:user-alice-123"]
	if !ok {
		t.Fatalf("missing user-scoped WriteConditional on user:user-alice-123; calls=%+v", calls)
	}
	if userGot.User != "user:user-alice-123" {
		t.Errorf("user-scoped WriteConditional User = %q, want user:user-alice-123", userGot.User)
	}
	if userGot.Relation != "active_session" {
		t.Errorf("user-scoped WriteConditional Relation = %q, want active_session", userGot.Relation)
	}
	if v, ok := userGot.ConditionContext["revoked_at"]; !ok || v != epoch {
		t.Errorf("user-scoped WriteConditional ConditionContext[revoked_at] = %v, want %q", v, epoch)
	}

	// TM must be transitioned to Active.
	var updated gibsonv1alpha1.TenantMember
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "alice"}, &updated); err != nil {
		t.Fatalf("get TM after reconcile: %v", err)
	}
	if updated.Status.Phase != gibsonv1alpha1.TenantMemberPhaseActive {
		t.Errorf("TM Phase = %q, want Active", updated.Status.Phase)
	}
}

// TestAcceptInvitation_WriteConditional_NonFatal verifies that when
// WriteConditional returns an error, acceptInvitation logs it but still
// succeeds (non-fatal) and the TM transitions to Active.
func TestAcceptInvitation_WriteConditional_NonFatal(t *testing.T) {
	fga := &fakeFGAClient{
		writeConditionalErr: errors.New("FGA timeout"),
	}
	member := invitedMemberFixture("bob", "user-bob-456")
	r := buildMemberReconcilerWithFGA(t, fga, tenantWithOrgID(), member)

	doReconcile(t, r, "bob")

	fga.mu.Lock()
	callCount := len(fga.writeConditionalCalls)
	fga.mu.Unlock()

	// Both WriteConditional writes must still have been attempted (both
	// non-fatal). gibson#1244: per-tenant + user-scoped.
	if callCount != 2 {
		t.Fatalf("expected 2 WriteConditional calls (even on error), got %d", callCount)
	}

	// TM must still be Active — FGA failure is non-fatal.
	var updated gibsonv1alpha1.TenantMember
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "bob"}, &updated); err != nil {
		t.Fatalf("get TM after reconcile: %v", err)
	}
	if updated.Status.Phase != gibsonv1alpha1.TenantMemberPhaseActive {
		t.Errorf("TM Phase = %q, want Active (FGA failure must be non-fatal)", updated.Status.Phase)
	}
}

// A pre-existing role tuple must read as success: the vanilla first-admin
// bootstrap writes the owner tuple directly before the pre-accepted member
// reconciles (gibson#1510), and a reconciler that errors on its own desired
// state retries forever — the member sat Invited crash-looping on
// "fga 400: already exists" while the session tuples never got written.
func TestAcceptInvitation_RoleTupleAlreadyExists_IsSuccess(t *testing.T) {
	fga := &fakeFGAClient{writeErr: fmt.Errorf("fga 400: %w", clients.ErrAlreadyExists)}
	member := invitedMemberFixture("alice", "user-alice-123")
	r := buildMemberReconcilerWithFGA(t, fga, tenantWithOrgID(), member)

	doReconcile(t, r, "alice")

	fga.mu.Lock()
	conditionals := len(fga.writeConditionalCalls)
	fga.mu.Unlock()
	if conditionals != 2 {
		t.Fatalf("session tuples must still be written past an already-present role tuple; got %d WriteConditional calls", conditionals)
	}

	got := &gibsonv1alpha1.TenantMember{}
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "alice"}, got); err != nil {
		t.Fatalf("get member: %v", err)
	}
	if got.Status.Phase != gibsonv1alpha1.TenantMemberPhaseActive {
		t.Fatalf("phase = %q, want Active — an already-present role tuple must not strand the member Invited", got.Status.Phase)
	}
}

// Any other role-write failure still surfaces: tolerance is scoped to
// already-exists, not to FGA being down.
func TestAcceptInvitation_RoleTupleOtherFailure_StillErrors(t *testing.T) {
	fga := &fakeFGAClient{writeErr: errors.New("fga 503: unavailable")}
	member := invitedMemberFixture("alice", "user-alice-123")
	r := buildMemberReconcilerWithFGA(t, fga, tenantWithOrgID(), member)

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "alice"},
	}); err == nil {
		t.Fatal("a non-already-exists FGA failure must surface from Reconcile")
	}

	got := &gibsonv1alpha1.TenantMember{}
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "alice"}, got); err != nil {
		t.Fatalf("get member: %v", err)
	}
	if got.Status.Phase == gibsonv1alpha1.TenantMemberPhaseActive {
		t.Fatal("a non-already-exists FGA failure must not promote the member")
	}
}
