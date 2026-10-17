// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/zitadel"
)

// isNotFoundErr reports whether err is a Kubernetes API not-found error.
func isNotFoundErr(err error) bool {
	return apierrors.IsNotFound(err)
}

// fakeZitadelClient is a test double for zitadel.Client.
type fakeZitadelClient struct {
	mu sync.Mutex
}

func (f *fakeZitadelClient) CreateOrganization(_ context.Context, _, _ string) (string, error) {
	return "fake-org", nil
}
func (f *fakeZitadelClient) GetOrganization(_ context.Context, _ string) (*zitadel.Organization, error) {
	return &zitadel.Organization{ID: "fake-org"}, nil
}
func (f *fakeZitadelClient) DeleteOrganization(_ context.Context, _ string) error { return nil }
func (f *fakeZitadelClient) CreateServiceAccount(_ context.Context, _, name string) (string, string, string, error) {
	return "svc-" + name, "client-" + name, "secret-" + name, nil
}
func (f *fakeZitadelClient) DeleteServiceAccount(_ context.Context, _, _ string) error { return nil }
func (f *fakeZitadelClient) EnsureProjectGrant(_ context.Context, _, _ string, _ []string) error {
	return nil
}

var _ zitadel.Client = (*fakeZitadelClient)(nil)

// --- test helpers ---

func newMemberTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := gibsonv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// buildMemberReconciler wires a Roles Syncer over fresh in-memory fakes
// (grants, tuples) alongside the fz Zitadel client. Tests that need to
// inspect or fail the role-grant side call buildMemberReconcilerWithRoles
// directly.
func buildMemberReconciler(
	t *testing.T,
	fz *fakeZitadelClient,
	tenant *gibsonv1alpha1.Tenant,
	member *gibsonv1alpha1.TenantMember,
) (*TenantMemberReconciler, client.Client) {
	t.Helper()
	r, fc, _, _ := buildMemberReconcilerWithRoles(t, fz, tenant, member, &fakeRoleGrants{}, &fakeRoleTuples{})
	return r, fc
}

// buildMemberReconcilerWithRoles is buildMemberReconciler with caller-supplied
// Grants/Tuples fakes, so a test can inject an error or pre-seed state and
// then inspect it after Reconcile.
func buildMemberReconcilerWithRoles(
	t *testing.T,
	fz *fakeZitadelClient,
	tenant *gibsonv1alpha1.Tenant,
	member *gibsonv1alpha1.TenantMember,
	grants *fakeRoleGrants,
	tuples *fakeRoleTuples,
) (*TenantMemberReconciler, client.Client, *fakeRoleGrants, *fakeRoleTuples) {
	t.Helper()
	s := newMemberTestScheme(t)
	fc := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&gibsonv1alpha1.Tenant{}, &gibsonv1alpha1.TenantMember{}).
		WithObjects(tenant, member).
		Build()
	if err := fc.Status().Update(context.Background(), tenant); err != nil {
		t.Fatalf("seed tenant status: %v", err)
	}
	r := &TenantMemberReconciler{
		Audit:    (&audittest.Sink{}).Emitter(t),
		Client:   fc,
		Scheme:   s,
		Recorder: events.NewFakeRecorder(20),
		Zitadel:  fz,
		Roles:    tenantrole.NewSyncer(grants, tuples, nil),
	}
	return r, fc, grants, tuples
}

func doReconcile(t *testing.T, r *TenantMemberReconciler, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: name},
	})
	if err != nil {
		t.Fatalf("reconcile returned error: %v", err)
	}
	return res
}

// localRef returns the canonical fixture tenant ref. Every caller passed
// "acme"; if a new test ever needs a different ref, construct one inline.
func localRef() corev1.LocalObjectReference {
	return corev1.LocalObjectReference{Name: "acme"}
}

// tenantWithOrgID returns the canonical fixture Tenant. Every caller passed
// "org-111" as the orgID, so it's inlined. Construct a literal Tenant inline
// if a future test needs a different value.
func tenantWithOrgID() *gibsonv1alpha1.Tenant {
	return &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: "Acme",
			Owner:       "owner@acme.com",
			Tier:        gibsonv1alpha1.TenantPlanTeam,
		},
		Status: gibsonv1alpha1.TenantStatus{
			ZitadelOrgID: "org-111",
		},
	}
}

// --- tests ---

// TestSyncZitadel_AddMember_HappyPath: ZitadelUserID set → the tenant role is
// assigned through the Syncer (ADR-0093), which writes the Zitadel grant and
// copies it into FGA in the same call; status.ZitadelMembershipID populated.
// There is no separate org-membership write on this path (hosted#203): a
// tenant role IS the membership.
func TestSyncZitadel_AddMember_HappyPath(t *testing.T) {
	fz := &fakeZitadelClient{}
	grants := &fakeRoleGrants{}
	tuples := &fakeRoleTuples{}
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "alice",
			Namespace:  "default",
			Finalizers: []string{gibsonv1alpha1.TenantMemberFinalizer},
		},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:     "alice@acme.com",
			Role:      gibsonv1alpha1.MemberRoleMember,
			TenantRef: localRef(),
		},
		Status: gibsonv1alpha1.TenantMemberStatus{
			ZitadelUserID: "zuser-alice",
		},
	}

	r, fc, grants, tuples := buildMemberReconcilerWithRoles(t, fz, tenantWithOrgID(), member, grants, tuples)
	doReconcile(t, r, "alice")

	if len(grants.grants) != 1 || grants.grants[0].UserID != "zuser-alice" || grants.grants[0].OrgID != "org-111" {
		t.Fatalf("grants = %+v, want one grant for zuser-alice in org-111", grants.grants)
	}
	if len(grants.grants[0].RoleKeys) != 1 || grants.grants[0].RoleKeys[0] != string(tenantrole.Viewer) {
		t.Errorf("RoleKeys = %v, want [%s] (member maps to Viewer)", grants.grants[0].RoleKeys, tenantrole.Viewer)
	}
	if len(tuples.tuples) != 1 || tuples.tuples[0].User != "user:zuser-alice" || tuples.tuples[0].Relation != "member" {
		t.Errorf("tuples = %+v, want one (user:zuser-alice, member, tenant:acme) tuple", tuples.tuples)
	}

	var got gibsonv1alpha1.TenantMember
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "alice"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ZitadelMembershipID == "" {
		t.Error("ZitadelMembershipID not set after Roles.Assign")
	}
}

// TestSyncZitadel_AlreadyInZitadel_Idempotent: ZitadelMembershipID already
// set → no Zitadel calls, no error.
// TestSyncZitadel_MemberWithNoAccountWaits: the operator creates no user
// (gibson#1188). A member with an email and no account waits for the daemon:
// no Zitadel grant, no FGA tuple, no error, not Active.
func TestSyncZitadel_MemberWithNoAccountWaits(t *testing.T) {
	fz := &fakeZitadelClient{}
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "carol",
			Namespace:  "default",
			Finalizers: []string{gibsonv1alpha1.TenantMemberFinalizer},
		},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:     "carol@acme.com",
			Role:      gibsonv1alpha1.MemberRoleAdmin,
			TenantRef: localRef(),
		},
	}
	r, fc, grants, _ := buildMemberReconcilerWithRoles(
		t, fz, tenantWithOrgID(), member, &fakeRoleGrants{}, &fakeRoleTuples{})
	res, err := r.Reconcile(context.Background(),
		ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "carol"}})
	if err != nil || res.RequeueAfter != 0 {
		t.Fatalf("reconcile = (%+v, %v), want a quiet wait", res, err)
	}
	if len(grants.grants) != 0 {
		t.Fatalf("a member with no account got grants %+v", grants.grants)
	}
	var got gibsonv1alpha1.TenantMember
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "carol"}, &got); err != nil {
		t.Fatal(err)
	}
	active := got.Status.Phase == gibsonv1alpha1.TenantMemberPhaseActive
	if got.Status.ZitadelUserID != "" || got.Status.ZitadelMembershipID != "" || active {
		t.Fatalf("status = %+v, want no user, no membership and not Active", got.Status)
	}
}

func TestSyncZitadel_AlreadyInZitadel_Idempotent(t *testing.T) {
	fz := &fakeZitadelClient{}
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "carol",
			Namespace:  "default",
			Finalizers: []string{gibsonv1alpha1.TenantMemberFinalizer},
		},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:     "carol@acme.com",
			Role:      gibsonv1alpha1.MemberRoleMember,
			TenantRef: localRef(),
		},
		Status: gibsonv1alpha1.TenantMemberStatus{
			ZitadelUserID:       "zuser-carol",
			ZitadelMembershipID: "org-111/zuser-carol",
		},
	}

	r, _ := buildMemberReconciler(t, fz, tenantWithOrgID(), member)
	doReconcile(t, r, "carol")

}

// TestSyncZitadel_RemoveMember_HappyPath: deletion with MembershipID set →
// cleanup revokes the tenant role through the Syncer (ADR-0093), which
// deletes the Zitadel grant and copies the change into FGA in one call —
// replacing the old direct Zitadel RemoveMember call. Finalizer removed.
func TestSyncZitadel_RemoveMember_HappyPath(t *testing.T) {
	fz := &fakeZitadelClient{}
	grants := &fakeRoleGrants{grants: []tenantrole.Grant{
		{ID: "g1", UserID: "zuser-dave", UserOrgID: "org-111", OrgID: "org-111", RoleKeys: []string{string(tenantrole.Viewer)}, Active: true},
	}}
	tuples := &fakeRoleTuples{tuples: []tenantrole.Tuple{
		{User: "user:zuser-dave", Relation: "member", Object: "tenant:acme"},
	}}
	now := metav1.Now()
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "dave",
			Namespace:         "default",
			Finalizers:        []string{gibsonv1alpha1.TenantMemberFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:     "dave@acme.com",
			Role:      gibsonv1alpha1.MemberRoleMember,
			TenantRef: localRef(),
		},
		Status: gibsonv1alpha1.TenantMemberStatus{
			ZitadelUserID:       "zuser-dave",
			ZitadelMembershipID: "org-111/zuser-dave",
		},
	}

	r, fc, grants, tuples := buildMemberReconcilerWithRoles(t, fz, tenantWithOrgID(), member, grants, tuples)
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "dave"},
	})
	if err != nil {
		t.Fatalf("reconcile error: %v", err)
	}

	if len(grants.grants) != 0 {
		t.Errorf("grants = %+v, want the Zitadel grant deleted", grants.grants)
	}
	if len(tuples.tuples) != 0 {
		t.Errorf("tuples = %+v, want the FGA role tuple deleted", tuples.tuples)
	}

	// After the finalizer is removed the fake client garbage-collects the
	// object (mirrors real cluster GC behaviour). Either the object is gone
	// or its finalizer list no longer contains TenantMemberFinalizer.
	var got gibsonv1alpha1.TenantMember
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "dave"}, &got); err != nil {
		// Not-found means the object was fully deleted — finalizer was removed.
		if !isNotFoundErr(err) {
			t.Fatalf("unexpected get error: %v", err)
		}
		return
	}
	for _, f := range got.Finalizers {
		if f == gibsonv1alpha1.TenantMemberFinalizer {
			t.Error("finalizer not removed after cleanup")
		}
	}
}

// A "grant already gone" cleanup case is covered where that idempotence
// actually lives now: the concrete Grants adapter (see
// internal/platform/tenantrole/zitadel_test.go), not here. cleanup() calls
// Roles.Revoke exclusively (ADR-0093) — there is no separate legacy
// RemoveMember call left in this controller to exercise a 404 against.

// TestSyncZitadel_AddMember_Unavailable: the Zitadel grant call inside
// Roles.Assign fails (unreachable) → syncZitadel surfaces a hard error
// (ADR-0093: only ErrOwnerConflict gets the soft-requeue treatment; every
// other Assign failure is real and must retry the whole reconcile via
// controller-runtime's error backoff, not a silent RequeueAfter).
func TestSyncZitadel_AddMember_Unavailable(t *testing.T) {
	fz := &fakeZitadelClient{}
	grants := &fakeRoleGrants{createErr: fmt.Errorf("connect: %w", tenantrole.ErrUnreachable)}
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "frank",
			Namespace:  "default",
			Finalizers: []string{gibsonv1alpha1.TenantMemberFinalizer},
		},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:     "frank@acme.com",
			Role:      gibsonv1alpha1.MemberRoleMember,
			TenantRef: localRef(),
		},
		Status: gibsonv1alpha1.TenantMemberStatus{
			ZitadelUserID: "zuser-frank",
		},
	}

	r, _, _, _ := buildMemberReconcilerWithRoles(t, fz, tenantWithOrgID(), member, grants, &fakeRoleTuples{})
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "frank"},
	})
	if err == nil {
		t.Fatal("expected an error when the tenant role grant is unreachable")
	}
}

// TestSyncZitadel_PreAccepted_BootstrapsFromSpec: TM with AcceptedByUserID set
// and no ZitadelUserID (self-signup / founding-user path) → ZitadelUserID is
// bootstrapped from spec, the Owner tenant role is assigned through the
// Syncer, and the legacy SendInvitation path is NOT taken.
func TestSyncZitadel_PreAccepted_BootstrapsFromSpec(t *testing.T) {
	fz := &fakeZitadelClient{}
	grants := &fakeRoleGrants{}
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
			AcceptedByUserID: "12345",
		},
		// status.ZitadelUserID intentionally empty — pre-accepted path.
	}

	r, fc, grants, _ := buildMemberReconcilerWithRoles(t, fz, tenantWithOrgID(), member, grants, &fakeRoleTuples{})
	doReconcile(t, r, "founder")

	if len(grants.grants) != 1 || grants.grants[0].UserID != "12345" {
		t.Fatalf("grants = %+v, want one grant for user 12345", grants.grants)
	}
	if grants.grants[0].RoleKeys[0] != string(tenantrole.Owner) {
		t.Errorf("RoleKeys = %v, want [%s]", grants.grants[0].RoleKeys, tenantrole.Owner)
	}

	// status.ZitadelUserID must be persisted.
	var got gibsonv1alpha1.TenantMember
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "founder"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ZitadelUserID != "12345" {
		t.Errorf("ZitadelUserID=%q want 12345", got.Status.ZitadelUserID)
	}
	if got.Status.ZitadelMembershipID == "" {
		t.Error("ZitadelMembershipID not set after Roles.Assign on the pre-accepted path")
	}
}

// TestSyncZitadel_ExistingGrantIsKept: a member whose user already holds a
// grant keeps it. The daemon owns every role change (ADR-0093), so a record
// whose role differs from the grant assigns nothing. It only records the
// membership id (gibson#1190).
func TestSyncZitadel_ExistingGrantIsKept(t *testing.T) {
	fz := &fakeZitadelClient{}
	grants := &fakeRoleGrants{grants: []tenantrole.Grant{
		{ID: "g1", UserID: "zuser-henry", UserOrgID: "org-111", OrgID: "org-111", RoleKeys: []string{string(tenantrole.Viewer)}, Active: true},
	}}
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "henry",
			Namespace:  "default",
			Finalizers: []string{gibsonv1alpha1.TenantMemberFinalizer},
		},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:     "henry@acme.com",
			Role:      gibsonv1alpha1.MemberRoleAdmin,
			TenantRef: localRef(),
		},
		Status: gibsonv1alpha1.TenantMemberStatus{
			ZitadelUserID: "zuser-henry",
			Phase:         gibsonv1alpha1.TenantMemberPhaseActive,
		},
	}

	r, fc, grants, _ := buildMemberReconcilerWithRoles(t, fz, tenantWithOrgID(), member, grants, &fakeRoleTuples{})
	doReconcile(t, r, "henry")

	if len(grants.grants) != 1 || grants.grants[0].ID != "g1" || grants.grants[0].RoleKeys[0] != string(tenantrole.Viewer) {
		t.Fatalf("grants = %+v, want g1 unchanged with role %s", grants.grants, tenantrole.Viewer)
	}
	var got gibsonv1alpha1.TenantMember
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "henry"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ZitadelMembershipID != "org-111/zuser-henry" {
		t.Errorf("ZitadelMembershipID = %q, want org-111/zuser-henry", got.Status.ZitadelMembershipID)
	}
}

// TestSyncZitadel_StaleOwnerRecordAssignsNothing: the Owner of the tenant was
// transferred from alice to bob, and the record of alice, made before
// gibson#1189, still names Owner and has no membership id. The reconcile
// assigns nothing, makes no second Owner, returns no error, and the next
// reconcile does nothing (gibson#1190).
func TestSyncZitadel_StaleOwnerRecordAssignsNothing(t *testing.T) {
	fz := &fakeZitadelClient{}
	grants := &fakeRoleGrants{grants: []tenantrole.Grant{
		{ID: "g-alice", UserID: "zuser-alice", UserOrgID: "org-111", OrgID: "org-111", RoleKeys: []string{string(tenantrole.Admin)}, Active: true},
		{ID: "g-bob", UserID: "zuser-bob", UserOrgID: "org-111", OrgID: "org-111", RoleKeys: []string{string(tenantrole.Owner)}, Active: true},
	}}
	tuples := &fakeRoleTuples{tuples: []tenantrole.Tuple{
		{User: "user:zuser-alice", Relation: "admin", Object: "tenant:acme"},
		{User: "user:zuser-bob", Relation: "owner", Object: "tenant:acme"},
	}}
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "alice",
			Namespace:  "default",
			Finalizers: []string{gibsonv1alpha1.TenantMemberFinalizer},
		},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:     "alice@acme.com",
			Role:      gibsonv1alpha1.MemberRoleOwner,
			TenantRef: localRef(),
		},
		Status: gibsonv1alpha1.TenantMemberStatus{
			ZitadelUserID: "zuser-alice",
			Phase:         gibsonv1alpha1.TenantMemberPhaseActive,
		},
	}

	r, fc, grants, tuples := buildMemberReconcilerWithRoles(t, fz, tenantWithOrgID(), member, grants, tuples)
	for range 2 {
		res, err := r.Reconcile(context.Background(),
			ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "alice"}})
		if err != nil || res.RequeueAfter != 0 {
			t.Fatalf("reconcile = (%+v, %v), want done with no retry", res, err)
		}
	}

	owners := 0
	for _, g := range grants.grants {
		if slices.Contains(g.RoleKeys, string(tenantrole.Owner)) {
			owners++
		}
	}
	if owners != 1 || len(grants.grants) != 2 {
		t.Fatalf("grants = %+v, want the two grants unchanged and one Owner", grants.grants)
	}
	if len(tuples.tuples) != 2 {
		t.Errorf("tuples = %+v, want the two tuples unchanged", tuples.tuples)
	}
	var got gibsonv1alpha1.TenantMember
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "alice"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ZitadelMembershipID != "org-111/zuser-alice" {
		t.Errorf("ZitadelMembershipID = %q, want org-111/zuser-alice", got.Status.ZitadelMembershipID)
	}
}

// TestSyncZitadel_RemoveMember_Unavailable: the Zitadel grant delete inside
// Roles.Revoke fails (unreachable) → cleanup surfaces the error, so
// controller-runtime requeues with backoff; finalizer NOT removed.
func TestSyncZitadel_RemoveMember_Unavailable(t *testing.T) {
	fz := &fakeZitadelClient{}
	grants := &fakeRoleGrants{
		grants:    []tenantrole.Grant{{ID: "g1", UserID: "zuser-grace", UserOrgID: "org-111", OrgID: "org-111", RoleKeys: []string{string(tenantrole.Viewer)}, Active: true}},
		deleteErr: fmt.Errorf("connect: %w", tenantrole.ErrUnreachable),
	}
	now := metav1.Now()
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "grace",
			Namespace:         "default",
			Finalizers:        []string{gibsonv1alpha1.TenantMemberFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:     "grace@acme.com",
			Role:      gibsonv1alpha1.MemberRoleMember,
			TenantRef: localRef(),
		},
		Status: gibsonv1alpha1.TenantMemberStatus{
			ZitadelUserID:       "zuser-grace",
			ZitadelMembershipID: "org-111/zuser-grace",
		},
	}

	r, fc, _, _ := buildMemberReconcilerWithRoles(t, fz, tenantWithOrgID(), member, grants, &fakeRoleTuples{})
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "grace"},
	})
	// The reconcile loop returns RequeueAfter on cleanup error for transient issues.
	if err == nil && res.RequeueAfter == 0 {
		t.Error("expected error or RequeueAfter when the tenant role grant is unreachable on remove")
	}

	var got gibsonv1alpha1.TenantMember
	if err2 := fc.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "grace"}, &got); err2 != nil {
		t.Fatal(err2)
	}
	found := slices.Contains(got.Finalizers, gibsonv1alpha1.TenantMemberFinalizer)
	if !found {
		t.Error("finalizer must remain when Zitadel is unavailable on remove")
	}
}

// TestSyncZitadel_RoleWriteFailureSurfaces: a failed Zitadel grant write on a
// pre-accepted member fails the reconcile, it is not a wait.
func TestSyncZitadel_RoleWriteFailureSurfaces(t *testing.T) {
	fz := &fakeZitadelClient{}
	grants := &fakeRoleGrants{createErr: errors.New("zitadel refused the grant")}
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{Name: "stale", Namespace: "default", Finalizers: []string{gibsonv1alpha1.TenantMemberFinalizer}},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email: "stale@acme.com", Role: gibsonv1alpha1.MemberRoleOwner, TenantRef: localRef(), AcceptedByUserID: "zuser-stale",
		},
	}
	r, _, _, _ := buildMemberReconcilerWithRoles(t, fz, tenantWithOrgID(), member, grants, &fakeRoleTuples{})
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "stale"}})
	if err == nil || res.RequeueAfter != 0 {
		t.Fatalf("reconcile = (%+v, %v), want the role write failure to surface as an error", res, err)
	}
}

// TestCleanup_MemberOfAMissingTenantFinishes: the tenant is gone, so there is
// no org to revoke in. The finalizer completes.
func TestCleanup_MemberOfAMissingTenantFinishes(t *testing.T) {
	fz := &fakeZitadelClient{}
	now := metav1.Now()
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{
			Name: "orphan", Namespace: "default",
			Finalizers: []string{gibsonv1alpha1.TenantMemberFinalizer}, DeletionTimestamp: &now,
		},
		Spec:   gibsonv1alpha1.TenantMemberSpec{Email: "o@acme.com", Role: gibsonv1alpha1.MemberRoleMember, TenantRef: localRef()},
		Status: gibsonv1alpha1.TenantMemberStatus{ZitadelUserID: "zuser-o", ZitadelMembershipID: "org-111/zuser-o"},
	}
	tenant := tenantWithOrgID()
	r, fc, grants, _ := buildMemberReconcilerWithRoles(t, fz, tenant, member, &fakeRoleGrants{}, &fakeRoleTuples{})
	if err := fc.Delete(context.Background(), tenant); err != nil {
		t.Fatalf("delete tenant: %v", err)
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "orphan"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(grants.grants) != 0 {
		t.Fatalf("grants = %+v, want none touched", grants.grants)
	}
	var got gibsonv1alpha1.TenantMember
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "orphan"}, &got); err == nil {
		t.Fatalf("member still exists with finalizers %v", got.Finalizers)
	}
}
