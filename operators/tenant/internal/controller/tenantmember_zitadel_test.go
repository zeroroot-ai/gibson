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
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/zitadel"
)

// isNotFoundErr reports whether err is a Kubernetes API not-found error.
func isNotFoundErr(err error) bool {
	return apierrors.IsNotFound(err)
}

// fakeZitadelClient is a test double for zitadel.Client.
type fakeZitadelClient struct {
	mu sync.Mutex

	ensureHumanUserCalls []ensureHumanUserCall

	ensureHumanUserErr error
	ensureHumanUserID  string
}

type ensureHumanUserCall struct {
	OrgID string
	Email string
}

func (f *fakeZitadelClient) EnsureHumanUser(_ context.Context, orgID, email string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureHumanUserCalls = append(f.ensureHumanUserCalls, ensureHumanUserCall{OrgID: orgID, Email: email})
	if f.ensureHumanUserErr != nil {
		return "", f.ensureHumanUserErr
	}
	id := f.ensureHumanUserID
	if id == "" {
		id = "fake-invitation-user-id"
	}
	return id, nil
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
// (grants, tuples) alongside the fz Zitadel client (used for EnsureHumanUser,
// the no-ZitadelUserID-yet path). Tests that need to inspect or fail the
// role-grant side call buildMemberReconcilerWithRoles directly.
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

	if len(fz.ensureHumanUserCalls) != 0 {
		t.Errorf("expected 0 EnsureHumanUser calls (ZitadelUserID already set), got %d", len(fz.ensureHumanUserCalls))
	}
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

// TestSyncZitadel_EnsureHumanUser: no ZitadelUserID, email set →
// EnsureHumanUser called (never SendInvitation/AddMember — hosted#203
// deleted the org-member API write this branch used to make), the tenant
// role is assigned through the Syncer, and ZitadelUserID/ZitadelMembershipID
// are persisted.
func TestSyncZitadel_EnsureHumanUser(t *testing.T) {
	fz := &fakeZitadelClient{ensureHumanUserID: "invited-user-777"}
	grants := &fakeRoleGrants{}
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "bob",
			Namespace:  "default",
			Finalizers: []string{gibsonv1alpha1.TenantMemberFinalizer},
		},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:     "bob@acme.com",
			Role:      gibsonv1alpha1.MemberRoleAdmin,
			TenantRef: localRef(),
		},
	}

	r, fc, grants, _ := buildMemberReconcilerWithRoles(t, fz, tenantWithOrgID(), member, grants, &fakeRoleTuples{})
	doReconcile(t, r, "bob")

	fz.mu.Lock()
	ensured := append([]ensureHumanUserCall(nil), fz.ensureHumanUserCalls...)
	fz.mu.Unlock()

	if len(ensured) != 1 {
		t.Fatalf("expected 1 EnsureHumanUser call, got %d", len(ensured))
	}
	if ensured[0].Email != "bob@acme.com" {
		t.Errorf("EnsureHumanUser email=%q", ensured[0].Email)
	}
	if ensured[0].OrgID != "org-111" {
		t.Errorf("EnsureHumanUser orgID=%q want org-111", ensured[0].OrgID)
	}
	if len(grants.grants) != 1 || grants.grants[0].UserID != "invited-user-777" || grants.grants[0].RoleKeys[0] != string(tenantrole.Admin) {
		t.Fatalf("grants = %+v, want one admin grant for invited-user-777", grants.grants)
	}

	var got gibsonv1alpha1.TenantMember
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "bob"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ZitadelUserID != "invited-user-777" {
		t.Errorf("ZitadelUserID=%q want invited-user-777", got.Status.ZitadelUserID)
	}
	if got.Status.ZitadelMembershipID == "" {
		t.Error("ZitadelMembershipID not persisted after EnsureHumanUser + Roles.Assign")
	}
}

// noRoleSyncerMember builds the fixture the next several tests share: an
// email-only TenantMember (no ZitadelUserID yet), used to exercise the
// no-ZitadelUserID-yet branch's non-happy-path returns.
func noRoleSyncerMember(name string) *gibsonv1alpha1.TenantMember {
	return &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  "default",
			Finalizers: []string{gibsonv1alpha1.TenantMemberFinalizer},
		},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:     name + "@acme.com",
			Role:      gibsonv1alpha1.MemberRoleAdmin,
			TenantRef: localRef(),
		},
	}
}

// TestSyncZitadel_EnsureHumanUser_RolesNilIsAnError: no Syncer configured →
// the role write has nowhere to land, so this must fail loudly rather than
// silently skip creating the account's tenant role.
func TestSyncZitadel_EnsureHumanUser_RolesNilIsAnError(t *testing.T) {
	fz := &fakeZitadelClient{ensureHumanUserID: "user-x"}
	tenant := tenantWithOrgID()
	s := newMemberTestScheme(t)
	fc := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&gibsonv1alpha1.Tenant{}, &gibsonv1alpha1.TenantMember{}).
		WithObjects(tenant, noRoleSyncerMember("dana")).
		Build()
	if err := fc.Status().Update(context.Background(), tenant); err != nil {
		t.Fatalf("seed tenant status: %v", err)
	}
	r := &TenantMemberReconciler{
		Client:   fc,
		Scheme:   s,
		Recorder: events.NewFakeRecorder(20),
		Zitadel:  fz,
		// Roles deliberately left nil.
	}
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "dana"},
	})
	if err == nil {
		t.Fatal("expected an error when Roles is not configured")
	}
}

// TestSyncZitadel_EnsureHumanUser_Unreachable: a transient Zitadel failure
// creating the account must requeue with backoff, not fail the reconcile.
func TestSyncZitadel_EnsureHumanUser_Unreachable(t *testing.T) {
	fz := &fakeZitadelClient{ensureHumanUserErr: fmt.Errorf("connect: %w", clients.ErrUnreachable)}
	r, _ := buildMemberReconciler(t, fz, tenantWithOrgID(), noRoleSyncerMember("erin"))

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "erin"},
	})
	if err != nil {
		t.Fatalf("expected no error, a soft requeue instead: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Error("expected RequeueAfter on an unreachable Zitadel")
	}
}

// TestSyncZitadel_EnsureHumanUser_PermanentErrorSurfaces: a non-transient
// EnsureHumanUser failure must fail the reconcile (controller-runtime's own
// error backoff), not be swallowed.
func TestSyncZitadel_EnsureHumanUser_PermanentErrorSurfaces(t *testing.T) {
	fz := &fakeZitadelClient{ensureHumanUserErr: errors.New("permanently rejected")}
	r, _ := buildMemberReconciler(t, fz, tenantWithOrgID(), noRoleSyncerMember("frank"))

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "frank"},
	})
	if err == nil {
		t.Fatal("expected the permanent EnsureHumanUser error to surface")
	}
}

// TestSyncZitadel_EnsureHumanUser_InvalidRoleMapping: a MemberRole with no
// tenant-role mapping must fail rather than assign a made-up default.
func TestSyncZitadel_EnsureHumanUser_InvalidRoleMapping(t *testing.T) {
	fz := &fakeZitadelClient{ensureHumanUserID: "user-x"}
	member := noRoleSyncerMember("grace")
	member.Spec.Role = "not-a-real-role"

	r, _ := buildMemberReconciler(t, fz, tenantWithOrgID(), member)
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "grace"},
	})
	if err == nil {
		t.Fatal("expected an error for an unmapped MemberRole")
	}
}

// TestSyncZitadel_EnsureHumanUser_AssignErrorSurfaces: a role-write failure
// after EnsureHumanUser succeeded must fail the reconcile.
func TestSyncZitadel_EnsureHumanUser_AssignErrorSurfaces(t *testing.T) {
	fz := &fakeZitadelClient{ensureHumanUserID: "user-x"}
	grants := &fakeRoleGrants{createErr: errors.New("create boom")}

	r, _, _, _ := buildMemberReconcilerWithRoles(t, fz, tenantWithOrgID(), noRoleSyncerMember("henry"), grants, &fakeRoleTuples{})
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "henry"},
	})
	if err == nil {
		t.Fatal("expected the Roles.Assign error to surface")
	}
}

// TestSyncZitadel_AlreadyInZitadel_Idempotent: ZitadelMembershipID already
// set → no Zitadel calls, no error.
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

	fz.mu.Lock()
	ensures := len(fz.ensureHumanUserCalls)
	fz.mu.Unlock()

	if ensures != 0 {
		t.Errorf("expected 0 Zitadel calls on idempotent reconcile, got ensures=%d", ensures)
	}
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

	if len(fz.ensureHumanUserCalls) != 0 {
		t.Errorf("expected 0 EnsureHumanUser calls, got %d — duplicate account would be created", len(fz.ensureHumanUserCalls))
	}
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

// TestSyncZitadel_RoleChange_UpdatesExistingGrant replaces the pre-ADR-0093
// TestSyncZitadel_AddMember_AlreadyExists: Assign no longer blindly creates
// and catches a conflict — it looks up the user's existing active grant
// first (Roles.activeGrant) and calls Update when one exists, so a role
// change (e.g. promoted from Member to Admin in spec) converges to exactly
// one grant rather than a rejected duplicate create.
func TestSyncZitadel_RoleChange_UpdatesExistingGrant(t *testing.T) {
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

	if len(grants.grants) != 1 {
		t.Fatalf("grants = %+v, want exactly 1 (updated, not duplicated)", grants.grants)
	}
	if grants.grants[0].ID != "g1" || grants.grants[0].RoleKeys[0] != string(tenantrole.Admin) {
		t.Errorf("grant = %+v, want id=g1 role=%s", grants.grants[0], tenantrole.Admin)
	}

	var got gibsonv1alpha1.TenantMember
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "henry"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ZitadelMembershipID == "" {
		t.Error("ZitadelMembershipID not set after Roles.Assign updated the existing grant")
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
