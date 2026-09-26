// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
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

	addMemberCalls      []addMemberCall
	removeMemberCalls   []removeMemberCall
	sendInvitationCalls []sendInvitationCall

	addMemberErr      error
	addMemberID       string
	removeMemberErr   error
	sendInvitationErr error
	sendInvitationID  string
}

type addMemberCall struct {
	OrgID  string
	UserID string
	Roles  []string
}

type removeMemberCall struct {
	OrgID  string
	UserID string
}

type sendInvitationCall struct {
	OrgID string
	Email string
	Roles []string
}

func (f *fakeZitadelClient) AddMember(_ context.Context, orgID, userID string, roles []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addMemberCalls = append(f.addMemberCalls, addMemberCall{OrgID: orgID, UserID: userID, Roles: roles})
	if f.addMemberErr != nil {
		return "", f.addMemberErr
	}
	id := f.addMemberID
	if id == "" {
		id = fmt.Sprintf("%s/%s", orgID, userID)
	}
	return id, nil
}

func (f *fakeZitadelClient) RemoveMember(_ context.Context, orgID, userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeMemberCalls = append(f.removeMemberCalls, removeMemberCall{OrgID: orgID, UserID: userID})
	return f.removeMemberErr
}

func (f *fakeZitadelClient) SendInvitation(_ context.Context, orgID, email string, roles []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sendInvitationCalls = append(f.sendInvitationCalls, sendInvitationCall{OrgID: orgID, Email: email, Roles: roles})
	if f.sendInvitationErr != nil {
		return "", f.sendInvitationErr
	}
	id := f.sendInvitationID
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
// (grants, tuples) alongside the legacy fz Zitadel client (still used for
// SendInvitation, the non-role legacy path). Tests that need to inspect or
// fail the role-grant side call buildMemberReconcilerWithRoles directly.
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
// (Pre-ADR-0093 this called Zitadel AddMember with a gibson.* org role key —
// see zitadelRoleKey's doc comment for why that path is legacy-only now.)
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

	if len(fz.addMemberCalls) != 0 {
		t.Errorf("expected 0 legacy AddMember calls, got %d", len(fz.addMemberCalls))
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

// TestSyncZitadel_SendInvitation: no ZitadelUserID, email set →
// SendInvitation called, invitationID and ZitadelUserID persisted.
func TestSyncZitadel_SendInvitation(t *testing.T) {
	fz := &fakeZitadelClient{sendInvitationID: "invited-user-777"}
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

	r, fc := buildMemberReconciler(t, fz, tenantWithOrgID(), member)
	doReconcile(t, r, "bob")

	fz.mu.Lock()
	inv := append([]sendInvitationCall(nil), fz.sendInvitationCalls...)
	fz.mu.Unlock()

	if len(inv) != 1 {
		t.Fatalf("expected 1 SendInvitation call, got %d", len(inv))
	}
	if inv[0].Email != "bob@acme.com" {
		t.Errorf("SendInvitation email=%q", inv[0].Email)
	}
	if len(inv[0].Roles) != 1 || inv[0].Roles[0] != "gibson.admin" {
		t.Errorf("SendInvitation roles=%v want [gibson.admin]", inv[0].Roles)
	}

	var got gibsonv1alpha1.TenantMember
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "bob"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ZitadelUserID != "invited-user-777" {
		t.Errorf("ZitadelUserID=%q want invited-user-777", got.Status.ZitadelUserID)
	}
	if got.Status.ZitadelMembershipID == "" {
		t.Error("ZitadelMembershipID not persisted after SendInvitation")
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
	adds := len(fz.addMemberCalls)
	invs := len(fz.sendInvitationCalls)
	fz.mu.Unlock()

	if adds != 0 || invs != 0 {
		t.Errorf("expected 0 Zitadel calls on idempotent reconcile, got adds=%d invs=%d", adds, invs)
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

	if len(fz.removeMemberCalls) != 0 {
		t.Errorf("expected 0 legacy RemoveMember calls, got %d", len(fz.removeMemberCalls))
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

// TestSyncZitadel_RemoveMember_NotFound: RemoveMember returns ErrNotFound →
// idempotent, finalizer still removed.
func TestSyncZitadel_RemoveMember_NotFound(t *testing.T) {
	fz := &fakeZitadelClient{
		removeMemberErr: fmt.Errorf("zitadel: %w", clients.ErrNotFound),
	}
	now := metav1.Now()
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "eve",
			Namespace:         "default",
			Finalizers:        []string{gibsonv1alpha1.TenantMemberFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:     "eve@acme.com",
			Role:      gibsonv1alpha1.MemberRoleMember,
			TenantRef: localRef(),
		},
		Status: gibsonv1alpha1.TenantMemberStatus{
			ZitadelUserID:       "zuser-eve",
			ZitadelMembershipID: "org-111/zuser-eve",
		},
	}

	r, fc := buildMemberReconciler(t, fz, tenantWithOrgID(), member)
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "eve"},
	})
	if err != nil {
		t.Fatalf("expected nil error on 404 RemoveMember, got: %v", err)
	}

	var got gibsonv1alpha1.TenantMember
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "eve"}, &got); err != nil {
		if !isNotFoundErr(err) {
			t.Fatalf("unexpected get error: %v", err)
		}
		return // object fully deleted — finalizer was removed, test passes
	}
	for _, f := range got.Finalizers {
		if f == gibsonv1alpha1.TenantMemberFinalizer {
			t.Error("finalizer must be removed even after 404 RemoveMember")
		}
	}
}

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

	if len(fz.sendInvitationCalls) != 0 {
		t.Errorf("expected 0 SendInvitation calls, got %d — duplicate account would be created", len(fz.sendInvitationCalls))
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
