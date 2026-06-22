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

func buildMemberReconciler(
	t *testing.T,
	fz *fakeZitadelClient,
	tenant *gibsonv1alpha1.Tenant,
	member *gibsonv1alpha1.TenantMember,
) (*TenantMemberReconciler, client.Client) {
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
	}
	return r, fc
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

// TestSyncZitadel_AddMember_HappyPath: ZitadelUserID set → AddMember called
// once, status.ZitadelMembershipID populated.
func TestSyncZitadel_AddMember_HappyPath(t *testing.T) {
	fz := &fakeZitadelClient{}
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

	r, fc := buildMemberReconciler(t, fz, tenantWithOrgID(), member)
	doReconcile(t, r, "alice")

	fz.mu.Lock()
	calls := append([]addMemberCall(nil), fz.addMemberCalls...)
	fz.mu.Unlock()

	if len(calls) != 1 {
		t.Fatalf("expected 1 AddMember call, got %d", len(calls))
	}
	if calls[0].OrgID != "org-111" {
		t.Errorf("AddMember OrgID=%q want org-111", calls[0].OrgID)
	}
	if calls[0].UserID != "zuser-alice" {
		t.Errorf("AddMember UserID=%q want zuser-alice", calls[0].UserID)
	}
	if len(calls[0].Roles) != 1 || calls[0].Roles[0] != "gibson.member" {
		t.Errorf("AddMember roles=%v want [gibson.member]", calls[0].Roles)
	}

	var got gibsonv1alpha1.TenantMember
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "alice"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ZitadelMembershipID == "" {
		t.Error("ZitadelMembershipID not set after AddMember")
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
// RemoveMember called, finalizer removed.
func TestSyncZitadel_RemoveMember_HappyPath(t *testing.T) {
	fz := &fakeZitadelClient{}
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

	r, fc := buildMemberReconciler(t, fz, tenantWithOrgID(), member)
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "dave"},
	})
	if err != nil {
		t.Fatalf("reconcile error: %v", err)
	}

	fz.mu.Lock()
	removals := append([]removeMemberCall(nil), fz.removeMemberCalls...)
	fz.mu.Unlock()

	if len(removals) != 1 {
		t.Fatalf("expected 1 RemoveMember call, got %d", len(removals))
	}
	if removals[0].OrgID != "org-111" || removals[0].UserID != "zuser-dave" {
		t.Errorf("RemoveMember args=%+v", removals[0])
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

// TestSyncZitadel_AddMember_Unavailable: Zitadel unreachable on add →
// requeue with backoff, nil error.
func TestSyncZitadel_AddMember_Unavailable(t *testing.T) {
	fz := &fakeZitadelClient{
		addMemberErr: fmt.Errorf("connect: %w", clients.ErrUnreachable),
	}
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

	r, _ := buildMemberReconciler(t, fz, tenantWithOrgID(), member)
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "frank"},
	})
	if err != nil {
		t.Fatalf("expected nil error on unavailable Zitadel (add), got: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Error("expected non-zero RequeueAfter when Zitadel unavailable on add")
	}
}

// TestSyncZitadel_PreAccepted_BootstrapsFromSpec: TM with AcceptedByUserID set
// and no ZitadelUserID (self-signup / founding-user path) → ZitadelUserID is
// bootstrapped from spec, AddMember is called, SendInvitation is NOT called.
func TestSyncZitadel_PreAccepted_BootstrapsFromSpec(t *testing.T) {
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
			AcceptedByUserID: "12345",
		},
		// status.ZitadelUserID intentionally empty — pre-accepted path.
	}

	r, fc := buildMemberReconciler(t, fz, tenantWithOrgID(), member)
	doReconcile(t, r, "founder")

	fz.mu.Lock()
	adds := append([]addMemberCall(nil), fz.addMemberCalls...)
	invs := append([]sendInvitationCall(nil), fz.sendInvitationCalls...)
	fz.mu.Unlock()

	// Must call AddMember, never SendInvitation.
	if len(adds) != 1 {
		t.Fatalf("expected 1 AddMember call, got %d", len(adds))
	}
	if adds[0].UserID != "12345" {
		t.Errorf("AddMember UserID=%q want 12345", adds[0].UserID)
	}
	if len(invs) != 0 {
		t.Errorf("expected 0 SendInvitation calls, got %d — duplicate account would be created", len(invs))
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
		t.Error("ZitadelMembershipID not set after AddMember on pre-accepted path")
	}
}

// TestSyncZitadel_AddMember_AlreadyExists: AddMember returns ErrAlreadyExists →
// reconcile treats it as success (nil error), membership is recorded as synced.
// The member is placed in Active phase so the reconcile loop exits cleanly after
// syncZitadel and we can assert on ZitadelMembershipID without noise from
// phase-specific requeueing.
func TestSyncZitadel_AddMember_AlreadyExists(t *testing.T) {
	fz := &fakeZitadelClient{
		addMemberErr: fmt.Errorf("zitadel 409: %w", clients.ErrAlreadyExists),
	}
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "henry",
			Namespace:  "default",
			Finalizers: []string{gibsonv1alpha1.TenantMemberFinalizer},
		},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:     "henry@acme.com",
			Role:      gibsonv1alpha1.MemberRoleMember,
			TenantRef: localRef(),
		},
		Status: gibsonv1alpha1.TenantMemberStatus{
			ZitadelUserID: "zuser-henry",
			Phase:         gibsonv1alpha1.TenantMemberPhaseActive,
		},
	}

	r, fc := buildMemberReconciler(t, fz, tenantWithOrgID(), member)
	// doReconcile asserts nil error — if ErrAlreadyExists propagated the test fails here.
	doReconcile(t, r, "henry")

	// ZitadelMembershipID should be set even when AddMember returned AlreadyExists.
	var got gibsonv1alpha1.TenantMember
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "henry"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ZitadelMembershipID == "" {
		t.Error("ZitadelMembershipID not set after ErrAlreadyExists from AddMember")
	}
}

// TestSyncZitadel_RemoveMember_Unavailable: Zitadel unreachable on remove →
// reconcile returns error (so controller-runtime requeueues), finalizer NOT
// removed.
func TestSyncZitadel_RemoveMember_Unavailable(t *testing.T) {
	fz := &fakeZitadelClient{
		removeMemberErr: fmt.Errorf("connect: %w", clients.ErrUnreachable),
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

	r, fc := buildMemberReconciler(t, fz, tenantWithOrgID(), member)
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "grace"},
	})
	// The reconcile loop returns RequeueAfter on cleanup error for transient issues.
	if err == nil && res.RequeueAfter == 0 {
		t.Error("expected error or RequeueAfter when Zitadel unavailable on remove")
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
