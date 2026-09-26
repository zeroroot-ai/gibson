// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// fakeRoleGrants and fakeRoleTuples are minimal in-memory implementations of
// tenantrole.Grants/Tuples for the reconciler's Sync call — the Syncer
// itself is exercised in depth by internal/platform/tenantrole's own tests;
// this file only needs enough to prove the reconciler wires Get, the
// deletion/unmapped skips, the interval, and the two event paths.
type fakeRoleGrants struct {
	grants []tenantrole.Grant
	nextID int

	listErr, createErr, updateErr, deleteErr error
}

func (g *fakeRoleGrants) List(_ context.Context, orgID string, userIDs []string) ([]tenantrole.Grant, error) {
	if g.listErr != nil {
		return nil, g.listErr
	}
	var want map[string]bool
	if len(userIDs) > 0 {
		want = map[string]bool{}
		for _, id := range userIDs {
			want[id] = true
		}
	}
	out := make([]tenantrole.Grant, 0, len(g.grants))
	for _, gr := range g.grants {
		if gr.OrgID != orgID {
			continue
		}
		if want != nil && !want[gr.UserID] {
			continue
		}
		out = append(out, gr)
	}
	return out, nil
}

// Create mutates g.grants so a subsequent List (the one Sync itself makes
// inside the same Assign call) sees the new grant — a no-op fake here would
// make every Assign silently write nothing.
func (g *fakeRoleGrants) Create(_ context.Context, orgID, userID string, r tenantrole.Role) (string, error) {
	if g.createErr != nil {
		return "", g.createErr
	}
	g.nextID++
	id := fmt.Sprintf("grant-%d", g.nextID)
	g.grants = append(g.grants, tenantrole.Grant{
		ID: id, UserID: userID, UserOrgID: orgID, OrgID: orgID,
		RoleKeys: []string{string(r)}, Active: true,
	})
	return id, nil
}

func (g *fakeRoleGrants) Update(_ context.Context, grantID string, r tenantrole.Role) error {
	if g.updateErr != nil {
		return g.updateErr
	}
	for i := range g.grants {
		if g.grants[i].ID == grantID {
			g.grants[i].RoleKeys = []string{string(r)}
			return nil
		}
	}
	return tenantrole.ErrNotFound
}

func (g *fakeRoleGrants) Delete(_ context.Context, grantID string) error {
	if g.deleteErr != nil {
		return g.deleteErr
	}
	for i, gr := range g.grants {
		if gr.ID == grantID {
			g.grants = append(g.grants[:i], g.grants[i+1:]...)
			return nil
		}
	}
	return nil
}

type fakeRoleTuples struct {
	tuples []tenantrole.Tuple
}

func (t *fakeRoleTuples) ReadRoles(_ context.Context, tenantID string, _ []string) ([]tenantrole.Tuple, error) {
	object := "tenant:" + tenantID
	var out []tenantrole.Tuple
	for _, tup := range t.tuples {
		if tup.Object == object {
			out = append(out, tup)
		}
	}
	return out, nil
}
func (t *fakeRoleTuples) WriteAndDelete(_ context.Context, writes, deletes []tenantrole.Tuple) error {
	for _, d := range deletes {
		for i, tup := range t.tuples {
			if tup == d {
				t.tuples = append(t.tuples[:i], t.tuples[i+1:]...)
				break
			}
		}
	}
	t.tuples = append(t.tuples, writes...)
	return nil
}

func TestTenantRoleSync_TenantWithOrgIDIsSyncedAndRequeued(t *testing.T) {
	scheme := setupScheme(t)
	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	tenant.Status.ZitadelOrgID = "org-1"
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()

	grants := &fakeRoleGrants{grants: []tenantrole.Grant{
		{ID: "g1", UserID: "u1", UserOrgID: "org-1", OrgID: "org-1", RoleKeys: []string{"owner"}, Active: true},
	}}
	tuples := &fakeRoleTuples{}
	r := &TenantRoleSyncReconciler{
		Client: c, Recorder: events.NewFakeRecorder(10),
		Syncer: tenantrole.NewSyncer(grants, tuples, nil), Interval: 5 * time.Second,
	}

	res, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "acme"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter != 5*time.Second {
		t.Fatalf("RequeueAfter = %v, want 5s", res.RequeueAfter)
	}
	if len(tuples.tuples) != 1 || tuples.tuples[0].User != "user:u1" || tuples.tuples[0].Relation != "owner" {
		t.Fatalf("tuples after sync = %+v, want the owner tuple written", tuples.tuples)
	}
}

func TestTenantRoleSync_NoOrgIDRequeuesAt30Seconds(t *testing.T) {
	scheme := setupScheme(t)
	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()

	r := &TenantRoleSyncReconciler{
		Client: c, Recorder: events.NewFakeRecorder(10),
		Syncer: tenantrole.NewSyncer(&fakeRoleGrants{}, &fakeRoleTuples{}, nil), Interval: 5 * time.Second,
	}
	res, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "acme"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter != tenantRoleUnmappedRequeue {
		t.Fatalf("RequeueAfter = %v, want %v", res.RequeueAfter, tenantRoleUnmappedRequeue)
	}
}

func TestTenantRoleSync_DeletingTenantIsSkipped(t *testing.T) {
	scheme := setupScheme(t)
	now := metav1.Now()
	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{
		Name: "acme", Finalizers: []string{"gibson.zeroroot.ai/test"}, DeletionTimestamp: &now,
	}}
	tenant.Status.ZitadelOrgID = "org-1"
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()

	grants := &fakeRoleGrants{grants: []tenantrole.Grant{
		{ID: "g1", UserID: "u1", UserOrgID: "org-1", OrgID: "org-1", RoleKeys: []string{"owner"}, Active: true},
	}}
	tuples := &fakeRoleTuples{}
	r := &TenantRoleSyncReconciler{
		Client: c, Recorder: events.NewFakeRecorder(10),
		Syncer: tenantrole.NewSyncer(grants, tuples, nil),
	}
	res, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "acme"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("Result = %+v, want no requeue for a deleting tenant", res)
	}
	if len(tuples.tuples) != 0 {
		t.Fatalf("tuples = %+v, want untouched for a deleting tenant", tuples.tuples)
	}
}

func TestTenantRoleSync_OwnerConflictGivesAWarningEvent(t *testing.T) {
	scheme := setupScheme(t)
	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	tenant.Status.ZitadelOrgID = "org-1"
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()

	// Two active Owner grants: Sync must refuse and report, not pick one.
	grants := &fakeRoleGrants{grants: []tenantrole.Grant{
		{ID: "g1", UserID: "u1", UserOrgID: "org-1", OrgID: "org-1", RoleKeys: []string{"owner"}, Active: true},
		{ID: "g2", UserID: "u2", UserOrgID: "org-1", OrgID: "org-1", RoleKeys: []string{"owner"}, Active: true},
	}}
	rec := events.NewFakeRecorder(10)
	r := &TenantRoleSyncReconciler{
		Client: c, Recorder: rec,
		Syncer: tenantrole.NewSyncer(grants, &fakeRoleTuples{}, nil), Interval: 5 * time.Second,
	}
	res, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "acme"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter != 5*time.Second {
		t.Fatalf("RequeueAfter = %v, want the interval even on conflict", res.RequeueAfter)
	}
	select {
	case evt := <-rec.Events:
		if evt == "" {
			t.Fatal("empty event")
		}
	default:
		t.Fatal("expected a Warning event on owner conflict, got none")
	}
}

func TestTenantRoleSync_SetupWithManager(t *testing.T) {
	scheme := setupScheme(t)
	mgr, err := manager.New(&rest.Config{Host: "localhost:1"}, manager.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	r := &TenantRoleSyncReconciler{Client: mgr.GetClient()}
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatalf("SetupWithManager: %v", err)
	}
	if r.Recorder == nil {
		t.Error("SetupWithManager must default Recorder from the manager")
	}
	if r.Interval != DefaultTenantRoleSyncInterval {
		t.Errorf("Interval = %v, want the default %v", r.Interval, DefaultTenantRoleSyncInterval)
	}
}

func TestTenantRoleSync_EmitWithNoRecorderIsANoOp(_ *testing.T) {
	r := &TenantRoleSyncReconciler{}
	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	r.emit(tenant, "Normal", "Whatever", "no recorder wired, must not panic")
}

func TestTenantRoleSyncPredicate_Create(t *testing.T) {
	p := tenantRoleSyncPredicate()
	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	if !p.Create(event.CreateEvent{Object: tenant}) {
		t.Error("Create must always pass")
	}
}

func TestTenantRoleSyncPredicate_Delete(t *testing.T) {
	p := tenantRoleSyncPredicate()
	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	if p.Delete(event.DeleteEvent{Object: tenant}) {
		t.Error("Delete must never pass: the timer, not a delete, drives sync")
	}
}

func TestTenantRoleSyncPredicate_Generic(t *testing.T) {
	p := tenantRoleSyncPredicate()
	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	if p.Generic(event.GenericEvent{Object: tenant}) {
		t.Error("Generic must never pass")
	}
}

func TestTenantRoleSyncPredicate_Update(t *testing.T) {
	older := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	older.Status.ZitadelOrgID = ""
	newer := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	newer.Status.ZitadelOrgID = "org-1"
	unchanged := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	unchanged.Status.ZitadelOrgID = "org-1"

	p := tenantRoleSyncPredicate()
	if !p.Update(event.UpdateEvent{ObjectOld: older, ObjectNew: newer}) {
		t.Error("Update must pass when status.zitadelOrgID changed")
	}
	if p.Update(event.UpdateEvent{ObjectOld: newer, ObjectNew: unchanged}) {
		t.Error("Update must not pass when status.zitadelOrgID is unchanged")
	}
}

// TestTenantRoleSyncPredicate_UpdateWithTheWrongType pins the fail-open type
// assertion: an object that is not a *gibsonv1alpha1.Tenant (should never
// happen given For(&Tenant{}), but the predicate must not panic) passes,
// same as every other predicate function in this package.
func TestTenantRoleSyncPredicate_UpdateWithTheWrongType(t *testing.T) {
	p := tenantRoleSyncPredicate()
	notATenant := &metav1.PartialObjectMetadata{}
	if !p.Update(event.UpdateEvent{ObjectOld: notATenant, ObjectNew: notATenant}) {
		t.Error("Update with the wrong object type must fail open (return true)")
	}
}

func TestTenantRoleSync_UnknownTenantIgnoresNotFound(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &TenantRoleSyncReconciler{Client: c, Recorder: events.NewFakeRecorder(1)}

	res, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "does-not-exist"}})
	if err != nil {
		t.Fatalf("Reconcile: %v, want IgnoreNotFound to swallow it", err)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("Result = %+v, want a zero Result for a not-found tenant", res)
	}
}

func TestTenantRoleSync_UnsetSyncerRequeuesAndLogsWithoutPanicking(t *testing.T) {
	scheme := setupScheme(t)
	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	tenant.Status.ZitadelOrgID = "org-1"
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()

	r := &TenantRoleSyncReconciler{Client: c, Recorder: events.NewFakeRecorder(1), Interval: 5 * time.Second}
	res, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "acme"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter != 5*time.Second {
		t.Fatalf("RequeueAfter = %v, want the interval when Syncer is unset (operator misconfigured)", res.RequeueAfter)
	}
}

func TestTenantRoleSync_NonConflictSyncErrorRequeuesWithoutAnEvent(t *testing.T) {
	scheme := setupScheme(t)
	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	tenant.Status.ZitadelOrgID = "org-1"
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()

	grants := &fakeRoleGrants{listErr: errors.New("zitadel unreachable")}
	rec := events.NewFakeRecorder(10)
	r := &TenantRoleSyncReconciler{
		Client: c, Recorder: rec,
		Syncer: tenantrole.NewSyncer(grants, &fakeRoleTuples{}, nil), Interval: 5 * time.Second,
	}
	res, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "acme"}})
	if err != nil {
		t.Fatalf("Reconcile: %v, want the sync error logged and swallowed, not returned", err)
	}
	if res.RequeueAfter != 5*time.Second {
		t.Fatalf("RequeueAfter = %v, want the interval on a non-conflict sync error", res.RequeueAfter)
	}
	select {
	case evt := <-rec.Events:
		t.Fatalf("expected no event for a plain sync error, got %q", evt)
	default:
	}
}
