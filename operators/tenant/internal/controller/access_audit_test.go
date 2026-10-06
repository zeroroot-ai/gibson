// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// gibson#583: each identity, access or credential change of these
// controllers has its audit record first, and a failed record stops it.

func TestTenantMember_FailedRecordStopsTheInvitationToken(t *testing.T) {
	s := newMemberTestScheme(t)
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{Name: "eve", Namespace: "default", Finalizers: []string{gibsonv1alpha1.TenantMemberFinalizer}},
		Spec:       gibsonv1alpha1.TenantMemberSpec{Email: "eve@acme.com", Role: gibsonv1alpha1.MemberRoleMember, TenantRef: localRef()},
	}
	c := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&gibsonv1alpha1.TenantMember{}).WithObjects(member).Build()
	r := &TenantMemberReconciler{Client: c, Scheme: s, Recorder: events.NewFakeRecorder(10),
		Audit: (&audittest.Sink{Err: errDaemonDown}).Emitter(t)}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "eve"}}); !errors.Is(err, audit.ErrNotRecorded) {
		t.Fatalf("reconcile = %v, want ErrNotRecorded", err)
	}
	var secrets corev1.SecretList
	if err := c.List(context.Background(), &secrets); err != nil {
		t.Fatal(err)
	}
	if len(secrets.Items) != 0 {
		t.Fatalf("an invitation token was created with no record: %d secrets", len(secrets.Items))
	}
}

func TestTenantMember_FailedRecordStopsTheRoleAssign(t *testing.T) {
	fz := &fakeZitadelClient{}
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{Name: "bob", Namespace: "default", Finalizers: []string{gibsonv1alpha1.TenantMemberFinalizer}},
		Spec:       gibsonv1alpha1.TenantMemberSpec{Email: "bob@acme.com", Role: gibsonv1alpha1.MemberRoleAdmin, TenantRef: localRef()},
	}
	r, _, grants, _ := buildMemberReconcilerWithRoles(t, fz, tenantWithOrgID(), member, &fakeRoleGrants{}, &fakeRoleTuples{})
	r.Audit = (&audittest.Sink{Err: errDaemonDown}).Emitter(t)
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "bob"}}); !errors.Is(err, audit.ErrNotRecorded) {
		t.Fatalf("reconcile = %v, want ErrNotRecorded", err)
	}
	if len(fz.ensureHumanUserCalls) != 0 || len(grants.grants) != 0 {
		t.Fatalf("Zitadel changed with no record: users %v, grants %v", fz.ensureHumanUserCalls, grants.grants)
	}
}

func TestTenantMember_FailedRecordStopsTheRoleRevoke(t *testing.T) {
	grants := &fakeRoleGrants{grants: []tenantrole.Grant{
		{ID: "g1", UserID: "zuser-dave", UserOrgID: "org-111", OrgID: "org-111", RoleKeys: []string{string(tenantrole.Viewer)}, Active: true},
	}}
	now := metav1.Now()
	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{Name: "dave", Namespace: "default",
			Finalizers: []string{gibsonv1alpha1.TenantMemberFinalizer}, DeletionTimestamp: &now},
		Spec:   gibsonv1alpha1.TenantMemberSpec{Email: "dave@acme.com", Role: gibsonv1alpha1.MemberRoleMember, TenantRef: localRef()},
		Status: gibsonv1alpha1.TenantMemberStatus{ZitadelUserID: "zuser-dave", ZitadelMembershipID: "org-111/zuser-dave"},
	}
	r, _, grants, _ := buildMemberReconcilerWithRoles(t, &fakeZitadelClient{}, tenantWithOrgID(), member, grants, &fakeRoleTuples{})
	r.Audit = (&audittest.Sink{Err: errDaemonDown}).Emitter(t)
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "dave"}}); err == nil {
		t.Fatal("reconcile returned no error with no audit record")
	}
	if len(grants.grants) != 1 {
		t.Fatalf("the role was revoked with no record: %v", grants.grants)
	}
}

func TestConnectorAuthz_RecordsFirstOncePerGeneration(t *testing.T) {
	stub := &authzStubFGA{}
	r := newAuthzReconciler(t, stub, connectorCR("gitlab", "tenant-acme"))
	sink := &audittest.Sink{}
	r.Audit = sink.Emitter(t)
	writtenAtRecord := -1
	sink.OnEmit = func(audit.Event) { writtenAtRecord = len(stub.written) }
	reconcileOnce(t, r, "gitlab", "tenant-acme")
	reconcileOnce(t, r, "gitlab", "tenant-acme")
	got := sink.Events()
	if len(got) != 1 || got[0].Action != audit.ActionConnectorGrantsWrite || got[0].TenantID != "acme" || writtenAtRecord != 0 {
		t.Fatalf("records = %+v, written at record = %d; want one record before the first write", got, writtenAtRecord)
	}
}

func TestConnectorAuthz_FailedRecordStopsTheChange(t *testing.T) {
	stub := &authzStubFGA{}
	r := newAuthzReconciler(t, stub, connectorCR("gitlab", "tenant-acme", connectorAuthzFinalizer))
	r.Audit = (&audittest.Sink{Err: errDaemonDown}).Emitter(t)
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "gitlab", Namespace: "tenant-acme"}}); err == nil {
		t.Fatal("reconcile returned no error with no audit record")
	}
	if len(stub.written) != 0 || len(stub.deleted) != 0 {
		t.Fatalf("FGA changed with no record: written %v, deleted %v", stub.written, stub.deleted)
	}
}

func TestTenantRoleSync_RecordsOnlyARepair(t *testing.T) {
	scheme := setupScheme(t)
	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	tenant.Status.ZitadelOrgID = "org-1"
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()
	grants := &fakeRoleGrants{grants: []tenantrole.Grant{
		{ID: "g1", UserID: "u1", UserOrgID: "org-1", OrgID: "org-1", RoleKeys: []string{"owner"}, Active: true},
	}}
	tuples := &fakeRoleTuples{}
	sink := &audittest.Sink{}
	r := &TenantRoleSyncReconciler{Client: c, Recorder: events.NewFakeRecorder(10), Audit: sink.Emitter(t),
		Syncer: tenantrole.NewSyncer(grants, tuples, nil), Interval: time.Second}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "acme"}}
	for range 2 {
		if _, err := r.Reconcile(context.Background(), req); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
	}
	if got := sink.Events(); len(got) != 1 || got[0].Action != audit.ActionTenantRoleSync || got[0].Fields["written"] != "1" {
		t.Fatalf("records = %+v, want one record of the one repair", got)
	}
}

func TestTenantRoleSync_FailedRecordStopsTheRepair(t *testing.T) {
	scheme := setupScheme(t)
	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	tenant.Status.ZitadelOrgID = "org-1"
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()
	grants := &fakeRoleGrants{grants: []tenantrole.Grant{
		{ID: "g1", UserID: "u1", UserOrgID: "org-1", OrgID: "org-1", RoleKeys: []string{"owner"}, Active: true},
	}}
	tuples := &fakeRoleTuples{}
	r := &TenantRoleSyncReconciler{Client: c, Recorder: events.NewFakeRecorder(10),
		Audit: (&audittest.Sink{Err: errDaemonDown}).Emitter(t), Syncer: tenantrole.NewSyncer(grants, tuples, nil)}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "acme"}}); !errors.Is(err, audit.ErrNotRecorded) {
		t.Fatalf("reconcile = %v, want ErrNotRecorded", err)
	}
	if len(tuples.tuples) != 0 {
		t.Fatalf("FGA changed with no record: %v", tuples.tuples)
	}
}

func TestOrphanReaper_FailedRecordKeepsTheFinalizer(t *testing.T) {
	scheme := setupScheme(t)
	ns := newTerminatingNamespace(10*time.Minute, "tenant-acme")
	tm := newChildWithFinalizer("TenantMember", "invite-1", gibsonv1alpha1.TenantMemberFinalizer)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, tm).Build()
	r := &OrphanReaperReconciler{Client: c, Recorder: events.NewFakeRecorder(20), GracePeriodSeconds: 300, Enabled: true,
		Audit: (&audittest.Sink{Err: errDaemonDown}).Emitter(t)}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "tenant-acme"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var got gibsonv1alpha1.TenantMember
	if err := c.Get(context.Background(), types.NamespacedName{Name: "invite-1", Namespace: "tenant-acme"}, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) != 1 {
		t.Fatalf("the finalizer was removed with no record: %v", got.Finalizers)
	}
}

func TestOrphanReaper_RecordsTheRemoval(t *testing.T) {
	scheme := setupScheme(t)
	ns := newTerminatingNamespace(10*time.Minute, "tenant-acme")
	tm := newChildWithFinalizer("TenantMember", "invite-1", gibsonv1alpha1.TenantMemberFinalizer)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, tm).Build()
	sink := &audittest.Sink{}
	r := &OrphanReaperReconciler{Client: c, Recorder: events.NewFakeRecorder(20), GracePeriodSeconds: 300, Enabled: true, Audit: sink.Emitter(t)}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "tenant-acme"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := sink.Events(); len(got) != 1 || got[0].Action != audit.ActionOrphanFinalizerRemove || got[0].TenantID != "acme" {
		t.Fatalf("records = %+v", got)
	}
}

func TestFirstTenantSeed_FailedRecordStopsTheEnqueue(t *testing.T) {
	enq := &stubEnqueuer{}
	r := &FirstTenantSeedRunnable{Daemon: enq, TenantID: "founding", OwnerEmail: "o@x.test",
		Audit: (&audittest.Sink{Err: errDaemonDown}).Emitter(t)}
	if r.seedOnce(context.Background(), ctrl.Log) {
		t.Fatal("the seed reported done with no record")
	}
	if enq.callCount() != 0 {
		t.Fatalf("the tenant was queued with no record: %d calls", enq.callCount())
	}
	sink := &audittest.Sink{}
	r.Audit = sink.Emitter(t)
	if !r.seedOnce(context.Background(), ctrl.Log) || enq.callCount() != 1 {
		t.Fatalf("the seed did not enqueue after its record: calls %d", enq.callCount())
	}
	if got := sink.Events(); len(got) != 1 || got[0].Action != audit.ActionFirstTenantEnqueue || got[0].TenantID != "founding" {
		t.Fatalf("records = %+v", got)
	}
}

func TestIdentityAccessReconcilers_RefuseToStartWithoutAudit(t *testing.T) {
	for name, setup := range map[string]func() error{
		"TenantMember":           func() error { return (&TenantMemberReconciler{}).SetupWithManager(nil) },
		"ConnectorInstanceAuthz": func() error { return (&ConnectorInstanceAuthzReconciler{}).SetupWithManager(nil) },
		"TenantRoleSync":         func() error { return (&TenantRoleSyncReconciler{}).SetupWithManager(nil) },
		"OrphanReaper":           func() error { return (&OrphanReaperReconciler{Enabled: true}).SetupWithManager(nil) },
	} {
		if err := setup(); err == nil {
			t.Errorf("%s started without an audit emitter", name)
		}
	}
}
