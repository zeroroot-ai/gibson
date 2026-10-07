// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
)

// A drift pass that removes a human administrator keeps its record in the
// status before the removal, and a status write that fails stops the removal.
func TestDriftPass_RecordIsInTheStatusBeforeTheRemoval(t *testing.T) {
	srv, removedIAM, _ := humanAdminsMux(t, []iamMemberFixture{
		{UserID: "UID-OWNER", PreferredLoginName: "owner@example.com", DisplayName: "Platform Owner", UserType: "TYPE_HUMAN", UserResourceOwner: "ORG-1"},
		{UserID: "UID-INTRUDER", PreferredLoginName: "intruder@example.com", DisplayName: "Intruder", UserType: "TYPE_HUMAN", UserResourceOwner: "ORG-1"},
	})
	r := newHumanAdminsTestReconciler(t, srv.URL)
	pb := humanAdminsCR(srv.URL)

	// The status write fails: nothing is removed.
	failing := interceptor.NewClient(r.Client.(client.WithWatch), interceptor.Funcs{
		SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
			return errors.New("api server down")
		},
	})
	good := r.Client
	r.Client = failing
	if _, err := r.reconcileHumanAdminsScoped(context.Background(), pb, logr.Discard()); err == nil {
		t.Fatal("want an error when the record cannot be kept")
	}
	if len(*removedIAM) != 0 {
		t.Fatalf("removed %v with no record kept", *removedIAM)
	}

	// The status write works: the record is stored, then the member goes.
	r.Client = good
	pb = humanAdminsCR(srv.URL)
	if _, err := r.reconcileHumanAdminsScoped(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcileHumanAdminsScoped: %v", err)
	}
	if len(*removedIAM) != 1 {
		t.Fatalf("removed = %v, want the intruder", *removedIAM)
	}
	var stored gibsonv1alpha1.PlatformBootstrap
	if err := good.Get(context.Background(), client.ObjectKey{Name: "platform"}, &stored); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range stored.Status.PendingAuditRecords {
		if p.Fields["change"] == "remove_human_iam_member" && p.Fields["user_id"] == "UID-INTRUDER" {
			found = true
		}
	}
	if !found {
		t.Fatalf("pending = %+v, want the removal record", stored.Status.PendingAuditRecords)
	}
}

// A status write that loses a conflict keeps the record that another writer
// added in the meantime, and does not bring back a record that this pass sent.
func TestStatusUpdate_ConflictKeepsAConcurrentPendingRecord(t *testing.T) {
	s := mustScheme(t)
	obj := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{Name: "platform"}}
	sent := pendingRecord(audit.ActionPlatformBootstrap, obj, "", "", map[string]string{"generation": "1"})
	other := pendingRecord(audit.ActionOIDCClientDelete, obj, "", "", map[string]string{"client": "dashboard"})
	stored := obj.DeepCopy()
	stored.Status.PendingAuditRecords = []gibsonv1alpha1.PendingAuditRecord{sent}
	base := fake.NewClientBuilder().WithScheme(s).WithObjects(stored).WithStatusSubresource(stored).Build()
	conflicts := 0
	cli := interceptor.NewClient(base, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, _ string, o client.Object, opts ...client.SubResourceUpdateOption) error {
			if conflicts == 0 {
				conflicts++
				// The other writer adds its record, then this write loses.
				var cur gibsonv1alpha1.PlatformBootstrap
				if err := c.Get(ctx, client.ObjectKey{Name: "platform"}, &cur); err != nil {
					return fmt.Errorf("get: %w", err)
				}
				cur.Status.PendingAuditRecords = append(cur.Status.PendingAuditRecords, other)
				if err := c.Status().Update(ctx, &cur); err != nil {
					return fmt.Errorf("update: %w", err)
				}
				return apierrors.NewConflict(schema.GroupResource{Group: "gibson.zeroroot.ai", Resource: "platformbootstraps"}, o.GetName(), nil)
			}
			return c.Status().Update(ctx, o, opts...)
		},
	})
	r := &PlatformBootstrapReconciler{Audit: (&audittest.Sink{}).Emitter(t), Client: cli, Scheme: s}

	got := &gibsonv1alpha1.PlatformBootstrap{}
	if err := cli.Get(context.Background(), client.ObjectKey{Name: "platform"}, got); err != nil {
		t.Fatal(err)
	}
	flushed, err := flushPendingSent(context.Background(), (&audittest.Sink{}).Emitter(t), &got.Status.PendingAuditRecords)
	if err != nil || len(flushed) != 1 {
		t.Fatalf("flush = %v, %v", flushed, err)
	}
	if err := r.statusUpdateFlushed(context.Background(), got, flushed); err != nil {
		t.Fatalf("statusUpdateFlushed: %v", err)
	}
	after := &gibsonv1alpha1.PlatformBootstrap{}
	if err := cli.Get(context.Background(), client.ObjectKey{Name: "platform"}, after); err != nil {
		t.Fatal(err)
	}
	if p := after.Status.PendingAuditRecords; len(p) != 1 || p[0].Action != audit.ActionOIDCClientDelete {
		t.Fatalf("pending = %+v, want only the record of the other writer", p)
	}
}

// With no daemon and no parent to hold the record, the delete of an OIDC
// client is refused.
func TestOIDCClientDelete_RefusedWhenNoRecordIsKept(t *testing.T) {
	s := mustScheme(t)
	oc := &gibsonv1alpha1.OIDCClient{ObjectMeta: metav1.ObjectMeta{Name: "dashboard", Namespace: "gibson"}}
	oc.Status.ClientID = "client-1"
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(oc).WithStatusSubresource(oc).Build()
	r := &OIDCClientReconciler{Client: cli, Scheme: s, Audit: (&audittest.Sink{Err: errNoDaemon}).Emitter(t)}
	if err := r.recordDeletion(context.Background(), oc, "app-1"); err == nil {
		t.Fatal("want an error: no daemon and no parent keeps the record")
	}
}

// A conflict on the parent status is retried, so the delete record is kept.
func TestOIDCClientDelete_RecordRetriesAParentConflict(t *testing.T) {
	s := mustScheme(t)
	pb := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{Name: "platform", UID: "pb-uid"}}
	oc := &gibsonv1alpha1.OIDCClient{ObjectMeta: metav1.ObjectMeta{
		Name: "dashboard", Namespace: "gibson",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: gibsonv1alpha1.GroupVersion.String(), Kind: "PlatformBootstrap", Name: "platform", UID: "pb-uid"}},
	}}
	base := fake.NewClientBuilder().WithScheme(s).WithObjects(pb, oc).WithStatusSubresource(pb, oc).Build()
	conflicts := 0
	cli := interceptor.NewClient(base, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, _ string, o client.Object, opts ...client.SubResourceUpdateOption) error {
			if conflicts == 0 {
				conflicts++
				return apierrors.NewConflict(schema.GroupResource{Group: "gibson.zeroroot.ai", Resource: "platformbootstraps"}, o.GetName(), nil)
			}
			return c.Status().Update(ctx, o, opts...)
		},
	})
	r := &OIDCClientReconciler{Client: cli, Scheme: s, Audit: (&audittest.Sink{Err: errNoDaemon}).Emitter(t)}
	if err := r.recordDeletion(context.Background(), oc, "app-1"); err != nil {
		t.Fatalf("recordDeletion: %v", err)
	}
	var got gibsonv1alpha1.PlatformBootstrap
	if err := base.Get(context.Background(), client.ObjectKey{Name: "platform"}, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Status.PendingAuditRecords) != 1 || conflicts != 1 {
		t.Fatalf("pending = %+v, conflicts = %d; want one record after one retried conflict", got.Status.PendingAuditRecords, conflicts)
	}
}

// The pending records of a deleted OIDC client move to the parent before the
// finalizer goes.
func TestOIDCClientDelete_PendingRecordsMoveToTheParent(t *testing.T) {
	s := mustScheme(t)
	pb := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{Name: "platform", UID: "pb-uid"}}
	oc := &gibsonv1alpha1.OIDCClient{ObjectMeta: metav1.ObjectMeta{
		Name: "dashboard", Namespace: "gibson",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: gibsonv1alpha1.GroupVersion.String(), Kind: "PlatformBootstrap", Name: "platform", UID: "pb-uid"}},
	}}
	oc.Status.PendingAuditRecords = []gibsonv1alpha1.PendingAuditRecord{
		pendingRecord(audit.ActionOIDCClientApply, oc, "", "", map[string]string{"client": "dashboard"}),
	}
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(pb, oc).WithStatusSubresource(pb, oc).Build()
	r := &OIDCClientReconciler{Client: cli, Scheme: s, Audit: (&audittest.Sink{}).Emitter(t)}
	if err := r.parkPendingBeforeDelete(context.Background(), oc); err != nil {
		t.Fatalf("parkPendingBeforeDelete: %v", err)
	}
	var got gibsonv1alpha1.PlatformBootstrap
	if err := cli.Get(context.Background(), client.ObjectKey{Name: "platform"}, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Status.PendingAuditRecords) != 1 || got.Status.PendingAuditRecords[0].Action != audit.ActionOIDCClientApply {
		t.Fatalf("parent pending = %+v, want the client record", got.Status.PendingAuditRecords)
	}
}

// A delete of the PlatformBootstrap sends its pending records first. With no
// daemon the finalizer stays, and after the grace it goes and the records are
// logged.
func TestPlatformBootstrap_DeleteKeepsPendingRecords(t *testing.T) {
	s := mustScheme(t)
	now := metav1.Now()
	pb := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{
		Name: "platform", Finalizers: []string{platformBootstrapFinalizer}, DeletionTimestamp: &now,
	}}
	pb.Status.PendingAuditRecords = []gibsonv1alpha1.PendingAuditRecord{
		pendingRecord(audit.ActionOIDCClientDelete, pb, "", "", map[string]string{"client": "dashboard"}),
	}
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(pb).WithStatusSubresource(pb).Build()
	down := &audittest.Sink{Err: errNoDaemon}
	r := &PlatformBootstrapReconciler{Client: cli, Scheme: s, Audit: down.Emitter(t)}

	res, err := r.reconcileDeletion(context.Background(), pb)
	if err != nil || res.RequeueAfter == 0 {
		t.Fatalf("with no daemon: res = %+v, err = %v; want a requeue and the finalizer kept", res, err)
	}
	if len(pb.Status.PendingAuditRecords) != 1 || len(pb.Finalizers) != 1 {
		t.Fatalf("pending = %d, finalizers = %v; want the record and the finalizer kept", len(pb.Status.PendingAuditRecords), pb.Finalizers)
	}

	up := &audittest.Sink{}
	r.Audit = up.Emitter(t)
	if _, err := r.reconcileDeletion(context.Background(), pb); err != nil {
		t.Fatalf("with the daemon: %v", err)
	}
	if len(up.Events()) != 1 || len(pb.Finalizers) != 0 {
		t.Fatalf("sent = %d, finalizers = %v; want the record sent and the finalizer gone", len(up.Events()), pb.Finalizers)
	}
}

// After the grace, a delete with no daemon ends: the finalizer goes and the
// records go to the operator log.
func TestPlatformBootstrap_DeleteEndsAfterTheGrace(t *testing.T) {
	s := mustScheme(t)
	old := metav1.NewTime(metav1.Now().Add(-2 * pendingDeleteGrace))
	pb := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{
		Name: "platform", Finalizers: []string{platformBootstrapFinalizer}, DeletionTimestamp: &old,
	}}
	pb.Status.PendingAuditRecords = []gibsonv1alpha1.PendingAuditRecord{
		pendingRecord(audit.ActionOIDCClientDelete, pb, "", "", map[string]string{"client": "dashboard"}),
	}
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(pb).WithStatusSubresource(pb).Build()
	r := &PlatformBootstrapReconciler{Client: cli, Scheme: s, Audit: (&audittest.Sink{Err: errNoDaemon}).Emitter(t)}
	if _, err := r.reconcileDeletion(context.Background(), pb); err != nil {
		t.Fatalf("reconcileDeletion: %v", err)
	}
	if len(pb.Finalizers) != 0 {
		t.Fatalf("finalizers = %v, want none after the grace", pb.Finalizers)
	}
	var cms corev1.ConfigMapList
	if err := cli.List(context.Background(), &cms, client.InNamespace(defaultChildNamespace), client.MatchingLabels{pendingAuditLabel: "true"}); err != nil {
		t.Fatal(err)
	}
	if len(cms.Items) != 1 {
		t.Fatalf("ConfigMaps = %d, want one that holds the pending records", len(cms.Items))
	}
}

// When the status that holds the record cannot be written, no step runs.
func TestPlatformBootstrap_NoStatusWriteMeansNoStep(t *testing.T) {
	s := mustScheme(t)
	pb := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{
		Name: "platform", Generation: 1, Finalizers: []string{platformBootstrapFinalizer},
	}}
	base := fake.NewClientBuilder().WithScheme(s).WithObjects(pb).WithStatusSubresource(pb).Build()
	cli := interceptor.NewClient(base, interceptor.Funcs{
		SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
			return errors.New("api server down")
		},
	})
	r := &PlatformBootstrapReconciler{Client: cli, Scheme: s, Audit: (&audittest.Sink{}).Emitter(t)}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pb)}); err == nil {
		t.Fatal("want an error when the record cannot be kept")
	}
	var got gibsonv1alpha1.PlatformBootstrap
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(pb), &got); err != nil {
		t.Fatal(err)
	}
	if findCondition(got.Status.Conditions, gibsonv1alpha1.ConditionUnsealKeyEscrowed) != nil {
		t.Fatal("a step ran with no record kept")
	}
}

// The delete of an OIDC client waits while its pending records cannot move to
// a parent, and ends after the grace.
func TestOIDCClientDelete_PendingRecordsWaitThenEnd(t *testing.T) {
	s := mustScheme(t)
	mk := func(age time.Duration) (*OIDCClientReconciler, *gibsonv1alpha1.OIDCClient) {
		ts := metav1.NewTime(metav1.Now().Add(-age))
		oc := &gibsonv1alpha1.OIDCClient{ObjectMeta: metav1.ObjectMeta{
			Name: "dashboard", Namespace: "gibson", Finalizers: []string{oidcClientFinalizer}, DeletionTimestamp: &ts,
		}}
		oc.Spec.ApplicationType = gibsonv1alpha1.OIDCAppTypeMachineUser
		oc.Status.PendingAuditRecords = []gibsonv1alpha1.PendingAuditRecord{
			pendingRecord(audit.ActionOIDCClientApply, oc, "", "", map[string]string{"client": "dashboard"}),
		}
		cli := fake.NewClientBuilder().WithScheme(s).WithObjects(oc).WithStatusSubresource(oc).Build()
		return &OIDCClientReconciler{Client: cli, Scheme: s, Audit: (&audittest.Sink{Err: errNoDaemon}).Emitter(t)}, oc
	}

	r, oc := mk(time.Minute)
	res, err := r.reconcileDeletion(context.Background(), oc)
	if err == nil || res.RequeueAfter == 0 || len(oc.Finalizers) != 1 {
		t.Fatalf("within the grace: res = %+v, err = %v, finalizers = %v; want a wait", res, err, oc.Finalizers)
	}
	r, oc = mk(2 * pendingDeleteGrace)
	if _, err := r.reconcileDeletion(context.Background(), oc); err != nil || len(oc.Finalizers) != 0 {
		t.Fatalf("after the grace: err = %v, finalizers = %v; want the finalizer gone", err, oc.Finalizers)
	}
	// An app client with no Zitadel client id takes the same path.
	r, oc = mk(time.Minute)
	oc.Spec.ApplicationType = ""
	oc.Status.ClientID = ""
	if res, err := r.reconcileDeletion(context.Background(), oc); err == nil || res.RequeueAfter == 0 {
		t.Fatalf("app client within the grace: res = %+v, err = %v; want a wait", res, err)
	}
	r, oc = mk(2 * pendingDeleteGrace)
	oc.Spec.ApplicationType = ""
	oc.Status.ClientID = ""
	if _, err := r.reconcileDeletion(context.Background(), oc); err != nil || len(oc.Finalizers) != 0 {
		t.Fatalf("app client after the grace: err = %v, finalizers = %v", err, oc.Finalizers)
	}
}

// Past the grace a delete moves its records to a ConfigMap, and the flusher
// sends them when the daemon returns and then deletes the ConfigMap.
func TestPendingAuditFlusher_SendsWhenTheDaemonReturns(t *testing.T) {
	s := mustScheme(t)
	cli := fake.NewClientBuilder().WithScheme(s).Build()
	obj := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{Name: "platform"}}
	recs := []gibsonv1alpha1.PendingAuditRecord{
		pendingRecord(audit.ActionOIDCClientDelete, obj, "", "", map[string]string{"client": "a"}),
		pendingRecord(audit.ActionOIDCClientDelete, obj, "", "", map[string]string{"client": "b"}),
	}
	if err := saveDurable(context.Background(), cli, recs); err != nil {
		t.Fatal(err)
	}
	if err := saveDurable(context.Background(), cli, recs); err != nil {
		t.Fatalf("the same records twice: %v", err)
	}
	if err := saveDurable(context.Background(), cli, nil); err != nil {
		t.Fatalf("no records: %v", err)
	}
	count := func() int {
		var cms corev1.ConfigMapList
		if err := cli.List(context.Background(), &cms, client.InNamespace(defaultChildNamespace)); err != nil {
			t.Fatal(err)
		}
		return len(cms.Items)
	}
	if count() != 1 {
		t.Fatalf("ConfigMaps = %d, want one for the same records", count())
	}

	f := &PendingAuditFlusher{Client: cli, Audit: (&audittest.Sink{Err: errNoDaemon}).Emitter(t)}
	if err := f.FlushOnce(context.Background()); err == nil || count() != 1 {
		t.Fatalf("daemon down: err = %v, ConfigMaps = %d; want the ConfigMap kept", err, count())
	}
	up := &audittest.Sink{}
	f.Audit = up.Emitter(t)
	if err := f.FlushOnce(context.Background()); err != nil || count() != 0 || len(up.Events()) != 2 {
		t.Fatalf("daemon up: err = %v, ConfigMaps = %d, sent = %d; want both sent and the ConfigMap gone", err, count(), len(up.Events()))
	}
}

// A client delete past the grace keeps its records in a ConfigMap. When that
// fails too, it goes on only in a teardown of the whole platform. In any other
// case it keeps waiting.
func TestOIDCClientDelete_LastResort(t *testing.T) {
	s := mustScheme(t)
	old := metav1.NewTime(metav1.Now().Add(-2 * pendingDeleteGrace))
	mk := func(parent *gibsonv1alpha1.PlatformBootstrap, failCreate bool) (*OIDCClientReconciler, *gibsonv1alpha1.OIDCClient) {
		oc := &gibsonv1alpha1.OIDCClient{ObjectMeta: metav1.ObjectMeta{
			Name: "dashboard", Namespace: "gibson", Finalizers: []string{oidcClientFinalizer}, DeletionTimestamp: &old,
			OwnerReferences: []metav1.OwnerReference{{APIVersion: gibsonv1alpha1.GroupVersion.String(), Kind: "PlatformBootstrap", Name: "platform", UID: "pb-uid"}},
		}}
		oc.Spec.ApplicationType = gibsonv1alpha1.OIDCAppTypeMachineUser
		oc.Status.PendingAuditRecords = []gibsonv1alpha1.PendingAuditRecord{
			pendingRecord(audit.ActionOIDCClientApply, oc, "", "", map[string]string{"client": "dashboard"}),
		}
		b := fake.NewClientBuilder().WithScheme(s).WithObjects(oc).WithStatusSubresource(oc)
		if parent != nil {
			b = b.WithObjects(parent).WithStatusSubresource(parent)
		}
		var c client.Client = b.Build()
		if failCreate {
			c = interceptor.NewClient(c.(client.WithWatch), interceptor.Funcs{
				Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
					return errors.New("namespace is going away")
				},
			})
		}
		return &OIDCClientReconciler{Client: c, Scheme: s, Audit: (&audittest.Sink{Err: errNoDaemon}).Emitter(t)}, oc
	}
	live := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{Name: "platform", UID: "pb-uid"}}

	// The parent exists and is live: the records go to the parent.
	r, oc := mk(live, false)
	if wait, _ := r.parkPendingOrLog(context.Background(), oc); wait {
		t.Error("live parent: the delete must not wait")
	}
	// No parent, the ConfigMap works: the records go to the ConfigMap.
	r, oc = mk(nil, false)
	// A missing parent is a teardown, but the ConfigMap is written first.
	if wait, _ := r.parkPendingOrLog(context.Background(), oc); wait {
		t.Error("no parent, ConfigMap works: the delete must not wait")
	}
	var cms corev1.ConfigMapList
	if err := r.List(context.Background(), &cms, client.InNamespace(defaultChildNamespace)); err != nil || len(cms.Items) != 1 {
		t.Fatalf("ConfigMaps = %d, err = %v; want one", len(cms.Items), err)
	}
	// The ConfigMap fails and the platform is in teardown (no parent): the log is the last copy.
	r, oc = mk(nil, true)
	if wait, _ := r.parkPendingOrLog(context.Background(), oc); wait {
		t.Error("teardown: the delete must go on")
	}
	// The ConfigMap fails, the parent is live and cannot hold the record: wait.
	r, oc = mk(live, true)
	r.Client = interceptor.NewClient(r.Client.(client.WithWatch), interceptor.Funcs{
		SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
			return errors.New("status write refused")
		},
	})
	if wait, _ := r.parkPendingOrLog(context.Background(), oc); !wait {
		t.Error("live platform, no copy possible: the delete must wait")
	}
	// The same through recordDeletionOrLog.
	if wait := r.recordDeletionOrLog(context.Background(), oc, "app-1"); !wait {
		t.Error("recordDeletionOrLog: the delete must wait")
	}
}

// A retry of the same delete stamps a new first-seen time and still writes the
// same ConfigMap. The flusher refuses a record that this operator does not
// write for a delete, and keeps the unsent rest of a ConfigMap.
func TestPendingDurable_NameFlusherAndTeardown(t *testing.T) {
	ctx := context.Background()
	s := mustScheme(t)
	obj := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{Name: "platform"}}
	cli := fake.NewClientBuilder().WithScheme(s).Build()
	mk := func() []gibsonv1alpha1.PendingAuditRecord {
		return []gibsonv1alpha1.PendingAuditRecord{pendingRecord(audit.ActionOIDCClientDelete, obj, "", "", map[string]string{"client": "a"})}
	}
	if err := saveDurable(ctx, cli, mk()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // a new second for FirstAt
	if err := saveDurable(ctx, cli, mk()); err != nil {
		t.Fatal(err)
	}
	var cms corev1.ConfigMapList
	if err := cli.List(ctx, &cms, client.InNamespace(defaultChildNamespace)); err != nil || len(cms.Items) != 1 {
		t.Fatalf("ConfigMaps = %d, err = %v; want one for a retried delete", len(cms.Items), err)
	}

	// A ConfigMap with a foreign action is not sent.
	foreign := []gibsonv1alpha1.PendingAuditRecord{pendingRecord("tenant.delete", obj, "", "", nil)}
	if err := saveDurable(ctx, cli, foreign); err != nil {
		t.Fatal(err)
	}
	up := &audittest.Sink{}
	f := &PendingAuditFlusher{Client: cli, Audit: up.Emitter(t)}
	if err := f.FlushOnce(ctx); err == nil {
		t.Fatal("want an error for the foreign record")
	}
	if got := up.Events(); len(got) != 1 || got[0].Action != audit.ActionOIDCClientDelete {
		t.Fatalf("sent = %+v, want only the delete record", got)
	}

	// A ConfigMap with records the daemon takes in part keeps the rest.
	two := []gibsonv1alpha1.PendingAuditRecord{
		pendingRecord(audit.ActionOIDCClientDelete, obj, "", "", map[string]string{"client": "x"}),
		pendingRecord(audit.ActionOIDCClientDelete, obj, "", "", map[string]string{"client": "y"}),
	}
	cli2 := fake.NewClientBuilder().WithScheme(s).Build()
	if err := saveDurable(ctx, cli2, two); err != nil {
		t.Fatal(err)
	}
	n := 0
	partial := &audittest.Sink{}
	partial.OnEmit = func(audit.Event) { n++ }
	flaky := &flakySink{inner: partial, failAfter: 1}
	em, err := audit.NewSagaEmitter(flaky)
	if err != nil {
		t.Fatal(err)
	}
	f2 := &PendingAuditFlusher{Client: cli2, Audit: em}
	if err := f2.FlushOnce(ctx); err == nil {
		t.Fatal("want an error: the daemon refused the second record")
	}
	var left corev1.ConfigMapList
	if err := cli2.List(ctx, &left, client.InNamespace(defaultChildNamespace)); err != nil || len(left.Items) != 1 {
		t.Fatalf("ConfigMaps = %d, err = %v", len(left.Items), err)
	}
	var kept []gibsonv1alpha1.PendingAuditRecord
	if err := json.Unmarshal([]byte(left.Items[0].Data[pendingAuditKey]), &kept); err != nil || len(kept) != 1 || kept[0].Fields["client"] != "y" {
		t.Fatalf("kept = %+v, err = %v; want only the second record", kept, err)
	}

	// A parent that is deleting is a teardown. A live parent is not.
	now := metav1.Now()
	dying := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{Name: "platform", Finalizers: []string{platformBootstrapFinalizer}, DeletionTimestamp: &now}}
	oc := &gibsonv1alpha1.OIDCClient{ObjectMeta: metav1.ObjectMeta{
		Name: "dashboard", Namespace: "gibson",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: gibsonv1alpha1.GroupVersion.String(), Kind: "PlatformBootstrap", Name: "platform"}},
	}}
	cd := fake.NewClientBuilder().WithScheme(s).WithObjects(dying).Build()
	if !parentInTeardown(ctx, cd, oc) {
		t.Error("a deleting parent is a teardown")
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(&gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{Name: "platform"}}).Build()
	if parentInTeardown(ctx, cl, oc) {
		t.Error("a live parent is not a teardown")
	}
	failing := interceptor.NewClient(cl.(client.WithWatch), interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errors.New("api server down")
		},
	})
	if parentInTeardown(ctx, failing, oc) {
		t.Error("an unreadable parent is not a teardown")
	}
}

// flakySink accepts failAfter records and refuses the rest.
type flakySink struct {
	inner     *audittest.Sink
	failAfter int
	n         int
}

func (f *flakySink) EmitAuditEvent(ctx context.Context, ev audit.Event) error {
	if f.n >= f.failAfter {
		return errNoDaemon
	}
	f.n++
	return f.inner.EmitAuditEvent(ctx, ev)
}

// A PlatformBootstrap delete that cannot write its ConfigMap goes on and logs
// the records as a teardown.
func TestPlatformBootstrap_DeleteLogsATeardownWhenNoConfigMapCanBeWritten(t *testing.T) {
	s := mustScheme(t)
	old := metav1.NewTime(metav1.Now().Add(-2 * pendingDeleteGrace))
	pb := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{
		Name: "platform", Finalizers: []string{platformBootstrapFinalizer}, DeletionTimestamp: &old,
	}}
	pb.Status.PendingAuditRecords = []gibsonv1alpha1.PendingAuditRecord{
		pendingRecord(audit.ActionOIDCClientDelete, pb, "", "", map[string]string{"client": "dashboard"}),
	}
	base := fake.NewClientBuilder().WithScheme(s).WithObjects(pb).WithStatusSubresource(pb).Build()
	cli := interceptor.NewClient(base, interceptor.Funcs{
		Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
			return errors.New("namespace is going away")
		},
	})
	r := &PlatformBootstrapReconciler{Client: cli, Scheme: s, Audit: (&audittest.Sink{Err: errNoDaemon}).Emitter(t)}
	if _, err := r.reconcileDeletion(context.Background(), pb); err != nil || len(pb.Finalizers) != 0 {
		t.Fatalf("err = %v, finalizers = %v; want the delete to go on", err, pb.Finalizers)
	}
}
