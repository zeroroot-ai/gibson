// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
					return err
				}
				cur.Status.PendingAuditRecords = append(cur.Status.PendingAuditRecords, other)
				if err := c.Status().Update(ctx, &cur); err != nil {
					return err
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
