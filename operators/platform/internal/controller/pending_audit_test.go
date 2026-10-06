// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
)

var errNoDaemon = errors.New("the daemon does not exist yet")

// The platform operator runs before the daemon. A pass does its change with
// no daemon, keeps the record pending in the status, and sends it when the
// daemon answers, then clears it (gibson#583).
func TestPlatformBootstrap_RecordWaitsForTheDaemon(t *testing.T) {
	s := mustScheme(t)
	pb := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{
		Name: "platform", Generation: 1, Finalizers: []string{platformBootstrapFinalizer},
	}}
	pb.Spec.Zitadel.AdminTokenRef = gibsonv1alpha1.SecretKeyRef{Name: "zitadel-admin-pat", Key: "pat"}
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(pb).WithStatusSubresource(pb).Build()
	down := &audittest.Sink{Err: errNoDaemon}
	r := &PlatformBootstrapReconciler{Client: cli, Scheme: s, Audit: down.Emitter(t)}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pb)}
	stored := func() gibsonv1alpha1.PlatformBootstrap {
		t.Helper()
		var got gibsonv1alpha1.PlatformBootstrap
		if err := cli.Get(context.Background(), req.NamespacedName, &got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	// Two passes with no daemon: the steps run, one record waits.
	for range 2 {
		res, err := r.Reconcile(context.Background(), req)
		if err != nil {
			t.Fatalf("Reconcile with no daemon: %v", err)
		}
		if res.RequeueAfter == 0 || res.RequeueAfter > pendingRequeue {
			t.Fatalf("result = %+v, want a requeue within %s", res, pendingRequeue)
		}
	}
	got := stored()
	if findCondition(got.Status.Conditions, gibsonv1alpha1.ConditionUnsealKeyEscrowed) == nil {
		t.Fatal("the pass did not run its steps with no daemon")
	}
	if len(got.Status.PendingAuditRecords) != 1 || got.Status.PendingAuditRecords[0].Action != audit.ActionPlatformBootstrap {
		t.Fatalf("pending = %+v, want one platform_bootstrap record", got.Status.PendingAuditRecords)
	}

	// The daemon answers: the record goes to it and leaves the status.
	up := &audittest.Sink{}
	r.Audit = up.Emitter(t)
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile with the daemon: %v", err)
	}
	if pending := stored().Status.PendingAuditRecords; len(pending) != 0 {
		t.Fatalf("pending after the daemon answered = %+v, want none", pending)
	}
	sent := up.Events()
	if len(sent) != 1 || sent[0].TenantID != auth.SystemTenantString || sent[0].TargetType != "platformbootstrap" ||
		sent[0].Fields["changed_at"] == "" {
		t.Fatalf("sent = %+v, want the waiting record in the system tenant with its change time", sent)
	}
}

// keepPending adds a record once, keeps a failure apart from its change, and
// counts the records past the size limit in one overflow record.
func TestKeepPending_DedupesAndBounds(t *testing.T) {
	obj := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{Name: "platform"}}
	var list []gibsonv1alpha1.PendingAuditRecord
	rec := pendingRecord(audit.ActionPlatformBootstrap, obj, "", "", map[string]string{"generation": "1"})
	keepPending(&list, rec)
	keepPending(&list, rec)
	keepPending(&list, pendingRecord(audit.ActionPlatformBootstrap, obj, audit.ResultFailure, "zitadel down", map[string]string{"generation": "1"}))
	if len(list) != 2 {
		t.Fatalf("pending = %+v, want the change and its failure once each", list)
	}
	for i := range 2 * maxPending {
		keepPending(&list, pendingRecord(audit.ActionPlatformBootstrap, obj, audit.ResultFailure, "reason "+string(rune('a'+i%26))+string(rune('a'+i/26)), nil))
	}
	if len(list) != maxPending || list[maxPending-1].Fields["overflow"] != "true" {
		t.Fatalf("len = %d, last = %+v; want a full list that ends in the overflow record", len(list), list[len(list)-1])
	}
	total := 0
	for _, p := range list {
		total += int(p.Count)
	}
	if total != 2+2*maxPending {
		t.Fatalf("the list stands for %d records, want %d", total, 2+2*maxPending)
	}
}

// flushPending sends in order, keeps what the daemon refused, and sends a
// failure record as a failure.
func TestFlushPending_KeepsWhatTheDaemonRefused(t *testing.T) {
	obj := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{Name: "platform"}}
	list := []gibsonv1alpha1.PendingAuditRecord{
		pendingRecord(audit.ActionPlatformBootstrap, obj, "", "", nil),
		pendingRecord(audit.ActionPlatformBootstrap, obj, audit.ResultFailure, "fga down", nil),
	}
	if err := flushPending(context.Background(), (&audittest.Sink{Err: errNoDaemon}).Emitter(t), &list); err == nil || len(list) != 2 {
		t.Fatalf("flush with no daemon = %v, pending %d; want an error and both kept", err, len(list))
	}
	sink := &audittest.Sink{}
	if err := flushPending(context.Background(), sink.Emitter(t), &list); err != nil || list != nil {
		t.Fatalf("flush = %v, pending %+v; want both sent", err, list)
	}
	if got := sink.Events(); len(got) != 2 || got[1].Result != audit.ResultFailure || got[1].Reason != "fga down" {
		t.Fatalf("sent = %+v", got)
	}
}

// The delete of an OIDC client never waits for the daemon: with no daemon,
// its record waits in the status of the parent PlatformBootstrap.
func TestOIDCClientDelete_RecordWaitsOnTheParent(t *testing.T) {
	s := mustScheme(t)
	pb := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{Name: "platform", UID: "pb-uid"}}
	oc := &gibsonv1alpha1.OIDCClient{ObjectMeta: metav1.ObjectMeta{
		Name: "dashboard", Namespace: "gibson",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: gibsonv1alpha1.GroupVersion.String(), Kind: "PlatformBootstrap", Name: "platform", UID: "pb-uid"}},
	}}
	oc.Status.ClientID = "client-1"
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(pb, oc).WithStatusSubresource(pb, oc).Build()
	r := &OIDCClientReconciler{Client: cli, Scheme: s, Audit: (&audittest.Sink{Err: errNoDaemon}).Emitter(t)}
	r.recordDeletion(context.Background(), oc, "app-1")
	var got gibsonv1alpha1.PlatformBootstrap
	if err := cli.Get(context.Background(), client.ObjectKey{Name: "platform"}, &got); err != nil {
		t.Fatal(err)
	}
	if p := got.Status.PendingAuditRecords; len(p) != 1 || p[0].Action != audit.ActionOIDCClientDelete || p[0].Fields["app_id"] != "app-1" {
		t.Fatalf("parent pending = %+v, want the delete record", p)
	}

	sink := &audittest.Sink{}
	r.Audit = sink.Emitter(t)
	r.recordDeletion(context.Background(), oc, "app-1")
	if len(sink.Events()) != 1 {
		t.Fatalf("with the daemon up the delete record goes straight to it: %+v", sink.Events())
	}
}

// An OIDCClient pass with no daemon keeps its record pending, and the record
// leaves when the daemon answers.
func TestOIDCClient_RecordWaitsForTheDaemon(t *testing.T) {
	s := mustScheme(t)
	oc := &gibsonv1alpha1.OIDCClient{ObjectMeta: metav1.ObjectMeta{
		Name: "dashboard", Namespace: "gibson", Generation: 1, Finalizers: []string{oidcClientFinalizer},
	}}
	oc.Spec.ClientName = "dashboard"
	oc.Spec.AdminTokenRef = gibsonv1alpha1.SecretKeyRef{Name: "zitadel-admin-pat", Key: "pat"}
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(oc).WithStatusSubresource(oc).Build()
	r := &OIDCClientReconciler{Client: cli, Scheme: s, Audit: (&audittest.Sink{Err: errNoDaemon}).Emitter(t)}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(oc)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile with no daemon: %v", err)
	}
	var got gibsonv1alpha1.OIDCClient
	if err := cli.Get(context.Background(), req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if p := got.Status.PendingAuditRecords; len(p) != 1 || p[0].Action != audit.ActionOIDCClientApply {
		t.Fatalf("pending = %+v, want the apply record", p)
	}
	sink := &audittest.Sink{}
	r.Audit = sink.Emitter(t)
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile with the daemon: %v", err)
	}
	if err := cli.Get(context.Background(), req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Status.PendingAuditRecords) != 0 || len(sink.Events()) != 1 {
		t.Fatalf("pending = %+v, sent = %+v; want the record sent and cleared", got.Status.PendingAuditRecords, sink.Events())
	}
}
