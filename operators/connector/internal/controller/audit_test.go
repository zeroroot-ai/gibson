// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"
)

var errDaemonDown = errors.New("daemon down")

// gibson#583: each change of the connector operator has its record first,
// and a failed record stops it.

func TestConnectorInstance_RecordsTheApplyOncePerGeneration(t *testing.T) {
	r := newReconciler(t, hostedInstance("hosted-fixture", "tenant-acme"))
	sink := &audittest.Sink{}
	r.Audit = sink.Emitter(t)
	key := types.NamespacedName{Namespace: "tenant-acme", Name: "hosted-fixture"}
	npAtRecord := true
	sink.OnEmit = func(audit.Event) {
		var np networkingv1.NetworkPolicy
		npAtRecord = r.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "connector-hosted-fixture"}, &np) == nil
	}
	for range 2 {
		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}
	got := sink.Events()
	if len(got) != 1 || got[0].Action != audit.ActionConnectorApply || got[0].TenantID != "acme" || npAtRecord {
		t.Fatalf("records = %+v, network policy at record = %v; want one record before the first change", got, npAtRecord)
	}
}

func TestConnectorInstance_FailedRecordStopsTheApply(t *testing.T) {
	r := newReconciler(t, hostedInstance("hosted-fixture", "tenant-acme"))
	r.Audit = (&audittest.Sink{Err: errDaemonDown}).Emitter(t)
	key := types.NamespacedName{Namespace: "tenant-acme", Name: "hosted-fixture"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); !errors.Is(err, audit.ErrNotRecorded) {
		t.Fatalf("reconcile = %v, want ErrNotRecorded", err)
	}
	var np networkingv1.NetworkPolicy
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "connector-hosted-fixture"}, &np); err == nil {
		t.Fatal("the network policy was created with no record")
	}
	if err := r.Get(context.Background(), key, newToolHive(kindMCPServer)); err == nil {
		t.Fatal("the ToolHive resource was created with no record")
	}
}

func TestConnectorInstance_FailedRecordStopsTheRevoke(t *testing.T) {
	deletedAt := time.Unix(1_700_000_000, 0).UTC()
	ci := deletingInstance(remoteInstance("gitlab", "tenant-primary"), deletedAt)
	r := newReconciler(t, ci)
	r.Audit = (&audittest.Sink{Err: errDaemonDown}).Emitter(t)
	// Past the revoke deadline: even then, no record means no release.
	r.Now = func() time.Time { return deletedAt.Add(24 * time.Hour) }
	key := types.NamespacedName{Namespace: "tenant-primary", Name: "gitlab"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err == nil {
		t.Fatal("reconcile returned no error with no audit record")
	}
	if calls := r.Revoker.(*fakeRevoker).calls; len(calls) != 0 {
		t.Fatalf("the grant was revoked with no record: %v", calls)
	}
	var got connectorv1alpha1.ConnectorInstance
	if err := r.Get(context.Background(), key, &got); err != nil || len(got.Finalizers) == 0 {
		t.Fatalf("the finalizer was released with no record: err %v, finalizers %v", err, got.Finalizers)
	}
}

func TestDesiredConnectors_FailedRecordStopsTheCreate(t *testing.T) {
	d := &fakeDesiredDaemon{desired: []*daemonoperatorv1.DesiredConnector{gitlabWish("acme")}}
	r, c := desiredLoop(t, d)
	r.Audit = (&audittest.Sink{Err: errDaemonDown}).Emitter(t)
	_ = r.converge(context.Background())
	var list connectorv1alpha1.ConnectorInstanceList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 0 {
		t.Fatalf("a ConnectorInstance was created with no record: %d", len(list.Items))
	}
}

func TestDesiredConnectors_CredentialRecordedOnlyWhenItChanges(t *testing.T) {
	d := &fakeDesiredDaemon{
		desired: []*daemonoperatorv1.DesiredConnector{gitlabWish("acme")},
		cred:    &daemonoperatorv1.GetConnectorCredentialResponse{Data: map[string][]byte{"TOKEN": []byte("t1")}},
	}
	r, c := desiredLoop(t, d)
	sink := &audittest.Sink{}
	r.Audit = sink.Emitter(t)
	for range 2 {
		if err := r.converge(context.Background()); err != nil {
			t.Fatalf("converge: %v", err)
		}
	}
	var writes []audit.Event
	for _, ev := range sink.Events() {
		if ev.Action == audit.ActionConnectorCredentialWrite {
			writes = append(writes, ev)
		}
	}
	if len(writes) != 1 || writes[0].Fields["keys"] != "TOKEN" {
		t.Fatalf("credential records = %+v, want one that names the key", writes)
	}
	for _, v := range writes[0].Fields {
		if v == "t1" {
			t.Fatal("a credential record holds the credential value")
		}
	}

	r.Audit = (&audittest.Sink{Err: errDaemonDown}).Emitter(t)
	d.cred = &daemonoperatorv1.GetConnectorCredentialResponse{Data: map[string][]byte{"TOKEN": []byte("t2")}}
	_ = r.converge(context.Background())
	var sec corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "tenant-acme", Name: credentialSecretName("gitlab")}, &sec); err != nil {
		t.Fatal(err)
	}
	if string(sec.Data["TOKEN"]) != "t1" {
		t.Fatalf("the credential changed with no record: %q", sec.Data["TOKEN"])
	}
}
