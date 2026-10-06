// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/audit/audittest"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/identity"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

var errDaemonDown = errors.New("daemon down")

// withFinalizer returns obj with the finalizer and, when deleting, a
// deletion timestamp.
func withFinalizer[T client.Object](obj T, finalizer string, deleting bool) T {
	controllerutil.AddFinalizer(obj, finalizer)
	if deleting {
		now := metav1.Now()
		obj.SetDeletionTimestamp(&now)
	}
	return obj
}

func identityFixture(t *testing.T, ti *gibsonv1alpha1.TenantIdentity, sink *audittest.Sink) (*TenantIdentityReconciler, *stubIdentityProvisioner, *stubOrgMapping, client.Client) {
	t.Helper()
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantIdentity{}).WithObjects(ti).Build()
	stub := &stubIdentityProvisioner{result: identity.Result{OrgID: "org-123", Slug: "acme"}}
	orgs := &stubOrgMapping{}
	r := &TenantIdentityReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100),
		Audit: sink.Emitter(t), Provisioner: stub, OrgMapping: orgs}
	return r, stub, orgs, c
}

func secretsFixture(t *testing.T, tsb *gibsonv1alpha1.TenantSecretsBackend, sink *audittest.Sink) (*TenantSecretsBackendReconciler, *stubSecretsProvisioner, client.Client) {
	t.Helper()
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantSecretsBackend{}).WithObjects(tsb).Build()
	stub := &stubSecretsProvisioner{}
	r := &TenantSecretsBackendReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100),
		Audit: sink.Emitter(t), Provisioner: stub}
	return r, stub, c
}

// The Zitadel controller records the change before it, and changes nothing
// when the record fails (gibson#583).
func TestTenantIdentity_RecordsBeforeZitadel(t *testing.T) {
	ti := withFinalizer(newTenantIdentity("acme-identity", "acme"), gibsonv1alpha1.TenantIdentityFinalizer, false)
	sink := &audittest.Sink{}
	r, stub, _, _ := identityFixture(t, ti, sink)
	provisionedAtRecord := -1
	sink.OnEmit = func(audit.Event) { provisionedAtRecord = len(stub.provisioned) }
	if _, err := reconcileTI(t, r, "acme-identity"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := sink.Events()
	if len(got) != 1 || got[0].Action != audit.ActionIdentityProvision || got[0].TenantID != "acme" ||
		got[0].TargetID != "tenant-acme/acme-identity" || provisionedAtRecord != 0 {
		t.Fatalf("records = %+v, provisioned at record = %d", got, provisionedAtRecord)
	}
}

func TestTenantIdentity_FailedRecordStopsTheChange(t *testing.T) {
	ti := withFinalizer(newTenantIdentity("acme-identity", "acme"), gibsonv1alpha1.TenantIdentityFinalizer, false)
	r, stub, orgs, _ := identityFixture(t, ti, &audittest.Sink{Err: errDaemonDown})
	if _, err := reconcileTI(t, r, "acme-identity"); !errors.Is(err, errDaemonDown) {
		t.Fatalf("reconcile = %v, want the audit error", err)
	}
	if len(stub.provisioned) != 0 || len(orgs.seeds) != 0 {
		t.Fatalf("Zitadel or the org mapping changed with no record: %v / %v", stub.provisioned, orgs.seeds)
	}
}

func TestTenantIdentity_FailedRecordStopsTheDelete(t *testing.T) {
	ti := withFinalizer(newTenantIdentity("acme-identity", "acme"), gibsonv1alpha1.TenantIdentityFinalizer, true)
	ti.Status.ZitadelOrgID = "org-123"
	r, stub, _, c := identityFixture(t, ti, &audittest.Sink{Err: errDaemonDown})
	if _, err := reconcileTI(t, r, "acme-identity"); err == nil {
		t.Fatal("reconcile returned no error with no audit record")
	}
	if len(stub.deprovisioned) != 0 {
		t.Fatalf("the Zitadel org was deleted with no record: %v", stub.deprovisioned)
	}
	var got gibsonv1alpha1.TenantIdentity
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-identity"}, &got); err != nil {
		t.Fatalf("the finalizer was removed with no record: %v", err)
	}
}

// A failed Zitadel change writes the second record with the reason.
func TestTenantIdentity_FailedChangeIsRecorded(t *testing.T) {
	ti := withFinalizer(newTenantIdentity("acme-identity", "acme"), gibsonv1alpha1.TenantIdentityFinalizer, false)
	sink := &audittest.Sink{}
	r, stub, _, _ := identityFixture(t, ti, sink)
	stub.provisionErr = errors.New("zitadel down")
	_, _ = reconcileTI(t, r, "acme-identity")
	got := sink.Events()
	if len(got) != 2 || got[1].Result != audit.ResultFailure || got[1].Reason != "zitadel down" {
		t.Fatalf("records = %+v", got)
	}
}

// The OpenBao controller records the change before it, and changes nothing
// when the record fails (gibson#583).
func TestTenantSecretsBackend_RecordsBeforeOpenBao(t *testing.T) {
	tsb := withFinalizer(newTenantSecretsBackend("acme-secrets", "acme"), gibsonv1alpha1.TenantSecretsBackendFinalizer, false)
	sink := &audittest.Sink{}
	r, stub, _ := secretsFixture(t, tsb, sink)
	provisionedAtRecord := -1
	sink.OnEmit = func(audit.Event) { provisionedAtRecord = len(stub.provisioned) }
	if _, err := reconcileTSB(t, r, "acme-secrets"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := sink.Events()
	if len(got) != 1 || got[0].Action != audit.ActionSecretsBackendProvision || got[0].TenantID != "acme" || provisionedAtRecord != 0 {
		t.Fatalf("records = %+v, provisioned at record = %d", got, provisionedAtRecord)
	}
}

func TestTenantSecretsBackend_FailedRecordStopsTheChange(t *testing.T) {
	tsb := withFinalizer(newTenantSecretsBackend("acme-secrets", "acme"), gibsonv1alpha1.TenantSecretsBackendFinalizer, false)
	r, stub, _ := secretsFixture(t, tsb, &audittest.Sink{Err: errDaemonDown})
	if _, err := reconcileTSB(t, r, "acme-secrets"); !errors.Is(err, errDaemonDown) {
		t.Fatalf("reconcile = %v, want the audit error", err)
	}
	if len(stub.provisioned) != 0 {
		t.Fatalf("OpenBao changed with no record: %v", stub.provisioned)
	}
}

func TestTenantSecretsBackend_FailedRecordStopsTheDelete(t *testing.T) {
	tsb := withFinalizer(newTenantSecretsBackend("acme-secrets", "acme"), gibsonv1alpha1.TenantSecretsBackendFinalizer, true)
	r, stub, c := secretsFixture(t, tsb, &audittest.Sink{Err: errDaemonDown})
	if _, err := reconcileTSB(t, r, "acme-secrets"); err == nil {
		t.Fatal("reconcile returned no error with no audit record")
	}
	if len(stub.deprovisioned) != 0 {
		t.Fatalf("the OpenBao namespace was deleted with no record: %v", stub.deprovisioned)
	}
	var got gibsonv1alpha1.TenantSecretsBackend
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-secrets"}, &got); err != nil {
		t.Fatalf("the finalizer was removed with no record: %v", err)
	}
}

// A stamped resource names the human request in its records. A resource
// with no stamp names the operator only (gibson#583).
func TestSubCRDRecords_CarryTheRequestStamp(t *testing.T) {
	for name, stamp := range map[string]string{"stamped": "rec-123", "no stamp": ""} {
		t.Run(name, func(t *testing.T) {
			tsb := withFinalizer(newTenantSecretsBackend("acme-secrets", "acme"), gibsonv1alpha1.TenantSecretsBackendFinalizer, false)
			if stamp != "" {
				tsb.Annotations = map[string]string{audit.AnnotationCorrelationID: stamp}
			}
			sink := &audittest.Sink{}
			r, _, _ := secretsFixture(t, tsb, sink)
			if _, err := reconcileTSB(t, r, "acme-secrets"); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			id, ok := sink.Events()[0].Fields[audit.FieldCorrelationID]
			if stamp == "" && ok {
				t.Fatalf("an unstamped resource got correlation_id %q", id)
			}
			if stamp != "" && id != stamp {
				t.Fatalf("correlation_id = %q, want %q", id, stamp)
			}
		})
	}
}

// The Zitadel, OpenBao, data-plane and grants controllers do not start
// without the emitter.
func TestSubCRDReconcilers_RefuseToStartWithoutAudit(t *testing.T) {
	if err := (&TenantIdentityReconciler{}).SetupWithManager(nil); !errors.Is(err, saga.ErrNoAudit) {
		t.Errorf("TenantIdentityReconciler.SetupWithManager = %v, want ErrNoAudit", err)
	}
	if err := (&TenantSecretsBackendReconciler{}).SetupWithManager(nil); !errors.Is(err, saga.ErrNoAudit) {
		t.Errorf("TenantSecretsBackendReconciler.SetupWithManager = %v, want ErrNoAudit", err)
	}
	if err := (&TenantDataPlaneReconciler{}).SetupWithManager(nil); !errors.Is(err, saga.ErrNoAudit) {
		t.Errorf("TenantDataPlaneReconciler.SetupWithManager = %v, want ErrNoAudit", err)
	}
	if err := (&TenantGrantsReconciler{}).SetupWithManager(nil); !errors.Is(err, saga.ErrNoAudit) {
		t.Errorf("TenantGrantsReconciler.SetupWithManager = %v, want ErrNoAudit", err)
	}
}

func dataPlaneFixture(t *testing.T, tdp *gibsonv1alpha1.TenantDataPlane, sink *audittest.Sink) (*TenantDataPlaneReconciler, *stubProvisioner, client.Client) {
	t.Helper()
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantDataPlane{}).WithObjects(tdp).Build()
	stub := &stubProvisioner{}
	r := &TenantDataPlaneReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100),
		Audit: sink.Emitter(t), Provisioner: stub}
	return r, stub, c
}

func grantsFixture(t *testing.T, tg *gibsonv1alpha1.TenantGrants, sink *audittest.Sink) (*TenantGrantsReconciler, *stubGrantsProvisioner, client.Client) {
	t.Helper()
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantGrants{}).WithObjects(tg).Build()
	stub := &stubGrantsProvisioner{}
	r := &TenantGrantsReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100),
		Audit: sink.Emitter(t), Provisioner: stub}
	return r, stub, c
}

// The data-plane controller records the change first with the request stamp,
// writes the failure record, and changes nothing when the record fails.
func TestTenantDataPlane_AuditsEachChange(t *testing.T) {
	stamped := func(deleting bool) *gibsonv1alpha1.TenantDataPlane {
		tdp := withFinalizer(newTenantDataPlane("acme-dataplane", "acme"), gibsonv1alpha1.TenantDataPlaneFinalizer, deleting)
		tdp.Annotations = map[string]string{audit.AnnotationCorrelationID: "rec-1"}
		return tdp
	}
	t.Run("record first, with the stamp", func(t *testing.T) {
		sink := &audittest.Sink{}
		r, stub, _ := dataPlaneFixture(t, stamped(false), sink)
		at := -1
		sink.OnEmit = func(audit.Event) { at = len(stub.provisioned) }
		if _, err := reconcileTDP(t, r, "acme-dataplane"); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		got := sink.Events()
		if len(got) != 1 || got[0].Action != audit.ActionDataPlaneProvision || at != 0 ||
			got[0].Fields[audit.FieldCorrelationID] != "rec-1" {
			t.Fatalf("records = %+v, provisioned at record = %d", got, at)
		}
	})
	t.Run("failed change is recorded", func(t *testing.T) {
		sink := &audittest.Sink{}
		r, stub, _ := dataPlaneFixture(t, stamped(false), sink)
		stub.provisionErr = errors.New("postgres down")
		_, _ = reconcileTDP(t, r, "acme-dataplane")
		if got := sink.Events(); len(got) != 2 || got[1].Result != audit.ResultFailure || got[1].Reason != "postgres down" {
			t.Fatalf("records = %+v", got)
		}
	})
	t.Run("failed record stops the provision", func(t *testing.T) {
		r, stub, _ := dataPlaneFixture(t, stamped(false), &audittest.Sink{Err: errDaemonDown})
		if _, err := reconcileTDP(t, r, "acme-dataplane"); !errors.Is(err, errDaemonDown) {
			t.Fatalf("reconcile = %v, want the audit error", err)
		}
		if len(stub.provisioned) != 0 {
			t.Fatalf("the data plane changed with no record: %v", stub.provisioned)
		}
	})
	t.Run("failed record stops the delete", func(t *testing.T) {
		r, stub, c := dataPlaneFixture(t, stamped(true), &audittest.Sink{Err: errDaemonDown})
		if _, err := reconcileTDP(t, r, "acme-dataplane"); err == nil {
			t.Fatal("reconcile returned no error with no audit record")
		}
		if len(stub.deprovisioned) != 0 {
			t.Fatalf("the data plane was deleted with no record: %v", stub.deprovisioned)
		}
		var got gibsonv1alpha1.TenantDataPlane
		if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-dataplane"}, &got); err != nil {
			t.Fatalf("the finalizer was removed with no record: %v", err)
		}
	})
}

// The grants controller records each FGA change first with the request
// stamp, writes the failure record, and changes nothing when the record fails.
func TestTenantGrants_AuditsEachChange(t *testing.T) {
	stamped := func(deleting bool) *gibsonv1alpha1.TenantGrants {
		tg := withFinalizer(newTenantGrants("acme-grants", "acme"), gibsonv1alpha1.TenantGrantsFinalizer, deleting)
		tg.Annotations = map[string]string{audit.AnnotationCorrelationID: "rec-1"}
		return tg
	}
	t.Run("record first, with the stamp", func(t *testing.T) {
		sink := &audittest.Sink{}
		r, stub, _ := grantsFixture(t, stamped(false), sink)
		at := -1
		sink.OnEmit = func(audit.Event) { at = len(stub.provisioned) }
		if _, err := reconcileTG(t, r, "acme-grants"); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		got := sink.Events()
		if len(got) != 1 || got[0].Action != audit.ActionGrantsProvision || at != 0 ||
			got[0].Fields[audit.FieldCorrelationID] != "rec-1" {
			t.Fatalf("records = %+v, provisioned at record = %d", got, at)
		}
	})
	t.Run("failed change is recorded", func(t *testing.T) {
		sink := &audittest.Sink{}
		r, stub, _ := grantsFixture(t, stamped(false), sink)
		stub.provisionErr = errors.New("fga down")
		_, _ = reconcileTG(t, r, "acme-grants")
		if got := sink.Events(); len(got) != 2 || got[1].Result != audit.ResultFailure || got[1].Reason != "fga down" {
			t.Fatalf("records = %+v", got)
		}
	})
	t.Run("failed record stops the provision", func(t *testing.T) {
		r, stub, _ := grantsFixture(t, stamped(false), &audittest.Sink{Err: errDaemonDown})
		if _, err := reconcileTG(t, r, "acme-grants"); !errors.Is(err, errDaemonDown) {
			t.Fatalf("reconcile = %v, want the audit error", err)
		}
		if len(stub.provisioned) != 0 {
			t.Fatalf("FGA changed with no record: %v", stub.provisioned)
		}
	})
	t.Run("failed record stops the delete", func(t *testing.T) {
		r, stub, c := grantsFixture(t, stamped(true), &audittest.Sink{Err: errDaemonDown})
		if _, err := reconcileTG(t, r, "acme-grants"); err == nil {
			t.Fatal("reconcile returned no error with no audit record")
		}
		if len(stub.deprovisioned) != 0 {
			t.Fatalf("the grants were deleted with no record: %v", stub.deprovisioned)
		}
		var got gibsonv1alpha1.TenantGrants
		if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-grants"}, &got); err != nil {
			t.Fatalf("the finalizer was removed with no record: %v", err)
		}
	})
}
