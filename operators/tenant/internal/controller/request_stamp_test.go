// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

// stampOf returns the correlation stamp of the Tenant acme, and whether it
// has one.
func stampOf(t *testing.T, c client.Client) (string, bool) {
	t.Helper()
	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), client.ObjectKey{Name: "acme"}, &got); err != nil {
		t.Fatalf("get Tenant: %v", err)
	}
	id, ok := got.Annotations[audit.AnnotationCorrelationID]
	return id, ok
}

// A queued signup that has a daemon audit record stamps its id on the new
// Tenant. A queue entry with no record (the first-tenant seed) leaves no
// stamp, so the operator is the only actor of the records (gibson#583).
func TestPendingDrain_StampsTheRequestRecord(t *testing.T) {
	for name, recordID := range map[string]string{"recorded request": "rec-1", "no record": ""} {
		t.Run(name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(setupScheme(t)).Build()
			d := &stubDaemon{pending: []provision.PendingTenant{{
				TenantID: "acme", OwnerEmail: "owner@acme.test", WorkspaceName: "Acme", Tier: "team",
				AuditRecordID: recordID,
			}}}
			if err := newRunnable(t, c, d).drain(context.Background()); err != nil {
				t.Fatalf("drain: %v", err)
			}
			id, ok := stampOf(t, c)
			if recordID == "" && ok {
				t.Fatalf("an unrecorded entry stamped %q", id)
			}
			if recordID != "" && id != recordID {
				t.Fatalf("stamp = %q, want %q", id, recordID)
			}
		})
	}
}

// Each admin op stamps the id of its request record on the Tenant before the
// change, so the saga records of the change name the admin.
func TestAdminDrain_StampsTheRequestRecord(t *testing.T) {
	newTenant := func() *gibsonv1alpha1.Tenant {
		return &gibsonv1alpha1.Tenant{
			ObjectMeta: metav1.ObjectMeta{
				Name: "acme", Finalizers: []string{gibsonv1alpha1.TenantFinalizer},
				Annotations: map[string]string{audit.AnnotationCorrelationID: "rec-old"},
			},
			Spec: gibsonv1alpha1.TenantSpec{DisplayName: "Acme", Owner: "owner@acme.test", Tier: "team"},
		}
	}
	cases := map[string]struct {
		op       provision.TenantAdminOp
		existing bool
		want     string
	}{
		"provision": {op: provision.TenantAdminOp{OpID: "op-1", TenantID: "acme", OpType: "provision",
			DisplayName: "Acme", DisplayNameSet: true, OwnerEmail: "owner@acme.test", Tier: "team", TierSet: true,
			AuditRecordID: "rec-p"}, want: "rec-p"},
		"update": {op: provision.TenantAdminOp{OpID: "op-2", TenantID: "acme", OpType: "update",
			Tier: "org", TierSet: true, AuditRecordID: "rec-u"}, existing: true, want: "rec-u"},
		"delete": {op: provision.TenantAdminOp{OpID: "op-3", TenantID: "acme", OpType: "delete",
			AuditRecordID: "rec-d"}, existing: true, want: "rec-d"},
		"update with no record": {op: provision.TenantAdminOp{OpID: "op-4", TenantID: "acme", OpType: "update",
			Tier: "org", TierSet: true}, existing: true, want: ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			b := fake.NewClientBuilder().WithScheme(setupScheme(t))
			if tc.existing {
				b = b.WithObjects(newTenant())
			}
			c := b.Build()
			d := &stubAdminDaemon{ops: []provision.TenantAdminOp{tc.op}}
			if err := newAdminOpsRunnable(c, d).drain(context.Background()); err != nil {
				t.Fatalf("drain: %v", err)
			}
			id, ok := stampOf(t, c)
			if tc.want == "" && ok {
				t.Fatalf("an unrecorded op left the stamp %q", id)
			}
			if tc.want != "" && id != tc.want {
				t.Fatalf("stamp = %q, want %q", id, tc.want)
			}
		})
	}
}

// A child of a stamped Tenant carries the same stamp, so the Zitadel and
// OpenBao records of the child name the request of the Tenant.
func TestNewChild_CarriesTheTenantStamp(t *testing.T) {
	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme",
		Annotations: map[string]string{audit.AnnotationCorrelationID: "rec-1"}}}
	tenant.Status.Namespace = "tenant-acme"
	for _, kind := range []childKind{childIdentity, childSecretsBackend} {
		if got := audit.CorrelationIDOf(newChild(kind, tenant)); got != "rec-1" {
			t.Errorf("%s stamp = %q, want rec-1", childKindName(kind), got)
		}
	}
	tenant.Annotations = nil
	if got := newChild(childIdentity, tenant).GetAnnotations(); got != nil {
		t.Errorf("a child of an unstamped Tenant got annotations %v", got)
	}
}
