// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

// stubAdminDaemon is a TenantAdminOpsClient that returns a fixed queue and
// records acks.
type stubAdminDaemon struct {
	ops     []provision.TenantAdminOp
	listErr error
	ackErr  error
	acked   []string
}

func (s *stubAdminDaemon) ListPendingTenantOps(_ context.Context) ([]provision.TenantAdminOp, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.ops, nil
}

func (s *stubAdminDaemon) AckTenantOp(_ context.Context, opID string) error {
	if s.ackErr != nil {
		return s.ackErr
	}
	s.acked = append(s.acked, opID)
	return nil
}

func newAdminOpsRunnable(c client.Client, d TenantAdminOpsClient) *TenantAdminOpsRunnable {
	return &TenantAdminOpsRunnable{Client: c, Daemon: d}
}

func TestAdminDrain_Provision_CreatesTenantCRAndAcks(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	d := &stubAdminDaemon{ops: []provision.TenantAdminOp{{
		OpID:           "op-1",
		TenantID:       "acme",
		OpType:         "provision",
		DisplayName:    "Acme Inc",
		DisplayNameSet: true,
		OwnerEmail:     "owner@acme.test",
		Tier:           "team",
		TierSet:        true,
	}}}

	r := newAdminOpsRunnable(c, d)
	if err := r.drain(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), client.ObjectKey{Name: "acme"}, &got); err != nil {
		t.Fatalf("expected Tenant CR created: %v", err)
	}
	if got.Spec.DisplayName != "Acme Inc" || got.Spec.Owner != "owner@acme.test" || string(got.Spec.Tier) != "team" {
		t.Errorf("unexpected spec: %+v", got.Spec)
	}
	if len(d.acked) != 1 || d.acked[0] != "op-1" {
		t.Errorf("expected op-1 acked, got %v", d.acked)
	}
}

func TestAdminDrain_Provision_Idempotent_ExistingCRNoOp(t *testing.T) {
	scheme := setupScheme(t)
	existing := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
		Spec:       gibsonv1alpha1.TenantSpec{DisplayName: "Old", Owner: "old@acme.test", Tier: "org"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()
	d := &stubAdminDaemon{ops: []provision.TenantAdminOp{{
		OpID: "op-1", TenantID: "acme", OpType: "provision",
		DisplayName: "New", DisplayNameSet: true, OwnerEmail: "new@acme.test", Tier: "team", TierSet: true,
	}}}

	r := newAdminOpsRunnable(c, d)
	if err := r.drain(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), client.ObjectKey{Name: "acme"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	// Provision must NOT clobber an existing CR.
	if got.Spec.DisplayName != "Old" || string(got.Spec.Tier) != "org" {
		t.Errorf("provision clobbered existing CR: %+v", got.Spec)
	}
	if len(d.acked) != 1 || d.acked[0] != "op-1" {
		t.Errorf("expected op-1 acked (idempotent), got %v", d.acked)
	}
}

func TestAdminDrain_Update_PatchesMarkedFieldsOnly(t *testing.T) {
	scheme := setupScheme(t)
	existing := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
		Spec:       gibsonv1alpha1.TenantSpec{DisplayName: "Acme Inc", Owner: "owner@acme.test", Tier: "team"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()
	// tier-only update: tier_set=true, display_name_set=false.
	d := &stubAdminDaemon{ops: []provision.TenantAdminOp{{
		OpID: "op-2", TenantID: "acme", OpType: "update",
		Tier: "org", TierSet: true, DisplayName: "IGNORED", DisplayNameSet: false,
	}}}

	r := newAdminOpsRunnable(c, d)
	if err := r.drain(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), client.ObjectKey{Name: "acme"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got.Spec.Tier) != "org" {
		t.Errorf("tier not patched: %q", got.Spec.Tier)
	}
	// display_name_set=false → displayName must be untouched.
	if got.Spec.DisplayName != "Acme Inc" {
		t.Errorf("displayName clobbered by unset field: %q", got.Spec.DisplayName)
	}
	if len(d.acked) != 1 || d.acked[0] != "op-2" {
		t.Errorf("expected op-2 acked, got %v", d.acked)
	}
}

func TestAdminDrain_Update_MissingCR_NoOpAcks(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	d := &stubAdminDaemon{ops: []provision.TenantAdminOp{{
		OpID: "op-2", TenantID: "ghost", OpType: "update", Tier: "org", TierSet: true,
	}}}

	r := newAdminOpsRunnable(c, d)
	if err := r.drain(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(d.acked) != 1 || d.acked[0] != "op-2" {
		t.Errorf("expected op-2 acked even with missing CR, got %v", d.acked)
	}
}

func TestAdminDrain_Delete_DeletesCRAndAcks(t *testing.T) {
	scheme := setupScheme(t)
	existing := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
		Spec:       gibsonv1alpha1.TenantSpec{DisplayName: "Acme Inc", Owner: "owner@acme.test", Tier: "team"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()
	d := &stubAdminDaemon{ops: []provision.TenantAdminOp{{
		OpID: "op-3", TenantID: "acme", OpType: "delete",
	}}}

	r := newAdminOpsRunnable(c, d)
	if err := r.drain(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	var got gibsonv1alpha1.Tenant
	err := c.Get(context.Background(), client.ObjectKey{Name: "acme"}, &got)
	if err == nil {
		t.Errorf("expected Tenant CR deleted, but it still exists")
	}
	if len(d.acked) != 1 || d.acked[0] != "op-3" {
		t.Errorf("expected op-3 acked, got %v", d.acked)
	}
}

func TestAdminDrain_Delete_AlreadyAbsent_NoOpAcks(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	d := &stubAdminDaemon{ops: []provision.TenantAdminOp{{
		OpID: "op-3", TenantID: "ghost", OpType: "delete",
	}}}

	r := newAdminOpsRunnable(c, d)
	if err := r.drain(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(d.acked) != 1 || d.acked[0] != "op-3" {
		t.Errorf("expected op-3 acked even when CR absent, got %v", d.acked)
	}
}

func TestAdminDrain_PerOpErrorIsolation(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	// First op has empty op_id (errors before apply); second is a valid provision.
	d := &stubAdminDaemon{ops: []provision.TenantAdminOp{
		{OpID: "", TenantID: "bad", OpType: "provision", DisplayName: "Bad", OwnerEmail: "b@x.test", Tier: "team"},
		{OpID: "op-ok", TenantID: "good", OpType: "provision", DisplayName: "Good", OwnerEmail: "g@x.test", Tier: "team", DisplayNameSet: true, TierSet: true},
	}}

	r := newAdminOpsRunnable(c, d)
	if err := r.drain(context.Background()); err != nil {
		t.Fatalf("drain should not fail the pass on a bad op: %v", err)
	}

	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), client.ObjectKey{Name: "good"}, &got); err != nil {
		t.Fatalf("expected good Tenant CR created despite bad op: %v", err)
	}
	if len(d.acked) != 1 || d.acked[0] != "op-ok" {
		t.Errorf("expected only op-ok acked, got %v", d.acked)
	}
}

func TestAdminDrain_UnknownOpType_AcksToUnwedge(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	d := &stubAdminDaemon{ops: []provision.TenantAdminOp{{
		OpID: "op-x", TenantID: "acme", OpType: "bogus",
	}}}

	r := newAdminOpsRunnable(c, d)
	if err := r.drain(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(d.acked) != 1 || d.acked[0] != "op-x" {
		t.Errorf("expected unknown-op-type acked to unwedge queue, got %v", d.acked)
	}
}

func TestAdminDrain_ListError_Propagates(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	d := &stubAdminDaemon{listErr: errors.New("daemon unreachable")}

	r := newAdminOpsRunnable(c, d)
	if err := r.drain(context.Background()); err == nil {
		t.Errorf("expected drain to surface the list error")
	}
}
