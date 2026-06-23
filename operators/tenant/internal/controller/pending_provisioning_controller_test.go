/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

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

// stubDaemon is a PendingProvisioningClient that returns a fixed queue and
// records acks.
type stubDaemon struct {
	pending  []provision.PendingTenant
	listErr  error
	ackErr   error
	acked    []string
	ackCalls int
}

func (s *stubDaemon) ListPendingTenantProvisioning(_ context.Context) ([]provision.PendingTenant, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.pending, nil
}

func (s *stubDaemon) AckTenantProvisioned(_ context.Context, tenantID string) error {
	s.ackCalls++
	if s.ackErr != nil {
		return s.ackErr
	}
	s.acked = append(s.acked, tenantID)
	return nil
}

func newRunnable(t *testing.T, c client.Client, d PendingProvisioningClient) *PendingProvisioningRunnable {
	t.Helper()
	return &PendingProvisioningRunnable{Client: c, Daemon: d}
}

func TestDrain_CreatesTenantCRAndAcks(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	d := &stubDaemon{pending: []provision.PendingTenant{{
		TenantID:         "acme",
		OwnerUserID:      "u-1",
		OwnerEmail:       "owner@acme.test",
		WorkspaceName:    "Acme Inc",
		Tier:             "team",
		StripeCustomerID: "cus_123",
	}}}

	r := newRunnable(t, c, d)
	if err := r.drain(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), client.ObjectKey{Name: "acme"}, &got); err != nil {
		t.Fatalf("expected Tenant CR created: %v", err)
	}
	if got.Spec.DisplayName != "Acme Inc" {
		t.Errorf("displayName: got %q", got.Spec.DisplayName)
	}
	if got.Spec.Owner != "owner@acme.test" {
		t.Errorf("owner: got %q", got.Spec.Owner)
	}
	if string(got.Spec.Tier) != "team" {
		t.Errorf("tier: got %q", got.Spec.Tier)
	}
	if got.Annotations[AnnotationStripeCustomerID] != "cus_123" {
		t.Errorf("stripe annotation: got %q", got.Annotations[AnnotationStripeCustomerID])
	}
	if len(d.acked) != 1 || d.acked[0] != "acme" {
		t.Errorf("expected acme acked, got %v", d.acked)
	}
}

func TestDrain_NoStripeCustomer_NoAnnotation(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	d := &stubDaemon{pending: []provision.PendingTenant{{
		TenantID:      "globex",
		OwnerEmail:    "ceo@globex.test",
		WorkspaceName: "Globex",
		Tier:          "org",
	}}}

	if err := newRunnable(t, c, d).drain(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), client.ObjectKey{Name: "globex"}, &got); err != nil {
		t.Fatalf("expected Tenant CR: %v", err)
	}
	if _, ok := got.Annotations[AnnotationStripeCustomerID]; ok {
		t.Errorf("expected no stripe annotation when stripe_customer_id empty")
	}
}

func TestDrain_ExistingTenant_NoDoubleCreateButAcks(t *testing.T) {
	scheme := setupScheme(t)
	// Seed an existing Tenant CR with a DIFFERENT spec so we can prove the
	// runnable does NOT overwrite it (no double-create / no update).
	existing := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: "Original Acme",
			Owner:       "original@acme.test",
			Tier:        "enterprise",
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()
	d := &stubDaemon{pending: []provision.PendingTenant{{
		TenantID:      "acme",
		OwnerEmail:    "new@acme.test",
		WorkspaceName: "New Acme",
		Tier:          "team",
	}}}

	if err := newRunnable(t, c, d).drain(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), client.ObjectKey{Name: "acme"}, &got); err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	// Spec must be the ORIGINAL — the runnable saw an existing CR and did not
	// re-create or mutate it.
	if got.Spec.DisplayName != "Original Acme" || string(got.Spec.Tier) != "enterprise" {
		t.Errorf("existing Tenant CR was overwritten: %+v", got.Spec)
	}
	// But the record is still acked so it leaves the queue (recovers from a
	// crash between create and ack).
	if len(d.acked) != 1 || d.acked[0] != "acme" {
		t.Errorf("expected acme acked even though CR existed, got %v", d.acked)
	}
}

func TestReconcileOne_EmptyTenantID_NoAck(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	d := &stubDaemon{}
	err := newRunnable(t, c, d).reconcileOne(context.Background(), provision.PendingTenant{})
	if err == nil {
		t.Fatalf("expected error for empty tenant_id")
	}
	if d.ackCalls != 0 {
		t.Errorf("expected no ack for invalid record, got %d", d.ackCalls)
	}
}

func TestReconcileOne_AckFails_RecordStaysPending(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	d := &stubDaemon{ackErr: errors.New("daemon unreachable")}

	err := newRunnable(t, c, d).reconcileOne(context.Background(), provision.PendingTenant{
		TenantID:      "acme",
		OwnerEmail:    "owner@acme.test",
		WorkspaceName: "Acme",
		Tier:          "team",
	})
	if err == nil {
		t.Fatalf("expected error when ack fails")
	}
	// CR was created (so a subsequent retry will no-op the create) but the ack
	// failure surfaces so the record stays pending for retry.
	var got gibsonv1alpha1.Tenant
	if getErr := c.Get(context.Background(), client.ObjectKey{Name: "acme"}, &got); getErr != nil {
		t.Errorf("expected CR created even though ack failed: %v", getErr)
	}
}

func TestDrain_ListError_Propagates(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	d := &stubDaemon{listErr: errors.New("boom")}
	if err := newRunnable(t, c, d).drain(context.Background()); err == nil {
		t.Fatalf("expected drain to propagate list error")
	}
}

func TestDrain_OneBadRecordDoesNotAbortOthers(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	// First record is invalid (empty tenant_id); second is valid. The valid one
	// must still be created + acked.
	d := &stubDaemon{pending: []provision.PendingTenant{
		{TenantID: ""},
		{TenantID: "globex", OwnerEmail: "ceo@globex.test", WorkspaceName: "Globex", Tier: "org"},
	}}
	if err := newRunnable(t, c, d).drain(context.Background()); err != nil {
		t.Fatalf("drain should not fail on a single bad record: %v", err)
	}
	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), client.ObjectKey{Name: "globex"}, &got); err != nil {
		t.Fatalf("expected globex created despite bad first record: %v", err)
	}
	if len(d.acked) != 1 || d.acked[0] != "globex" {
		t.Errorf("expected only globex acked, got %v", d.acked)
	}
}
