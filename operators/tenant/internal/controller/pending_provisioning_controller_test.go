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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

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

func TestDrain_CreatesFoundingOwnerMember(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	d := &stubDaemon{pending: []provision.PendingTenant{{
		TenantID:    "acme",
		OwnerUserID: "u-1",
		OwnerEmail:  "owner@acme.test",
		Tier:        "team",
	}}}

	if err := newRunnable(t, c, d).drain(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	var member gibsonv1alpha1.TenantMember
	key := client.ObjectKey{Namespace: "tenant-acme", Name: "owner-acme-test-owner"}
	if err := c.Get(context.Background(), key, &member); err != nil {
		t.Fatalf("expected founding-owner TenantMember created: %v", err)
	}
	if member.Spec.Email != "owner@acme.test" {
		t.Errorf("email: got %q", member.Spec.Email)
	}
	if member.Spec.Role != gibsonv1alpha1.MemberRoleOwner {
		t.Errorf("role: got %q, want owner", member.Spec.Role)
	}
	if member.Spec.TenantRef.Name != "acme" {
		t.Errorf("tenantRef: got %q", member.Spec.TenantRef.Name)
	}
	if member.Spec.AcceptedByUserID != "u-1" {
		t.Errorf("acceptedByUserId: got %q (founding owner must be pre-accepted)", member.Spec.AcceptedByUserID)
	}
	if len(d.acked) != 1 {
		t.Errorf("expected ack after both CR + member created, got %v", d.acked)
	}
}

func TestEnsureFoundingOwnerMember_Idempotent(t *testing.T) {
	scheme := setupScheme(t)
	existing := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{Name: "owner-acme-test-owner", Namespace: "tenant-acme"},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email: "owner@acme.test", Role: gibsonv1alpha1.MemberRoleOwner,
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()
	r := newRunnable(t, c, &stubDaemon{})
	err := r.ensureFoundingOwnerMember(context.Background(), provision.PendingTenant{
		TenantID: "acme", OwnerEmail: "owner@acme.test", OwnerUserID: "u-1",
	})
	if err != nil {
		t.Fatalf("expected no-op for existing member, got %v", err)
	}
}

func TestFoundingOwnerMemberName_Deterministic(t *testing.T) {
	cases := map[string]string{
		"owner@acme.test":       "owner-acme-test-owner",
		"Jane.Doe+x@Globex.COM": "jane-doe-x-globex-com-owner",
		"@@@":                   "owner-owner",
	}
	for in, want := range cases {
		if got := foundingOwnerMemberName(in); got != want {
			t.Errorf("foundingOwnerMemberName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReconcileOne_MemberCreateFails_NoAck(t *testing.T) {
	scheme := setupScheme(t)
	// Simulate the tenant namespace not existing yet: Create on the TenantMember
	// fails, so the record must NOT be acked (it retries next drain pass).
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*gibsonv1alpha1.TenantMember); ok {
					return apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, "tenant-acme")
				}
				return cl.Create(ctx, obj, opts...)
			},
		}).Build()
	d := &stubDaemon{}
	err := newRunnable(t, c, d).reconcileOne(context.Background(), provision.PendingTenant{
		TenantID: "acme", OwnerEmail: "owner@acme.test", OwnerUserID: "u-1", Tier: "team",
	})
	if err == nil {
		t.Fatal("expected error when founding-owner member create fails (namespace not ready)")
	}
	if d.ackCalls != 0 {
		t.Errorf("must NOT ack when the founding-owner member could not be created, got %d acks", d.ackCalls)
	}
	// The Tenant CR was still created (idempotent on retry).
	var tn gibsonv1alpha1.Tenant
	if getErr := c.Get(context.Background(), client.ObjectKey{Name: "acme"}, &tn); getErr != nil {
		t.Errorf("expected Tenant CR created even though member create failed: %v", getErr)
	}
}

func TestEnsureFoundingOwnerMember_EmptyEmail_Errors(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := newRunnable(t, c, &stubDaemon{})
	if err := r.ensureFoundingOwnerMember(context.Background(), provision.PendingTenant{TenantID: "acme"}); err == nil {
		t.Fatal("expected error for empty owner_email")
	}
}
