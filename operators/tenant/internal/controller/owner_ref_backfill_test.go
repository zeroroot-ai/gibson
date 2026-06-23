/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

const testTenantUID = "tuid-backfill-test"

func tenantNamespaceWithAnnot(t *testing.T) *corev1.Namespace {
	t.Helper()
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tenant-acme",
			Annotations: map[string]string{
				AnnotationOwnerTenantUID:  testTenantUID,
				AnnotationOwnerTenantName: "acme",
			},
		},
	}
}

func tenantNamespaceNoAnnot(t *testing.T) *corev1.Namespace {
	t.Helper()
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "random-ns"},
	}
}

func seededTenant(t *testing.T) *gibsonv1alpha1.Tenant {
	t.Helper()
	return &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme", UID: types.UID(testTenantUID)},
	}
}

// --- AgentEnrollment backfill -----------------------------------------------

func TestAgentEnrollment_OwnerRefBackfill(t *testing.T) {
	scheme := setupScheme(t)
	ae := &gibsonv1alpha1.AgentEnrollment{
		ObjectMeta: metav1.ObjectMeta{Name: "scanner-01", Namespace: "tenant-acme"},
		Spec:       gibsonv1alpha1.AgentEnrollmentSpec{AgentName: "breach-checker", Mode: "autonomous"},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.AgentEnrollment{}).
		WithObjects(tenantNamespaceWithAnnot(t), seededTenant(t), ae).
		Build()

	r := &AgentEnrollmentReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100)}
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "tenant-acme", Name: "scanner-01"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got gibsonv1alpha1.AgentEnrollment
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "scanner-01"}, &got); err != nil {
		t.Fatalf("get ae: %v", err)
	}
	if len(got.OwnerReferences) != 1 || got.OwnerReferences[0].Name != "acme" {
		t.Fatalf("want 1 ownerRef to Tenant/acme, got %+v", got.OwnerReferences)
	}
}

func TestAgentEnrollment_NoBackfillWhenAnnotationMissing(t *testing.T) {
	scheme := setupScheme(t)
	ae := &gibsonv1alpha1.AgentEnrollment{
		ObjectMeta: metav1.ObjectMeta{Name: "scanner-01", Namespace: "random-ns"},
		Spec:       gibsonv1alpha1.AgentEnrollmentSpec{AgentName: "x", Mode: "autonomous"},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.AgentEnrollment{}).
		WithObjects(tenantNamespaceNoAnnot(t), ae).
		Build()

	r := &AgentEnrollmentReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100)}
	_, _ = r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "random-ns", Name: "scanner-01"},
	})
	var got gibsonv1alpha1.AgentEnrollment
	_ = c.Get(context.Background(), types.NamespacedName{Namespace: "random-ns", Name: "scanner-01"}, &got)
	if len(got.OwnerReferences) != 0 {
		t.Fatalf("want no ownerRef when annotation missing, got %+v", got.OwnerReferences)
	}
}

// --- TenantMember backfill --------------------------------------------------

func TestTenantMember_OwnerRefBackfill(t *testing.T) {
	scheme := setupScheme(t)
	tm := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{Name: "invite-abc123", Namespace: "tenant-acme"},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:     "b@example.com",
			Role:      "member",
			TenantRef: corev1.LocalObjectReference{Name: "acme"},
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantMember{}).
		WithObjects(tenantNamespaceWithAnnot(t), seededTenant(t), tm).
		Build()

	r := &TenantMemberReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), StatusReporter: noopTenantStatusReporter{}}
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "tenant-acme", Name: "invite-abc123"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got gibsonv1alpha1.TenantMember
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "invite-abc123"}, &got); err != nil {
		t.Fatalf("get tm: %v", err)
	}
	if len(got.OwnerReferences) != 1 || got.OwnerReferences[0].Name != "acme" {
		t.Fatalf("want 1 ownerRef to Tenant/acme, got %+v", got.OwnerReferences)
	}
}
