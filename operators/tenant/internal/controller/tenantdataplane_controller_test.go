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
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// stubProvisioner is a fake dataplane.Provisioner that records the tenant ids
// it was asked to provision/deprovision and can be configured to fail.
type stubProvisioner struct {
	provisionErr   error
	deprovisionErr error
	provisioned    []string
	deprovisioned  []string
}

func (s *stubProvisioner) Provision(_ context.Context, tenantID string) error {
	s.provisioned = append(s.provisioned, tenantID)
	return s.provisionErr
}

func (s *stubProvisioner) Deprovision(_ context.Context, tenantID string) error {
	s.deprovisioned = append(s.deprovisioned, tenantID)
	return s.deprovisionErr
}

func newTenantDataPlane(name, tenantID string) *gibsonv1alpha1.TenantDataPlane {
	return &gibsonv1alpha1.TenantDataPlane{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tenant-acme"},
		Spec: gibsonv1alpha1.TenantDataPlaneSpec{
			TenantID: tenantID,
			Stores: gibsonv1alpha1.TenantDataPlaneStores{
				Postgres: true, Neo4j: true, Redis: true, Vector: true,
			},
		},
	}
}

func reconcileTDP(t *testing.T, r *TenantDataPlaneReconciler, name string) (ctrl.Result, error) {
	t.Helper()
	return r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "tenant-acme", Name: name},
	})
}

// First reconcile adds the finalizer; second provisions and marks Ready.
func TestTenantDataPlane_ProvisionsAndMarksReady(t *testing.T) {
	scheme := setupScheme(t)
	tdp := newTenantDataPlane("acme-dp", "acme")
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantDataPlane{}).
		WithObjects(tdp).
		Build()

	stub := &stubProvisioner{}
	r := &TenantDataPlaneReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	// Pass 1: finalizer added, requeue.
	if _, err := reconcileTDP(t, r, "acme-dp"); err != nil {
		t.Fatalf("reconcile pass 1: %v", err)
	}
	var afterFinalizer gibsonv1alpha1.TenantDataPlane
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-dp"}, &afterFinalizer); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !controllerutil.ContainsFinalizer(&afterFinalizer, gibsonv1alpha1.TenantDataPlaneFinalizer) {
		t.Fatalf("expected finalizer added on pass 1")
	}
	if len(stub.provisioned) != 0 {
		t.Fatalf("provision must not run before finalizer is set, got %v", stub.provisioned)
	}

	// Pass 2: provision runs, status becomes Ready.
	if _, err := reconcileTDP(t, r, "acme-dp"); err != nil {
		t.Fatalf("reconcile pass 2: %v", err)
	}
	if len(stub.provisioned) != 1 || stub.provisioned[0] != "acme" {
		t.Fatalf("want Provision(acme) once, got %v", stub.provisioned)
	}

	var got gibsonv1alpha1.TenantDataPlane
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-dp"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.Status.Ready {
		t.Fatalf("want Ready=true, got %+v", got.Status)
	}
	if got.Status.Phase != gibsonv1alpha1.TenantDataPlanePhaseReady {
		t.Fatalf("want phase Ready, got %q", got.Status.Phase)
	}
	// postgres, neo4j, redis, vector, kek
	if len(got.Status.Stores) != 5 {
		t.Fatalf("want 5 store conditions, got %d: %+v", len(got.Status.Stores), got.Status.Stores)
	}
	cond := findCond(got.Status.Conditions, gibsonv1alpha1.ConditionDataPlaneReady)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("want Ready condition True, got %+v", cond)
	}
}

// A provision failure surfaces an error (so controller-runtime backs off) and
// records Failed status without mutating spec.
func TestTenantDataPlane_ProvisionFailureSetsFailed(t *testing.T) {
	scheme := setupScheme(t)
	tdp := newTenantDataPlane("acme-dp", "acme")
	controllerutil.AddFinalizer(tdp, gibsonv1alpha1.TenantDataPlaneFinalizer)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantDataPlane{}).
		WithObjects(tdp).
		Build()

	stub := &stubProvisioner{provisionErr: errors.New("cnpg cluster not ready")}
	r := &TenantDataPlaneReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	_, err := reconcileTDP(t, r, "acme-dp")
	if err == nil {
		t.Fatalf("want error from failed provision so controller-runtime requeues")
	}

	var got gibsonv1alpha1.TenantDataPlane
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-dp"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status.Phase != gibsonv1alpha1.TenantDataPlanePhaseFailed {
		t.Fatalf("want phase Failed, got %q", got.Status.Phase)
	}
	if got.Status.Ready {
		t.Fatalf("want Ready=false on failure")
	}
	if got.Status.LastError == "" {
		t.Fatalf("want LastError populated on failure")
	}
}

// Deletion runs the idempotent Deprovision and drops the finalizer.
func TestTenantDataPlane_FinalizerTeardown(t *testing.T) {
	scheme := setupScheme(t)
	tdp := newTenantDataPlane("acme-dp", "acme")
	controllerutil.AddFinalizer(tdp, gibsonv1alpha1.TenantDataPlaneFinalizer)
	now := metav1.Now()
	tdp.DeletionTimestamp = &now
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantDataPlane{}).
		WithObjects(tdp).
		Build()

	stub := &stubProvisioner{}
	r := &TenantDataPlaneReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	if _, err := reconcileTDP(t, r, "acme-dp"); err != nil {
		t.Fatalf("reconcile delete: %v", err)
	}
	if len(stub.deprovisioned) != 1 || stub.deprovisioned[0] != "acme" {
		t.Fatalf("want Deprovision(acme), got %v", stub.deprovisioned)
	}
	// After finalizer removal the fake client GCs the object.
	var got gibsonv1alpha1.TenantDataPlane
	err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-dp"}, &got)
	if err == nil {
		t.Fatalf("want object gone after finalizer removal, still present: %+v", got)
	}
}

// A NotFound from Deprovision (stores already gone) is treated as success.
func TestTenantDataPlane_TeardownNotFoundIsSuccess(t *testing.T) {
	scheme := setupScheme(t)
	tdp := newTenantDataPlane("acme-dp", "acme")
	controllerutil.AddFinalizer(tdp, gibsonv1alpha1.TenantDataPlaneFinalizer)
	now := metav1.Now()
	tdp.DeletionTimestamp = &now
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantDataPlane{}).
		WithObjects(tdp).
		Build()

	stub := &stubProvisioner{deprovisionErr: clients.ErrNotFound}
	r := &TenantDataPlaneReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub}

	if _, err := reconcileTDP(t, r, "acme-dp"); err != nil {
		t.Fatalf("NotFound from deprovision must not error: %v", err)
	}
	var got gibsonv1alpha1.TenantDataPlane
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-dp"}, &got); err == nil {
		t.Fatalf("want object gone after teardown, still present: %+v", got)
	}
}

func findCond(conds []metav1.Condition, t string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == t {
			return &conds[i]
		}
	}
	return nil
}
