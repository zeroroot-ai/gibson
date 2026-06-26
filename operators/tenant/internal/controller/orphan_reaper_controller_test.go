// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

func newTerminatingNamespace(deletedAgo time.Duration, name string) *corev1.Namespace {
	ts := metav1.NewTime(time.Now().Add(-deletedAgo))
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			DeletionTimestamp: &ts,
			Finalizers:        []string{"kubernetes"},
			Annotations: map[string]string{
				AnnotationOwnerTenantName: strings.TrimPrefix(name, "tenant-"),
			},
		},
	}
}

// newChildWithFinalizer returns a Gibson child object in the canonical
// fixture namespace ("tenant-acme"). The namespace was previously a
// parameter; every caller passed "tenant-acme", so it's inlined.
func newChildWithFinalizer(kind, name, finalizer string) client.Object {
	const namespace = "tenant-acme"
	switch kind {
	case "AgentEnrollment":
		return &gibsonv1alpha1.AgentEnrollment{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: namespace,
				Finalizers: []string{finalizer},
			},
		}
	case "TenantMember":
		return &gibsonv1alpha1.TenantMember{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: namespace,
				Finalizers: []string{finalizer},
			},
		}
	}
	return nil
}

func TestReaper_NoOpWhenNotTenantNamespace(t *testing.T) {
	scheme := setupScheme(t)
	ns := newTerminatingNamespace(10*time.Minute, "random-ns")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns).Build()
	r := &OrphanReaperReconciler{Client: c, Recorder: events.NewFakeRecorder(10), GracePeriodSeconds: 300, Enabled: true}
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "random-ns"}})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("expected no requeue for non-tenant ns, got %v", res.RequeueAfter)
	}
}

func TestReaper_RequeueWithinGracePeriod(t *testing.T) {
	scheme := setupScheme(t)
	ns := newTerminatingNamespace(30*time.Second, "tenant-acme") // well under 300s grace
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns).Build()
	r := &OrphanReaperReconciler{Client: c, Recorder: events.NewFakeRecorder(10), GracePeriodSeconds: 300, Enabled: true}
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "tenant-acme"}})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.RequeueAfter < time.Second {
		t.Fatalf("expected positive requeue (grace period), got %v", res.RequeueAfter)
	}
}

func TestReaper_SkipWhenParentTenantExists(t *testing.T) {
	scheme := setupScheme(t)
	ns := newTerminatingNamespace(10*time.Minute, "tenant-acme")
	// Parent Tenant still exists.
	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme", UID: "tuid"}}
	ae := newChildWithFinalizer("AgentEnrollment", "scanner-01", gibsonv1alpha1.AgentEnrollmentFinalizer)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, tenant, ae).Build()
	rec := events.NewFakeRecorder(10)
	r := &OrphanReaperReconciler{Client: c, Recorder: rec, GracePeriodSeconds: 300, Enabled: true}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "tenant-acme"}})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// Child should still have the finalizer — parent exists, reaper deferred.
	var got gibsonv1alpha1.AgentEnrollment
	if err := c.Get(context.Background(), types.NamespacedName{Name: "scanner-01", Namespace: "tenant-acme"}, &got); err != nil {
		t.Fatalf("get ae: %v", err)
	}
	if len(got.Finalizers) == 0 {
		t.Fatalf("reaper should NOT strip while parent Tenant exists")
	}
}

func TestReaper_StripsAllowlistedFinalizers(t *testing.T) {
	scheme := setupScheme(t)
	ns := newTerminatingNamespace(10*time.Minute, "tenant-acme")
	ae := newChildWithFinalizer("AgentEnrollment", "scanner-01", gibsonv1alpha1.AgentEnrollmentFinalizer)
	tm := newChildWithFinalizer("TenantMember", "invite-1", gibsonv1alpha1.TenantMemberFinalizer)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, ae, tm).Build()
	rec := events.NewFakeRecorder(20)
	r := &OrphanReaperReconciler{Client: c, Recorder: rec, GracePeriodSeconds: 300, Enabled: true}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "tenant-acme"}})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	var ae2 gibsonv1alpha1.AgentEnrollment
	_ = c.Get(context.Background(), types.NamespacedName{Name: "scanner-01", Namespace: "tenant-acme"}, &ae2)
	if len(ae2.Finalizers) != 0 {
		t.Errorf("ae finalizer not stripped: %v", ae2.Finalizers)
	}
	var tm2 gibsonv1alpha1.TenantMember
	_ = c.Get(context.Background(), types.NamespacedName{Name: "invite-1", Namespace: "tenant-acme"}, &tm2)
	if len(tm2.Finalizers) != 0 {
		t.Errorf("tm finalizer not stripped: %v", tm2.Finalizers)
	}
}

func TestReaper_PreservesUnknownFinalizers(t *testing.T) {
	scheme := setupScheme(t)
	ns := newTerminatingNamespace(10*time.Minute, "tenant-acme")
	// AgentEnrollment with an unknown finalizer — must NOT be stripped.
	ae := &gibsonv1alpha1.AgentEnrollment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ae-1", Namespace: "tenant-acme",
			Finalizers: []string{"foreign.example.com/cleanup"},
		},
		Spec: gibsonv1alpha1.AgentEnrollmentSpec{AgentName: "x", Mode: "autonomous"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, ae).Build()
	rec := events.NewFakeRecorder(10)
	r := &OrphanReaperReconciler{Client: c, Recorder: rec, GracePeriodSeconds: 300, Enabled: true}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "tenant-acme"}})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	var got gibsonv1alpha1.AgentEnrollment
	_ = c.Get(context.Background(), types.NamespacedName{Name: "ae-1", Namespace: "tenant-acme"}, &got)
	if len(got.Finalizers) != 1 || got.Finalizers[0] != "foreign.example.com/cleanup" {
		t.Fatalf("unknown finalizer should be preserved, got %v", got.Finalizers)
	}
}
