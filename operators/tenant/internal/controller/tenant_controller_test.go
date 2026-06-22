/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/go-logr/logr/testr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

func setupScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := networkingv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := rbacv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := gibsonv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func newFakeReconciler(t *testing.T, tenant *gibsonv1alpha1.Tenant) (*TenantReconciler, client.Client) {
	t.Helper()
	scheme := setupScheme(t)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.Tenant{}).
		WithObjects(tenant).
		Build()

	runner := saga.NewRunner(fakeClient, events.NewFakeRecorder(100), testr.New(t))
	r := &TenantReconciler{
		Client:               fakeClient,
		Scheme:               scheme,
		Runner:               runner,
		NamespaceProvisioner: NewNamespaceProvisioner(fakeClient, "gibson-platform", nil),
	}
	return r, fakeClient
}

func TestReconcile_AddsFinalizerOnFirstPass(t *testing.T) {
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: "Acme Corp",
			Owner:       "owner@acme.com",
			Tier:        gibsonv1alpha1.TenantPlanTeam,
		},
	}
	r, c := newFakeReconciler(t, tenant)

	_, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "acme"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), types.NamespacedName{Name: "acme"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	found := false
	for _, f := range got.Finalizers {
		if f == gibsonv1alpha1.TenantFinalizer {
			found = true
		}
	}
	if !found {
		t.Errorf("expected finalizer, got %v", got.Finalizers)
	}
}

func TestReconcile_ProvisionsNamespaceAndPolicy(t *testing.T) {
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "acme",
			Finalizers: []string{gibsonv1alpha1.TenantFinalizer},
		},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: "Acme",
			Owner:       "owner@acme.com",
			Tier:        gibsonv1alpha1.TenantPlanEnterprise,
		},
	}
	r, c := newFakeReconciler(t, tenant)

	// Run reconcile twice — saga is idempotent.
	for i := range 2 {
		_, err := r.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "acme"},
		})
		if err != nil {
			t.Fatalf("reconcile %d: %v", i, err)
		}
	}

	// Namespace should exist.
	ns := &corev1.Namespace{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "tenant-acme"}, ns); err != nil {
		t.Fatalf("namespace missing: %v", err)
	}
	if ns.Labels["gibson.zeroroot.ai/tenant"] != "acme" {
		t.Errorf("missing tenant label: %v", ns.Labels)
	}
	if ns.Labels["gibson.zeroroot.ai/tier"] != "enterprise" {
		t.Errorf("missing tier label: %v", ns.Labels)
	}

	// NetworkPolicy should exist.
	np := &networkingv1.NetworkPolicy{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "gibson-tenant-default-deny"}, np); err != nil {
		t.Fatalf("networkpolicy missing: %v", err)
	}

	// Per-tenant K8s ResourceQuota was removed by spec
	// plans-and-quotas-simplification — daemon enforces concurrent_missions
	// / concurrent_agents instead. Verify NO ResourceQuota exists.
	rq := &corev1.ResourceQuota{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "gibson-tenant-quota"}, rq); err == nil {
		t.Errorf("resourcequota should not be created any more, but found one")
	} else if !apierrors.IsNotFound(err) {
		t.Errorf("unexpected error checking ResourceQuota: %v", err)
	}

	// Tenant status should have Phase=Ready (foundation has only namespace step).
	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), types.NamespacedName{Name: "acme"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != gibsonv1alpha1.TenantPhaseReady {
		t.Errorf("phase got %q, want Ready", got.Status.Phase)
	}
	if got.Status.Namespace != "tenant-acme" {
		t.Errorf("status.namespace got %q, want tenant-acme", got.Status.Namespace)
	}
}

// TestReconcile_NetworkPolicy_DaemonNeo4jIngress verifies that the provisioned
// NetworkPolicy includes an ingress rule permitting the daemon pod (in the
// platform namespace) to reach Neo4j on bolt port 7687. Without this rule the
// default-deny policy blocks cross-namespace daemon→Neo4j connections and every
// graph query fails with ConnectivityError timeout across all tenants.
func TestReconcile_NetworkPolicy_DaemonNeo4jIngress(t *testing.T) {
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "acme",
			Finalizers: []string{gibsonv1alpha1.TenantFinalizer},
		},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: "Acme",
			Owner:       "owner@acme.com",
			Tier:        gibsonv1alpha1.TenantPlanEnterprise,
		},
	}
	r, c := newFakeReconciler(t, tenant)
	_, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "acme"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	np := &networkingv1.NetworkPolicy{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "gibson-tenant-default-deny"}, np); err != nil {
		t.Fatalf("networkpolicy missing: %v", err)
	}

	// There must be an ingress rule allowing the daemon on port 7687.
	found7687 := false
	for _, rule := range np.Spec.Ingress {
		for _, port := range rule.Ports {
			if port.Port != nil && port.Port.IntValue() == 7687 {
				found7687 = true
				// Verify the rule comes from the platform namespace + daemon selector.
				if len(rule.From) == 0 {
					t.Error("ingress rule for 7687 has no From peers")
				}
				peer := rule.From[0]
				if peer.NamespaceSelector == nil {
					t.Error("ingress rule for 7687 missing NamespaceSelector")
				}
				if peer.PodSelector == nil {
					t.Error("ingress rule for 7687 missing PodSelector (must restrict to daemon component)")
				} else {
					got := peer.PodSelector.MatchLabels["app.kubernetes.io/component"]
					if got != "daemon" {
						t.Errorf("ingress rule for 7687 PodSelector component = %q, want daemon", got)
					}
				}
			}
		}
	}
	if !found7687 {
		t.Error("NetworkPolicy has no ingress rule for Neo4j bolt port 7687 — daemon cannot reach per-tenant graph store")
	}
}

// ---------------------------------------------------------------------------
// Correlation-ID propagation tests (Task 20.1)
// ---------------------------------------------------------------------------

// newAuditCapturingRunner creates a runner whose audit emitter writes to buf,
// allowing tests to inspect emitted correlation IDs.
func newAuditCapturingRunner(t *testing.T, fakeClient client.Client, buf *bytes.Buffer) *saga.Runner {
	t.Helper()
	r := saga.NewRunner(fakeClient, events.NewFakeRecorder(100), testr.New(t))
	r.Audit = audit.NewSagaEmitter("tenant-operator", buf)
	return r
}

// decodedAuditLines parses lines from buf and returns them as JSON maps.
func decodedAuditLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for l := range strings.SplitSeq(buf.String(), "\n") {
		if l == "" {
			continue
		}
		const prefix = "[audit.tenant-operator] "
		if !strings.HasPrefix(l, prefix) {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(l, prefix)), &m); err == nil {
			out = append(out, m)
		}
	}
	return out
}

// TestReconcile_CorrelationID_FromAnnotation verifies that when the Tenant CR
// carries a gibson.zeroroot.ai/correlation-id annotation, the Reconcile loop threads it
// into audit events emitted by the runner.
func TestReconcile_CorrelationID_FromAnnotation(t *testing.T) {
	const wantCorrID = "test-correlation-xyz-123"
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "corr-test",
			Finalizers: []string{gibsonv1alpha1.TenantFinalizer},
			Annotations: map[string]string{
				saga.AnnotationCorrelationID: wantCorrID,
			},
		},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: "Corr Test",
			Owner:       "owner@example.com",
			Tier:        gibsonv1alpha1.TenantPlanTeam,
		},
	}

	scheme := setupScheme(t)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.Tenant{}).
		WithObjects(tenant).
		Build()

	var buf bytes.Buffer
	runner := newAuditCapturingRunner(t, fakeClient, &buf)

	r := &TenantReconciler{
		Client:               fakeClient,
		Scheme:               scheme,
		Runner:               runner,
		NamespaceProvisioner: NewNamespaceProvisioner(fakeClient, "gibson-platform", nil),
	}

	_, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "corr-test"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	lines := decodedAuditLines(t, &buf)
	if len(lines) == 0 {
		t.Fatal("expected audit lines, got none")
	}
	for _, m := range lines {
		if got, _ := m["correlationId"].(string); got != wantCorrID {
			t.Errorf("audit correlationId: got %q, want %q (line: %v)", got, wantCorrID, m)
		}
	}
}

// TestReconcile_CorrelationID_GeneratedWhenMissing verifies that when the
// Tenant CR has no annotation, Reconcile generates a fresh UUID and the audit
// events carry a non-empty correlationId.
func TestReconcile_CorrelationID_GeneratedWhenMissing(t *testing.T) {
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "no-corr",
			Finalizers: []string{gibsonv1alpha1.TenantFinalizer},
			// No annotation.
		},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: "No Corr",
			Owner:       "owner@example.com",
			Tier:        gibsonv1alpha1.TenantPlanTeam,
		},
	}

	scheme := setupScheme(t)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.Tenant{}).
		WithObjects(tenant).
		Build()

	var buf bytes.Buffer
	runner := newAuditCapturingRunner(t, fakeClient, &buf)

	r := &TenantReconciler{
		Client:               fakeClient,
		Scheme:               scheme,
		Runner:               runner,
		NamespaceProvisioner: NewNamespaceProvisioner(fakeClient, "gibson-platform", nil),
	}

	_, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "no-corr"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	lines := decodedAuditLines(t, &buf)
	if len(lines) == 0 {
		t.Fatal("expected audit lines, got none")
	}
	for _, m := range lines {
		corrID, _ := m["correlationId"].(string)
		if corrID == "" {
			t.Errorf("expected non-empty generated correlationId in audit line, got empty (line: %v)", m)
		}
	}
}

func TestReconcile_DeletionRunsFinalizer(t *testing.T) {
	now := metav1.Now()
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "acme",
			Finalizers:        []string{gibsonv1alpha1.TenantFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: "Acme",
			Owner:       "owner@acme.com",
			Tier:        gibsonv1alpha1.TenantPlanTeam,
		},
		Status: gibsonv1alpha1.TenantStatus{
			Namespace: "tenant-acme",
		},
	}
	r, c := newFakeReconciler(t, tenant)

	// Pre-create the namespace so deletion has something to target.
	_ = c.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-acme"}})

	// First reconcile: issues delete; namespace transitions to Terminating.
	_, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "acme"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// Simulate cascade: remove namespace.
	ns := &corev1.Namespace{}
	_ = c.Get(context.Background(), types.NamespacedName{Name: "tenant-acme"}, ns)
	_ = c.Delete(context.Background(), ns)

	// Second reconcile: finalizer should be removed.
	_, err = r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "acme"},
	})
	if err != nil {
		t.Fatalf("reconcile delete: %v", err)
	}

	// Tenant should either have finalizer removed (then garbage collected by
	// the fake client) or be gone entirely.
	var got gibsonv1alpha1.Tenant
	err = c.Get(context.Background(), types.NamespacedName{Name: "acme"}, &got)
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected error: %v", err)
	}
	if err == nil {
		for _, f := range got.Finalizers {
			if f == gibsonv1alpha1.TenantFinalizer {
				t.Errorf("finalizer still present after reconcile")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Issue #157 regression tests — finalizer removal on deletion.
// ---------------------------------------------------------------------------

// alwaysFailStep is a saga.Step whose Provision always returns a permanent
// error (via clients.WrapPermanent). Used to force the teardown saga into
// the Blocked state to exercise the #157 fix: even when a teardown step
// exhausts its retry budget, the controller MUST proceed to finalizer
// removal so the CR isn't stranded forever in Terminating.
type alwaysFailStep struct {
	saga.StepBase
}

func newAlwaysFailStep(name string) *alwaysFailStep {
	return &alwaysFailStep{
		StepBase: saga.StepBase{
			N:     name,
			C:     name + "Complete",
			Owner: "test",
		},
	}
}

func (s *alwaysFailStep) Provision(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	// clients.WrapPermanent flags the error as permanent via errors.Is,
	// which classifyForPSaga maps to psaga.ErrorPermanent on the first
	// attempt — so the saga sets Blocked=true immediately rather than
	// burning through the retry budget. Keeps this test fast.
	return false, clients.WrapPermanent(errors.New("alwaysFailStep: forced failure"))
}

// TestReconcile_157_DeletionRemovesFinalizerEvenWhenTeardownBlocked is the
// regression test for #157. It forces a teardown step to permanently fail
// and asserts the finalizer is still removed (preventing the CR from being
// stuck in Terminating forever).
func TestReconcile_157_DeletionRemovesFinalizerEvenWhenTeardownBlocked(t *testing.T) {
	now := metav1.Now()
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "stuck",
			Finalizers:        []string{gibsonv1alpha1.TenantFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: "Stuck",
			Owner:       "owner@stuck.com",
			Tier:        gibsonv1alpha1.TenantPlanTeam,
		},
		Status: gibsonv1alpha1.TenantStatus{
			Namespace: "tenant-stuck",
		},
	}
	r, c := newFakeReconciler(t, tenant)
	// Inject a teardown step that permanently fails. The foundation
	// DeleteNamespace step still runs (and would succeed) but the
	// alwaysFailStep ahead of it (no Requires) trips the saga into
	// Blocked. Under the old behavior the controller would log "saga
	// blocked; not requeueing" and exit WITHOUT removing the finalizer,
	// leaving the CR stuck.
	r.TeardownSteps = []saga.Step{newAlwaysFailStep("ForcedFailureTeardown")}

	// Pre-create the namespace so deletion has something to target.
	_ = c.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-stuck"}})

	// Drive reconciles until the CR is gone or finalizer is cleared, OR
	// we hit the iteration cap (the regression: with the bug, the
	// finalizer never clears even after many reconciles).
	const maxIters = 5
	for i := range maxIters {
		_, err := r.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "stuck"},
		})
		if err != nil {
			t.Fatalf("reconcile iter %d: %v", i, err)
		}
		var got gibsonv1alpha1.Tenant
		err = c.Get(context.Background(), types.NamespacedName{Name: "stuck"}, &got)
		if err != nil && apierrors.IsNotFound(err) {
			// Best case — finalizer removed, fake client GC'd the CR.
			return
		}
		if err == nil && !hasFinalizer(got.Finalizers, gibsonv1alpha1.TenantFinalizer) {
			return // finalizer removed
		}
	}

	// Still has finalizer after maxIters → regression.
	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), types.NamespacedName{Name: "stuck"}, &got); err == nil {
		if hasFinalizer(got.Finalizers, gibsonv1alpha1.TenantFinalizer) {
			t.Fatalf("BUG #157 regression: finalizer %q still present after %d reconciles with blocked teardown; CR is stuck",
				gibsonv1alpha1.TenantFinalizer, maxIters)
		}
	}
}

// TestReconcile_157_DeletionSkipsProvisionSaga verifies that when a Tenant
// has DeletionTimestamp set, the controller does NOT start a provision-saga
// pass (which would log "dataplane: provision start" on a tenant being
// deleted, then fail with "tenant is being deleted" — the symptom #157
// described in the live log).
//
// We assert this indirectly: the Reconcile call never touches the
// provisioningSteps slice. We do that by injecting an alwaysFailStep into
// ProvisionSteps and asserting that even after reconcile, the
// "ForcedFailureProvision" condition is NOT set on the tenant (it would be
// if the provision saga ran).
func TestReconcile_157_DeletionSkipsProvisionSaga(t *testing.T) {
	now := metav1.Now()
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "deleting",
			Finalizers:        []string{gibsonv1alpha1.TenantFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: "Deleting",
			Owner:       "owner@deleting.com",
			Tier:        gibsonv1alpha1.TenantPlanTeam,
		},
		Status: gibsonv1alpha1.TenantStatus{
			Namespace: "tenant-deleting",
		},
	}
	r, c := newFakeReconciler(t, tenant)
	r.ProvisionSteps = []saga.Step{newAlwaysFailStep("ForcedFailureProvision")}

	_ = c.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-deleting"}})

	_, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "deleting"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// The tenant may already be GC'd by the fake client (finalizer
	// removed, no other refs). If still present, the provision-step
	// condition MUST be absent — that's the structural assertion.
	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), types.NamespacedName{Name: "deleting"}, &got); err == nil {
		for _, cond := range got.Status.Conditions {
			if cond.Type == "ForcedFailureProvisionComplete" {
				t.Fatalf("BUG #157 regression: provision step ran during deletion (condition %q set with status=%v reason=%q)",
					cond.Type, cond.Status, cond.Reason)
			}
		}
	}
}

func hasFinalizer(fs []string, f string) bool {
	return slices.Contains(fs, f)
}
