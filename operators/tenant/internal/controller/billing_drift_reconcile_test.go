/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Integration tests for the DriftReconciler and BillingReconciler.
//
// Spec stripe-billing-integration Task 38 / R5.1, R5.2, R10.1, R10.2.
//
// Each test wires a sigs.k8s.io/controller-runtime fake client with the
// Tenant CRs under test, plus a fakeStripeClient implementing
// stripeclient.Client. The reconciler is driven via its public Reconcile
// method (a single requeue cycle) and the side effects are asserted on:
//
//   - DriftReconciler: the metrics.StripeDriftTotal counter and absence
//     of state mutation (drift detection is alerting-only per R10.2).
//   - BillingReconciler: Tenant CR status transitions, teardown-after
//     annotation, and TeardownQueue receives.
//
// No real Stripe network calls; no envtest harness; deterministic.

package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	stripeclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/stripe"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/metrics"
)

// fakeStripeClient is a deterministic stub satisfying stripeclient.Client.
// Only the two methods the reconcilers exercise (GetSubscription,
// UpdateSubscriptionTrialEnd) need meaningful behaviour; the rest return
// zero values. Callers configure GetSubscription via the subs map and
// the optional err override.
type fakeStripeClient struct {
	subs map[string]*stripeclient.SubscriptionState
	err  error // global override; non-nil ⇒ every GetSubscription returns it
}

func (f *fakeStripeClient) GetSubscription(_ context.Context, id string) (*stripeclient.SubscriptionState, error) {
	if f.err != nil {
		return nil, f.err
	}
	s, ok := f.subs[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return s, nil
}

func (f *fakeStripeClient) CreateCustomer(_ context.Context, _ stripeclient.CustomerSpec) (stripeclient.CustomerID, error) {
	return "", nil
}
func (f *fakeStripeClient) UpdateCustomer(_ context.Context, _ stripeclient.CustomerID, _ map[string]string) error {
	return nil
}
func (f *fakeStripeClient) CancelSubscription(_ context.Context, _ stripeclient.CustomerID) error {
	return nil
}
func (f *fakeStripeClient) DeleteCustomer(_ context.Context, _ stripeclient.CustomerID) error {
	return nil
}
func (f *fakeStripeClient) UpdateSubscriptionTrialEnd(_ context.Context, _ string, _ time.Time, _ string) error {
	return nil
}
func (f *fakeStripeClient) Ping(_ context.Context) error { return nil }
func (f *fakeStripeClient) FindCustomerByTenant(_ context.Context, _ string) (stripeclient.CustomerID, error) {
	return "", errors.New("not found")
}

// --- Helpers ---------------------------------------------------------------

// counterValue reads the current value of a labelled counter.
func counterValue(t *testing.T, vec *prometheus.CounterVec, label string) float64 {
	t.Helper()
	c, err := vec.GetMetricWithLabelValues(label)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(%q): %v", label, err)
	}
	return testutil.ToFloat64(c)
}

// makeTenant builds the canonical fixture Tenant ("acme"). The name was
// previously a parameter; every caller passed "acme", so it's inlined.
func makeTenant(billing gibsonv1alpha1.BillingSubscriptionStatus, annotations map[string]string) *gibsonv1alpha1.Tenant {
	return &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme", Annotations: annotations},
		Status:     gibsonv1alpha1.TenantStatus{Billing: billing},
	}
}

// --- DriftReconciler -------------------------------------------------------

func TestDriftReconciler_NoDriftWhenInSync(t *testing.T) {
	scheme := setupScheme(t)
	tenant := makeTenant(gibsonv1alpha1.BillingSubscriptionStatus{
		SubscriptionID: "sub_111",
		Status:         "active",
		PriceID:        "price_team",
	},
		nil)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()

	stripe := &fakeStripeClient{
		subs: map[string]*stripeclient.SubscriptionState{
			"sub_111": {ID: "sub_111", Status: "active", PriceID: "price_team"},
		},
	}
	r := &DriftReconciler{Client: c, StripeClient: stripe}

	before := counterValue(t, metrics.StripeDriftTotal, "status") +
		counterValue(t, metrics.StripeDriftTotal, "priceId") +
		counterValue(t, metrics.StripeDriftTotal, "currentPeriodEnd")

	if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	after := counterValue(t, metrics.StripeDriftTotal, "status") +
		counterValue(t, metrics.StripeDriftTotal, "priceId") +
		counterValue(t, metrics.StripeDriftTotal, "currentPeriodEnd")
	if delta := after - before; delta != 0 {
		t.Fatalf("expected no drift increments, got delta=%f", delta)
	}
}

func TestDriftReconciler_StatusDrift(t *testing.T) {
	scheme := setupScheme(t)
	tenant := makeTenant(gibsonv1alpha1.BillingSubscriptionStatus{
		SubscriptionID: "sub_111",
		Status:         "active",
		PriceID:        "price_team",
	},
		nil)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()

	stripe := &fakeStripeClient{
		subs: map[string]*stripeclient.SubscriptionState{
			// Stripe reports past_due, CR says active.
			"sub_111": {ID: "sub_111", Status: "past_due", PriceID: "price_team"},
		},
	}
	r := &DriftReconciler{Client: c, StripeClient: stripe}

	before := counterValue(t, metrics.StripeDriftTotal, "status")
	if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	after := counterValue(t, metrics.StripeDriftTotal, "status")
	if after-before != 1 {
		t.Fatalf("expected status drift +1, got delta=%f", after-before)
	}
}

func TestDriftReconciler_PriceIdDrift(t *testing.T) {
	scheme := setupScheme(t)
	tenant := makeTenant(gibsonv1alpha1.BillingSubscriptionStatus{
		SubscriptionID: "sub_222",
		Status:         "active",
		PriceID:        "price_team",
	},
		nil)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()

	stripe := &fakeStripeClient{
		subs: map[string]*stripeclient.SubscriptionState{
			"sub_222": {ID: "sub_222", Status: "active", PriceID: "price_enterprise"},
		},
	}
	r := &DriftReconciler{Client: c, StripeClient: stripe}

	before := counterValue(t, metrics.StripeDriftTotal, "priceId")
	if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	after := counterValue(t, metrics.StripeDriftTotal, "priceId")
	if after-before != 1 {
		t.Fatalf("expected priceId drift +1, got delta=%f", after-before)
	}
}

func TestDriftReconciler_CurrentPeriodEndDriftOverTolerance(t *testing.T) {
	scheme := setupScheme(t)
	// CR says period ends at a specific time; Stripe disagrees by 2 hours.
	crEnd := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	stripeEnd := time.Date(2026, 6, 15, 14, 0, 0, 0, time.UTC).Unix()
	tenant := makeTenant(gibsonv1alpha1.BillingSubscriptionStatus{
		SubscriptionID:   "sub_333",
		Status:           "active",
		PriceID:          "price_team",
		CurrentPeriodEnd: crEnd,
	},
		nil)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()

	stripe := &fakeStripeClient{
		subs: map[string]*stripeclient.SubscriptionState{
			"sub_333": {ID: "sub_333", Status: "active", PriceID: "price_team", CurrentPeriodEnd: stripeEnd},
		},
	}
	r := &DriftReconciler{Client: c, StripeClient: stripe}

	before := counterValue(t, metrics.StripeDriftTotal, "currentPeriodEnd")
	if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	after := counterValue(t, metrics.StripeDriftTotal, "currentPeriodEnd")
	if after-before != 1 {
		t.Fatalf("expected currentPeriodEnd drift +1, got delta=%f", after-before)
	}
}

func TestDriftReconciler_CurrentPeriodEndWithinTolerance(t *testing.T) {
	scheme := setupScheme(t)
	// 30-minute drift is within the 1-hour anchor-rounding tolerance.
	crEnd := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	stripeEnd := time.Date(2026, 6, 15, 12, 30, 0, 0, time.UTC).Unix()
	tenant := makeTenant(gibsonv1alpha1.BillingSubscriptionStatus{
		SubscriptionID:   "sub_444",
		Status:           "active",
		PriceID:          "price_team",
		CurrentPeriodEnd: crEnd,
	},
		nil)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()

	stripe := &fakeStripeClient{
		subs: map[string]*stripeclient.SubscriptionState{
			"sub_444": {ID: "sub_444", Status: "active", PriceID: "price_team", CurrentPeriodEnd: stripeEnd},
		},
	}
	r := &DriftReconciler{Client: c, StripeClient: stripe}

	before := counterValue(t, metrics.StripeDriftTotal, "currentPeriodEnd")
	if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	after := counterValue(t, metrics.StripeDriftTotal, "currentPeriodEnd")
	if after-before != 0 {
		t.Fatalf("expected no drift inside tolerance, got delta=%f", after-before)
	}
}

func TestDriftReconciler_StripeErrorDoesNotPanic(t *testing.T) {
	scheme := setupScheme(t)
	tenant := makeTenant(gibsonv1alpha1.BillingSubscriptionStatus{
		SubscriptionID: "sub_err",
		Status:         "active",
		PriceID:        "price_team",
	},
		nil)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()

	stripe := &fakeStripeClient{err: errors.New("stripe upstream broken")}
	r := &DriftReconciler{Client: c, StripeClient: stripe}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err != nil {
		t.Fatalf("reconcile must not surface Stripe errors at the top level: %v", err)
	}
}

// --- BillingReconciler -----------------------------------------------------

func TestBillingReconciler_TrialExpiryTriggersCancelledTransition(t *testing.T) {
	scheme := setupScheme(t)
	// Trial ended an hour ago.
	trialEnd := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	tenant := makeTenant(gibsonv1alpha1.BillingSubscriptionStatus{
		SubscriptionID: "sub_trial",
		Status:         "trialing",
		TrialEnd:       trialEnd,
	},
		nil)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.Tenant{}).
		WithObjects(tenant).
		Build()
	stripe := &fakeStripeClient{
		subs: map[string]*stripeclient.SubscriptionState{
			"sub_trial": {ID: "sub_trial", Status: "canceled"},
		},
	}
	teardownQ := make(chan string, 1)
	r := &BillingReconciler{Client: c, StripeClient: stripe, TeardownQueue: teardownQ}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var updated gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), types.NamespacedName{Name: "acme"}, &updated); err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if got := updated.Status.Billing.Status; got != "cancelled" {
		t.Fatalf("expected status=cancelled, got %q", got)
	}
	if _, ok := updated.Annotations[teardownAfterAnnotation]; !ok {
		t.Fatalf("expected teardown-after annotation to be written")
	}
}

func TestBillingReconciler_TrialExpiryStripeStillTrialingNoTransition(t *testing.T) {
	scheme := setupScheme(t)
	trialEnd := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	tenant := makeTenant(gibsonv1alpha1.BillingSubscriptionStatus{
		SubscriptionID: "sub_grace",
		Status:         "trialing",
		TrialEnd:       trialEnd,
	},
		nil)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.Tenant{}).
		WithObjects(tenant).
		Build()
	stripe := &fakeStripeClient{
		// Stripe disagrees with the CR — it considers the trial still active
		// (perhaps the webhook for the trial-end is still pending).
		subs: map[string]*stripeclient.SubscriptionState{
			"sub_grace": {ID: "sub_grace", Status: "trialing"},
		},
	}
	teardownQ := make(chan string, 1)
	r := &BillingReconciler{Client: c, StripeClient: stripe, TeardownQueue: teardownQ}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var updated gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), types.NamespacedName{Name: "acme"}, &updated); err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if got := updated.Status.Billing.Status; got != "trialing" {
		t.Fatalf("expected status to remain trialing (Stripe is source of truth), got %q", got)
	}
}

func TestBillingReconciler_TeardownAnnotationElapsedEnqueues(t *testing.T) {
	scheme := setupScheme(t)
	teardownAt := time.Now().Add(-1 * time.Minute).UTC().Format(time.RFC3339)
	tenant := makeTenant(gibsonv1alpha1.BillingSubscriptionStatus{Status: "cancelled"},
		map[string]string{teardownAfterAnnotation: teardownAt})
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.Tenant{}).
		WithObjects(tenant).
		Build()
	stripe := &fakeStripeClient{}
	teardownQ := make(chan string, 1)
	r := &BillingReconciler{Client: c, StripeClient: stripe, TeardownQueue: teardownQ}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	select {
	case name := <-teardownQ:
		if name != "acme" {
			t.Fatalf("expected teardown enqueue for acme, got %q", name)
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("expected teardown enqueue, none received")
	}
}

func TestBillingReconciler_TeardownAnnotationFutureNoEnqueue(t *testing.T) {
	scheme := setupScheme(t)
	teardownAt := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	tenant := makeTenant(gibsonv1alpha1.BillingSubscriptionStatus{Status: "cancelled"},
		map[string]string{teardownAfterAnnotation: teardownAt})
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.Tenant{}).
		WithObjects(tenant).
		Build()
	stripe := &fakeStripeClient{}
	teardownQ := make(chan string, 1)
	r := &BillingReconciler{Client: c, StripeClient: stripe, TeardownQueue: teardownQ}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	select {
	case got := <-teardownQ:
		t.Fatalf("did not expect teardown enqueue for future annotation, got %q", got)
	case <-time.After(50 * time.Millisecond):
		// ok
	}
}

func TestBillingReconciler_PastDueNoEntitlementsReconcilerNoPanic(t *testing.T) {
	scheme := setupScheme(t)
	pastDueSince := time.Now().Add(-10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	tenant := makeTenant(gibsonv1alpha1.BillingSubscriptionStatus{
		Status:       "past_due",
		PastDueSince: pastDueSince,
	},
		nil)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.Tenant{}).
		WithObjects(tenant).
		Build()
	stripe := &fakeStripeClient{}
	teardownQ := make(chan string, 1)
	// Entitlements left nil — past-due path must short-circuit without panic.
	r := &BillingReconciler{Client: c, StripeClient: stripe, TeardownQueue: teardownQ}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

// TestBillingReconciler_AbandonedSchedulesImmediateTeardown verifies the
// card-first abandoned-signup path (deploy #359): a tenant carrying the
// BillingAbandoned condition gets teardown-after stamped at "now" and is
// enqueued for teardown on the same tick — no 7-day grace (nothing was paid).
func TestBillingReconciler_AbandonedSchedulesImmediateTeardown(t *testing.T) {
	scheme := setupScheme(t)
	tenant := makeTenant(gibsonv1alpha1.BillingSubscriptionStatus{}, nil)
	apimeta.SetStatusCondition(&tenant.Status.Conditions, metav1.Condition{
		Type:    gibsonv1alpha1.ConditionBillingAbandoned,
		Status:  metav1.ConditionTrue,
		Reason:  "ConfirmationTimeout",
		Message: "card-first signup abandoned",
	})
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.Tenant{}).
		WithObjects(tenant).
		Build()
	teardownQ := make(chan string, 1)
	r := &BillingReconciler{Client: c, StripeClient: &fakeStripeClient{}, TeardownQueue: teardownQ}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var updated gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), types.NamespacedName{Name: "acme"}, &updated); err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	ts, ok := updated.Annotations[teardownAfterAnnotation]
	if !ok {
		t.Fatalf("expected teardown-after annotation on the abandoned tenant")
	}
	teardownAt, perr := time.Parse(time.RFC3339, ts)
	if perr != nil {
		t.Fatalf("teardown-after not RFC3339: %v", perr)
	}
	if teardownAt.After(time.Now().Add(time.Minute)) {
		t.Fatalf("abandoned teardown-after should be ~now, got %s (future)", ts)
	}
	select {
	case name := <-teardownQ:
		if name != "acme" {
			t.Fatalf("enqueued wrong tenant: %q", name)
		}
	default:
		t.Fatalf("expected the abandoned tenant to be enqueued for teardown")
	}
}

// TestBillingReconciler_NonAbandonedNotTornDown ensures a healthy trialing
// tenant is never enqueued for teardown by the abandoned path.
func TestBillingReconciler_NonAbandonedNotTornDown(t *testing.T) {
	scheme := setupScheme(t)
	tenant := makeTenant(gibsonv1alpha1.BillingSubscriptionStatus{
		SubscriptionID: "sub_ok",
		Status:         "trialing",
		TrialEnd:       time.Now().Add(14 * 24 * time.Hour).UTC().Format(time.RFC3339),
	}, nil)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.Tenant{}).
		WithObjects(tenant).
		Build()
	teardownQ := make(chan string, 1)
	r := &BillingReconciler{Client: c, StripeClient: &fakeStripeClient{}, TeardownQueue: teardownQ}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var updated gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), types.NamespacedName{Name: "acme"}, &updated); err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if _, ok := updated.Annotations[teardownAfterAnnotation]; ok {
		t.Fatalf("healthy trialing tenant must not get teardown-after")
	}
	select {
	case name := <-teardownQ:
		t.Fatalf("healthy tenant must not be enqueued for teardown, got %q", name)
	default:
	}
}
