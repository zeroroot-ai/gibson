/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package flows

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	stripeclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/stripe"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// stripeNoopClient embeds zero-value implementations of every
// stripeclient.Client method so counting fakes only override what they
// exercise.
type stripeNoopClient struct{}

func (stripeNoopClient) CreateCustomer(context.Context, stripeclient.CustomerSpec) (stripeclient.CustomerID, error) {
	return "", nil
}
func (stripeNoopClient) UpdateCustomer(context.Context, stripeclient.CustomerID, map[string]string) error {
	return nil
}
func (stripeNoopClient) CancelSubscription(context.Context, stripeclient.CustomerID) error {
	return nil
}
func (stripeNoopClient) DeleteCustomer(context.Context, stripeclient.CustomerID) error { return nil }
func (stripeNoopClient) FindCustomerByTenant(context.Context, string) (stripeclient.CustomerID, error) {
	return "", clients.ErrNotFound
}
func (stripeNoopClient) GetSubscription(context.Context, string) (*stripeclient.SubscriptionState, error) {
	return nil, clients.ErrNotFound
}
func (stripeNoopClient) UpdateSubscriptionTrialEnd(context.Context, string, time.Time, string) error {
	return nil
}
func (stripeNoopClient) Ping(context.Context) error { return nil }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newProTenant returns a paid-tier Tenant named "acme" created at createdAt.
// The name was previously a parameter; every caller passed "acme", so it's
// inlined here. Pass a literal Tenant if a future test needs a different name.
func newProTenant(createdAt time.Time) *gibsonv1alpha1.Tenant {
	const name = "acme"
	t := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			CreationTimestamp: metav1.NewTime(createdAt),
		},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: name,
			Owner:       "owner@example.com",
			Tier:        gibsonv1alpha1.TenantPlanEnterprise,
		},
	}
	return t
}

// withAnnotation mutates t.Annotations to set key=value. No return — every
// caller discards the result of the equivalent return value anyway.
func withAnnotation(t *gibsonv1alpha1.Tenant, key, value string) {
	if t.Annotations == nil {
		t.Annotations = map[string]string{}
	}
	t.Annotations[key] = value
}

// ---------------------------------------------------------------------------
// WaitForBillingConfirmation tests
// ---------------------------------------------------------------------------

// TestWaitForBillingConfirmation_AlreadyConfirmed verifies that when the
// gibson.zeroroot.ai/billing-active=true annotation is already present the step
// returns done=true immediately without performing any side effects.
func TestWaitForBillingConfirmation_AlreadyConfirmed(t *testing.T) {
	tenant := newProTenant(time.Now().Add(-30 * time.Minute))
	withAnnotation(tenant, annotationBillingActive, "true")

	step := newWaitForBillingConfirmationStep(ProvisionDeps{})
	done, err := step.Provision(context.Background(), tenant, nil)

	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if !done {
		t.Fatal("expected done=true when billing-active annotation is present")
	}
	// BillingAbandoned must NOT be set.
	if c := findConditionByType(tenant, gibsonv1alpha1.ConditionBillingAbandoned); c != nil && c.Status == metav1.ConditionTrue {
		t.Errorf("BillingAbandoned must not be set when billing is already confirmed")
	}
}

// TestWaitForBillingConfirmation_WithinWindow verifies that a tenant younger
// than billingConfirmationWindow returns done=false, nil (in-progress signal —
// saga runner requeues without treating it as an error).
func TestWaitForBillingConfirmation_WithinWindow(t *testing.T) {
	// Created 30 minutes ago — well within the 1-hour window.
	tenant := newProTenant(time.Now().Add(-30 * time.Minute))

	step := newWaitForBillingConfirmationStep(ProvisionDeps{})
	done, err := step.Provision(context.Background(), tenant, nil)

	if err != nil {
		t.Fatalf("expected nil error within window, got: %v", err)
	}
	if done {
		t.Fatal("expected done=false while still within billing window")
	}
	// BillingAbandoned must NOT be set yet.
	if c := findConditionByType(tenant, gibsonv1alpha1.ConditionBillingAbandoned); c != nil && c.Status == metav1.ConditionTrue {
		t.Errorf("BillingAbandoned must not be set while window is still open")
	}
}

// TestWaitForBillingConfirmation_WindowElapsed verifies that once the
// billingConfirmationWindow has elapsed without a billing-active annotation,
// the step sets BillingAbandoned=True and returns a permanent error so the
// saga runner sets Blocked and stops retrying.
func TestWaitForBillingConfirmation_WindowElapsed(t *testing.T) {
	// Created 90 minutes ago — past the 1-hour window.
	tenant := newProTenant(time.Now().Add(-90 * time.Minute))

	step := newWaitForBillingConfirmationStep(ProvisionDeps{})
	done, err := step.Provision(context.Background(), tenant, nil)

	if done {
		t.Fatal("expected done=false when billing abandoned")
	}
	if err == nil {
		t.Fatal("expected non-nil error when billing window elapsed")
	}
	if !saga.IsPermanent(err) {
		t.Errorf("expected permanent error (no retry), got transient: %v", err)
	}

	// BillingAbandoned=True must be set.
	c := findConditionByType(tenant, gibsonv1alpha1.ConditionBillingAbandoned)
	if c == nil {
		t.Fatal("expected BillingAbandoned condition to be set")
	}
	if c.Status != metav1.ConditionTrue {
		t.Errorf("BillingAbandoned status: want True, got %v", c.Status)
	}
	if c.Reason != "ConfirmationTimeout" {
		t.Errorf("BillingAbandoned reason: want ConfirmationTimeout, got %q", c.Reason)
	}
}

// TestWaitForBillingConfirmation_Idempotent verifies that calling the step
// again after it already returned done=true (annotation present + previous
// BillingPending=True condition) is a clean no-op.
func TestWaitForBillingConfirmation_Idempotent(t *testing.T) {
	tenant := newProTenant(time.Now().Add(-45 * time.Minute))
	withAnnotation(tenant, annotationBillingActive, "true")
	// Pre-seed condition as True from a previous reconcile.
	tenant.Status.Conditions = []metav1.Condition{
		{
			Type:   gibsonv1alpha1.ConditionBillingPending,
			Status: metav1.ConditionTrue,
			Reason: saga.ReasonReady,
		},
	}

	step := newWaitForBillingConfirmationStep(ProvisionDeps{})
	// Call twice — both must succeed.
	for i := range 2 {
		done, err := step.Provision(context.Background(), tenant, nil)
		if err != nil || !done {
			t.Fatalf("call %d: expected (true, nil), got (%v, %v)", i+1, done, err)
		}
	}
}

// TestWaitForBillingConfirmation_UnbilledTierSkipped verifies the skip
// predicate (skipUnbilledTier): only the enterprise-deploy plan skips
// Stripe-related steps; team and enterprise both run them.
func TestWaitForBillingConfirmation_UnbilledTierSkipped(t *testing.T) {
	teamTenant := &gibsonv1alpha1.Tenant{
		Spec: gibsonv1alpha1.TenantSpec{
			Tier: gibsonv1alpha1.TenantPlanTeam,
		},
	}
	if skipUnbilledTier(teamTenant) {
		t.Error("expected skipUnbilledTier=false for team tenant (Stripe-billed)")
	}

	entTenant := &gibsonv1alpha1.Tenant{
		Spec: gibsonv1alpha1.TenantSpec{
			Tier: gibsonv1alpha1.TenantPlanEnterprise,
		},
	}
	if skipUnbilledTier(entTenant) {
		t.Error("expected skipUnbilledTier=false for enterprise tenant (Stripe-billed)")
	}

	deployTenant := &gibsonv1alpha1.Tenant{
		Spec: gibsonv1alpha1.TenantSpec{
			Tier: gibsonv1alpha1.TenantPlanEnterpriseDeploy,
		},
	}
	if !skipUnbilledTier(deployTenant) {
		t.Error("expected skipUnbilledTier=true for enterprise-deploy tenant (no Stripe)")
	}
}

// TestWaitForBillingConfirmation_WindowElapsed_PermanentWraps verifies that
// the returned error is recognized both as permanent by IsPermanent and that
// errors.Unwrap chains work correctly (not just a sentinel check).
func TestWaitForBillingConfirmation_WindowElapsed_PermanentWraps(t *testing.T) {
	tenant := newProTenant(time.Now().Add(-2 * time.Hour))

	step := newWaitForBillingConfirmationStep(ProvisionDeps{})
	_, err := step.Provision(context.Background(), tenant, nil)

	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if !errors.Is(err, saga.ErrPermanent) {
		t.Errorf("expected errors.Is(err, saga.ErrPermanent)=true, got false: %v", err)
	}
}

// TestWaitForBillingConfirmation_AnnotationFalseValue verifies that a
// billing-active annotation with value != "true" is NOT treated as confirmed.
func TestWaitForBillingConfirmation_AnnotationFalseValue(t *testing.T) {
	tenant := newProTenant(time.Now().Add(-30 * time.Minute))
	// Annotation exists but with a non-"true" value.
	withAnnotation(tenant, annotationBillingActive, "false")

	step := newWaitForBillingConfirmationStep(ProvisionDeps{})
	done, err := step.Provision(context.Background(), tenant, nil)

	if err != nil {
		t.Fatalf("unexpected error within window: %v", err)
	}
	if done {
		t.Fatal("expected done=false: annotation value 'false' must not be treated as confirmed")
	}
}

// ---------------------------------------------------------------------------
// Helper — find a condition by type from the tenant's status.
// ---------------------------------------------------------------------------

func findConditionByType(t *gibsonv1alpha1.Tenant, condType string) *metav1.Condition {
	for i := range t.Status.Conditions {
		if t.Status.Conditions[i].Type == condType {
			return &t.Status.Conditions[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// CreateStripeCustomer tests (tenant-operator#354)
// ---------------------------------------------------------------------------

// countingStripeClient counts CreateCustomer calls and lets tests pre-seed
// an existing customer for the FindCustomerByTenant adopt path.
type countingStripeClient struct {
	stripeNoopClient
	createCalls int
	findCalls   int
	existing    stripeclient.CustomerID // returned by FindCustomerByTenant when set
	findErr     error                   // returned by FindCustomerByTenant when set
}

func (c *countingStripeClient) CreateCustomer(_ context.Context, _ stripeclient.CustomerSpec) (stripeclient.CustomerID, error) {
	c.createCalls++
	return "cus_test_created", nil
}

func (c *countingStripeClient) FindCustomerByTenant(_ context.Context, _ string) (stripeclient.CustomerID, error) {
	c.findCalls++
	if c.findErr != nil {
		return "", c.findErr
	}
	if c.existing != "" {
		return c.existing, nil
	}
	return "", clients.ErrNotFound
}

// TestCreateStripeCustomer_IdempotentAcrossReconciles locks the
// tenant-operator#354 bug pattern: psaga re-runs every step's Provision on
// every reconcile, and the controller persists only STATUS after the saga.
// The step's idempotency key must therefore live on status — two Provision
// walks over the same (status-preserved) object must create exactly ONE
// Stripe customer. The original code keyed on a spec field whose write was
// discarded, creating a customer per reconcile (2000+ leaked on staging).
func TestCreateStripeCustomer_IdempotentAcrossReconciles(t *testing.T) {
	tenant := newProTenant(time.Now())
	fake := &countingStripeClient{}
	step := newCreateStripeCustomerStep(ProvisionDeps{Stripe: fake})

	for i := 1; i <= 2; i++ {
		done, err := step.Provision(context.Background(), tenant, nil)
		if err != nil {
			t.Fatalf("walk %d: unexpected error: %v", i, err)
		}
		if !done {
			t.Fatalf("walk %d: expected done=true", i)
		}
	}

	if fake.createCalls != 1 {
		t.Fatalf("expected exactly 1 CreateCustomer call across 2 reconciles, got %d", fake.createCalls)
	}
	if tenant.Status.StripeCustomerID != "cus_test_created" {
		t.Fatalf("expected status.stripeCustomerId persisted in-memory for the Status().Patch, got %q", tenant.Status.StripeCustomerID)
	}
}

// TestCreateStripeCustomer_AdoptsExistingByMetadata verifies the
// belt-and-braces path: when a customer tagged metadata tenant_id=<name>
// already exists in Stripe (lost status write, or pre-#354 leak), the step
// adopts it instead of creating a duplicate.
func TestCreateStripeCustomer_AdoptsExistingByMetadata(t *testing.T) {
	tenant := newProTenant(time.Now())
	fake := &countingStripeClient{existing: "cus_preexisting"}
	step := newCreateStripeCustomerStep(ProvisionDeps{Stripe: fake})

	done, err := step.Provision(context.Background(), tenant, nil)
	if err != nil || !done {
		t.Fatalf("expected done=true, nil error; got done=%v err=%v", done, err)
	}
	if fake.createCalls != 0 {
		t.Fatalf("expected 0 CreateCustomer calls when an existing customer is adoptable, got %d", fake.createCalls)
	}
	if tenant.Status.StripeCustomerID != "cus_preexisting" {
		t.Fatalf("expected adopted customer id on status, got %q", tenant.Status.StripeCustomerID)
	}
}

// TestCreateStripeCustomer_AdoptsPinnedAnnotation locks the card-first signup
// contract (dashboard#785): when the dashboard pins the pre-created customer id
// on the Tenant annotation, the step adopts it deterministically WITHOUT
// searching or creating — so an eventually-consistent Stripe search can never
// race into a duplicate customer.
func TestCreateStripeCustomer_AdoptsPinnedAnnotation(t *testing.T) {
	tenant := newProTenant(time.Now())
	if tenant.Annotations == nil {
		tenant.Annotations = map[string]string{}
	}
	tenant.Annotations["gibson.zeroroot.ai/stripe-customer-id"] = "cus_dashboard_pinned"
	fake := &countingStripeClient{existing: "cus_should_not_be_used"}
	step := newCreateStripeCustomerStep(ProvisionDeps{Stripe: fake})

	done, err := step.Provision(context.Background(), tenant, nil)
	if err != nil || !done {
		t.Fatalf("expected done=true, nil error; got done=%v err=%v", done, err)
	}
	if fake.findCalls != 0 {
		t.Fatalf("expected 0 FindCustomerByTenant calls (annotation is authoritative), got %d", fake.findCalls)
	}
	if fake.createCalls != 0 {
		t.Fatalf("expected 0 CreateCustomer calls when annotation is pinned, got %d", fake.createCalls)
	}
	if tenant.Status.StripeCustomerID != "cus_dashboard_pinned" {
		t.Fatalf("expected pinned customer id on status, got %q", tenant.Status.StripeCustomerID)
	}
}

// TestCreateStripeCustomer_SearchUnsupportedFallsBackToCreate verifies the
// stripe-mock degradation path: kind dev's stripe-mock does not implement
// /v1/customers/search, so a search error other than ErrNotFound must fall
// through to creation rather than failing the saga.
func TestCreateStripeCustomer_SearchUnsupportedFallsBackToCreate(t *testing.T) {
	tenant := newProTenant(time.Now())
	fake := &countingStripeClient{findErr: errors.New("search not supported")}
	step := newCreateStripeCustomerStep(ProvisionDeps{Stripe: fake})

	done, err := step.Provision(context.Background(), tenant, nil)
	if err != nil || !done {
		t.Fatalf("expected done=true, nil error; got done=%v err=%v", done, err)
	}
	if fake.createCalls != 1 {
		t.Fatalf("expected creation fallback when search errors, got %d calls", fake.createCalls)
	}
}
