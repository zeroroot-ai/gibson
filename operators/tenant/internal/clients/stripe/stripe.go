/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package stripe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	stripego "github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/balance"
	"github.com/stripe/stripe-go/v82/customer"
	"github.com/stripe/stripe-go/v82/subscription"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/metrics"
)

// APIClient implements Client using the official stripe-go SDK.
type APIClient struct {
	apiKey     string
	apiVersion string
	timeout    time.Duration
}

// NewAPIClient constructs a Stripe client. APIKey is required.
//
// STRIPE_API_BASE_URL overrides the Stripe API endpoint; used only in
// E2E/local environments where a stub server replaces the real Stripe API.
// Unset in production.
func NewAPIClient(cfg Config) (*APIClient, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("stripe: APIKey required: %w", clients.ErrInvalidInput)
	}
	stripego.Key = cfg.APIKey
	if baseURL := os.Getenv("STRIPE_API_BASE_URL"); baseURL != "" {
		stripego.SetBackend(stripego.APIBackend, stripego.GetBackendWithConfig(
			stripego.APIBackend,
			&stripego.BackendConfig{URL: &baseURL},
		))
	}
	t := cfg.Timeout
	if t == 0 {
		t = 15 * time.Second
	}
	return &APIClient{apiKey: cfg.APIKey, apiVersion: cfg.APIVersion, timeout: t}, nil
}

// CreateCustomer implements Client.
func (c *APIClient) CreateCustomer(ctx context.Context, spec CustomerSpec) (CustomerID, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	params := &stripego.CustomerParams{
		Email: stripego.String(spec.Email),
		Name:  stripego.String(spec.Name),
	}
	for k, v := range spec.Metadata {
		params.AddMetadata(k, v)
	}
	params.Context = ctx
	cust, err := customer.New(params)
	mapped := mapStripeError(err)
	metrics.ObserveSubsystemCall("stripe", "CreateCustomer", start, mapped)
	if mapped != nil {
		return "", mapped
	}
	return CustomerID(cust.ID), nil
}

// FindCustomerByTenant implements Client via /v1/customers/search on the
// tenant_id metadata key. ErrNotFound when no match; any transport/API
// error is returned as-is for the caller's fall-back-to-create path
// (stripe-mock has no search endpoint).
func (c *APIClient) FindCustomerByTenant(ctx context.Context, tenantID string) (CustomerID, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	params := &stripego.CustomerSearchParams{
		SearchParams: stripego.SearchParams{
			Query:   fmt.Sprintf("metadata['tenant_id']:'%s'", tenantID),
			Context: ctx,
		},
	}
	params.Limit = stripego.Int64(1)
	iter := customer.Search(params)
	var found CustomerID
	for iter.Next() {
		found = CustomerID(iter.Customer().ID)
		break
	}
	mapped := mapStripeError(iter.Err())
	metrics.ObserveSubsystemCall("stripe", "FindCustomerByTenant", start, mapped)
	if mapped != nil {
		return "", mapped
	}
	if found == "" {
		return "", clients.ErrNotFound
	}
	return found, nil
}

// UpdateCustomer implements Client.
func (c *APIClient) UpdateCustomer(ctx context.Context, id CustomerID, metadata map[string]string) error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	params := &stripego.CustomerParams{}
	for k, v := range metadata {
		params.AddMetadata(k, v)
	}
	params.Context = ctx
	_, err := customer.Update(string(id), params)
	mapped := mapStripeError(err)
	metrics.ObserveSubsystemCall("stripe", "UpdateCustomer", start, mapped)
	return mapped
}

// CancelSubscription implements Client. Cancels ALL active subscriptions
// for the customer (no proration). Tenant teardown is intentionally hard.
func (c *APIClient) CancelSubscription(ctx context.Context, customerID CustomerID) error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	params := &stripego.SubscriptionListParams{
		Customer: stripego.String(string(customerID)),
	}
	params.Context = ctx
	it := subscription.List(params)
	for it.Next() {
		sub := it.Subscription()
		if sub.Status == stripego.SubscriptionStatusCanceled {
			continue
		}
		cancelParams := &stripego.SubscriptionCancelParams{}
		cancelParams.Context = ctx
		if _, err := subscription.Cancel(sub.ID, cancelParams); err != nil {
			mapped := mapStripeError(err)
			metrics.ObserveSubsystemCall("stripe", "CancelSubscription", start, mapped)
			return mapped
		}
	}
	if err := it.Err(); err != nil {
		mapped := mapStripeError(err)
		metrics.ObserveSubsystemCall("stripe", "CancelSubscription", start, mapped)
		return mapped
	}
	metrics.ObserveSubsystemCall("stripe", "CancelSubscription", start, nil)
	return nil
}

// DeleteCustomer implements Client.
func (c *APIClient) DeleteCustomer(ctx context.Context, id CustomerID) error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	params := &stripego.CustomerParams{}
	params.Context = ctx
	_, err := customer.Del(string(id), params)
	mapped := mapStripeError(err)
	metrics.ObserveSubsystemCall("stripe", "DeleteCustomer", start, mapped)
	return mapped
}

// Ping implements Client. Calls balance.Get to verify API credentials and
// reachability without any destructive side effects.
func (c *APIClient) Ping(_ context.Context) error {
	start := time.Now()
	_, err := balance.Get(nil)
	mapped := mapStripeError(err)
	metrics.ObserveSubsystemCall("stripe", "Ping", start, mapped)
	return mapped
}

// GetSubscription implements Client. Retrieves a Stripe subscription by ID and
// returns the minimal fields needed by the billing reconciler.
func (c *APIClient) GetSubscription(ctx context.Context, subscriptionID string) (*SubscriptionState, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	params := &stripego.SubscriptionParams{}
	params.Context = ctx
	sub, err := subscription.Get(subscriptionID, params)
	mapped := mapStripeError(err)
	metrics.ObserveSubsystemCall("stripe", "GetSubscription", start, mapped)
	if mapped != nil {
		return nil, mapped
	}

	state := &SubscriptionState{
		ID:       sub.ID,
		Status:   string(sub.Status),
		TrialEnd: sub.TrialEnd,
	}
	if len(sub.Items.Data) > 0 {
		item := sub.Items.Data[0]
		state.PriceID = item.Price.ID
		// CurrentPeriodEnd lives on the subscription item, not the subscription.
		state.CurrentPeriodEnd = item.CurrentPeriodEnd
	}
	if sub.Metadata != nil {
		state.TenantID = sub.Metadata["tenantId"]
	}
	return state, nil
}

// UpdateSubscriptionTrialEnd implements Client. Updates the trial_end of a
// Stripe subscription. trialEnd is the new trial end time; idempotencyKey
// must be unique per extension event to prevent duplicate extensions.
func (c *APIClient) UpdateSubscriptionTrialEnd(ctx context.Context, subscriptionID string, trialEnd time.Time, idempotencyKey string) error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	trialEndUnix := trialEnd.Unix()
	params := &stripego.SubscriptionParams{
		TrialEnd: &trialEndUnix,
	}
	params.Context = ctx
	params.SetIdempotencyKey(idempotencyKey)
	_, err := subscription.Update(subscriptionID, params)
	mapped := mapStripeError(err)
	metrics.ObserveSubsystemCall("stripe", "UpdateSubscriptionTrialEnd", start, mapped)
	return mapped
}

func mapStripeError(err error) error {
	if err == nil {
		return nil
	}
	var se *stripego.Error
	if errors.As(err, &se) {
		switch se.Code {
		case stripego.ErrorCodeResourceMissing:
			// "No such price" and similar resource-missing errors are permanent —
			// the referenced resource does not exist and retrying will not create it.
			return clients.WrapPermanent(fmt.Errorf("stripe: %v: %w", err, clients.ErrNotFound))
		case stripego.ErrorCodeRateLimit:
			return fmt.Errorf("stripe: %v: %w", err, clients.ErrRateLimited)
		}
		if se.HTTPStatusCode == 400 || se.HTTPStatusCode == 422 {
			// Validation failures (e.g. invalid price ID) are permanent.
			return clients.WrapPermanent(fmt.Errorf("stripe: %v: %w", err, clients.ErrInvalidInput))
		}
		if se.HTTPStatusCode == 401 || se.HTTPStatusCode == 403 {
			// Auth failures are permanent — require credential rotation.
			return clients.WrapPermanent(fmt.Errorf("stripe: %v: %w", err, clients.ErrUnauthorized))
		}
		if se.HTTPStatusCode == 429 {
			return fmt.Errorf("stripe: %v: %w", err, clients.ErrRateLimited)
		}
		if se.HTTPStatusCode >= 500 {
			return fmt.Errorf("stripe: %v: %w", err, clients.ErrUnreachable)
		}
	}
	return fmt.Errorf("stripe: %v: %w", err, clients.ErrUnreachable)
}
