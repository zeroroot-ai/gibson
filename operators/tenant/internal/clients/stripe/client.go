/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package stripe is the operator's client to Stripe for customer and
// subscription lifecycle tied to Tenant lifecycle.
package stripe

import (
	"context"
	"time"
)

// CustomerID is the Stripe customer identifier.
type CustomerID string

// CustomerSpec describes a Stripe customer to create.
type CustomerSpec struct {
	Email    string
	Name     string
	Metadata map[string]string // must include "tenant_id" and "tier"
}

// SubscriptionState holds the minimal fields from a Stripe subscription
// needed by the operator for billing enforcement and drift detection.
type SubscriptionState struct {
	// ID is the Stripe subscription ID (sub_...).
	ID string
	// Status is the Stripe subscription status (trialing, active, past_due,
	// canceled, incomplete, incomplete_expired).
	Status string
	// PriceID is the Stripe price ID of the first line item.
	PriceID string
	// CurrentPeriodEnd is the Unix timestamp of the end of the current billing period.
	CurrentPeriodEnd int64
	// TrialEnd is the Unix timestamp of the trial end. Zero if not trialing.
	TrialEnd int64
	// TenantID is the tenantId value from the subscription's metadata field.
	TenantID string
}

// Client is the Stripe integration interface.
type Client interface {
	CreateCustomer(ctx context.Context, spec CustomerSpec) (CustomerID, error)
	UpdateCustomer(ctx context.Context, id CustomerID, metadata map[string]string) error
	CancelSubscription(ctx context.Context, customerID CustomerID) error
	DeleteCustomer(ctx context.Context, id CustomerID) error

	// FindCustomerByTenant looks up an existing customer carrying
	// metadata tenant_id=<tenantID>. Returns clients.ErrNotFound when
	// none exists. Callers must treat any other error as
	// "search unavailable" and fall back to creation — stripe-mock
	// (kind dev) does not implement /v1/customers/search.
	// (tenant-operator#354 adopt-don't-duplicate contract.)
	FindCustomerByTenant(ctx context.Context, tenantID string) (CustomerID, error)

	// GetSubscription retrieves a Stripe subscription by ID and returns its
	// current state. Used by the billing reconciler for drift detection and
	// trial enforcement.
	GetSubscription(ctx context.Context, subscriptionID string) (*SubscriptionState, error)

	// UpdateSubscriptionTrialEnd updates the trial_end of a Stripe subscription.
	// trialEnd is a Unix timestamp (seconds). idempotencyKey must be unique per
	// extension event to prevent duplicate extensions.
	UpdateSubscriptionTrialEnd(ctx context.Context, subscriptionID string, trialEnd time.Time, idempotencyKey string) error

	// Ping calls balance.Retrieve to verify the Stripe API key is valid and
	// the API is reachable. A successful call (any non-error response) is
	// treated as healthy.
	Ping(ctx context.Context) error
}

// Config holds connection details.
type Config struct {
	APIKey     string
	APIVersion string
	Timeout    time.Duration
}
