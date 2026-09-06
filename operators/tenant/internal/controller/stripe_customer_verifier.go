// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// stripe_customer_verifier.go — defense-in-depth ownership check on
// stripe_customer_id adoption (gibson#1099, residual of the signup/
// entitlements seam assessment gibson#1093, threat-model path B2).
//
// The signup path lets the client pin a pre-created stripe_customer_id
// (signup.proto; the daemon only records it). The PRIMARY control is the
// dashboard's verifySignupCustomer gate (src/lib/billing/stripe.ts), which
// checks the customer's email against the signup email before any
// subscription is created. This file adds the residual reconciler-side
// check: when the pending-provisioning drain ADOPTS the recorded id onto
// the Tenant CR (the gibson.zeroroot.ai/stripe-customer-id annotation the
// downstream billing path trusts, adopt-don't-duplicate contract,
// tenant-operator#354), it re-verifies the customer actually belongs to
// this tenant instead of trusting the recorded id alone — so a future code
// path that reaches adoption without the dashboard gate cannot silently
// attach a wrong or forged customer.
//
// Ownership is established by the tenant-linkage metadata the CREATION
// path writes: the dashboard's findOrCreateSignupCustomer tags the signup
// customer with metadata.tenant_id = <slug> (and the closed billing tier's
// CustomerSpec contract likewise requires "tenant_id"). Verification
// therefore checks metadata["tenant_id"] == tenant name.
//
// Seam posture (mirrors pkg/billing: the no-op is the bypass): OSS /
// self-hosted operators carry no Stripe credentials (E7/gibson#798) and
// bind NoopStripeCustomerVerifier — adoption is unaffected. Hosted
// deployments (STRIPE_API_KEY set, no dev STRIPE_API_BASE_URL redirect)
// bind the metadata verifier backed by a read-only Stripe customer fetch.

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// stripeMetadataTenantIDKey is the customer-metadata key the creation path
// writes to link a Stripe customer to its tenant: the dashboard's
// findOrCreateSignupCustomer (src/lib/billing/stripe.ts) sets
// metadata.tenant_id = <slug>, and the closed billing tier's CustomerSpec
// requires the same key. Byte-identical here so verification checks exactly
// the linkage creation establishes.
const stripeMetadataTenantIDKey = "tenant_id"

// ErrStripeCustomerMismatch is the permanent verification failure: the
// recorded customer exists but does not belong to this tenant (wrong
// tenant_id metadata, no linkage metadata at all, deleted, or missing).
// Callers must NOT adopt the customer. Distinguished from transient fetch
// errors (Stripe unreachable), which callers retry.
var ErrStripeCustomerMismatch = errors.New(
	"stripe customer ownership mismatch: recorded stripe_customer_id does not belong to this tenant")

// StripeCustomerVerifier verifies that a recorded stripe_customer_id belongs
// to the tenant before the pending-provisioning drain adopts it onto the
// Tenant CR. Implementations return nil to allow adoption,
// ErrStripeCustomerMismatch (wrapped) to permanently refuse it, and any other
// error for transient verification failure (retried next drain).
//
// Always non-nil on the drain path: cmd/main.go injects
// NoopStripeCustomerVerifier when the operator has no Stripe credentials, so
// verification is disabled by substituting a no-op rather than a nil-guard
// (same pattern as TenantStatusReporter / NoopTenantStatusReporter).
type StripeCustomerVerifier interface {
	VerifyStripeCustomer(ctx context.Context, customerID, tenantID string) error
}

// NoopStripeCustomerVerifier is the OSS / self-hosted default: the operator
// carries no Stripe client (E7/gibson#798), billing is bypassed (pkg/billing
// no-op posture), and adoption proceeds exactly as before — the no-op path
// is unaffected by this check.
type NoopStripeCustomerVerifier struct{}

// VerifyStripeCustomer always allows adoption.
func (NoopStripeCustomerVerifier) VerifyStripeCustomer(context.Context, string, string) error {
	return nil
}

// StripeCustomer is the minimal slice of a Stripe customer the ownership
// check needs.
type StripeCustomer struct {
	ID       string            `json:"id"`
	Deleted  bool              `json:"deleted"`
	Metadata map[string]string `json:"metadata"`
}

// ErrStripeCustomerNotFound is returned by fetchers when the customer id does
// not exist (Stripe 404 / resource_missing). The metadata verifier maps it to
// ErrStripeCustomerMismatch: a nonexistent customer must never be adopted.
var ErrStripeCustomerNotFound = errors.New("stripe customer not found")

// StripeCustomerFetcher is the narrow read-only slice of a Stripe client the
// metadata verifier needs (mirrors health.StripePinger: a narrow interface so
// tests inject fakes without a concrete Stripe dependency).
type StripeCustomerFetcher interface {
	FetchStripeCustomer(ctx context.Context, customerID string) (*StripeCustomer, error)
}

// MetadataStripeCustomerVerifier verifies ownership via the tenant-linkage
// metadata the creation path writes: adoption is allowed only when the
// fetched customer is live and carries metadata tenant_id == tenantID.
// Absent linkage metadata is a mismatch — every platform-created signup
// customer carries the tag, so an untagged customer is by definition not
// this tenant's.
type MetadataStripeCustomerVerifier struct {
	Fetcher StripeCustomerFetcher
}

// VerifyStripeCustomer implements StripeCustomerVerifier.
func (v *MetadataStripeCustomerVerifier) VerifyStripeCustomer(ctx context.Context, customerID, tenantID string) error {
	cust, err := v.Fetcher.FetchStripeCustomer(ctx, customerID)
	if err != nil {
		if errors.Is(err, ErrStripeCustomerNotFound) {
			return fmt.Errorf("customer %q does not exist: %w", customerID, ErrStripeCustomerMismatch)
		}
		// Transient (Stripe unreachable, auth, rate-limit): NOT a mismatch —
		// the caller retries next drain rather than permanently refusing.
		return fmt.Errorf("fetch stripe customer %q for ownership verification: %w", customerID, err)
	}
	if cust.Deleted {
		return fmt.Errorf("customer %q is deleted: %w", customerID, ErrStripeCustomerMismatch)
	}
	if got := cust.Metadata[stripeMetadataTenantIDKey]; got != tenantID {
		return fmt.Errorf("customer %q metadata %s=%q, want %q: %w",
			customerID, stripeMetadataTenantIDKey, got, tenantID, ErrStripeCustomerMismatch)
	}
	return nil
}

// defaultStripeAPIBaseURL is the live Stripe API origin.
const defaultStripeAPIBaseURL = "https://api.stripe.com"

// stripeFetchTimeout bounds the read-only customer retrieve.
const stripeFetchTimeout = 10 * time.Second

// HTTPStripeCustomerFetcher retrieves customers via a plain read-only
// GET /v1/customers/{id}. Deliberately net/http only — gibson never takes a
// hard Stripe SDK dependency (open-core rule: billing is the one closed
// seam); this is the minimal read needed for the defense-in-depth check.
type HTTPStripeCustomerFetcher struct {
	// APIKey is the Stripe secret key (sk_...).
	APIKey string
	// BaseURL overrides the Stripe API origin (tests). Empty → live Stripe.
	BaseURL string
	// Client overrides the HTTP client (tests). Nil → default with timeout.
	Client *http.Client
}

// FetchStripeCustomer implements StripeCustomerFetcher.
func (f *HTTPStripeCustomerFetcher) FetchStripeCustomer(ctx context.Context, customerID string) (*StripeCustomer, error) {
	base := f.BaseURL
	if base == "" {
		base = defaultStripeAPIBaseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/v1/customers/"+url.PathEscape(customerID), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build stripe customer request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+f.APIKey)

	hc := f.Client
	if hc == nil {
		hc = &http.Client{Timeout: stripeFetchTimeout}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stripe customer retrieve: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read stripe customer response: %w", err)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("stripe customer %q: %w", customerID, ErrStripeCustomerNotFound)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("stripe customer retrieve: status %d: %s", resp.StatusCode, truncate(body, 256))
	}
	var cust StripeCustomer
	if err := json.Unmarshal(body, &cust); err != nil {
		return nil, fmt.Errorf("decode stripe customer response: %w", err)
	}
	return &cust, nil
}

// truncate caps an error-body excerpt.
func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
