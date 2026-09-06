// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"testing"

	"github.com/go-logr/logr/testr"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/controller"
)

// env returns a getenv func that reads from a fixed map, so tests control env
// state without os.Setenv (same approach as system_tenant_kek_test.go).
func env(kv map[string]string) func(string) string {
	return func(key string) string { return kv[key] }
}

// TestSelectStripeCustomerVerifier_NoAPIKey returns a no-op when
// STRIPE_API_KEY is empty (OSS / self-hosted deployment).
func TestSelectStripeCustomerVerifier_NoAPIKey(t *testing.T) {
	v := selectStripeCustomerVerifier(env(map[string]string{}), testr.New(t))
	if _, ok := v.(controller.NoopStripeCustomerVerifier); !ok {
		t.Errorf("expected NoopStripeCustomerVerifier when no key, got %T", v)
	}
}

// TestSelectStripeCustomerVerifier_WithAPIKeyNoBaseURL returns a
// MetadataStripeCustomerVerifier when STRIPE_API_KEY is set and
// STRIPE_API_BASE_URL is empty (hosted deployment against real Stripe).
func TestSelectStripeCustomerVerifier_WithAPIKeyNoBaseURL(t *testing.T) {
	v := selectStripeCustomerVerifier(env(map[string]string{
		"STRIPE_API_KEY": "sk_test_realkey",
	}), testr.New(t))
	m, ok := v.(*controller.MetadataStripeCustomerVerifier)
	if !ok {
		t.Fatalf("expected *MetadataStripeCustomerVerifier when API key set, got %T", v)
	}
	f, ok := m.Fetcher.(*controller.HTTPStripeCustomerFetcher)
	if !ok {
		t.Fatalf("expected HTTPStripeCustomerFetcher, got %T", m.Fetcher)
	}
	if f.APIKey != "sk_test_realkey" {
		t.Errorf("APIKey = %q, want %q", f.APIKey, "sk_test_realkey")
	}
}

// TestSelectStripeCustomerVerifier_APIKeyWithBaseURL returns a no-op when
// STRIPE_API_BASE_URL is set (dev stripe-mock redirect — the mock serves
// canned fixtures with no real tenant_id metadata, so the verifier must not
// consult it; adoption must be unaffected).
func TestSelectStripeCustomerVerifier_APIKeyWithBaseURL(t *testing.T) {
	v := selectStripeCustomerVerifier(env(map[string]string{
		"STRIPE_API_KEY":      "sk_test_x",
		"STRIPE_API_BASE_URL": "http://stripe-mock:12111",
	}), testr.New(t))
	if _, ok := v.(controller.NoopStripeCustomerVerifier); !ok {
		t.Errorf("expected NoopStripeCustomerVerifier when mock redirect set, got %T", v)
	}
}
