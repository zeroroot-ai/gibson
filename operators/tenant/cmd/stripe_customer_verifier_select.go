// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// stripe_customer_verifier_select.go — env-driven selection of the
// StripeCustomerVerifier implementation wired into the pending-provisioning
// drain (gibson#1099 defense-in-depth).
//
// Extracted from cmd/main.go so the env-decision logic is unit-testable
// (mirrors loadSystemTenantKEK / system_tenant_kek.go, same package).
// cmd/main.go calls selectStripeCustomerVerifier(os.Getenv, setupLog).

package main

import (
	"github.com/go-logr/logr"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/controller"
)

// selectStripeCustomerVerifier reads the two governing env vars and returns
// the appropriate StripeCustomerVerifier:
//
//   - STRIPE_API_KEY set AND STRIPE_API_BASE_URL empty → MetadataStripeCustomerVerifier
//     backed by HTTPStripeCustomerFetcher (hosted deployments, real Stripe).
//   - Otherwise → NoopStripeCustomerVerifier (OSS/self-hosted: no Stripe
//     credentials; or dev stripe-mock redirect: the mock serves canned
//     fixtures with no real tenant_id metadata).
//
// The getenv argument is injected so tests can drive env state without
// calling os.Setenv (same pattern as other env-driven helpers in this
// package).
func selectStripeCustomerVerifier(getenv func(string) string, log logr.Logger) controller.StripeCustomerVerifier {
	key := getenv("STRIPE_API_KEY")
	if key != "" && getenv("STRIPE_API_BASE_URL") == "" {
		log.Info("stripe customer ownership verification on adoption ENABLED (gibson#1099)")
		return &controller.MetadataStripeCustomerVerifier{
			Fetcher: &controller.HTTPStripeCustomerFetcher{APIKey: key},
		}
	}
	log.Info("stripe customer ownership verification on adoption disabled " +
		"(no STRIPE_API_KEY, or dev STRIPE_API_BASE_URL redirect set) — no-op verifier bound (gibson#1099)")
	return controller.NoopStripeCustomerVerifier{}
}
