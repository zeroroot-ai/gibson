/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package main

import (
	"fmt"
	"strings"
)

// validateStripeMode is the card-first-signup (epic, dashboard#767) boot
// contract that staging runs Stripe TEST mode and production runs LIVE
// mode — so a dummy card is the only thing that works on staging and a
// real card is required in prod, and the two can never be crossed by a
// mis-mounted secret.
//
// STRIPE_EXPECTED_MODE is the declared mode for the environment ("test"
// or "live"); the chart sets it per overlay (kind/staging=test,
// prod=live) and it is required (no silent default — one-code-path
// ADR-0003). The check asserts the live STRIPE_API_KEY's prefix matches:
// sk_test_/rk_test_ ⇒ test, sk_live_/rk_live_ ⇒ live. Any mismatch, an
// unknown expected mode, or an unrecognised key prefix fails the boot
// (fail-closed). Pure functor for testability; main() wires os.Getenv.
func validateStripeMode(getenv func(string) string) error {
	expected := getenv("STRIPE_EXPECTED_MODE")
	if expected == "" {
		return fmt.Errorf(
			"STRIPE_EXPECTED_MODE is required (epic card-first-signup / dashboard#767): " +
				"set it to \"test\" (kind/staging — dummy cards only) or \"live\" " +
				"(production — real cards); the chart sets it per env overlay",
		)
	}
	if expected != stripeModeTest && expected != stripeModeLive {
		return fmt.Errorf(
			"STRIPE_EXPECTED_MODE must be %q or %q, got %q",
			stripeModeTest, stripeModeLive, expected,
		)
	}
	key := getenv("STRIPE_API_KEY")
	actual, err := stripeKeyMode(key)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf(
			"Stripe key/mode mismatch: STRIPE_EXPECTED_MODE=%q but STRIPE_API_KEY is a %q-mode key — "+
				"refusing to boot (a %q-mode key in a %q environment would let the wrong cards through)",
			expected, actual, actual, expected,
		)
	}
	return nil
}

const (
	stripeModeTest = "test"
	stripeModeLive = "live"
)

// stripeKeyMode derives test/live from a Stripe secret or restricted key
// prefix. Returns an error for an empty or unrecognised key so the boot
// guard fails closed rather than guessing the environment's billing mode.
func stripeKeyMode(key string) (string, error) {
	switch {
	case strings.HasPrefix(key, "sk_test_"), strings.HasPrefix(key, "rk_test_"):
		return stripeModeTest, nil
	case strings.HasPrefix(key, "sk_live_"), strings.HasPrefix(key, "rk_live_"):
		return stripeModeLive, nil
	default:
		return "", fmt.Errorf(
			"STRIPE_API_KEY has an unrecognised prefix; expected sk_test_/rk_test_ or sk_live_/rk_live_ " +
				"(card-first-signup mode guard cannot determine test vs live)",
		)
	}
}

// validateStripeEnvKey is the one-code-path (tenant-operator#95) startup
// contract for the Stripe billing client. The operator refuses to boot when
// STRIPE_API_KEY is absent. The previous behaviour (silently nil Stripe client
// → billing saga steps skipped for non-enterprise-deploy tenants) masked
// operator misconfiguration as phantom billing success.
//
// Enterprise-deploy tenants are excluded at the saga.Skip() level via
// skipUnbilledTier; every other tier requires a live Stripe client.
//
// The function is pure (takes a getenv functor) so the contract is testable
// without mutating process environment. main() wires it via os.Getenv.
func validateStripeEnvKey(getenv func(string) string) error {
	if getenv("STRIPE_API_KEY") == "" {
		return fmt.Errorf(
			"STRIPE_API_KEY is required (one-code-path / tenant-operator#95): " +
				"billing saga steps (CreateStripeCustomer, CancelStripeSubscription, " +
				"DeleteStripeCustomer) require a live Stripe client; " +
				"enterprise-deploy tenants are already excluded at the saga Skip() level",
		)
	}
	return nil
}

// validateSMTPEnvKey is the one-code-path (tenant-operator#95) startup
// contract for the SMTP mail sender. The operator refuses to boot when
// SMTP_HOST is absent. The previous behaviour (NullSender default → email
// silently discarded) masked missing SMTP configuration as phantom delivery.
//
// The function is pure (takes a getenv functor) so the contract is testable
// without mutating process environment. main() wires it via os.Getenv.
func validateSMTPEnvKey(getenv func(string) string) error {
	if getenv("SMTP_HOST") == "" {
		return fmt.Errorf(
			"SMTP_HOST is required (one-code-path / tenant-operator#95): " +
				"the operator sends transactional email (welcome, invitations) via SMTP; " +
				"set SMTP_HOST to enable email delivery",
		)
	}
	return nil
}
