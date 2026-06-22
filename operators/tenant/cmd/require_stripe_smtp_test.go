/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package main

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// validateStripeEnvKey
// ---------------------------------------------------------------------------

func TestValidateStripeEnvKey_Missing(t *testing.T) {
	t.Parallel()
	err := validateStripeEnvKey(func(string) string { return "" })
	if err == nil {
		t.Fatal("expected error when STRIPE_API_KEY is missing, got nil")
	}
}

func TestValidateStripeEnvKey_Present(t *testing.T) {
	t.Parallel()
	getenv := func(k string) string {
		if k == "STRIPE_API_KEY" {
			return "sk_test_abc123"
		}
		return ""
	}
	if err := validateStripeEnvKey(getenv); err != nil {
		t.Fatalf("expected nil error when STRIPE_API_KEY is set, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// validateSMTPEnvKey
// ---------------------------------------------------------------------------

func TestValidateSMTPEnvKey_Missing(t *testing.T) {
	t.Parallel()
	err := validateSMTPEnvKey(func(string) string { return "" })
	if err == nil {
		t.Fatal("expected error when SMTP_HOST is missing, got nil")
	}
}

func TestValidateSMTPEnvKey_Present(t *testing.T) {
	t.Parallel()
	getenv := func(k string) string {
		if k == "SMTP_HOST" {
			return "smtp.example.com"
		}
		return ""
	}
	if err := validateSMTPEnvKey(getenv); err != nil {
		t.Fatalf("expected nil error when SMTP_HOST is set, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// validateStripeMode (epic card-first-signup / dashboard#767)
// ---------------------------------------------------------------------------

func stripeModeEnv(expected, key string) func(string) string {
	return func(k string) string {
		switch k {
		case "STRIPE_EXPECTED_MODE":
			return expected
		case "STRIPE_API_KEY":
			return key
		default:
			return ""
		}
	}
}

func TestValidateStripeMode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		expected string
		key      string
		wantErr  string // substring; "" = expect success
	}{
		{"test mode with test key", "test", "sk_test_abc", ""},
		{"live mode with live key", "live", "sk_live_abc", ""},
		{"restricted test key", "test", "rk_test_abc", ""},
		{"restricted live key", "live", "rk_live_abc", ""},
		{"expected unset", "", "sk_test_abc", "STRIPE_EXPECTED_MODE is required"},
		{"expected garbage", "sandbox", "sk_test_abc", "must be"},
		{"live expected, test key", "live", "sk_test_abc", "mismatch"},
		{"test expected, live key", "test", "sk_live_abc", "mismatch"},
		{"unrecognised key prefix", "test", "pk_test_abc", "unrecognised prefix"},
		{"empty key", "test", "", "unrecognised prefix"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateStripeMode(stripeModeEnv(tc.expected, tc.key))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}
