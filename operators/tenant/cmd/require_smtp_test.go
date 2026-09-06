// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import "testing"

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
