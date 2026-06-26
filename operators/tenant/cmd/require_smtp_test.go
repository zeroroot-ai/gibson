// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

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
