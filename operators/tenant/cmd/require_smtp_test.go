/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

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
