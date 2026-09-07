// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

package e2e

import (
	"os"
	"testing"
)

// checkTestFixturesEnabled is the FIRST gate in every cluster-bound e2e test
// that relies on the mock LLM provider or on test-only target registration.
// It enforces the production-safety contract:
//
//	The mock LLM provider and the test-only fixtures MUST NOT run without the
//	explicit opt-in env var. Checking this BEFORE loading any other env var
//	makes an accidental run against a production cluster fail fast with a
//	clear message.
//
// cmd/fixtures-lint enforces that GIBSON_TEST_FIXTURES_ENABLED is absent from
// every production overlay.
func checkTestFixturesEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("GIBSON_TEST_FIXTURES_ENABLED") != "true" {
		t.Fatal(
			"e2e: test fixtures must be enabled to run this suite. " +
				"Set GIBSON_TEST_FIXTURES_ENABLED=true in the test environment. " +
				"NEVER set this in a production deployment overlay; " +
				"cmd/fixtures-lint enforces that it is absent from all production overlays.",
		)
	}
}
