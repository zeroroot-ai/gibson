// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build test_fixtures

// fixture_provider_type.go — the e2e mock provider as a tenant provider type.
//
// ONLY compiled with -tags=test_fixtures. Production `make bin` never uses that
// tag, so the type does not exist in a production binary
// (fixture_provider_type_stub.go). Even in a fixture build the type is known
// only when GIBSON_TEST_FIXTURES_ENABLED=true.
//
// It lets an exit test configure the deterministic e2e mock provider for a
// tenant through the normal ProviderService RPC, so the tenant's own slot
// manager and its model gate serve it (hosted#358).

// Package llm defines the LLM provider contract, the provider types and the
// slot model of the daemon. This file adds the e2e mock provider type to a
// fixture build.
package llm

import "os"

// FixtureProviderType is the provider type of the e2e mock provider. It equals
// the mock's registry name (tests/e2e/fixtures/providers/mock-llm ProviderName).
const FixtureProviderType ProviderType = "mock-llm-e2e-test"

// IsFixtureProviderType reports whether t is the e2e mock provider type and
// the runtime fixture gate is on.
func IsFixtureProviderType(t ProviderType) bool {
	return t == FixtureProviderType && os.Getenv("GIBSON_TEST_FIXTURES_ENABLED") == "true"
}

// fixtureProviderTypes holds the e2e mock type when the fixture gate is on.
func fixtureProviderTypes() []ProviderType {
	if !IsFixtureProviderType(FixtureProviderType) {
		return nil
	}
	return []ProviderType{FixtureProviderType}
}
