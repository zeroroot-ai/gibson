// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build !test_fixtures

// Package llm defines the LLM provider contract, the provider types and the
// slot model of the daemon. In a production build it knows no fixture
// provider type (fixture_provider_type.go is the fixture build).
package llm

// IsFixtureProviderType is false in every production build.
func IsFixtureProviderType(ProviderType) bool { return false }
