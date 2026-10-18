// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build test_fixtures

// fixture_factory.go — builds the e2e mock provider for its fixture type.
//
// ONLY compiled with -tags=test_fixtures (fixture_factory_stub.go is the
// production build), and it builds the mock only when the runtime fixture gate
// is on (llm.IsFixtureProviderType).

package providers

import (
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	mockllm "github.com/zeroroot-ai/gibson/tests/e2e/fixtures/providers/mock-llm"
)

// fixtureProvider returns the e2e mock provider for its fixture type.
func fixtureProvider(cfg llm.ProviderConfig) (llm.LLMProvider, bool) {
	if !llm.IsFixtureProviderType(cfg.Type) {
		return nil, false
	}
	return mockllm.New(), true
}
