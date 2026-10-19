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
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	mockllm "github.com/zeroroot-ai/gibson/tests/e2e/fixtures/providers/mock-llm"
)

// newFixtureProvider returns the e2e mock provider for its fixture type, and
// the unknown type error for every other type.
func newFixtureProvider(cfg llm.ProviderConfig) (llm.LLMProvider, error) {
	if !llm.IsFixtureProviderType(cfg.Type) {
		return nil, fmt.Errorf("new provider: %w", llm.NewInvalidInputError("factory", unknownTypeMessage(cfg)))
	}
	return mockllm.New(), nil
}
