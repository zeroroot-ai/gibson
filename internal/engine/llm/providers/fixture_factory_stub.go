// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build !test_fixtures

// fixture_factory_stub.go — production builds build no fixture provider
// (fixture_factory.go).

package providers

import (
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// newFixtureProvider builds nothing in a production build: every type that
// reaches it is unknown.
func newFixtureProvider(cfg llm.ProviderConfig) (llm.LLMProvider, error) {
	return nil, fmt.Errorf("new provider: %w", llm.NewInvalidInputError("factory", unknownTypeMessage(cfg)))
}
