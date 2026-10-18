// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build !test_fixtures

// fixture_factory_stub.go — production builds build no fixture provider
// (fixture_factory.go).

package providers

import "github.com/zeroroot-ai/gibson/internal/engine/llm"

// fixtureProvider builds nothing in a production build.
func fixtureProvider(llm.ProviderConfig) (llm.LLMProvider, bool) { return nil, false }
