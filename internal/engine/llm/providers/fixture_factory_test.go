// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build test_fixtures

package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	mockllm "github.com/zeroroot-ai/gibson/tests/e2e/fixtures/providers/mock-llm"
)

// In a fixture build with the gate on, the factory builds the e2e mock for
// the fixture type (hosted#358). With the gate off it knows no such type.
func TestNewProvider_TheFixtureTypeNeedsTheFixtureGate(t *testing.T) {
	assert.Equal(t, mockllm.ProviderName, string(llm.FixtureProviderType),
		"the fixture type is the mock's registry name")

	t.Setenv("GIBSON_TEST_FIXTURES_ENABLED", "true")
	assert.Contains(t, llm.AcceptedProviderTypes(), llm.FixtureProviderType)
	p, err := NewProvider(llm.ProviderConfig{Type: llm.FixtureProviderType})
	require.NoError(t, err)
	assert.Equal(t, mockllm.ProviderName, p.Name())

	t.Setenv("GIBSON_TEST_FIXTURES_ENABLED", "false")
	assert.NotContains(t, llm.AcceptedProviderTypes(), llm.FixtureProviderType)
	_, err = NewProvider(llm.ProviderConfig{Type: llm.FixtureProviderType})
	require.Error(t, err)
}
