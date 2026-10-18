// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build !test_fixtures

package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// A production build knows no fixture provider type, whatever the runtime
// flag says.
func TestNewProvider_AProductionBuildKnowsNoFixtureType(t *testing.T) {
	t.Setenv("GIBSON_TEST_FIXTURES_ENABLED", "true")
	assert.False(t, llm.IsFixtureProviderType("mock-llm-e2e-test"))
	_, err := NewProvider(llm.ProviderConfig{Type: "mock-llm-e2e-test"})
	require.Error(t, err)
}
