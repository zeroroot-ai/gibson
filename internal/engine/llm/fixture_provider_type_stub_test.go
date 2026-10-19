// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build !test_fixtures

package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A production build knows no fixture provider type, so it accepts exactly
// the supported provider types (hosted#358).
func TestAcceptedProviderTypes_ProductionBuildAddsNoFixtureType(t *testing.T) {
	assert.Empty(t, fixtureProviderTypes())
	assert.Equal(t, SupportedProviderTypes(), AcceptedProviderTypes())
}
