// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// TestTaxonomyRegistry_NilRegistry tests that TaxonomyRegistry() returns nil
// when no registry is configured.
func TestTaxonomyRegistry_NilRegistry(t *testing.T) {
	// Create a harness with nil taxonomy registry
	h := &DefaultAgentHarness{
		taxonomyRegistry: nil,
	}

	// Should return nil when not configured
	registry := h.TaxonomyRegistry()
	assert.Nil(t, registry, "expected nil registry when not configured")
}

// TestTaxonomyRegistry_WithRegistry tests that TaxonomyRegistry() returns
// the configured registry.
func TestTaxonomyRegistry_WithRegistry(t *testing.T) {
	// Create a taxonomy registry with core taxonomy
	coreTaxonomy := sdkgraphrag.NewSimpleTaxonomy()
	taxonomyRegistry := sdkgraphrag.NewTaxonomyRegistry(coreTaxonomy)

	// Create a harness with the registry
	h := &DefaultAgentHarness{
		taxonomyRegistry: taxonomyRegistry,
	}

	// Should return the configured registry
	registry := h.TaxonomyRegistry()
	require.NotNil(t, registry, "expected non-nil registry")

	// Verify we can query the registry
	version := registry.Version()
	assert.NotEmpty(t, version, "expected non-empty taxonomy version")

	// Verify we can get node types
	nodeTypes := registry.NodeTypes()
	assert.NotEmpty(t, nodeTypes, "expected core taxonomy to have node types")

	// Verify core types exist (taxonomy uses lowercase names)
	hostInfo := registry.NodeTypeInfo("host")
	require.NotNil(t, hostInfo, "expected host node type to exist in core taxonomy")
	assert.Equal(t, "host", hostInfo.Name)
}

// TestTaxonomyRegistry_Version tests that the taxonomy version is accessible
// through the harness.
func TestTaxonomyRegistry_Version(t *testing.T) {
	// Create a taxonomy registry with core taxonomy
	coreTaxonomy := sdkgraphrag.NewSimpleTaxonomy()
	taxonomyRegistry := sdkgraphrag.NewTaxonomyRegistry(coreTaxonomy)

	// Create harness
	h := &DefaultAgentHarness{
		taxonomyRegistry: taxonomyRegistry,
	}

	registry := h.TaxonomyRegistry()
	require.NotNil(t, registry)

	// Get taxonomy version
	version := registry.Version()
	assert.NotEmpty(t, version, "expected non-empty taxonomy version")
	assert.Regexp(t, `^\d+\.\d+\.\d+$`, version, "expected semver format")
}
