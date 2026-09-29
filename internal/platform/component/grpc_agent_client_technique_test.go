// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// TestGRPCAgentClientTechniqueTypesFromMetadata covers the no-descriptor path
// (ADR-0035, gibson#385): technique types parsed from the registry's
// comma-separated metadata are taxonomy category ids, not the retired
// types.TechniqueType enum.
func TestGRPCAgentClientTechniqueTypesFromMetadata(t *testing.T) {
	c := &GRPCAgentClient{
		info: ComponentInfo{
			Metadata: map[string]string{
				"technique_types": "prompt_injection,jailbreak",
			},
		},
	}

	got := c.TechniqueTypes()

	assert.Equal(t, []taxonomy.CategoryID{"prompt_injection", "jailbreak"}, got)
}

// TestGRPCAgentClientTechniqueTypesFromMetadataEmpty covers the missing-key case.
func TestGRPCAgentClientTechniqueTypesFromMetadataEmpty(t *testing.T) {
	c := &GRPCAgentClient{info: ComponentInfo{Metadata: map[string]string{}}}

	got := c.TechniqueTypes()

	assert.Empty(t, got)
}

// TestGRPCAgentClientTechniqueTypesFromCachedDescriptor proves a cached
// descriptor wins over metadata (mirrors TargetTypes' own contract), and that
// the descriptor's TechniqueTypes field carries taxonomy category ids
// end-to-end.
func TestGRPCAgentClientTechniqueTypesFromCachedDescriptor(t *testing.T) {
	c := &GRPCAgentClient{
		descriptor: &agent.AgentDescriptor{
			TechniqueTypes: []taxonomy.CategoryID{"custom"},
		},
		// Deliberately disagrees with the descriptor, to prove metadata is
		// never consulted once a descriptor is cached.
		info: ComponentInfo{Metadata: map[string]string{"technique_types": "jailbreak"}},
	}

	got := c.TechniqueTypes()

	assert.Equal(t, []taxonomy.CategoryID{"custom"}, got)
}

// TestConvertTechniqueTypes covers the proto-response conversion path
// (fetchDescriptor), which the same ADR-0035 migration retargeted from
// TechniqueType to taxonomy.CategoryID.
func TestConvertTechniqueTypes(t *testing.T) {
	got := convertTechniqueTypes([]string{"prompt_injection", "dos"})

	assert.Equal(t, []taxonomy.CategoryID{"prompt_injection", "dos"}, got)
}

func TestConvertTechniqueTypesEmpty(t *testing.T) {
	got := convertTechniqueTypes(nil)

	assert.Empty(t, got)
}
