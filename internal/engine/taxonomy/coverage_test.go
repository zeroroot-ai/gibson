// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package taxonomy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// NewCoverage validates every declared id against the hierarchy (ADR-0035
// decision 4, gibson#386 acceptance criterion 3: "validated against the
// taxonomy").
// ---------------------------------------------------------------------------

func testHierarchy(t *testing.T) *TechniqueHierarchy {
	t.Helper()
	h, err := NewTechniqueHierarchy(
		[]CategoryID{"prompt_injection", "data_exfiltration"},
		map[TechniqueID]CategoryID{
			"direct_prompt_injection":   "prompt_injection",
			"indirect_prompt_injection": "prompt_injection",
		},
	)
	require.NoError(t, err)
	return h
}

func TestNewCoverage_AcceptsAdmittedCategoriesAndTechniques(t *testing.T) {
	h := testHierarchy(t)

	cov, err := NewCoverage(h,
		[]CategoryID{"prompt_injection"},
		[]TechniqueID{"direct_prompt_injection"},
	)
	require.NoError(t, err)

	assert.True(t, cov.HasCategory("prompt_injection"))
	assert.True(t, cov.HasTechnique("direct_prompt_injection"))
	assert.False(t, cov.HasCategory("data_exfiltration"))
	assert.False(t, cov.HasTechnique("indirect_prompt_injection"))
	assert.ElementsMatch(t, []CategoryID{"prompt_injection"}, cov.Categories())
	assert.ElementsMatch(t, []TechniqueID{"direct_prompt_injection"}, cov.Techniques())
	assert.False(t, cov.IsEmpty())
}

func TestNewCoverage_RejectsUnknownCategory(t *testing.T) {
	h := testHierarchy(t)

	_, err := NewCoverage(h, []CategoryID{"not_a_real_category"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not_a_real_category")
}

func TestNewCoverage_RejectsUnknownTechnique(t *testing.T) {
	h := testHierarchy(t)

	_, err := NewCoverage(h, nil, []TechniqueID{"not_a_real_technique"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not_a_real_technique")
}

func TestNewCoverage_RejectsNilHierarchy(t *testing.T) {
	_, err := NewCoverage(nil, []CategoryID{"prompt_injection"}, nil)
	require.Error(t, err)
}

func TestNewCoverage_DedupesRepeatedIDs(t *testing.T) {
	h := testHierarchy(t)

	cov, err := NewCoverage(h,
		[]CategoryID{"prompt_injection", "prompt_injection"},
		[]TechniqueID{"direct_prompt_injection", "direct_prompt_injection"},
	)
	require.NoError(t, err)
	assert.Len(t, cov.Categories(), 1)
	assert.Len(t, cov.Techniques(), 1)
}

func TestNewCoverage_EmptyDeclarationIsEmpty(t *testing.T) {
	h := testHierarchy(t)

	cov, err := NewCoverage(h, nil, nil)
	require.NoError(t, err)
	assert.True(t, cov.IsEmpty())
	assert.Empty(t, cov.Categories())
	assert.Empty(t, cov.Techniques())
}

// ---------------------------------------------------------------------------
// The zero value and EmptyCoverage both behave as empty, queryable coverage —
// no graceful-nil surprises for a capability that has not declared anything.
// ---------------------------------------------------------------------------

func TestCoverage_ZeroValueIsEmptyAndQueryable(t *testing.T) {
	var cov Coverage
	assert.True(t, cov.IsEmpty())
	assert.False(t, cov.HasCategory("prompt_injection"))
	assert.False(t, cov.HasTechnique("direct_prompt_injection"))
	assert.Empty(t, cov.Categories())
	assert.Empty(t, cov.Techniques())
}

func TestEmptyCoverage_IsEmptyAndQueryable(t *testing.T) {
	cov := EmptyCoverage()
	assert.True(t, cov.IsEmpty())
	assert.False(t, cov.HasCategory("prompt_injection"))
	assert.Empty(t, cov.Categories())
}

// ---------------------------------------------------------------------------
// Coverage against the real GlobalTechniques hierarchy: a capability can
// declare coverage of a core category (seeded from types.TechniqueType) with
// no pack-defined techniques involved at all.
// ---------------------------------------------------------------------------

func TestNewCoverage_AgainstGlobalTechniques_AcceptsACoreCategory(t *testing.T) {
	coreCategory := GlobalTechniques.Categories()[0]

	cov, err := NewCoverage(GlobalTechniques, []CategoryID{coreCategory}, nil)
	require.NoError(t, err)
	assert.True(t, cov.HasCategory(coreCategory))
}

func TestNewCoverage_AgainstGlobalTechniques_RejectsUnknownCategory(t *testing.T) {
	_, err := NewCoverage(GlobalTechniques, []CategoryID{"totally_made_up"}, nil)
	require.Error(t, err)
}
