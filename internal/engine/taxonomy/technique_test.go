// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package taxonomy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// ---------------------------------------------------------------------------
// Category and Technique are taxonomy nodes (ADR-0135).
// ---------------------------------------------------------------------------

func TestCategoryAndTechniqueAreAdmittedNodeLabels(t *testing.T) {
	for _, label := range []string{CategoryLabel, TechniqueLabel} {
		d := Global.ClassifyNode(label)
		assert.True(t, d.InTaxonomy, "%s is not in the Taxonomy: %s", label, d.Reason)
		assert.Equal(t, label, d.Label)
	}
}

func TestRollsUpToIsAnAdmittedRelationshipType(t *testing.T) {
	d := Global.ClassifyRelationship(RollsUpToRelationshipType)
	assert.True(t, d.InTaxonomy, "%s is not in the Taxonomy: %s", RollsUpToRelationshipType, d.Reason)
	assert.Equal(t, RollsUpToRelationshipType, d.Label)
}

// ---------------------------------------------------------------------------
// Seeding: the core categories come from types.TechniqueType (ADR-0135,
// gibson#379 acceptance criterion 2).
// ---------------------------------------------------------------------------

func TestCoreCategoriesAreSeededFromTechniqueType(t *testing.T) {
	got := GlobalTechniques.Categories()

	want := make([]CategoryID, 0, len(types.AllTechniqueTypes()))
	for _, tt := range types.AllTechniqueTypes() {
		want = append(want, CategoryID(tt.String()))
	}

	assert.ElementsMatch(t, want, got)
}

func TestCoreCategoriesIncludeEveryEnumValue(t *testing.T) {
	// Pinned explicitly, alongside the derived check above, so a change to
	// target_technique.go that silently drops a value is caught two ways.
	for _, want := range []CategoryID{
		"dos", "reconnaissance", "initial_access", "credential_access",
		"privilege_escalation", "custom",
	} {
		assert.True(t, GlobalTechniques.HasCategory(want), "core categories missing %q", want)
	}
}

func TestCoreCategoriesAreValid(t *testing.T) {
	for _, category := range GlobalTechniques.Categories() {
		assert.NoError(t, ValidIdentifier(string(category)), "core category %q", category)
	}
}

func TestGlobalTechniquesSeedsNoTechniques(t *testing.T) {
	// The core pack fixes only the coarse level; fine-grained techniques are
	// pack-defined (ADR-0133) and arrive via WithTechnique, not the seed.
	assert.Empty(t, GlobalTechniques.Techniques())
}

// ---------------------------------------------------------------------------
// NewTechniqueHierarchy: ValidIdentifier applies to both levels (gibson#379
// acceptance criterion 3).
// ---------------------------------------------------------------------------

func TestNewTechniqueHierarchyValidatesCategories(t *testing.T) {
	_, err := NewTechniqueHierarchy([]CategoryID{"initial_access", "not a valid id"}, nil)
	require.Error(t, err)
}

func TestNewTechniqueHierarchyRejectsDuplicateCategory(t *testing.T) {
	_, err := NewTechniqueHierarchy([]CategoryID{"initial_access", "initial_access"}, nil)
	require.Error(t, err)
}

func TestNewTechniqueHierarchyValidatesTechniqueID(t *testing.T) {
	_, err := NewTechniqueHierarchy(
		[]CategoryID{"initial_access"},
		map[TechniqueID]CategoryID{"not a valid id": "initial_access"},
	)
	require.Error(t, err)
}

func TestNewTechniqueHierarchyValidatesRollupCategory(t *testing.T) {
	_, err := NewTechniqueHierarchy(
		[]CategoryID{"initial_access"},
		map[TechniqueID]CategoryID{"default_credentials": "not a valid id"},
	)
	require.Error(t, err)
}

func TestNewTechniqueHierarchyRejectsUnadmittedCategoryInRollup(t *testing.T) {
	// The rollup edge must point at something admitted, or it bridges to
	// nothing.
	_, err := NewTechniqueHierarchy(
		[]CategoryID{"initial_access"},
		map[TechniqueID]CategoryID{"default_credentials": "credential_access"},
	)
	require.Error(t, err)
}

func TestNewTechniqueHierarchyAcceptsAValidRollup(t *testing.T) {
	h, err := NewTechniqueHierarchy(
		[]CategoryID{"initial_access", "credential_access"},
		map[TechniqueID]CategoryID{
			"default_credentials": "initial_access",
			"token_leak":          "credential_access",
		},
	)
	require.NoError(t, err)
	assert.ElementsMatch(t, []CategoryID{"initial_access", "credential_access"}, h.Categories())
	assert.ElementsMatch(t, []TechniqueID{"default_credentials", "token_leak"}, h.Techniques())
}

// ---------------------------------------------------------------------------
// CategoryOf: the technique -> category rollup lookup (gibson#379 "a lookup
// API (technique->category)").
// ---------------------------------------------------------------------------

func TestCategoryOfLooksUpTheRollup(t *testing.T) {
	h, err := NewTechniqueHierarchy(
		[]CategoryID{"initial_access"},
		map[TechniqueID]CategoryID{"default_credentials": "initial_access"},
	)
	require.NoError(t, err)

	category, ok := h.CategoryOf("default_credentials")
	require.True(t, ok)
	assert.Equal(t, CategoryID("initial_access"), category)
}

func TestCategoryOfReportsNotFoundForAnUnadmittedTechnique(t *testing.T) {
	h, err := NewTechniqueHierarchy([]CategoryID{"initial_access"}, nil)
	require.NoError(t, err)

	category, ok := h.CategoryOf("never_registered")
	assert.False(t, ok)
	assert.Empty(t, category)
}

func TestHasCategoryAndHasTechnique(t *testing.T) {
	h, err := NewTechniqueHierarchy(
		[]CategoryID{"initial_access"},
		map[TechniqueID]CategoryID{"default_credentials": "initial_access"},
	)
	require.NoError(t, err)

	assert.True(t, h.HasCategory("initial_access"))
	assert.False(t, h.HasCategory("credential_access"))
	assert.True(t, h.HasTechnique("default_credentials"))
	assert.False(t, h.HasTechnique("never_registered"))
}

// ---------------------------------------------------------------------------
// WithTechnique: pack-extensible, immutable (ADR-0135 "pack-extensible").
// ---------------------------------------------------------------------------

func TestWithTechniqueAddsWithoutMutatingTheReceiver(t *testing.T) {
	base, err := NewTechniqueHierarchy([]CategoryID{"initial_access", "credential_access"}, nil)
	require.NoError(t, err)

	next, err := base.WithTechnique("default_credentials", "initial_access")
	require.NoError(t, err)

	assert.False(t, base.HasTechnique("default_credentials"), "WithTechnique mutated the receiver")
	assert.True(t, next.HasTechnique("default_credentials"))

	category, ok := next.CategoryOf("default_credentials")
	require.True(t, ok)
	assert.Equal(t, CategoryID("initial_access"), category)
}

func TestWithTechniqueRejectsAnUnadmittedCategory(t *testing.T) {
	base, err := NewTechniqueHierarchy([]CategoryID{"initial_access"}, nil)
	require.NoError(t, err)

	_, err = base.WithTechnique("token_leak", "credential_access")
	require.Error(t, err)
}

func TestWithTechniqueRejectsANonIdentifierTechnique(t *testing.T) {
	base, err := NewTechniqueHierarchy([]CategoryID{"initial_access"}, nil)
	require.NoError(t, err)

	_, err = base.WithTechnique("dan prompt", "initial_access")
	require.Error(t, err)
}

func TestWithTechniqueRejectsADuplicateTechnique(t *testing.T) {
	base, err := NewTechniqueHierarchy(
		[]CategoryID{"initial_access"},
		map[TechniqueID]CategoryID{"default_credentials": "initial_access"},
	)
	require.NoError(t, err)

	_, err = base.WithTechnique("default_credentials", "initial_access")
	require.Error(t, err)
}

func TestWithTechniqueChainsAcrossMultipleCalls(t *testing.T) {
	h, err := NewTechniqueHierarchy([]CategoryID{"initial_access", "credential_access"}, nil)
	require.NoError(t, err)

	h, err = h.WithTechnique("default_credentials", "initial_access")
	require.NoError(t, err)
	h, err = h.WithTechnique("token_leak", "credential_access")
	require.NoError(t, err)

	assert.ElementsMatch(t, []TechniqueID{"default_credentials", "token_leak"}, h.Techniques())
}

// ---------------------------------------------------------------------------
// mustNewTechniqueHierarchy: fail the process at startup, not silently later
// (mirrors mustNew's contract for the Registry).
// ---------------------------------------------------------------------------

func TestMustNewTechniqueHierarchyPanicsOnAnInvalidSeed(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("mustNewTechniqueHierarchy returned for a hierarchy NewTechniqueHierarchy refuses")
		}
	}()
	mustNewTechniqueHierarchy([]CategoryID{"not a valid id"}, nil)
}
