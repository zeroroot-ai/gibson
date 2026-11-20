// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ────────────────────────────────────────────────────────────────────────────
// FindingCategory Tests
// ────────────────────────────────────────────────────────────────────────────

func TestFindingCategory_String(t *testing.T) {
	assert.Equal(t, "prompt_injection", CategoryPromptInjection.String())
	assert.Equal(t, "data_extraction", CategoryDataExtraction.String())
	assert.Equal(t, "information_disclosure", CategoryInformationDisclosure.String())
	assert.Equal(t, "uncategorized", CategoryUncategorized.String())
}

func TestFindingCategory_IsValid(t *testing.T) {
	assert.True(t, CategoryPromptInjection.IsValid())
	assert.True(t, CategoryDataExtraction.IsValid())
	assert.True(t, CategoryInformationDisclosure.IsValid())
	assert.True(t, CategoryUncategorized.IsValid())
	assert.False(t, FindingCategory("invalid").IsValid())
}
