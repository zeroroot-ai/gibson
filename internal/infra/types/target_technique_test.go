// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package types

import (
	"testing"
)

// This file tests TechniqueType directly, in the package that owns it.
//
// TechniqueType degraded from "the technique authority" to "the core pack's
// category seed" under ADR-0035 (gibson#379/#385): the taxonomy
// (internal/engine/taxonomy, TechniqueHierarchy/GlobalTechniques) is the
// authority now, and every consumer that used to key on this enum keys on a
// taxonomy.CategoryID instead. The enum's eight values, String, and
// AllTechniqueTypes stay, purely as the seed coreCategories()
// (internal/engine/taxonomy/technique.go) derives GlobalTechniques'
// categories from. IsValid, the JSON (un)marshaling, and ParseTechniqueType
// were deleted (gibson#432, ADR-0027 hard cutover): nothing outside this
// file's own former tests called them once the taxonomy became the
// authority — coreCategories() only ever needs String().

// TestTechniqueType_String tests the String method
func TestTechniqueType_String(t *testing.T) {
	tests := []struct {
		name     string
		tt       TechniqueType
		expected string
	}{
		{"prompt_injection", TechniquePromptInjection, "prompt_injection"},
		{"jailbreak", TechniqueJailbreak, "jailbreak"},
		{"extraction", TechniqueExtraction, "extraction"},
		{"dos", TechniqueDoS, "dos"},
		{"poisoning", TechniquePoisoning, "poisoning"},
		{"evasion", TechniqueEvasion, "evasion"},
		{"reconnaissance", TechniqueReconnaissance, "reconnaissance"},
		{"custom", TechniqueCustom, "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tt.String(); got != tt.expected {
				t.Errorf("TechniqueType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestAllTechniqueTypes tests that AllTechniqueTypes returns exactly the
// eight seed values — this is the seed coreCategories() in
// internal/engine/taxonomy/technique.go builds GlobalTechniques from.
func TestAllTechniqueTypes(t *testing.T) {
	all := AllTechniqueTypes()

	const expected = 8
	if len(all) != expected {
		t.Errorf("AllTechniqueTypes() returned %d types, want %d", len(all), expected)
	}

	want := map[TechniqueType]bool{
		TechniquePromptInjection: true,
		TechniqueJailbreak:       true,
		TechniqueExtraction:      true,
		TechniqueDoS:             true,
		TechniquePoisoning:       true,
		TechniqueEvasion:         true,
		TechniqueReconnaissance:  true,
		TechniqueCustom:          true,
	}

	for _, tt := range all {
		if !want[tt] {
			t.Errorf("AllTechniqueTypes() returned unexpected type: %v", tt)
		}
		delete(want, tt)
	}

	if len(want) > 0 {
		t.Errorf("AllTechniqueTypes() missing types: %v", want)
	}
}
