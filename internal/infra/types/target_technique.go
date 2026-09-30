// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package types

// TechniqueType represents an attack technique category
type TechniqueType string

const (
	TechniquePromptInjection TechniqueType = "prompt_injection"
	TechniqueJailbreak       TechniqueType = "jailbreak"
	TechniqueExtraction      TechniqueType = "extraction"
	TechniqueDoS             TechniqueType = "dos"
	TechniquePoisoning       TechniqueType = "poisoning"
	TechniqueEvasion         TechniqueType = "evasion"
	TechniqueReconnaissance  TechniqueType = "reconnaissance"
	TechniqueCustom          TechniqueType = "custom"
)

// String returns the string representation of the TechniqueType
func (t TechniqueType) String() string {
	return string(t)
}

// AllTechniqueTypes returns a slice containing all valid TechniqueType values.
// This is the seed coreCategories() (internal/engine/taxonomy/technique.go)
// derives the taxonomy's core category ids from (ADR-0035): the taxonomy is
// the authority now, and types.TechniqueType degraded to this seed list.
func AllTechniqueTypes() []TechniqueType {
	return []TechniqueType{
		TechniquePromptInjection,
		TechniqueJailbreak,
		TechniqueExtraction,
		TechniqueDoS,
		TechniquePoisoning,
		TechniqueEvasion,
		TechniqueReconnaissance,
		TechniqueCustom,
	}
}
