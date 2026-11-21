// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package types

// TechniqueType represents an attack technique category
type TechniqueType string

// The technique categories of a target.
const (
	TechniqueDoS                 TechniqueType = "dos"
	TechniqueReconnaissance      TechniqueType = "reconnaissance"
	TechniqueInitialAccess       TechniqueType = "initial_access"
	TechniqueCredentialAccess    TechniqueType = "credential_access" //nolint:gosec // G101: a technique name, not a credential
	TechniquePrivilegeEscalation TechniqueType = "privilege_escalation"
	TechniqueCustom              TechniqueType = "custom"
)

// String returns the string representation of the TechniqueType
func (t TechniqueType) String() string {
	return string(t)
}

// AllTechniqueTypes returns a slice containing all valid TechniqueType values.
// This is the seed coreCategories() (internal/engine/taxonomy/technique.go)
// derives the taxonomy's core category ids from (ADR-0135): the taxonomy is
// the authority now, and types.TechniqueType degraded to this seed list.
func AllTechniqueTypes() []TechniqueType {
	return []TechniqueType{
		TechniqueDoS,
		TechniqueReconnaissance,
		TechniqueInitialAccess,
		TechniqueCredentialAccess,
		TechniquePrivilegeEscalation,
		TechniqueCustom,
	}
}
