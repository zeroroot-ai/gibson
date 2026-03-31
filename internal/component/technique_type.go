package component

import "github.com/zero-day-ai/gibson/internal/types"

// TechniqueType is an alias for types.TechniqueType.
// It is defined in internal/types to avoid import cycles with the agent package.
type TechniqueType = types.TechniqueType

const (
	TechniquePromptInjection = types.TechniquePromptInjection
	TechniqueJailbreak       = types.TechniqueJailbreak
	TechniqueExtraction      = types.TechniqueExtraction
	TechniqueDoS             = types.TechniqueDoS
	TechniquePoisoning       = types.TechniquePoisoning
	TechniqueEvasion         = types.TechniqueEvasion
	TechniqueReconnaissance  = types.TechniqueReconnaissance
	TechniqueCustom          = types.TechniqueCustom
)

// AllTechniqueTypes returns all valid TechniqueType values.
func AllTechniqueTypes() []TechniqueType {
	return types.AllTechniqueTypes()
}

// ParseTechniqueType parses a string into a TechniqueType.
func ParseTechniqueType(s string) (TechniqueType, error) {
	return types.ParseTechniqueType(s)
}
