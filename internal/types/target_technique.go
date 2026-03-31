package types

import (
	"encoding/json"
	"fmt"
)

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

// IsValid checks if the TechniqueType is a valid enum value
func (t TechniqueType) IsValid() bool {
	switch t {
	case TechniquePromptInjection, TechniqueJailbreak, TechniqueExtraction,
		TechniqueDoS, TechniquePoisoning, TechniqueEvasion,
		TechniqueReconnaissance, TechniqueCustom:
		return true
	default:
		return false
	}
}

// MarshalJSON implements the json.Marshaler interface
func (t TechniqueType) MarshalJSON() ([]byte, error) {
	if !t.IsValid() {
		return nil, fmt.Errorf("invalid technique type: %s", t)
	}
	return json.Marshal(string(t))
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (t *TechniqueType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	parsed, err := ParseTechniqueType(s)
	if err != nil {
		return err
	}

	*t = parsed
	return nil
}

// AllTechniqueTypes returns a slice containing all valid TechniqueType values
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

// ParseTechniqueType parses a string into a TechniqueType, returning an error if invalid
func ParseTechniqueType(s string) (TechniqueType, error) {
	t := TechniqueType(s)
	if !t.IsValid() {
		return "", fmt.Errorf("invalid technique type: %s", s)
	}
	return t, nil
}
