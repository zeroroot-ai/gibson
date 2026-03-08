package mission

import (
	"fmt"
	"strings"
)

// ValidSeedTypes defines the allowed seed types for target reconnaissance.
var ValidSeedTypes = []string{
	"domain",
	"host",
	"cidr",
	"org",
	"asn",
}

// ValidTargetProfiles defines the allowed target reconnaissance profiles.
var ValidTargetProfiles = []string{
	"aggressive",
	"balanced",
	"stealth",
}

// MinDepth is the minimum allowed enumeration depth.
const MinDepth = 1

// MaxDepth is the maximum allowed enumeration depth.
const MaxDepth = 5

// TargetSeed represents a target seed for reconnaissance.
type TargetSeed struct {
	Value string
	Type  string
	Scope string
}

// InlineTarget defines an inline target configuration.
type InlineTarget struct {
	Seeds    []*TargetSeed
	Profile  string
	Depth    int32
	Excluded []string
	Metadata map[string]any
}

// ValidateInlineTarget validates an inline target configuration.
// It ensures:
// - At least one seed is provided
// - All seeds have valid types
// - Profile is one of: aggressive, balanced, stealth
// - Depth is between 1 and 5
func ValidateInlineTarget(config *InlineTarget) error {
	if config == nil {
		return fmt.Errorf("inline target config is required")
	}

	// Validate seeds
	if len(config.Seeds) == 0 {
		return fmt.Errorf("at least one seed is required")
	}

	for i, seed := range config.Seeds {
		if err := validateTargetSeed(seed, i); err != nil {
			return err
		}
	}

	// Validate profile
	if config.Profile == "" {
		return fmt.Errorf("target profile is required")
	}
	if !isValidProfile(config.Profile) {
		return fmt.Errorf("invalid target profile '%s', allowed: %s",
			config.Profile, strings.Join(ValidTargetProfiles, ", "))
	}

	// Validate depth
	if config.Depth < MinDepth || config.Depth > MaxDepth {
		return fmt.Errorf("invalid depth %d, must be between %d and %d",
			config.Depth, MinDepth, MaxDepth)
	}

	return nil
}

// validateTargetSeed validates a single seed.
func validateTargetSeed(seed *TargetSeed, index int) error {
	if seed == nil {
		return fmt.Errorf("seed at index %d is nil", index)
	}

	if seed.Value == "" {
		return fmt.Errorf("seed at index %d has empty value", index)
	}

	if seed.Type == "" {
		return fmt.Errorf("seed at index %d has empty type", index)
	}

	if !isValidSeedType(seed.Type) {
		return fmt.Errorf("seed at index %d has invalid type '%s', allowed: %s",
			index, seed.Type, strings.Join(ValidSeedTypes, ", "))
	}

	// Validate scope if provided
	if seed.Scope != "" {
		if !isValidSeedScope(seed.Scope) {
			return fmt.Errorf("seed at index %d has invalid scope '%s', allowed: in_scope, expand",
				index, seed.Scope)
		}
	}

	return nil
}

// isValidSeedType checks if a seed type is valid.
func isValidSeedType(seedType string) bool {
	for _, valid := range ValidSeedTypes {
		if seedType == valid {
			return true
		}
	}
	return false
}

// isValidProfile checks if a target profile is valid.
func isValidProfile(profile string) bool {
	for _, valid := range ValidTargetProfiles {
		if profile == valid {
			return true
		}
	}
	return false
}

// isValidSeedScope checks if a seed scope is valid.
func isValidSeedScope(scope string) bool {
	return scope == "in_scope" || scope == "expand"
}
