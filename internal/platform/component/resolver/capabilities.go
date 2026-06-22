package resolver

import (
	"fmt"
	"strings"
)

// MatchMode defines how capabilities should be matched.
type MatchMode string

const (
	// MatchModeExact requires all capabilities to match exactly
	MatchModeExact MatchMode = "exact"

	// MatchModeSubset requires the component to have all required capabilities (can have more)
	MatchModeSubset MatchMode = "subset"

	// MatchModeSuperset requires the component to have only the specified capabilities (no more)
	MatchModeSuperset MatchMode = "superset"
)

// CapabilityMatcher provides methods for matching and scoring component capabilities.
// Capabilities are string identifiers that describe what a component can do, supporting:
// - Exact matches: "http", "streaming"
// - Wildcards: "network:*" matches "network:http", "network:tcp", etc.
// - Versioned: "http:v2" matches a specific capability version
type CapabilityMatcher interface {
	// Match checks if a component's capabilities satisfy the required capabilities.
	// Returns true if the match succeeds according to the specified mode.
	Match(required []string, actual []string, mode MatchMode) bool

	// Score calculates a match score between required and actual capabilities.
	// Returns a value between 0.0 (no match) and 1.0 (perfect match).
	// Higher scores indicate better matches.
	Score(required []string, actual []string) float64
}

// DefaultCapabilityMatcher is the standard implementation of CapabilityMatcher.
type DefaultCapabilityMatcher struct{}

// NewCapabilityMatcher creates a new capability matcher with default behavior.
func NewCapabilityMatcher() CapabilityMatcher {
	return &DefaultCapabilityMatcher{}
}

// Match checks if actual capabilities satisfy required capabilities.
// The matching behavior depends on the mode:
//   - MatchModeExact: actual must contain exactly the required capabilities (no more, no less)
//   - MatchModeSubset: actual must contain all required capabilities (can have more)
//   - MatchModeSuperset: actual must be a subset of required (no extra capabilities)
func (m *DefaultCapabilityMatcher) Match(required []string, actual []string, mode MatchMode) bool {
	if len(required) == 0 {
		// No requirements means always match
		return true
	}

	switch mode {
	case MatchModeExact:
		return m.matchExact(required, actual)
	case MatchModeSubset:
		return m.matchSubset(required, actual)
	case MatchModeSuperset:
		return m.matchSuperset(required, actual)
	default:
		// Unknown mode - default to subset matching
		return m.matchSubset(required, actual)
	}
}

// matchExact checks if capabilities match exactly (same set, order doesn't matter).
func (m *DefaultCapabilityMatcher) matchExact(required []string, actual []string) bool {
	if len(required) != len(actual) {
		return false
	}

	// Build a map of required capabilities for O(1) lookup
	requiredMap := make(map[string]bool, len(required))
	for _, cap := range required {
		requiredMap[cap] = true
	}

	// Check that all actual capabilities are in required
	for _, cap := range actual {
		if !requiredMap[cap] {
			return false
		}
	}

	// Check that all required capabilities are in actual
	actualMap := make(map[string]bool, len(actual))
	for _, cap := range actual {
		actualMap[cap] = true
	}
	for _, cap := range required {
		if !actualMap[cap] {
			return false
		}
	}

	return true
}

// matchSubset checks if actual capabilities contain all required capabilities.
// Actual may have additional capabilities beyond what's required.
func (m *DefaultCapabilityMatcher) matchSubset(required []string, actual []string) bool {
	// Build a set of actual capabilities for efficient lookup
	actualSet := make(map[string]bool, len(actual))
	for _, cap := range actual {
		actualSet[cap] = true
	}

	// Check that all required capabilities are present
	for _, reqCap := range required {
		if !m.matchCapability(reqCap, actualSet) {
			return false
		}
	}

	return true
}

// matchSuperset checks if actual capabilities are a subset of required.
// Actual cannot have any capabilities not in the required list.
func (m *DefaultCapabilityMatcher) matchSuperset(required []string, actual []string) bool {
	// Build a set of required capabilities
	requiredSet := make(map[string]bool, len(required))
	for _, cap := range required {
		requiredSet[cap] = true
	}

	// Check that all actual capabilities are in required
	for _, actualCap := range actual {
		// Check exact match first
		if requiredSet[actualCap] {
			continue
		}

		// Check if any required wildcard matches this actual capability
		matched := false
		for reqCap := range requiredSet {
			if m.isWildcard(reqCap) && m.matchesWildcard(actualCap, reqCap) {
				matched = true
				break
			}
		}

		if !matched {
			return false
		}
	}

	return true
}

// matchCapability checks if a required capability matches any in the actual set.
// Supports wildcards and versioned capabilities.
func (m *DefaultCapabilityMatcher) matchCapability(required string, actualSet map[string]bool) bool {
	// Check for exact match first (most common case)
	if actualSet[required] {
		return true
	}

	// If required has wildcard, check if any actual capability matches
	if m.isWildcard(required) {
		for actual := range actualSet {
			if m.matchesWildcard(actual, required) {
				return true
			}
		}
		return false
	}

	// Check for version compatibility
	// If required is "http:v2" and actual has "http:v2" or "http:*"
	if m.isVersioned(required) {
		baseRequired := m.getCapabilityBase(required)
		for actual := range actualSet {
			if actual == required {
				return true
			}
			if m.isWildcard(actual) && m.matchesWildcard(required, actual) {
				return true
			}
			// Check if actual is a wildcard for the same base
			if actual == baseRequired+":*" {
				return true
			}
		}
	}

	return false
}

// isWildcard checks if a capability uses wildcard syntax (e.g., "network:*").
func (m *DefaultCapabilityMatcher) isWildcard(capability string) bool {
	return strings.HasSuffix(capability, ":*")
}

// isVersioned checks if a capability includes a version (e.g., "http:v2").
func (m *DefaultCapabilityMatcher) isVersioned(capability string) bool {
	parts := strings.Split(capability, ":")
	if len(parts) != 2 {
		return false
	}
	// Check if the second part looks like a version (starts with 'v' followed by number)
	version := parts[1]
	return len(version) > 1 && version[0] == 'v' && version[1] >= '0' && version[1] <= '9'
}

// getCapabilityBase extracts the base capability name from a versioned capability.
// For "http:v2", returns "http".
func (m *DefaultCapabilityMatcher) getCapabilityBase(capability string) string {
	parts := strings.Split(capability, ":")
	if len(parts) > 0 {
		return parts[0]
	}
	return capability
}

// matchesWildcard checks if an actual capability matches a wildcard pattern.
// For example, "network:http" matches "network:*".
func (m *DefaultCapabilityMatcher) matchesWildcard(actual, wildcard string) bool {
	if !m.isWildcard(wildcard) {
		return actual == wildcard
	}

	// Extract the base from the wildcard (e.g., "network" from "network:*")
	base := strings.TrimSuffix(wildcard, ":*")

	// Check if actual starts with the base
	if actual == base {
		return true
	}

	// Check if actual has the format "base:something"
	return strings.HasPrefix(actual, base+":") && actual != wildcard
}

// Score calculates a match score between required and actual capabilities.
// Returns a value between 0.0 and 1.0:
//   - 1.0: Perfect match (all required capabilities present)
//   - 0.5: Partial match (some capabilities present)
//   - 0.0: No match (no required capabilities present)
//
// The score considers:
//   - Overlap: how many required capabilities are satisfied
//   - Precision: ratio of matched to required capabilities
//   - Bonus: extra actual capabilities reduce the score slightly (prefer exact fit)
func (m *DefaultCapabilityMatcher) Score(required []string, actual []string) float64 {
	// No requirements means perfect match
	if len(required) == 0 {
		return 1.0
	}

	// No actual capabilities means no match
	if len(actual) == 0 {
		return 0.0
	}

	// Build actual capability set
	actualSet := make(map[string]bool, len(actual))
	for _, cap := range actual {
		actualSet[cap] = true
	}

	// Count how many required capabilities are satisfied
	matchedCount := 0
	for _, reqCap := range required {
		if m.matchCapability(reqCap, actualSet) {
			matchedCount++
		}
	}

	// Base score is the ratio of matched to required
	baseScore := float64(matchedCount) / float64(len(required))

	// Apply penalty for extra capabilities (prefer exact fit)
	// This encourages selecting components that match requirements closely
	// without unnecessary extra capabilities
	extraCount := len(actual) - len(required)
	if extraCount > 0 {
		// Small penalty: reduce score by up to 10% based on extra capabilities
		penalty := float64(extraCount) / float64(len(required)+len(actual)) * 0.1
		baseScore -= penalty
		if baseScore < 0 {
			baseScore = 0
		}
	}

	return baseScore
}

// MatchCapabilities is a convenience function for matching capabilities with default matcher.
func MatchCapabilities(required []string, actual []string, mode MatchMode) bool {
	matcher := NewCapabilityMatcher()
	return matcher.Match(required, actual, mode)
}

// ScoreCapabilities is a convenience function for scoring capabilities with default matcher.
func ScoreCapabilities(required []string, actual []string) float64 {
	matcher := NewCapabilityMatcher()
	return matcher.Score(required, actual)
}

// ValidateCapability checks if a capability string is valid.
// Valid formats:
//   - Simple: "http", "streaming"
//   - Namespaced: "network:http", "storage:s3"
//   - Wildcard: "network:*", "storage:*"
//   - Versioned: "http:v2", "grpc:v1"
func ValidateCapability(capability string) error {
	if capability == "" {
		return fmt.Errorf("capability cannot be empty")
	}

	// Check for invalid characters
	if strings.ContainsAny(capability, " \t\n\r") {
		return fmt.Errorf("capability cannot contain whitespace: %q", capability)
	}

	// Split by colon to check format
	parts := strings.Split(capability, ":")
	if len(parts) > 2 {
		return fmt.Errorf("capability has too many colons: %q (expected format: name or name:version)", capability)
	}

	// Validate each part
	for i, part := range parts {
		if part == "" && !(i == 1 && len(parts) == 2 && parts[1] == "*") {
			return fmt.Errorf("capability has empty part: %q", capability)
		}
		if part != "*" && !isValidCapabilityPart(part) {
			return fmt.Errorf("capability part contains invalid characters: %q (must be alphanumeric, dash, underscore, or dot)", part)
		}
	}

	return nil
}

// isValidCapabilityPart checks if a capability part contains only valid characters.
func isValidCapabilityPart(part string) bool {
	if len(part) == 0 {
		return false
	}
	for _, ch := range part {
		if !((ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.') {
			return false
		}
	}
	return true
}
