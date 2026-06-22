package resolver

import (
	"fmt"
	"strconv"
	"strings"
)

// ConstraintType defines the type of version constraint.
type ConstraintType string

const (
	// ConstraintExact requires an exact version match
	ConstraintExact ConstraintType = "exact"

	// ConstraintMinimum requires a minimum version (inclusive)
	ConstraintMinimum ConstraintType = "minimum"

	// ConstraintMaximum requires a maximum version
	ConstraintMaximum ConstraintType = "maximum"

	// ConstraintRange requires a version within a range
	ConstraintRange ConstraintType = "range"

	// ConstraintAny accepts any version
	ConstraintAny ConstraintType = "any"
)

// VersionConstraint represents a parsed version constraint.
// It supports various constraint formats including exact matches, ranges, and bounds.
type VersionConstraint struct {
	// Type is the constraint type (exact, minimum, maximum, range, any)
	Type ConstraintType `json:"type" yaml:"type"`

	// MinVersion is the minimum version (for minimum and range constraints)
	MinVersion string `json:"minVersion,omitempty" yaml:"minVersion,omitempty"`

	// MaxVersion is the maximum version (for maximum and range constraints)
	MaxVersion string `json:"maxVersion,omitempty" yaml:"maxVersion,omitempty"`

	// MinInclusive indicates if the minimum bound is inclusive (>= vs >)
	MinInclusive bool `json:"minInclusive,omitempty" yaml:"minInclusive,omitempty"`

	// MaxInclusive indicates if the maximum bound is inclusive (<= vs <)
	MaxInclusive bool `json:"maxInclusive,omitempty" yaml:"maxInclusive,omitempty"`

	// ExactVersion is the exact version required (for exact constraints)
	ExactVersion string `json:"exactVersion,omitempty" yaml:"exactVersion,omitempty"`
}

// ParseVersionConstraint parses a version constraint string into a structured constraint.
// It supports the following formats:
//   - Exact: "1.0.0" or "v1.0.0"
//   - Minimum: ">=1.0.0"
//   - Maximum: "<=1.0.0" or "<2.0.0"
//   - Range: ">=1.0.0,<2.0.0"
//   - Wildcard: "1.2.*" (matches 1.2.x for any x)
//   - Caret: "^1.2.3" (compatible with 1.2.3, allows minor/patch updates)
//   - Tilde: "~1.2.3" (approximately 1.2.3, allows patch updates only)
//   - Any: "*" or "" (empty string)
//
// Examples:
//   - "1.0.0" → exact match
//   - ">=1.0.0" → minimum version 1.0.0 (inclusive)
//   - "<2.0.0" → maximum version 2.0.0 (exclusive)
//   - ">=1.0.0,<2.0.0" → range from 1.0.0 (inclusive) to 2.0.0 (exclusive)
//   - "1.2.*" → any version with major=1, minor=2
//   - "^1.2.3" → >=1.2.3, <2.0.0
//   - "~1.2.3" → >=1.2.3, <1.3.0
//   - "*" → any version
func ParseVersionConstraint(constraint string) (*VersionConstraint, error) {
	// Normalize the input
	constraint = strings.TrimSpace(constraint)

	// Handle empty string or wildcard as "any version"
	if constraint == "" || constraint == "*" {
		return &VersionConstraint{
			Type: ConstraintAny,
		}, nil
	}

	// Check for caret constraint (^1.2.3)
	if strings.HasPrefix(constraint, "^") {
		return parseCaretConstraint(constraint[1:])
	}

	// Check for tilde constraint (~1.2.3)
	if strings.HasPrefix(constraint, "~") {
		return parseTildeConstraint(constraint[1:])
	}

	// Check for wildcard constraint (1.2.*)
	if strings.Contains(constraint, "*") {
		return parseWildcardConstraint(constraint)
	}

	// Check for range constraint (contains comma)
	if strings.Contains(constraint, ",") {
		return parseRangeConstraint(constraint)
	}

	// Check for comparison operators
	if strings.HasPrefix(constraint, ">=") {
		version := strings.TrimSpace(constraint[2:])
		if err := validateVersion(version); err != nil {
			return nil, fmt.Errorf("invalid minimum version: %w", err)
		}
		return &VersionConstraint{
			Type:         ConstraintMinimum,
			MinVersion:   normalizeVersion(version),
			MinInclusive: true,
		}, nil
	}

	if strings.HasPrefix(constraint, ">") {
		version := strings.TrimSpace(constraint[1:])
		if err := validateVersion(version); err != nil {
			return nil, fmt.Errorf("invalid minimum version: %w", err)
		}
		return &VersionConstraint{
			Type:         ConstraintMinimum,
			MinVersion:   normalizeVersion(version),
			MinInclusive: false,
		}, nil
	}

	if strings.HasPrefix(constraint, "<=") {
		version := strings.TrimSpace(constraint[2:])
		if err := validateVersion(version); err != nil {
			return nil, fmt.Errorf("invalid maximum version: %w", err)
		}
		return &VersionConstraint{
			Type:         ConstraintMaximum,
			MaxVersion:   normalizeVersion(version),
			MaxInclusive: true,
		}, nil
	}

	if strings.HasPrefix(constraint, "<") {
		version := strings.TrimSpace(constraint[1:])
		if err := validateVersion(version); err != nil {
			return nil, fmt.Errorf("invalid maximum version: %w", err)
		}
		return &VersionConstraint{
			Type:         ConstraintMaximum,
			MaxVersion:   normalizeVersion(version),
			MaxInclusive: false,
		}, nil
	}

	// No operator means exact version
	if err := validateVersion(constraint); err != nil {
		return nil, fmt.Errorf("invalid exact version: %w", err)
	}

	return &VersionConstraint{
		Type:         ConstraintExact,
		ExactVersion: normalizeVersion(constraint),
	}, nil
}

// parseRangeConstraint parses a range constraint like ">=1.0.0,<2.0.0".
func parseRangeConstraint(constraint string) (*VersionConstraint, error) {
	parts := strings.Split(constraint, ",")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range constraint format: expected exactly 2 parts separated by comma, got %d", len(parts))
	}

	var result VersionConstraint
	result.Type = ConstraintRange

	// Parse first part (should be minimum)
	part1 := strings.TrimSpace(parts[0])
	if strings.HasPrefix(part1, ">=") {
		version := strings.TrimSpace(part1[2:])
		if err := validateVersion(version); err != nil {
			return nil, fmt.Errorf("invalid minimum version in range: %w", err)
		}
		result.MinVersion = normalizeVersion(version)
		result.MinInclusive = true
	} else if strings.HasPrefix(part1, ">") {
		version := strings.TrimSpace(part1[1:])
		if err := validateVersion(version); err != nil {
			return nil, fmt.Errorf("invalid minimum version in range: %w", err)
		}
		result.MinVersion = normalizeVersion(version)
		result.MinInclusive = false
	} else {
		return nil, fmt.Errorf("invalid range constraint: first part must start with > or >=, got %s", part1)
	}

	// Parse second part (should be maximum)
	part2 := strings.TrimSpace(parts[1])
	if strings.HasPrefix(part2, "<=") {
		version := strings.TrimSpace(part2[2:])
		if err := validateVersion(version); err != nil {
			return nil, fmt.Errorf("invalid maximum version in range: %w", err)
		}
		result.MaxVersion = normalizeVersion(version)
		result.MaxInclusive = true
	} else if strings.HasPrefix(part2, "<") {
		version := strings.TrimSpace(part2[1:])
		if err := validateVersion(version); err != nil {
			return nil, fmt.Errorf("invalid maximum version in range: %w", err)
		}
		result.MaxVersion = normalizeVersion(version)
		result.MaxInclusive = false
	} else {
		return nil, fmt.Errorf("invalid range constraint: second part must start with < or <=, got %s", part2)
	}

	// Validate that min < max
	if CompareVersions(result.MinVersion, result.MaxVersion) >= 0 {
		return nil, fmt.Errorf("invalid range: minimum version %s must be less than maximum version %s", result.MinVersion, result.MaxVersion)
	}

	return &result, nil
}

// SatisfiesConstraint checks if an actual version satisfies a version constraint.
// It returns true if the constraint is satisfied, false otherwise.
// Returns an error if the constraint or version strings are malformed.
//
// Examples:
//   - SatisfiesConstraint("1.5.0", ">=1.0.0") → true
//   - SatisfiesConstraint("0.9.0", ">=1.0.0") → false
//   - SatisfiesConstraint("1.5.0", ">=1.0.0,<2.0.0") → true
//   - SatisfiesConstraint("2.0.0", "<2.0.0") → false
func SatisfiesConstraint(actual, constraint string) (bool, error) {
	// Parse the constraint
	c, err := ParseVersionConstraint(constraint)
	if err != nil {
		return false, fmt.Errorf("failed to parse constraint: %w", err)
	}

	// Normalize and validate the actual version
	actual = strings.TrimSpace(actual)
	if err := validateVersion(actual); err != nil {
		return false, fmt.Errorf("invalid actual version: %w", err)
	}
	actual = normalizeVersion(actual)

	// Check based on constraint type
	switch c.Type {
	case ConstraintAny:
		return true, nil

	case ConstraintExact:
		return CompareVersions(actual, c.ExactVersion) == 0, nil

	case ConstraintMinimum:
		cmp := CompareVersions(actual, c.MinVersion)
		if c.MinInclusive {
			return cmp >= 0, nil
		}
		return cmp > 0, nil

	case ConstraintMaximum:
		cmp := CompareVersions(actual, c.MaxVersion)
		if c.MaxInclusive {
			return cmp <= 0, nil
		}
		return cmp < 0, nil

	case ConstraintRange:
		// Check minimum bound
		cmpMin := CompareVersions(actual, c.MinVersion)
		if c.MinInclusive {
			if cmpMin < 0 {
				return false, nil
			}
		} else {
			if cmpMin <= 0 {
				return false, nil
			}
		}

		// Check maximum bound
		cmpMax := CompareVersions(actual, c.MaxVersion)
		if c.MaxInclusive {
			if cmpMax > 0 {
				return false, nil
			}
		} else {
			if cmpMax >= 0 {
				return false, nil
			}
		}

		return true, nil

	default:
		return false, fmt.Errorf("unknown constraint type: %s", c.Type)
	}
}

// CompareVersions compares two semantic version strings.
// Returns:
//   - -1 if v1 < v2
//   - 0 if v1 == v2
//   - 1 if v1 > v2
//
// Both versions must be valid semantic versions (major.minor.patch).
// The "v" prefix is handled automatically (v1.0.0 == 1.0.0).
//
// Examples:
//   - CompareVersions("1.0.0", "2.0.0") → -1
//   - CompareVersions("1.5.0", "1.5.0") → 0
//   - CompareVersions("v2.0.0", "1.0.0") → 1
func CompareVersions(v1, v2 string) int {
	// Normalize versions (remove "v" prefix)
	v1 = normalizeVersion(v1)
	v2 = normalizeVersion(v2)

	// Parse versions into components
	parts1 := parseVersionParts(v1)
	parts2 := parseVersionParts(v2)

	// Compare each component (major, minor, patch)
	for i := 0; i < 3; i++ {
		if parts1[i] < parts2[i] {
			return -1
		}
		if parts1[i] > parts2[i] {
			return 1
		}
	}

	return 0
}

// normalizeVersion removes the "v" prefix from a version string if present.
func normalizeVersion(version string) string {
	return strings.TrimPrefix(version, "v")
}

// parseVersionParts parses a semantic version string into [major, minor, patch].
// Returns [0, 0, 0] if parsing fails (should not happen after validation).
func parseVersionParts(version string) [3]int {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return [3]int{0, 0, 0}
	}

	var result [3]int
	for i := 0; i < 3; i++ {
		val, err := strconv.Atoi(parts[i])
		if err != nil {
			return [3]int{0, 0, 0}
		}
		result[i] = val
	}

	return result
}

// validateVersion checks if a version string is a valid semantic version.
// Valid formats: "1.0.0", "v1.0.0", "10.20.30"
// Invalid formats: "1.0", "1", "abc", "1.0.0.0"
func validateVersion(version string) error {
	// Remove "v" prefix if present
	version = normalizeVersion(version)

	// Split into parts
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return fmt.Errorf("version must be in format major.minor.patch, got %s", version)
	}

	// Validate each part is a non-negative integer
	for i, part := range parts {
		if part == "" {
			return fmt.Errorf("version component %d is empty", i)
		}
		val, err := strconv.Atoi(part)
		if err != nil {
			return fmt.Errorf("version component %d is not a valid number: %s", i, part)
		}
		if val < 0 {
			return fmt.Errorf("version component %d must be non-negative, got %d", i, val)
		}
	}

	return nil
}

// parseWildcardConstraint parses a wildcard version constraint like "1.2.*".
// Supports wildcards in the patch position (1.2.*) or minor position (1.*).
func parseWildcardConstraint(constraint string) (*VersionConstraint, error) {
	constraint = strings.TrimSpace(constraint)
	constraint = normalizeVersion(constraint)

	parts := strings.Split(constraint, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid wildcard constraint format: %s (expected format: major.minor.* or major.*)", constraint)
	}

	// Check which position has the wildcard
	if parts[2] == "*" {
		// Wildcard in patch position: 1.2.* means >=1.2.0,<1.3.0
		major := parts[0]
		minor := parts[1]

		// Validate major and minor are numbers
		if _, err := strconv.Atoi(major); err != nil {
			return nil, fmt.Errorf("invalid major version in wildcard: %s", major)
		}
		minorNum, err := strconv.Atoi(minor)
		if err != nil {
			return nil, fmt.Errorf("invalid minor version in wildcard: %s", minor)
		}

		minVersion := fmt.Sprintf("%s.%s.0", major, minor)
		maxVersion := fmt.Sprintf("%s.%d.0", major, minorNum+1)

		return &VersionConstraint{
			Type:         ConstraintRange,
			MinVersion:   minVersion,
			MaxVersion:   maxVersion,
			MinInclusive: true,
			MaxInclusive: false,
		}, nil
	}

	if parts[1] == "*" {
		// Wildcard in minor position: 1.* means >=1.0.0,<2.0.0
		if parts[2] != "*" && parts[2] != "0" {
			return nil, fmt.Errorf("invalid wildcard constraint: when minor is *, patch must also be * or 0")
		}

		major := parts[0]
		majorNum, err := strconv.Atoi(major)
		if err != nil {
			return nil, fmt.Errorf("invalid major version in wildcard: %s", major)
		}

		minVersion := fmt.Sprintf("%s.0.0", major)
		maxVersion := fmt.Sprintf("%d.0.0", majorNum+1)

		return &VersionConstraint{
			Type:         ConstraintRange,
			MinVersion:   minVersion,
			MaxVersion:   maxVersion,
			MinInclusive: true,
			MaxInclusive: false,
		}, nil
	}

	return nil, fmt.Errorf("invalid wildcard constraint: %s (wildcard must be in minor or patch position)", constraint)
}

// parseCaretConstraint parses a caret version constraint like "^1.2.3".
// Caret allows changes that do not modify the left-most non-zero digit:
//   - ^1.2.3 → >=1.2.3, <2.0.0
//   - ^0.2.3 → >=0.2.3, <0.3.0
//   - ^0.0.3 → >=0.0.3, <0.0.4
func parseCaretConstraint(version string) (*VersionConstraint, error) {
	version = strings.TrimSpace(version)
	if err := validateVersion(version); err != nil {
		return nil, fmt.Errorf("invalid caret constraint version: %w", err)
	}

	version = normalizeVersion(version)
	parts := parseVersionParts(version)

	var maxVersion string
	if parts[0] > 0 {
		// Major version is non-zero: allow minor and patch updates
		// ^1.2.3 → >=1.2.3, <2.0.0
		maxVersion = fmt.Sprintf("%d.0.0", parts[0]+1)
	} else if parts[1] > 0 {
		// Major is zero, minor is non-zero: allow patch updates
		// ^0.2.3 → >=0.2.3, <0.3.0
		maxVersion = fmt.Sprintf("0.%d.0", parts[1]+1)
	} else {
		// Major and minor are zero: allow only exact patch version
		// ^0.0.3 → >=0.0.3, <0.0.4
		maxVersion = fmt.Sprintf("0.0.%d", parts[2]+1)
	}

	return &VersionConstraint{
		Type:         ConstraintRange,
		MinVersion:   version,
		MaxVersion:   maxVersion,
		MinInclusive: true,
		MaxInclusive: false,
	}, nil
}

// parseTildeConstraint parses a tilde version constraint like "~1.2.3".
// Tilde allows patch-level changes:
//   - ~1.2.3 → >=1.2.3, <1.3.0
//   - ~1.2 → >=1.2.0, <1.3.0
//   - ~1 → >=1.0.0, <2.0.0
func parseTildeConstraint(version string) (*VersionConstraint, error) {
	version = strings.TrimSpace(version)
	version = normalizeVersion(version)

	// Handle partial versions like ~1.2 or ~1
	parts := strings.Split(version, ".")
	switch len(parts) {
	case 1:
		// ~1 → >=1.0.0, <2.0.0
		major := parts[0]
		majorNum, err := strconv.Atoi(major)
		if err != nil {
			return nil, fmt.Errorf("invalid major version in tilde: %s", major)
		}
		return &VersionConstraint{
			Type:         ConstraintRange,
			MinVersion:   fmt.Sprintf("%s.0.0", major),
			MaxVersion:   fmt.Sprintf("%d.0.0", majorNum+1),
			MinInclusive: true,
			MaxInclusive: false,
		}, nil

	case 2:
		// ~1.2 → >=1.2.0, <1.3.0
		major := parts[0]
		minor := parts[1]
		minorNum, err := strconv.Atoi(minor)
		if err != nil {
			return nil, fmt.Errorf("invalid minor version in tilde: %s", minor)
		}
		return &VersionConstraint{
			Type:         ConstraintRange,
			MinVersion:   fmt.Sprintf("%s.%s.0", major, minor),
			MaxVersion:   fmt.Sprintf("%s.%d.0", major, minorNum+1),
			MinInclusive: true,
			MaxInclusive: false,
		}, nil

	case 3:
		// ~1.2.3 → >=1.2.3, <1.3.0
		if err := validateVersion(version); err != nil {
			return nil, fmt.Errorf("invalid tilde constraint version: %w", err)
		}
		parts := parseVersionParts(version)
		maxVersion := fmt.Sprintf("%d.%d.0", parts[0], parts[1]+1)

		return &VersionConstraint{
			Type:         ConstraintRange,
			MinVersion:   version,
			MaxVersion:   maxVersion,
			MinInclusive: true,
			MaxInclusive: false,
		}, nil

	default:
		return nil, fmt.Errorf("invalid tilde constraint format: %s", version)
	}
}
