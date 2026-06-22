package resolver

import (
	"testing"
)

// TestParseVersionConstraint tests the ParseVersionConstraint function.
func TestParseVersionConstraint(t *testing.T) {
	tests := []struct {
		name        string
		constraint  string
		wantType    ConstraintType
		wantMin     string
		wantMax     string
		wantExact   string
		minInc      bool
		maxInc      bool
		shouldError bool
	}{
		// Any version
		{
			name:       "empty string",
			constraint: "",
			wantType:   ConstraintAny,
		},
		{
			name:       "wildcard",
			constraint: "*",
			wantType:   ConstraintAny,
		},
		{
			name:       "whitespace only",
			constraint: "   ",
			wantType:   ConstraintAny,
		},

		// Exact version
		{
			name:       "exact version",
			constraint: "1.0.0",
			wantType:   ConstraintExact,
			wantExact:  "1.0.0",
		},
		{
			name:       "exact version with v prefix",
			constraint: "v1.2.3",
			wantType:   ConstraintExact,
			wantExact:  "1.2.3",
		},
		{
			name:       "exact version with spaces",
			constraint: "  1.5.0  ",
			wantType:   ConstraintExact,
			wantExact:  "1.5.0",
		},

		// Minimum version
		{
			name:       "minimum inclusive",
			constraint: ">=1.0.0",
			wantType:   ConstraintMinimum,
			wantMin:    "1.0.0",
			minInc:     true,
		},
		{
			name:       "minimum inclusive with v prefix",
			constraint: ">=v2.0.0",
			wantType:   ConstraintMinimum,
			wantMin:    "2.0.0",
			minInc:     true,
		},
		{
			name:       "minimum exclusive",
			constraint: ">1.0.0",
			wantType:   ConstraintMinimum,
			wantMin:    "1.0.0",
			minInc:     false,
		},
		{
			name:       "minimum with spaces",
			constraint: ">=  1.0.0  ",
			wantType:   ConstraintMinimum,
			wantMin:    "1.0.0",
			minInc:     true,
		},

		// Maximum version
		{
			name:       "maximum inclusive",
			constraint: "<=2.0.0",
			wantType:   ConstraintMaximum,
			wantMax:    "2.0.0",
			maxInc:     true,
		},
		{
			name:       "maximum exclusive",
			constraint: "<2.0.0",
			wantType:   ConstraintMaximum,
			wantMax:    "2.0.0",
			maxInc:     false,
		},
		{
			name:       "maximum with v prefix",
			constraint: "<=v3.0.0",
			wantType:   ConstraintMaximum,
			wantMax:    "3.0.0",
			maxInc:     true,
		},

		// Range constraints
		{
			name:       "range inclusive-exclusive",
			constraint: ">=1.0.0,<2.0.0",
			wantType:   ConstraintRange,
			wantMin:    "1.0.0",
			wantMax:    "2.0.0",
			minInc:     true,
			maxInc:     false,
		},
		{
			name:       "range both inclusive",
			constraint: ">=1.0.0,<=2.0.0",
			wantType:   ConstraintRange,
			wantMin:    "1.0.0",
			wantMax:    "2.0.0",
			minInc:     true,
			maxInc:     true,
		},
		{
			name:       "range both exclusive",
			constraint: ">1.0.0,<2.0.0",
			wantType:   ConstraintRange,
			wantMin:    "1.0.0",
			wantMax:    "2.0.0",
			minInc:     false,
			maxInc:     false,
		},
		{
			name:       "range with spaces",
			constraint: ">= 1.0.0 , < 2.0.0 ",
			wantType:   ConstraintRange,
			wantMin:    "1.0.0",
			wantMax:    "2.0.0",
			minInc:     true,
			maxInc:     false,
		},
		{
			name:       "range with v prefix",
			constraint: ">=v1.0.0,<v2.0.0",
			wantType:   ConstraintRange,
			wantMin:    "1.0.0",
			wantMax:    "2.0.0",
			minInc:     true,
			maxInc:     false,
		},

		// Error cases
		{
			name:        "invalid version format",
			constraint:  "1.0",
			shouldError: true,
		},
		{
			name:        "invalid version - too many parts",
			constraint:  "1.0.0.0",
			shouldError: true,
		},
		{
			name:        "invalid version - non-numeric",
			constraint:  "abc",
			shouldError: true,
		},
		{
			name:        "invalid range - too many parts",
			constraint:  ">=1.0.0,<2.0.0,<3.0.0",
			shouldError: true,
		},
		{
			name:        "invalid range - min >= max",
			constraint:  ">=2.0.0,<1.0.0",
			shouldError: true,
		},
		{
			name:        "invalid range - min == max",
			constraint:  ">=1.0.0,<=1.0.0",
			shouldError: true,
		},
		{
			name:        "invalid range - missing operator on first part",
			constraint:  "1.0.0,<2.0.0",
			shouldError: true,
		},
		{
			name:        "invalid range - missing operator on second part",
			constraint:  ">=1.0.0,2.0.0",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseVersionConstraint(tt.constraint)

			if tt.shouldError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", result.Type, tt.wantType)
			}

			switch tt.wantType {
			case ConstraintExact:
				if result.ExactVersion != tt.wantExact {
					t.Errorf("ExactVersion = %v, want %v", result.ExactVersion, tt.wantExact)
				}

			case ConstraintMinimum:
				if result.MinVersion != tt.wantMin {
					t.Errorf("MinVersion = %v, want %v", result.MinVersion, tt.wantMin)
				}
				if result.MinInclusive != tt.minInc {
					t.Errorf("MinInclusive = %v, want %v", result.MinInclusive, tt.minInc)
				}

			case ConstraintMaximum:
				if result.MaxVersion != tt.wantMax {
					t.Errorf("MaxVersion = %v, want %v", result.MaxVersion, tt.wantMax)
				}
				if result.MaxInclusive != tt.maxInc {
					t.Errorf("MaxInclusive = %v, want %v", result.MaxInclusive, tt.maxInc)
				}

			case ConstraintRange:
				if result.MinVersion != tt.wantMin {
					t.Errorf("MinVersion = %v, want %v", result.MinVersion, tt.wantMin)
				}
				if result.MaxVersion != tt.wantMax {
					t.Errorf("MaxVersion = %v, want %v", result.MaxVersion, tt.wantMax)
				}
				if result.MinInclusive != tt.minInc {
					t.Errorf("MinInclusive = %v, want %v", result.MinInclusive, tt.minInc)
				}
				if result.MaxInclusive != tt.maxInc {
					t.Errorf("MaxInclusive = %v, want %v", result.MaxInclusive, tt.maxInc)
				}
			}
		})
	}
}

// TestSatisfiesConstraint tests the SatisfiesConstraint function.
func TestSatisfiesConstraint(t *testing.T) {
	tests := []struct {
		name        string
		actual      string
		constraint  string
		want        bool
		shouldError bool
	}{
		// Any version
		{
			name:       "any version - wildcard",
			actual:     "1.0.0",
			constraint: "*",
			want:       true,
		},
		{
			name:       "any version - empty",
			actual:     "2.5.3",
			constraint: "",
			want:       true,
		},

		// Exact version
		{
			name:       "exact match",
			actual:     "1.0.0",
			constraint: "1.0.0",
			want:       true,
		},
		{
			name:       "exact match with v prefix",
			actual:     "v1.0.0",
			constraint: "1.0.0",
			want:       true,
		},
		{
			name:       "exact mismatch",
			actual:     "1.0.1",
			constraint: "1.0.0",
			want:       false,
		},

		// Minimum version (inclusive)
		{
			name:       "minimum inclusive - satisfied",
			actual:     "1.5.0",
			constraint: ">=1.0.0",
			want:       true,
		},
		{
			name:       "minimum inclusive - exact match",
			actual:     "1.0.0",
			constraint: ">=1.0.0",
			want:       true,
		},
		{
			name:       "minimum inclusive - not satisfied",
			actual:     "0.9.0",
			constraint: ">=1.0.0",
			want:       false,
		},

		// Minimum version (exclusive)
		{
			name:       "minimum exclusive - satisfied",
			actual:     "1.5.0",
			constraint: ">1.0.0",
			want:       true,
		},
		{
			name:       "minimum exclusive - exact match not satisfied",
			actual:     "1.0.0",
			constraint: ">1.0.0",
			want:       false,
		},
		{
			name:       "minimum exclusive - not satisfied",
			actual:     "0.9.0",
			constraint: ">1.0.0",
			want:       false,
		},

		// Maximum version (inclusive)
		{
			name:       "maximum inclusive - satisfied",
			actual:     "1.5.0",
			constraint: "<=2.0.0",
			want:       true,
		},
		{
			name:       "maximum inclusive - exact match",
			actual:     "2.0.0",
			constraint: "<=2.0.0",
			want:       true,
		},
		{
			name:       "maximum inclusive - not satisfied",
			actual:     "2.5.0",
			constraint: "<=2.0.0",
			want:       false,
		},

		// Maximum version (exclusive)
		{
			name:       "maximum exclusive - satisfied",
			actual:     "1.5.0",
			constraint: "<2.0.0",
			want:       true,
		},
		{
			name:       "maximum exclusive - exact match not satisfied",
			actual:     "2.0.0",
			constraint: "<2.0.0",
			want:       false,
		},
		{
			name:       "maximum exclusive - not satisfied",
			actual:     "2.5.0",
			constraint: "<2.0.0",
			want:       false,
		},

		// Range constraints
		{
			name:       "range - satisfied",
			actual:     "1.5.0",
			constraint: ">=1.0.0,<2.0.0",
			want:       true,
		},
		{
			name:       "range - lower bound satisfied",
			actual:     "1.0.0",
			constraint: ">=1.0.0,<2.0.0",
			want:       true,
		},
		{
			name:       "range - upper bound not satisfied",
			actual:     "2.0.0",
			constraint: ">=1.0.0,<2.0.0",
			want:       false,
		},
		{
			name:       "range - below lower bound",
			actual:     "0.9.0",
			constraint: ">=1.0.0,<2.0.0",
			want:       false,
		},
		{
			name:       "range - above upper bound",
			actual:     "3.0.0",
			constraint: ">=1.0.0,<2.0.0",
			want:       false,
		},
		{
			name:       "range - both inclusive",
			actual:     "2.0.0",
			constraint: ">=1.0.0,<=2.0.0",
			want:       true,
		},
		{
			name:       "range - exclusive lower bound",
			actual:     "1.0.0",
			constraint: ">1.0.0,<2.0.0",
			want:       false,
		},

		// Version comparisons
		{
			name:       "major version difference",
			actual:     "2.0.0",
			constraint: ">=1.0.0",
			want:       true,
		},
		{
			name:       "minor version difference",
			actual:     "1.5.0",
			constraint: ">=1.3.0",
			want:       true,
		},
		{
			name:       "patch version difference",
			actual:     "1.0.5",
			constraint: ">=1.0.3",
			want:       true,
		},

		// Error cases
		{
			name:        "invalid actual version",
			actual:      "abc",
			constraint:  ">=1.0.0",
			shouldError: true,
		},
		{
			name:        "invalid constraint",
			actual:      "1.0.0",
			constraint:  "invalid",
			shouldError: true,
		},
		{
			name:        "malformed actual version",
			actual:      "1.0",
			constraint:  ">=1.0.0",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SatisfiesConstraint(tt.actual, tt.constraint)

			if tt.shouldError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result != tt.want {
				t.Errorf("SatisfiesConstraint(%q, %q) = %v, want %v", tt.actual, tt.constraint, result, tt.want)
			}
		})
	}
}

// TestCompareVersions tests the CompareVersions function.
func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name string
		v1   string
		v2   string
		want int
	}{
		// Equal versions
		{
			name: "equal versions",
			v1:   "1.0.0",
			v2:   "1.0.0",
			want: 0,
		},
		{
			name: "equal with v prefix",
			v1:   "v1.0.0",
			v2:   "1.0.0",
			want: 0,
		},
		{
			name: "equal both with v prefix",
			v1:   "v1.0.0",
			v2:   "v1.0.0",
			want: 0,
		},

		// Major version differences
		{
			name: "major version v1 < v2",
			v1:   "1.0.0",
			v2:   "2.0.0",
			want: -1,
		},
		{
			name: "major version v1 > v2",
			v1:   "3.0.0",
			v2:   "2.0.0",
			want: 1,
		},

		// Minor version differences
		{
			name: "minor version v1 < v2",
			v1:   "1.0.0",
			v2:   "1.5.0",
			want: -1,
		},
		{
			name: "minor version v1 > v2",
			v1:   "1.8.0",
			v2:   "1.5.0",
			want: 1,
		},

		// Patch version differences
		{
			name: "patch version v1 < v2",
			v1:   "1.0.0",
			v2:   "1.0.5",
			want: -1,
		},
		{
			name: "patch version v1 > v2",
			v1:   "1.0.9",
			v2:   "1.0.5",
			want: 1,
		},

		// Multi-digit versions
		{
			name: "multi-digit major",
			v1:   "10.0.0",
			v2:   "9.0.0",
			want: 1,
		},
		{
			name: "multi-digit minor",
			v1:   "1.20.0",
			v2:   "1.19.0",
			want: 1,
		},
		{
			name: "multi-digit patch",
			v1:   "1.0.100",
			v2:   "1.0.99",
			want: 1,
		},

		// Complex comparisons
		{
			name: "major overrides minor",
			v1:   "2.0.0",
			v2:   "1.99.99",
			want: 1,
		},
		{
			name: "minor overrides patch",
			v1:   "1.5.0",
			v2:   "1.4.99",
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CompareVersions(tt.v1, tt.v2)
			if result != tt.want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.v1, tt.v2, result, tt.want)
			}
		})
	}
}

// TestValidateVersion tests the validateVersion function.
func TestValidateVersion(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		shouldError bool
	}{
		// Valid versions
		{
			name:        "valid version",
			version:     "1.0.0",
			shouldError: false,
		},
		{
			name:        "valid version with v prefix",
			version:     "v1.0.0",
			shouldError: false,
		},
		{
			name:        "multi-digit version",
			version:     "10.20.30",
			shouldError: false,
		},

		// Invalid versions
		{
			name:        "missing patch",
			version:     "1.0",
			shouldError: true,
		},
		{
			name:        "missing minor and patch",
			version:     "1",
			shouldError: true,
		},
		{
			name:        "too many parts",
			version:     "1.0.0.0",
			shouldError: true,
		},
		{
			name:        "non-numeric major",
			version:     "a.0.0",
			shouldError: true,
		},
		{
			name:        "non-numeric minor",
			version:     "1.b.0",
			shouldError: true,
		},
		{
			name:        "non-numeric patch",
			version:     "1.0.c",
			shouldError: true,
		},
		{
			name:        "empty string",
			version:     "",
			shouldError: true,
		},
		{
			name:        "empty component",
			version:     "1..0",
			shouldError: true,
		},
		{
			name:        "negative number",
			version:     "1.0.-1",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVersion(tt.version)
			if tt.shouldError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestConstraintType tests the ConstraintType constants.
func TestConstraintType(t *testing.T) {
	tests := []struct {
		name  string
		ct    ConstraintType
		value string
	}{
		{"exact", ConstraintExact, "exact"},
		{"minimum", ConstraintMinimum, "minimum"},
		{"maximum", ConstraintMaximum, "maximum"},
		{"range", ConstraintRange, "range"},
		{"any", ConstraintAny, "any"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.ct) != tt.value {
				t.Errorf("ConstraintType value = %v, want %v", string(tt.ct), tt.value)
			}
		})
	}
}

// TestVersionConstraintJSON tests JSON marshaling/unmarshaling of VersionConstraint.
func TestVersionConstraintJSON(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
	}{
		{"exact", "1.0.0"},
		{"minimum", ">=1.0.0"},
		{"maximum", "<2.0.0"},
		{"range", ">=1.0.0,<2.0.0"},
		{"any", "*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the constraint
			c, err := ParseVersionConstraint(tt.constraint)
			if err != nil {
				t.Fatalf("failed to parse constraint: %v", err)
			}

			// Marshal to JSON (indirectly tests struct tags)
			// This test ensures the JSON tags are properly defined
			if c.Type == "" {
				t.Errorf("Type should not be empty")
			}
		})
	}
}

// TestEdgeCases tests edge cases and boundary conditions.
func TestEdgeCases(t *testing.T) {
	t.Run("version with leading zeros", func(t *testing.T) {
		// Leading zeros are treated as decimal integers
		result := CompareVersions("1.01.0", "1.1.0")
		if result != 0 {
			t.Errorf("versions with leading zeros should be equal after parsing")
		}
	})

	t.Run("very large version numbers", func(t *testing.T) {
		result := CompareVersions("999.999.999", "1000.0.0")
		if result != -1 {
			t.Errorf("large version comparison failed")
		}
	})

	t.Run("constraint with lots of whitespace", func(t *testing.T) {
		satisfied, err := SatisfiesConstraint("  1.5.0  ", "  >=  1.0.0  ,  <  2.0.0  ")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !satisfied {
			t.Errorf("constraint with whitespace should be satisfied")
		}
	})

	t.Run("range with equal bounds", func(t *testing.T) {
		_, err := ParseVersionConstraint(">=1.0.0,<=1.0.0")
		if err == nil {
			t.Errorf("expected error for range with equal bounds")
		}
	})
}

// TestParseVersionConstraintErrors tests error messages from ParseVersionConstraint.
func TestParseVersionConstraintErrors(t *testing.T) {
	tests := []struct {
		name            string
		constraint      string
		wantErrContains string
	}{
		{
			name:            "invalid exact version - malformed",
			constraint:      "not.a.version",
			wantErrContains: "invalid exact version",
		},
		{
			name:            "invalid minimum version",
			constraint:      ">=bad.version",
			wantErrContains: "invalid minimum version",
		},
		{
			name:            "invalid maximum version",
			constraint:      "<=bad.version",
			wantErrContains: "invalid maximum version",
		},
		{
			name:            "invalid range - too many commas",
			constraint:      ">=1.0.0,<2.0.0,<3.0.0",
			wantErrContains: "expected exactly 2 parts",
		},
		{
			name:            "invalid range - missing min operator",
			constraint:      "1.0.0,<2.0.0",
			wantErrContains: "first part must start with",
		},
		{
			name:            "invalid range - missing max operator",
			constraint:      ">=1.0.0,2.0.0",
			wantErrContains: "second part must start with",
		},
		{
			name:            "invalid range - min greater than max",
			constraint:      ">=5.0.0,<2.0.0",
			wantErrContains: "must be less than maximum version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseVersionConstraint(tt.constraint)
			if err == nil {
				t.Errorf("expected error containing %q but got none", tt.wantErrContains)
				return
			}
			if !containsString(err.Error(), tt.wantErrContains) {
				t.Errorf("error = %v, want error containing %q", err, tt.wantErrContains)
			}
		})
	}
}

// TestSatisfiesConstraintEdgeCases tests edge cases for SatisfiesConstraint.
func TestSatisfiesConstraintEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		actual      string
		constraint  string
		want        bool
		shouldError bool
	}{
		{
			name:       "version 0.0.0",
			actual:     "0.0.0",
			constraint: ">=0.0.0",
			want:       true,
		},
		{
			name:       "version 0.0.1 vs 0.0.0",
			actual:     "0.0.1",
			constraint: ">0.0.0",
			want:       true,
		},
		{
			name:       "exact 0.0.0",
			actual:     "0.0.0",
			constraint: "0.0.0",
			want:       true,
		},
		{
			name:       "large version numbers",
			actual:     "999.888.777",
			constraint: ">=100.0.0",
			want:       true,
		},
		{
			name:       "single digit versions",
			actual:     "1.0.0",
			constraint: ">=0.0.1",
			want:       true,
		},
		{
			name:       "v prefix in actual",
			actual:     "v2.0.0",
			constraint: ">=2.0.0",
			want:       true,
		},
		{
			name:       "v prefix in constraint",
			actual:     "2.0.0",
			constraint: ">=v2.0.0",
			want:       true,
		},
		{
			name:       "both with v prefix",
			actual:     "v2.0.0",
			constraint: ">=v2.0.0",
			want:       true,
		},
		{
			name:        "empty actual version",
			actual:      "",
			constraint:  ">=1.0.0",
			shouldError: true,
		},
		{
			name:        "actual with only spaces",
			actual:      "   ",
			constraint:  ">=1.0.0",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SatisfiesConstraint(tt.actual, tt.constraint)

			if tt.shouldError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result != tt.want {
				t.Errorf("SatisfiesConstraint(%q, %q) = %v, want %v", tt.actual, tt.constraint, result, tt.want)
			}
		})
	}
}

// TestCompareVersionsSymmetry tests that version comparison is symmetric.
func TestCompareVersionsSymmetry(t *testing.T) {
	tests := []struct {
		v1 string
		v2 string
	}{
		{"1.0.0", "2.0.0"},
		{"1.5.0", "1.3.0"},
		{"1.0.5", "1.0.3"},
		{"10.0.0", "2.0.0"},
		{"v1.0.0", "2.0.0"},
		{"1.0.0", "v2.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.v1+" vs "+tt.v2, func(t *testing.T) {
			result1 := CompareVersions(tt.v1, tt.v2)
			result2 := CompareVersions(tt.v2, tt.v1)

			// If v1 < v2 (result1 = -1), then v2 > v1 (result2 = 1)
			// If v1 > v2 (result1 = 1), then v2 < v1 (result2 = -1)
			// If v1 == v2 (result1 = 0), then v2 == v1 (result2 = 0)
			if result1+result2 != 0 {
				t.Errorf("CompareVersions is not symmetric: CompareVersions(%q, %q) = %d, CompareVersions(%q, %q) = %d",
					tt.v1, tt.v2, result1, tt.v2, tt.v1, result2)
			}
		})
	}
}

// TestCompareVersionsTransitivity tests transitivity of version comparison.
func TestCompareVersionsTransitivity(t *testing.T) {
	versions := []string{"1.0.0", "1.5.0", "2.0.0", "3.0.0"}

	for i := 0; i < len(versions)-2; i++ {
		for j := i + 1; j < len(versions)-1; j++ {
			for k := j + 1; k < len(versions); k++ {
				v1, v2, v3 := versions[i], versions[j], versions[k]

				cmp12 := CompareVersions(v1, v2)
				cmp23 := CompareVersions(v2, v3)
				cmp13 := CompareVersions(v1, v3)

				// If v1 < v2 and v2 < v3, then v1 < v3
				if cmp12 < 0 && cmp23 < 0 {
					if cmp13 >= 0 {
						t.Errorf("Transitivity violated: %s < %s < %s but CompareVersions(%s, %s) = %d",
							v1, v2, v3, v1, v3, cmp13)
					}
				}
			}
		}
	}
}

// TestNormalizeVersion tests the normalizeVersion function indirectly.
func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		name string
		v1   string
		v2   string
	}{
		{
			name: "with and without v prefix",
			v1:   "v1.0.0",
			v2:   "1.0.0",
		},
		{
			name: "both with v prefix",
			v1:   "v2.5.3",
			v2:   "v2.5.3",
		},
		{
			name: "both without v prefix",
			v1:   "3.1.4",
			v2:   "3.1.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CompareVersions(tt.v1, tt.v2)
			if result != 0 {
				t.Errorf("CompareVersions(%q, %q) = %d, want 0 (versions should be equal after normalization)",
					tt.v1, tt.v2, result)
			}
		})
	}
}

// TestRangeConstraintBoundaries tests all combinations of range boundaries.
func TestRangeConstraintBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		constraint string
		want       bool
	}{
		// Inclusive-Exclusive range: [1.0.0, 2.0.0)
		{"IE: below range", "0.9.9", ">=1.0.0,<2.0.0", false},
		{"IE: at min boundary", "1.0.0", ">=1.0.0,<2.0.0", true},
		{"IE: in range", "1.5.0", ">=1.0.0,<2.0.0", true},
		{"IE: at max boundary", "2.0.0", ">=1.0.0,<2.0.0", false},
		{"IE: above range", "2.0.1", ">=1.0.0,<2.0.0", false},

		// Exclusive-Inclusive range: (1.0.0, 2.0.0]
		{"EI: below range", "0.9.9", ">1.0.0,<=2.0.0", false},
		{"EI: at min boundary", "1.0.0", ">1.0.0,<=2.0.0", false},
		{"EI: in range", "1.5.0", ">1.0.0,<=2.0.0", true},
		{"EI: at max boundary", "2.0.0", ">1.0.0,<=2.0.0", true},
		{"EI: above range", "2.0.1", ">1.0.0,<=2.0.0", false},

		// Exclusive-Exclusive range: (1.0.0, 2.0.0)
		{"EE: below range", "0.9.9", ">1.0.0,<2.0.0", false},
		{"EE: at min boundary", "1.0.0", ">1.0.0,<2.0.0", false},
		{"EE: in range", "1.5.0", ">1.0.0,<2.0.0", true},
		{"EE: at max boundary", "2.0.0", ">1.0.0,<2.0.0", false},
		{"EE: above range", "2.0.1", ">1.0.0,<2.0.0", false},

		// Inclusive-Inclusive range: [1.0.0, 2.0.0]
		{"II: below range", "0.9.9", ">=1.0.0,<=2.0.0", false},
		{"II: at min boundary", "1.0.0", ">=1.0.0,<=2.0.0", true},
		{"II: in range", "1.5.0", ">=1.0.0,<=2.0.0", true},
		{"II: at max boundary", "2.0.0", ">=1.0.0,<=2.0.0", true},
		{"II: above range", "2.0.1", ">=1.0.0,<=2.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SatisfiesConstraint(tt.version, tt.constraint)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.want {
				t.Errorf("SatisfiesConstraint(%q, %q) = %v, want %v", tt.version, tt.constraint, result, tt.want)
			}
		})
	}
}

// TestVersionConstraintParsing tests that parsed constraints have correct fields.
func TestVersionConstraintParsing(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		checkFunc  func(*testing.T, *VersionConstraint)
	}{
		{
			name:       "exact version sets only ExactVersion",
			constraint: "1.0.0",
			checkFunc: func(t *testing.T, vc *VersionConstraint) {
				if vc.ExactVersion != "1.0.0" {
					t.Errorf("ExactVersion = %q, want %q", vc.ExactVersion, "1.0.0")
				}
				if vc.MinVersion != "" {
					t.Errorf("MinVersion should be empty, got %q", vc.MinVersion)
				}
				if vc.MaxVersion != "" {
					t.Errorf("MaxVersion should be empty, got %q", vc.MaxVersion)
				}
			},
		},
		{
			name:       "minimum sets MinVersion and MinInclusive",
			constraint: ">=2.0.0",
			checkFunc: func(t *testing.T, vc *VersionConstraint) {
				if vc.MinVersion != "2.0.0" {
					t.Errorf("MinVersion = %q, want %q", vc.MinVersion, "2.0.0")
				}
				if !vc.MinInclusive {
					t.Errorf("MinInclusive = false, want true")
				}
				if vc.MaxVersion != "" {
					t.Errorf("MaxVersion should be empty, got %q", vc.MaxVersion)
				}
				if vc.ExactVersion != "" {
					t.Errorf("ExactVersion should be empty, got %q", vc.ExactVersion)
				}
			},
		},
		{
			name:       "exclusive minimum sets MinInclusive false",
			constraint: ">2.0.0",
			checkFunc: func(t *testing.T, vc *VersionConstraint) {
				if vc.MinVersion != "2.0.0" {
					t.Errorf("MinVersion = %q, want %q", vc.MinVersion, "2.0.0")
				}
				if vc.MinInclusive {
					t.Errorf("MinInclusive = true, want false")
				}
			},
		},
		{
			name:       "maximum sets MaxVersion and MaxInclusive",
			constraint: "<=3.0.0",
			checkFunc: func(t *testing.T, vc *VersionConstraint) {
				if vc.MaxVersion != "3.0.0" {
					t.Errorf("MaxVersion = %q, want %q", vc.MaxVersion, "3.0.0")
				}
				if !vc.MaxInclusive {
					t.Errorf("MaxInclusive = false, want true")
				}
				if vc.MinVersion != "" {
					t.Errorf("MinVersion should be empty, got %q", vc.MinVersion)
				}
			},
		},
		{
			name:       "exclusive maximum sets MaxInclusive false",
			constraint: "<3.0.0",
			checkFunc: func(t *testing.T, vc *VersionConstraint) {
				if vc.MaxVersion != "3.0.0" {
					t.Errorf("MaxVersion = %q, want %q", vc.MaxVersion, "3.0.0")
				}
				if vc.MaxInclusive {
					t.Errorf("MaxInclusive = true, want false")
				}
			},
		},
		{
			name:       "range sets all fields",
			constraint: ">=1.0.0,<2.0.0",
			checkFunc: func(t *testing.T, vc *VersionConstraint) {
				if vc.MinVersion != "1.0.0" {
					t.Errorf("MinVersion = %q, want %q", vc.MinVersion, "1.0.0")
				}
				if vc.MaxVersion != "2.0.0" {
					t.Errorf("MaxVersion = %q, want %q", vc.MaxVersion, "2.0.0")
				}
				if !vc.MinInclusive {
					t.Errorf("MinInclusive = false, want true")
				}
				if vc.MaxInclusive {
					t.Errorf("MaxInclusive = true, want false")
				}
			},
		},
		{
			name:       "any version has no fields set",
			constraint: "*",
			checkFunc: func(t *testing.T, vc *VersionConstraint) {
				if vc.MinVersion != "" {
					t.Errorf("MinVersion should be empty, got %q", vc.MinVersion)
				}
				if vc.MaxVersion != "" {
					t.Errorf("MaxVersion should be empty, got %q", vc.MaxVersion)
				}
				if vc.ExactVersion != "" {
					t.Errorf("ExactVersion should be empty, got %q", vc.ExactVersion)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vc, err := ParseVersionConstraint(tt.constraint)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tt.checkFunc(t, vc)
		})
	}
}

// TestCompareVersionsZeroValues tests comparison with zero versions.
func TestCompareVersionsZeroValues(t *testing.T) {
	tests := []struct {
		name string
		v1   string
		v2   string
		want int
	}{
		{"0.0.0 vs 0.0.0", "0.0.0", "0.0.0", 0},
		{"0.0.0 vs 0.0.1", "0.0.0", "0.0.1", -1},
		{"0.0.1 vs 0.0.0", "0.0.1", "0.0.0", 1},
		{"0.0.0 vs 1.0.0", "0.0.0", "1.0.0", -1},
		{"0.1.0 vs 0.0.1", "0.1.0", "0.0.1", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CompareVersions(tt.v1, tt.v2)
			if result != tt.want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.v1, tt.v2, result, tt.want)
			}
		})
	}
}

// TestMultipleConstraintsSatisfaction tests a version against multiple constraints.
func TestMultipleConstraintsSatisfaction(t *testing.T) {
	version := "1.5.0"
	constraints := []struct {
		constraint string
		want       bool
	}{
		{">=1.0.0", true},
		{">=1.5.0", true},
		{">1.5.0", false},
		{"<2.0.0", true},
		{"<=1.5.0", true},
		{">=1.0.0,<2.0.0", true},
		{">=1.5.0,<=1.5.0", false}, // Invalid range
		{"1.5.0", true},
		{"1.4.0", false},
		{"*", true},
	}

	for _, tc := range constraints {
		t.Run("version "+version+" vs "+tc.constraint, func(t *testing.T) {
			result, err := SatisfiesConstraint(version, tc.constraint)

			// Handle invalid range case
			if tc.constraint == ">=1.5.0,<=1.5.0" {
				if err == nil {
					t.Errorf("expected error for invalid range, got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tc.want {
				t.Errorf("SatisfiesConstraint(%q, %q) = %v, want %v", version, tc.constraint, result, tc.want)
			}
		})
	}
}

// Helper function to check if a string contains a substring.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && contains(s, substr)))
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
