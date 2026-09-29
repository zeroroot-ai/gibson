// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package types

import (
	"encoding/json"
	"testing"
)

// This file tests TechniqueType directly, in the package that owns it.
//
// TechniqueType degraded from "the technique authority" to "the core pack's
// category seed" under ADR-0035 (gibson#379/#385): the taxonomy
// (internal/engine/taxonomy, TechniqueHierarchy/GlobalTechniques) is the
// authority now, and every consumer that used to key on this enum keys on a
// taxonomy.CategoryID instead. The enum itself — its eight values, String,
// IsValid, JSON (un)marshaling, ParseTechniqueType — stays, purely as the seed
// coreCategories() (internal/engine/taxonomy/technique.go) derives
// GlobalTechniques' categories from, so it still deserves direct coverage
// here rather than only exercising it indirectly through a consumer.

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

// TestTechniqueType_IsValid tests the IsValid method
func TestTechniqueType_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		tt       TechniqueType
		expected bool
	}{
		{"prompt_injection", TechniquePromptInjection, true},
		{"jailbreak", TechniqueJailbreak, true},
		{"extraction", TechniqueExtraction, true},
		{"dos", TechniqueDoS, true},
		{"poisoning", TechniquePoisoning, true},
		{"evasion", TechniqueEvasion, true},
		{"reconnaissance", TechniqueReconnaissance, true},
		{"custom", TechniqueCustom, true},
		{"empty", TechniqueType(""), false},
		{"unknown", TechniqueType("unknown"), false},
		{"typo", TechniqueType("jailbreaak"), false},
		{"wrong case", TechniqueType("JAILBREAK"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tt.IsValid(); got != tt.expected {
				t.Errorf("TechniqueType.IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestTechniqueType_MarshalJSON tests JSON marshaling
func TestTechniqueType_MarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		tt        TechniqueType
		expected  string
		expectErr bool
	}{
		{"prompt_injection", TechniquePromptInjection, `"prompt_injection"`, false},
		{"jailbreak", TechniqueJailbreak, `"jailbreak"`, false},
		{"custom", TechniqueCustom, `"custom"`, false},
		{"invalid", TechniqueType("invalid"), "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.tt)
			if tt.expectErr {
				if err == nil {
					t.Fatal("MarshalJSON() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("MarshalJSON() unexpected error: %v", err)
			}
			if string(data) != tt.expected {
				t.Errorf("MarshalJSON() = %v, want %v", string(data), tt.expected)
			}
		})
	}
}

// TestTechniqueType_UnmarshalJSON tests JSON unmarshaling
func TestTechniqueType_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  TechniqueType
		expectErr bool
	}{
		{"prompt_injection", `"prompt_injection"`, TechniquePromptInjection, false},
		{"jailbreak", `"jailbreak"`, TechniqueJailbreak, false},
		{"extraction", `"extraction"`, TechniqueExtraction, false},
		{"invalid value", `"invalid"`, "", true},
		{"invalid json", `invalid`, "", true},
		{"empty", `""`, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TechniqueType
			err := json.Unmarshal([]byte(tt.input), &got)
			if tt.expectErr {
				if err == nil {
					t.Fatal("UnmarshalJSON() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalJSON() unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("UnmarshalJSON() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestTechniqueType_JSONRoundTrip marshals and unmarshals every seed value.
func TestTechniqueType_JSONRoundTrip(t *testing.T) {
	for _, tt := range AllTechniqueTypes() {
		t.Run(tt.String(), func(t *testing.T) {
			data, err := json.Marshal(tt)
			if err != nil {
				t.Fatalf("Marshal() error: %v", err)
			}

			var decoded TechniqueType
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Unmarshal() error: %v", err)
			}

			if decoded != tt {
				t.Errorf("round trip: got %v, want %v", decoded, tt)
			}
		})
	}
}

// TestAllTechniqueTypes tests that AllTechniqueTypes returns exactly the
// eight seed values, each valid — this is the seed coreCategories() in
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
		if !tt.IsValid() {
			t.Errorf("AllTechniqueTypes() returned invalid type: %v", tt)
		}
		if !want[tt] {
			t.Errorf("AllTechniqueTypes() returned unexpected type: %v", tt)
		}
		delete(want, tt)
	}

	if len(want) > 0 {
		t.Errorf("AllTechniqueTypes() missing types: %v", want)
	}
}

// TestParseTechniqueType tests parsing strings into TechniqueType
func TestParseTechniqueType(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  TechniqueType
		expectErr bool
	}{
		{"prompt_injection", "prompt_injection", TechniquePromptInjection, false},
		{"jailbreak", "jailbreak", TechniqueJailbreak, false},
		{"extraction", "extraction", TechniqueExtraction, false},
		{"dos", "dos", TechniqueDoS, false},
		{"poisoning", "poisoning", TechniquePoisoning, false},
		{"evasion", "evasion", TechniqueEvasion, false},
		{"reconnaissance", "reconnaissance", TechniqueReconnaissance, false},
		{"custom", "custom", TechniqueCustom, false},
		{"empty", "", "", true},
		{"unknown", "unknown", "", true},
		{"wrong case", "JAILBREAK", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTechniqueType(tt.input)
			if tt.expectErr {
				if err == nil {
					t.Fatal("ParseTechniqueType() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTechniqueType() unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("ParseTechniqueType() = %v, want %v", got, tt.expected)
			}
		})
	}
}
