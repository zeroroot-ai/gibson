// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"encoding/json"
	"testing"
)

// TestTargetType_String tests the String method for TargetType
func TestTargetType_String(t *testing.T) {
	tests := []struct {
		name     string
		target   TargetType
		expected string
	}{
		{"LLMChat", TargetTypeLLMChat, "llm_chat"},
		{"LLMAPI", TargetTypeLLMAPI, "llm_api"},
		{"RAG", TargetTypeRAG, "rag"},
		{"Agent", TargetTypeAgent, "agent"},
		{"Embedding", TargetTypeEmbedding, "embedding"},
		{"Multimodal", TargetTypeMultimodal, "multimodal"},
		{"Custom", TargetTypeCustom, "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.target.String()
			if result != tt.expected {
				t.Errorf("String() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestTargetType_IsValid tests the IsValid method for TargetType
func TestTargetType_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		target   TargetType
		expected bool
	}{
		{"ValidLLMChat", TargetTypeLLMChat, true},
		{"ValidLLMAPI", TargetTypeLLMAPI, true},
		{"ValidRAG", TargetTypeRAG, true},
		{"ValidAgent", TargetTypeAgent, true},
		{"ValidEmbedding", TargetTypeEmbedding, true},
		{"ValidMultimodal", TargetTypeMultimodal, true},
		{"ValidCustom", TargetTypeCustom, true},
		{"InvalidEmpty", TargetType(""), false},
		{"InvalidUnknown", TargetType("unknown"), false},
		{"InvalidTypo", TargetType("llm_chatt"), false},
		{"InvalidCase", TargetType("LLM_CHAT"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.target.IsValid()
			if result != tt.expected {
				t.Errorf("IsValid() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestTargetType_MarshalJSON tests JSON marshaling for TargetType
func TestTargetType_MarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		target    TargetType
		expected  string
		expectErr bool
	}{
		{"ValidLLMChat", TargetTypeLLMChat, `"llm_chat"`, false},
		{"ValidRAG", TargetTypeRAG, `"rag"`, false},
		{"ValidCustom", TargetTypeCustom, `"custom"`, false},
		{"InvalidType", TargetType("invalid"), "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.target)
			if tt.expectErr {
				if err == nil {
					t.Error("MarshalJSON() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("MarshalJSON() unexpected error: %v", err)
				return
			}
			if string(data) != tt.expected {
				t.Errorf("MarshalJSON() = %v, want %v", string(data), tt.expected)
			}
		})
	}
}

// TestTargetType_UnmarshalJSON tests JSON unmarshaling for TargetType
func TestTargetType_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  TargetType
		expectErr bool
	}{
		{"ValidLLMChat", `"llm_chat"`, TargetTypeLLMChat, false},
		{"ValidRAG", `"rag"`, TargetTypeRAG, false},
		{"ValidAgent", `"agent"`, TargetTypeAgent, false},
		{"InvalidType", `"invalid"`, "", true},
		{"InvalidJSON", `invalid`, "", true},
		{"InvalidEmpty", `""`, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var target TargetType
			err := json.Unmarshal([]byte(tt.input), &target)
			if tt.expectErr {
				if err == nil {
					t.Error("UnmarshalJSON() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("UnmarshalJSON() unexpected error: %v", err)
				return
			}
			if target != tt.expected {
				t.Errorf("UnmarshalJSON() = %v, want %v", target, tt.expected)
			}
		})
	}
}

// TestAllTargetTypes tests that AllTargetTypes returns all valid types
func TestAllTargetTypes(t *testing.T) {
	all := AllTargetTypes()
	expected := 7 // Number of defined target types

	if len(all) != expected {
		t.Errorf("AllTargetTypes() returned %d types, want %d", len(all), expected)
	}

	// Verify all returned types are valid
	for _, target := range all {
		if !target.IsValid() {
			t.Errorf("AllTargetTypes() returned invalid type: %v", target)
		}
	}

	// Verify specific types are present
	expectedTypes := map[TargetType]bool{
		TargetTypeLLMChat:    true,
		TargetTypeLLMAPI:     true,
		TargetTypeRAG:        true,
		TargetTypeAgent:      true,
		TargetTypeEmbedding:  true,
		TargetTypeMultimodal: true,
		TargetTypeCustom:     true,
	}

	for _, target := range all {
		if !expectedTypes[target] {
			t.Errorf("AllTargetTypes() returned unexpected type: %v", target)
		}
		delete(expectedTypes, target)
	}

	if len(expectedTypes) > 0 {
		t.Errorf("AllTargetTypes() missing types: %v", expectedTypes)
	}
}

// TestParseTargetType tests parsing strings into TargetType
func TestParseTargetType(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  TargetType
		expectErr bool
	}{
		{"ValidLLMChat", "llm_chat", TargetTypeLLMChat, false},
		{"ValidLLMAPI", "llm_api", TargetTypeLLMAPI, false},
		{"ValidRAG", "rag", TargetTypeRAG, false},
		{"ValidAgent", "agent", TargetTypeAgent, false},
		{"ValidEmbedding", "embedding", TargetTypeEmbedding, false},
		{"ValidMultimodal", "multimodal", TargetTypeMultimodal, false},
		{"ValidCustom", "custom", TargetTypeCustom, false},
		{"InvalidEmpty", "", "", true},
		{"InvalidUnknown", "unknown", "", true},
		{"InvalidCase", "LLM_CHAT", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseTargetType(tt.input)
			if tt.expectErr {
				if err == nil {
					t.Error("ParseTargetType() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("ParseTargetType() unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("ParseTargetType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestTargetType_JSONRoundTrip tests marshaling and unmarshaling TargetType
func TestTargetType_JSONRoundTrip(t *testing.T) {
	for _, target := range AllTargetTypes() {
		t.Run(target.String(), func(t *testing.T) {
			data, err := json.Marshal(target)
			if err != nil {
				t.Fatalf("Marshal() error: %v", err)
			}

			var decoded TargetType
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Unmarshal() error: %v", err)
			}

			if decoded != target {
				t.Errorf("Round trip failed: got %v, want %v", decoded, target)
			}
		})
	}
}
