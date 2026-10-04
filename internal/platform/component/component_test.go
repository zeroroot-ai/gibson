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

// Number of defined target types

// Verify all returned types are valid

// Verify specific types are present
