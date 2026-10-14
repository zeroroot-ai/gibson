// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestModelInfo_SupportsFeature(t *testing.T) {
	tests := []struct {
		name     string
		model    ModelInfo
		feature  string
		expected bool
	}{
		{
			name: "has feature",
			model: ModelInfo{
				Features: []string{"tool_use", "vision"},
			},
			feature:  "tool_use",
			expected: true,
		},
		{
			name: "does not have feature",
			model: ModelInfo{
				Features: []string{"tool_use"},
			},
			feature:  "vision",
			expected: false,
		},
		{
			name: "empty features",
			model: ModelInfo{
				Features: []string{},
			},
			feature:  "tool_use",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.model.SupportsFeature(tt.feature)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestModelInfo_SupportsToolUse(t *testing.T) {
	tests := []struct {
		name     string
		model    ModelInfo
		expected bool
	}{
		{
			name: "supports tool use",
			model: ModelInfo{
				Features: []string{"tool_use", "streaming"},
			},
			expected: true,
		},
		{
			name: "does not support tool use",
			model: ModelInfo{
				Features: []string{"streaming"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.model.SupportsToolUse()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestModelInfo_SupportsVision(t *testing.T) {
	tests := []struct {
		name     string
		model    ModelInfo
		expected bool
	}{
		{
			name: "supports vision",
			model: ModelInfo{
				Features: []string{"vision", "streaming"},
			},
			expected: true,
		},
		{
			name: "does not support vision",
			model: ModelInfo{
				Features: []string{"streaming"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.model.SupportsVision()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestModelInfo_SupportsStreaming(t *testing.T) {
	tests := []struct {
		name     string
		model    ModelInfo
		expected bool
	}{
		{
			name: "supports streaming",
			model: ModelInfo{
				Features: []string{"streaming", "tool_use"},
			},
			expected: true,
		},
		{
			name: "does not support streaming",
			model: ModelInfo{
				Features: []string{"tool_use"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.model.SupportsStreaming()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestModelInfo_SupportsJSONMode(t *testing.T) {
	tests := []struct {
		name     string
		model    ModelInfo
		expected bool
	}{
		{
			name: "supports JSON mode",
			model: ModelInfo{
				Features: []string{"json_mode", "tool_use"},
			},
			expected: true,
		},
		{
			name: "does not support JSON mode",
			model: ModelInfo{
				Features: []string{"tool_use"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.model.SupportsJSONMode()
			assert.Equal(t, tt.expected, result)
		})
	}
}
