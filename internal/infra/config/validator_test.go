// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsPlaceholderValue(t *testing.T) {
	tests := []struct {
		value    string
		expected bool
	}{
		{"sk-your-key-here", true},
		{"<your-api-key>", true},
		{"CHANGE_ME", true},
		{"TODO", true},
		{"xxx", true},
		{"replace-me", true},
		{"sk-ant-api03-real-key-abc123", false},
		{"sk-proj-real-openai-key", false},
		{"a-short-but-real-key", false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsPlaceholderValue(tt.value))
		})
	}
}

func TestMaskKey(t *testing.T) {
	assert.Equal(t, "****", maskKey("short"))
	assert.Equal(t, "****", maskKey("12345678"))
	assert.Equal(t, "sk-ant...****", maskKey("sk-ant-api03-abc123xyz"))
}
