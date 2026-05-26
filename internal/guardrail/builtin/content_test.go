package builtin

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/guardrail"
)

func TestContentFilter_Construction(t *testing.T) {
	tests := []struct {
		name        string
		config      ContentFilterConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid single pattern",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `\bpassword\b`, Action: guardrail.GuardrailActionBlock},
				},
			},
			expectError: false,
		},
		{
			name: "valid multiple patterns",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `\bpassword\b`, Action: guardrail.GuardrailActionBlock},
					{Pattern: `\bsecret\b`, Action: guardrail.GuardrailActionRedact},
				},
			},
			expectError: false,
		},
		{
			name: "empty patterns list",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{},
			},
			expectError: false,
		},
		{
			name: "invalid regex pattern",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `[invalid(`, Action: guardrail.GuardrailActionBlock},
				},
			},
			expectError: true,
			errorMsg:    "invalid regex pattern",
		},
		{
			name: "pattern with default action",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `test`, Action: ""},
				},
				DefaultAction: guardrail.GuardrailActionWarn,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, err := NewContentFilter(tt.config)
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, filter)
				assert.Equal(t, "content-filter", filter.Name())
				assert.Equal(t, guardrail.GuardrailTypeContent, filter.Type())
			}
		})
	}
}

func TestContentFilter_CheckInput(t *testing.T) {
	tests := []struct {
		name             string
		config           ContentFilterConfig
		content          string
		expectedAction   guardrail.GuardrailAction
		expectedReason   string
		checkModified    bool
		expectedModified string
		checkMetadata    bool
	}{
		{
			name: "single pattern match - block",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `\bpassword\b`, Action: guardrail.GuardrailActionBlock},
				},
			},
			content:        "The password is secret123",
			expectedAction: guardrail.GuardrailActionBlock,
			expectedReason: "matched pattern",
			checkMetadata:  true,
		},
		{
			name: "single pattern match - redact with replacement",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `\d{3}-\d{2}-\d{4}`, Action: guardrail.GuardrailActionRedact, Replace: "XXX-XX-XXXX"},
				},
			},
			content:          "SSN: 123-45-6789",
			expectedAction:   guardrail.GuardrailActionRedact,
			checkModified:    true,
			expectedModified: "SSN: XXX-XX-XXXX",
		},
		{
			name: "single pattern match - redact with default replacement",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `\bcreditcard\b`, Action: guardrail.GuardrailActionRedact},
				},
			},
			content:          "My creditcard number",
			expectedAction:   guardrail.GuardrailActionRedact,
			checkModified:    true,
			expectedModified: "My [REDACTED] number",
		},
		{
			name: "single pattern match - warn",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `\bwarning\b`, Action: guardrail.GuardrailActionWarn},
				},
			},
			content:        "This is a warning message",
			expectedAction: guardrail.GuardrailActionWarn,
			expectedReason: "matched pattern",
		},
		{
			name: "no pattern match - allow",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `\bsecret\b`, Action: guardrail.GuardrailActionBlock},
				},
			},
			content:        "This is a normal message",
			expectedAction: guardrail.GuardrailActionAllow,
		},
		{
			name: "multiple patterns - most restrictive wins (block beats redact)",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `\bpassword\b`, Action: guardrail.GuardrailActionRedact, Replace: "[PWD]"},
					{Pattern: `\bsecret\b`, Action: guardrail.GuardrailActionBlock},
				},
			},
			content:        "password and secret together",
			expectedAction: guardrail.GuardrailActionBlock,
		},
		{
			name: "multiple patterns - block beats warn",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `\bapi\b`, Action: guardrail.GuardrailActionWarn},
					{Pattern: `\bkey\b`, Action: guardrail.GuardrailActionBlock},
				},
			},
			content:        "api key detected",
			expectedAction: guardrail.GuardrailActionBlock,
		},
		{
			name: "multiple patterns - redact beats warn",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `\bemail\b`, Action: guardrail.GuardrailActionWarn},
					{Pattern: `\baddress\b`, Action: guardrail.GuardrailActionRedact, Replace: "[ADDR]"},
				},
			},
			content:          "email address is sensitive",
			expectedAction:   guardrail.GuardrailActionRedact,
			checkModified:    true,
			expectedModified: "email [ADDR] is sensitive",
		},
		{
			name: "multiple redact patterns - all applied",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `\d{3}-\d{2}-\d{4}`, Action: guardrail.GuardrailActionRedact, Replace: "XXX-XX-XXXX"},
					{Pattern: `\b[A-Z]{2}\d{6}\b`, Action: guardrail.GuardrailActionRedact, Replace: "XX######"},
				},
			},
			content:          "SSN: 123-45-6789 and ID: AB123456",
			expectedAction:   guardrail.GuardrailActionRedact,
			checkModified:    true,
			expectedModified: "SSN: XXX-XX-XXXX and ID: XX######",
		},
		{
			name: "empty patterns list - allow all",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{},
			},
			content:        "any content here",
			expectedAction: guardrail.GuardrailActionAllow,
		},
		{
			name: "pattern with capture groups",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `(\w+)@(\w+\.\w+)`, Action: guardrail.GuardrailActionRedact, Replace: "[EMAIL]"},
				},
			},
			content:          "Contact user@example.com for info",
			expectedAction:   guardrail.GuardrailActionRedact,
			checkModified:    true,
			expectedModified: "Contact [EMAIL] for info",
		},
		{
			name: "case-insensitive matching",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `(?i)\bpassword\b`, Action: guardrail.GuardrailActionBlock},
				},
			},
			content:        "The PASSWORD is secret",
			expectedAction: guardrail.GuardrailActionBlock,
		},
		{
			name: "custom replacement text",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `\bTODO\b.*`, Action: guardrail.GuardrailActionRedact, Replace: "[TASK REMOVED]"},
				},
			},
			content:          "TODO: implement feature",
			expectedAction:   guardrail.GuardrailActionRedact,
			checkModified:    true,
			expectedModified: "[TASK REMOVED]",
		},
		{
			name: "warn beats allow",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `\binfo\b`, Action: guardrail.GuardrailActionAllow},
					{Pattern: `\bwarning\b`, Action: guardrail.GuardrailActionWarn},
				},
			},
			content:        "info and warning together",
			expectedAction: guardrail.GuardrailActionWarn,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, err := NewContentFilter(tt.config)
			require.NoError(t, err)

			input := guardrail.GuardrailInput{
				Content: tt.content,
			}

			result, err := filter.CheckInput(context.Background(), input)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedAction, result.Action)

			if tt.expectedReason != "" {
				assert.Contains(t, result.Reason, tt.expectedReason)
			}

			if tt.checkModified {
				assert.Equal(t, tt.expectedModified, result.ModifiedContent)
			}

			if tt.checkMetadata {
				assert.NotNil(t, result.Metadata)
				assert.Contains(t, result.Metadata, "matched_patterns")
			}
		})
	}
}

func TestContentFilter_CheckOutput(t *testing.T) {
	tests := []struct {
		name             string
		config           ContentFilterConfig
		content          string
		expectedAction   guardrail.GuardrailAction
		checkModified    bool
		expectedModified string
	}{
		{
			name: "output with sensitive data - block",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `\bapi_key\b`, Action: guardrail.GuardrailActionBlock},
				},
			},
			content:        "Response contains api_key",
			expectedAction: guardrail.GuardrailActionBlock,
		},
		{
			name: "output with PII - redact",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `\d{3}-\d{3}-\d{4}`, Action: guardrail.GuardrailActionRedact, Replace: "XXX-XXX-XXXX"},
				},
			},
			content:          "Phone: 555-123-4567",
			expectedAction:   guardrail.GuardrailActionRedact,
			checkModified:    true,
			expectedModified: "Phone: XXX-XXX-XXXX",
		},
		{
			name: "safe output - allow",
			config: ContentFilterConfig{
				Patterns: []ContentPattern{
					{Pattern: `\bcritical\b`, Action: guardrail.GuardrailActionBlock},
				},
			},
			content:        "Normal response data",
			expectedAction: guardrail.GuardrailActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, err := NewContentFilter(tt.config)
			require.NoError(t, err)

			output := guardrail.GuardrailOutput{
				Content: tt.content,
			}

			result, err := filter.CheckOutput(context.Background(), output)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedAction, result.Action)

			if tt.checkModified {
				assert.Equal(t, tt.expectedModified, result.ModifiedContent)
			}
		})
	}
}

func TestContentFilter_ActionPriority(t *testing.T) {
	tests := []struct {
		name     string
		action   guardrail.GuardrailAction
		expected int
	}{
		{
			name:     "block has highest priority",
			action:   guardrail.GuardrailActionBlock,
			expected: 4,
		},
		{
			name:     "redact has second priority",
			action:   guardrail.GuardrailActionRedact,
			expected: 3,
		},
		{
			name:     "warn has third priority",
			action:   guardrail.GuardrailActionWarn,
			expected: 2,
		},
		{
			name:     "allow has lowest priority",
			action:   guardrail.GuardrailActionAllow,
			expected: 1,
		},
		{
			name:     "unknown action has zero priority",
			action:   guardrail.GuardrailAction("unknown"),
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priority := actionPriority(tt.action)
			assert.Equal(t, tt.expected, priority)
		})
	}
}

func TestContentFilter_ComplexScenarios(t *testing.T) {
	t.Run("multiple overlapping patterns with different actions", func(t *testing.T) {
		config := ContentFilterConfig{
			Patterns: []ContentPattern{
				{Pattern: `\bdata\b`, Action: guardrail.GuardrailActionWarn},
				{Pattern: `\bsensitive\b`, Action: guardrail.GuardrailActionRedact, Replace: "[SENS]"},
				{Pattern: `\bcritical\b`, Action: guardrail.GuardrailActionBlock},
			},
		}

		filter, err := NewContentFilter(config)
		require.NoError(t, err)

		// Test case 1: Only data (warn)
		result, err := filter.CheckInput(context.Background(), guardrail.GuardrailInput{
			Content: "This has data",
		})
		require.NoError(t, err)
		assert.Equal(t, guardrail.GuardrailActionWarn, result.Action)

		// Test case 2: Data and sensitive (redact wins)
		result, err = filter.CheckInput(context.Background(), guardrail.GuardrailInput{
			Content: "sensitive data here",
		})
		require.NoError(t, err)
		assert.Equal(t, guardrail.GuardrailActionRedact, result.Action)
		assert.Equal(t, "[SENS] data here", result.ModifiedContent)

		// Test case 3: All three (block wins)
		result, err = filter.CheckInput(context.Background(), guardrail.GuardrailInput{
			Content: "critical sensitive data",
		})
		require.NoError(t, err)
		assert.Equal(t, guardrail.GuardrailActionBlock, result.Action)
	})

	t.Run("sequential redactions preserve order", func(t *testing.T) {
		config := ContentFilterConfig{
			Patterns: []ContentPattern{
				{Pattern: `\bfirst\b`, Action: guardrail.GuardrailActionRedact, Replace: "1st"},
				{Pattern: `\bsecond\b`, Action: guardrail.GuardrailActionRedact, Replace: "2nd"},
				{Pattern: `\bthird\b`, Action: guardrail.GuardrailActionRedact, Replace: "3rd"},
			},
		}

		filter, err := NewContentFilter(config)
		require.NoError(t, err)

		result, err := filter.CheckInput(context.Background(), guardrail.GuardrailInput{
			Content: "first second third item",
		})
		require.NoError(t, err)
		assert.Equal(t, guardrail.GuardrailActionRedact, result.Action)
		assert.Equal(t, "1st 2nd 3rd item", result.ModifiedContent)
	})

	t.Run("metadata contains all matched patterns", func(t *testing.T) {
		config := ContentFilterConfig{
			Patterns: []ContentPattern{
				{Pattern: `\bone\b`, Action: guardrail.GuardrailActionWarn},
				{Pattern: `\btwo\b`, Action: guardrail.GuardrailActionWarn},
				{Pattern: `\bthree\b`, Action: guardrail.GuardrailActionWarn},
			},
		}

		filter, err := NewContentFilter(config)
		require.NoError(t, err)

		result, err := filter.CheckInput(context.Background(), guardrail.GuardrailInput{
			Content: "one two three",
		})
		require.NoError(t, err)
		assert.Equal(t, guardrail.GuardrailActionWarn, result.Action)

		patterns, ok := result.Metadata["matched_patterns"].([]string)
		require.True(t, ok)
		assert.Len(t, patterns, 3)
	})
}
