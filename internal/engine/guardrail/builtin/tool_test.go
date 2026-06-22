package builtin

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/guardrail"
)

func TestToolRestriction_Name(t *testing.T) {
	config := ToolRestrictionConfig{}
	tr := NewToolRestriction(config)
	assert.Equal(t, "tool_restriction", tr.Name())
}

func TestToolRestriction_Type(t *testing.T) {
	config := ToolRestrictionConfig{}
	tr := NewToolRestriction(config)
	assert.Equal(t, guardrail.GuardrailTypeTool, tr.Type())
}

func TestToolRestriction_CheckInput(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name                 string
		config               ToolRestrictionConfig
		input                guardrail.GuardrailInput
		expectAllowed        bool
		expectReasonContains string
	}{
		{
			name: "tool in allowed list",
			config: ToolRestrictionConfig{
				AllowedTools: []string{"bash", "python", "go"},
			},
			input: guardrail.GuardrailInput{
				ToolName: "bash",
			},
			expectAllowed:        true,
			expectReasonContains: "",
		},
		{
			name: "tool not in allowed list",
			config: ToolRestrictionConfig{
				AllowedTools: []string{"bash", "python"},
			},
			input: guardrail.GuardrailInput{
				ToolName: "curl",
			},
			expectAllowed:        false,
			expectReasonContains: "not in allowed list",
		},
		{
			name: "tool in blocked list",
			config: ToolRestrictionConfig{
				AllowedTools: []string{"bash", "curl"},
				BlockedTools: []string{"curl"},
			},
			input: guardrail.GuardrailInput{
				ToolName: "curl",
			},
			expectAllowed:        false,
			expectReasonContains: "is blocked",
		},
		{
			name: "empty allowed list allows all",
			config: ToolRestrictionConfig{
				AllowedTools: []string{},
				BlockedTools: []string{},
			},
			input: guardrail.GuardrailInput{
				ToolName: "anything",
			},
			expectAllowed:        true,
			expectReasonContains: "",
		},
		{
			name: "empty allowed list but tool is blocked",
			config: ToolRestrictionConfig{
				AllowedTools: []string{},
				BlockedTools: []string{"dangerous"},
			},
			input: guardrail.GuardrailInput{
				ToolName: "dangerous",
			},
			expectAllowed:        false,
			expectReasonContains: "is blocked",
		},
		{
			name: "case insensitive matching - uppercase tool",
			config: ToolRestrictionConfig{
				AllowedTools: []string{"bash"},
			},
			input: guardrail.GuardrailInput{
				ToolName: "BASH",
			},
			expectAllowed:        true,
			expectReasonContains: "",
		},
		{
			name: "case insensitive matching - mixed case config",
			config: ToolRestrictionConfig{
				AllowedTools: []string{"BaSh"},
			},
			input: guardrail.GuardrailInput{
				ToolName: "bash",
			},
			expectAllowed:        true,
			expectReasonContains: "",
		},
		{
			name: "no tool name in input",
			config: ToolRestrictionConfig{
				AllowedTools: []string{"bash"},
			},
			input: guardrail.GuardrailInput{
				ToolName: "",
			},
			expectAllowed:        true,
			expectReasonContains: "",
		},
		{
			name: "tool with allowed tag",
			config: ToolRestrictionConfig{
				AllowedTags: []string{"safe", "utility"},
			},
			input: guardrail.GuardrailInput{
				ToolName: "mytool",
				Metadata: map[string]interface{}{
					"tags": []string{"safe", "experimental"},
				},
			},
			expectAllowed:        true,
			expectReasonContains: "",
		},
		{
			name: "tool with blocked tag",
			config: ToolRestrictionConfig{
				AllowedTags: []string{"safe"},
				BlockedTags: []string{"dangerous"},
			},
			input: guardrail.GuardrailInput{
				ToolName: "mytool",
				Metadata: map[string]interface{}{
					"tags": []string{"safe", "dangerous"},
				},
			},
			expectAllowed:        false,
			expectReasonContains: "blocked tag",
		},
		{
			name: "tool without any allowed tags",
			config: ToolRestrictionConfig{
				AllowedTags: []string{"safe"},
			},
			input: guardrail.GuardrailInput{
				ToolName: "mytool",
				Metadata: map[string]interface{}{
					"tags": []string{"experimental", "beta"},
				},
			},
			expectAllowed:        false,
			expectReasonContains: "does not have any allowed tags",
		},
		{
			name: "empty both lists allows all",
			config: ToolRestrictionConfig{
				AllowedTools: []string{},
				BlockedTools: []string{},
			},
			input: guardrail.GuardrailInput{
				ToolName: "anytool",
			},
			expectAllowed:        true,
			expectReasonContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := NewToolRestriction(tt.config)
			result, err := tr.CheckInput(ctx, tt.input)

			require.NoError(t, err)
			assert.Equal(t, tt.expectAllowed, result.AllowContinue(), "Allowed mismatch")

			if tt.expectReasonContains != "" {
				assert.Contains(t, result.Reason, tt.expectReasonContains, "Reason should contain expected text")
			}

			if tt.expectAllowed {
				assert.Equal(t, guardrail.GuardrailActionAllow, result.Action)
			} else {
				assert.Equal(t, guardrail.GuardrailActionBlock, result.Action)
			}
		})
	}
}

func TestToolRestriction_CheckOutput(t *testing.T) {
	ctx := context.Background()
	config := ToolRestrictionConfig{
		BlockedTools: []string{"curl"},
	}
	tr := NewToolRestriction(config)

	output := guardrail.GuardrailOutput{
		Content: "some output",
	}

	result, err := tr.CheckOutput(ctx, output)
	require.NoError(t, err)
	assert.True(t, result.AllowContinue(), "Output should always be allowed")
	assert.Equal(t, guardrail.GuardrailActionAllow, result.Action)
}

func TestToolRestriction_MultipleTools(t *testing.T) {
	ctx := context.Background()
	config := ToolRestrictionConfig{
		AllowedTools: []string{"bash", "python", "go"},
		BlockedTools: []string{"curl", "wget"},
	}
	tr := NewToolRestriction(config)

	// Test multiple allowed tools
	allowedTools := []string{"bash", "python", "go", "BASH", "Python"}
	for _, tool := range allowedTools {
		result, err := tr.CheckInput(ctx, guardrail.GuardrailInput{ToolName: tool})
		require.NoError(t, err)
		assert.True(t, result.AllowContinue(), "Tool %s should be allowed", tool)
	}

	// Test blocked tools
	blockedTools := []string{"curl", "wget", "CURL", "WGet"}
	for _, tool := range blockedTools {
		result, err := tr.CheckInput(ctx, guardrail.GuardrailInput{ToolName: tool})
		require.NoError(t, err)
		assert.False(t, result.AllowContinue(), "Tool %s should be blocked", tool)
	}

	// Test not in allowed list
	notAllowedTools := []string{"rm", "dd", "netcat"}
	for _, tool := range notAllowedTools {
		result, err := tr.CheckInput(ctx, guardrail.GuardrailInput{ToolName: tool})
		require.NoError(t, err)
		assert.False(t, result.AllowContinue(), "Tool %s should not be allowed", tool)
	}
}
