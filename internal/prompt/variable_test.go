package prompt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestResolvePath(t *testing.T) {
	tests := []struct {
		name     string
		ctx      map[string]any
		path     string
		expected any
		found    bool
	}{
		{
			name: "simple path",
			ctx: map[string]any{
				"foo": "bar",
			},
			path:     "foo",
			expected: "bar",
			found:    true,
		},
		{
			name: "nested path",
			ctx: map[string]any{
				"mission": map[string]any{
					"target": map[string]any{
						"url": "https://example.com",
					},
				},
			},
			path:     "mission.target.url",
			expected: "https://example.com",
			found:    true,
		},
		{
			name: "deep nested path",
			ctx: map[string]any{
				"a": map[string]any{
					"b": map[string]any{
						"c": map[string]any{
							"d": 42,
						},
					},
				},
			},
			path:     "a.b.c.d",
			expected: 42,
			found:    true,
		},
		{
			name: "path not found",
			ctx: map[string]any{
				"foo": "bar",
			},
			path:     "missing",
			expected: nil,
			found:    false,
		},
		{
			name: "partial path not found",
			ctx: map[string]any{
				"mission": map[string]any{
					"target": "value",
				},
			},
			path:     "mission.missing.url",
			expected: nil,
			found:    false,
		},
		{
			name: "empty path",
			ctx: map[string]any{
				"foo": "bar",
			},
			path:     "",
			expected: nil,
			found:    false,
		},
		{
			name: "non-map intermediate value",
			ctx: map[string]any{
				"mission": "string_value",
			},
			path:     "mission.target.url",
			expected: nil,
			found:    false,
		},
		{
			name: "numeric value",
			ctx: map[string]any{
				"config": map[string]any{
					"timeout": 30,
				},
			},
			path:     "config.timeout",
			expected: 30,
			found:    true,
		},
		{
			name: "boolean value",
			ctx: map[string]any{
				"flags": map[string]any{
					"enabled": true,
				},
			},
			path:     "flags.enabled",
			expected: true,
			found:    true,
		},
		{
			name: "slice value",
			ctx: map[string]any{
				"data": map[string]any{
					"items": []string{"a", "b", "c"},
				},
			},
			path:     "data.items",
			expected: []string{"a", "b", "c"},
			found:    true,
		},
		{
			name: "nil value exists",
			ctx: map[string]any{
				"nullable": nil,
			},
			path:     "nullable",
			expected: nil,
			found:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := ResolvePath(tt.ctx, tt.path)
			assert.Equal(t, tt.found, found, "found mismatch")
			assert.Equal(t, tt.expected, result, "value mismatch")
		})
	}
}

func TestVariableDef_Resolve(t *testing.T) {
	tests := []struct {
		name        string
		variable    VariableDef
		ctx         map[string]any
		expected    any
		expectError bool
		errorCode   types.ErrorCode
	}{
		{
			name: "resolve from direct context",
			variable: VariableDef{
				Name: "username",
			},
			ctx: map[string]any{
				"username": "alice",
			},
			expected:    "alice",
			expectError: false,
		},
		{
			name: "resolve from source path",
			variable: VariableDef{
				Name:   "target_url",
				Source: "mission.target.url",
			},
			ctx: map[string]any{
				"mission": map[string]any{
					"target": map[string]any{
						"url": "https://example.com",
					},
				},
			},
			expected:    "https://example.com",
			expectError: false,
		},
		{
			name: "direct context takes precedence over source",
			variable: VariableDef{
				Name:   "value",
				Source: "other.path",
			},
			ctx: map[string]any{
				"value": "direct",
				"other": map[string]any{
					"path": "source",
				},
			},
			expected:    "direct",
			expectError: false,
		},
		{
			name: "use default when not found",
			variable: VariableDef{
				Name:    "missing",
				Default: "default_value",
			},
			ctx:         map[string]any{},
			expected:    "default_value",
			expectError: false,
		},
		{
			name: "required variable not found",
			variable: VariableDef{
				Name:     "required_var",
				Required: true,
			},
			ctx:         map[string]any{},
			expected:    nil,
			expectError: true,
			errorCode:   PROMPT_VAR_REQUIRED,
		},
		{
			name: "required variable found in context",
			variable: VariableDef{
				Name:     "required_var",
				Required: true,
			},
			ctx: map[string]any{
				"required_var": "present",
			},
			expected:    "present",
			expectError: false,
		},
		{
			name: "required variable found in source",
			variable: VariableDef{
				Name:     "required_var",
				Required: true,
				Source:   "nested.value",
			},
			ctx: map[string]any{
				"nested": map[string]any{
					"value": "present",
				},
			},
			expected:    "present",
			expectError: false,
		},
		{
			name: "default numeric value",
			variable: VariableDef{
				Name:    "timeout",
				Default: 30,
			},
			ctx:         map[string]any{},
			expected:    30,
			expectError: false,
		},
		{
			name: "default boolean value",
			variable: VariableDef{
				Name:    "enabled",
				Default: false,
			},
			ctx:         map[string]any{},
			expected:    false,
			expectError: false,
		},
		{
			name: "resolve nil value",
			variable: VariableDef{
				Name: "nullable",
			},
			ctx: map[string]any{
				"nullable": nil,
			},
			expected:    nil,
			expectError: false,
		},
		{
			name: "source path not found with default",
			variable: VariableDef{
				Name:    "var",
				Source:  "missing.path",
				Default: "fallback",
			},
			ctx:         map[string]any{},
			expected:    "fallback",
			expectError: false,
		},
		{
			name: "source path not found without default",
			variable: VariableDef{
				Name:   "var",
				Source: "missing.path",
			},
			ctx:         map[string]any{},
			expected:    nil,
			expectError: false,
		},
		{
			name: "complex nested source",
			variable: VariableDef{
				Name:   "credential",
				Source: "mission.auth.credentials.api_key",
			},
			ctx: map[string]any{
				"mission": map[string]any{
					"auth": map[string]any{
						"credentials": map[string]any{
							"api_key": "secret123",
						},
					},
				},
			},
			expected:    "secret123",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.variable.Resolve(tt.ctx)

			if tt.expectError {
				require.Error(t, err)
				var gibsonErr *types.GibsonError
				require.ErrorAs(t, err, &gibsonErr)
				assert.Equal(t, tt.errorCode, gibsonErr.Code)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestVariableDef_ResolveWithDescription(t *testing.T) {
	variable := VariableDef{
		Name:        "api_key",
		Description: "API key for authentication",
		Required:    true,
		Source:      "credentials.api_key",
	}

	ctx := map[string]any{
		"credentials": map[string]any{
			"api_key": "test_key",
		},
	}

	result, err := variable.Resolve(ctx)
	require.NoError(t, err)
	assert.Equal(t, "test_key", result)
}
