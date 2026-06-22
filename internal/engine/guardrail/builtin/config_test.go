package builtin

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/guardrail"
)

func TestParseScopeConfig(t *testing.T) {
	config := GuardrailConfig{
		Type: "scope",
		Config: map[string]any{
			"allowed_domains": []any{"example.com", "*.api.example.com"},
			"blocked_paths":   []any{"/admin/*", "/internal/*"},
		},
	}

	g, err := ParseGuardrailConfig(config)
	require.NoError(t, err)
	require.NotNil(t, g)

	assert.Equal(t, "scope-validator", g.Name())
	assert.Equal(t, guardrail.GuardrailTypeScope, g.Type())
}

func TestParseRateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      GuardrailConfig
		expectError bool
	}{
		{
			name: "valid config with window as string",
			config: GuardrailConfig{
				Type: "rate",
				Config: map[string]any{
					"max_requests": 100,
					"window":       "1m",
					"per_target":   true,
				},
			},
			expectError: false,
		},
		{
			name: "valid config with seconds",
			config: GuardrailConfig{
				Type: "rate",
				Config: map[string]any{
					"max_requests": 50,
					"window":       "30s",
					"burst_size":   60,
					"per_target":   false,
				},
			},
			expectError: false,
		},
		{
			name: "invalid window format",
			config: GuardrailConfig{
				Type: "rate",
				Config: map[string]any{
					"max_requests": 100,
					"window":       "invalid",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := ParseGuardrailConfig(tt.config)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, g)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, g)
				assert.Equal(t, "rate-limiter", g.Name())
				assert.Equal(t, guardrail.GuardrailTypeRate, g.Type())
			}
		})
	}
}

func TestParseToolConfig(t *testing.T) {
	config := GuardrailConfig{
		Type: "tool",
		Config: map[string]any{
			"allowed_tools": []any{"http_request", "dns_lookup"},
			"blocked_tools": []any{"shell_execute"},
		},
	}

	g, err := ParseGuardrailConfig(config)
	require.NoError(t, err)
	require.NotNil(t, g)

	assert.Equal(t, "tool_restriction", g.Name())
	assert.Equal(t, guardrail.GuardrailTypeTool, g.Type())
}

func TestParsePIIConfig(t *testing.T) {
	tests := []struct {
		name   string
		config GuardrailConfig
	}{
		{
			name: "with redact action",
			config: GuardrailConfig{
				Type: "pii",
				Config: map[string]any{
					"action":           "redact",
					"enabled_patterns": []any{"ssn", "email", "credit_card"},
				},
			},
		},
		{
			name: "with block action",
			config: GuardrailConfig{
				Type: "pii",
				Config: map[string]any{
					"action":           "block",
					"enabled_patterns": []any{"ssn"},
				},
			},
		},
		{
			name: "with custom patterns",
			config: GuardrailConfig{
				Type: "pii",
				Config: map[string]any{
					"action":           "redact",
					"enabled_patterns": []any{"email"},
					"custom_patterns": map[string]any{
						"custom_id": `\bCUST-\d{6}\b`,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := ParseGuardrailConfig(tt.config)
			require.NoError(t, err)
			require.NotNil(t, g)

			assert.Equal(t, "pii_detector", g.Name())
			assert.Equal(t, guardrail.GuardrailTypePII, g.Type())
		})
	}
}

func TestParseContentConfig(t *testing.T) {
	config := GuardrailConfig{
		Type: "content",
		Config: map[string]any{
			"patterns": []any{
				map[string]any{
					"pattern": "password",
					"action":  "redact",
					"replace": "[REDACTED]",
				},
				map[string]any{
					"pattern": "secret",
					"action":  "block",
				},
			},
		},
	}

	g, err := ParseGuardrailConfig(config)
	require.NoError(t, err)
	require.NotNil(t, g)

	assert.Equal(t, "content-filter", g.Name())
	assert.Equal(t, guardrail.GuardrailTypeContent, g.Type())
}

func TestParseGuardrailConfigs(t *testing.T) {
	configs := []GuardrailConfig{
		{
			Type: "scope",
			Config: map[string]any{
				"allowed_domains": []any{"example.com"},
			},
		},
		{
			Type: "rate",
			Config: map[string]any{
				"max_requests": 100,
				"window":       "1m",
			},
		},
		{
			Type: "tool",
			Config: map[string]any{
				"allowed_tools": []any{"http_request"},
			},
		},
	}

	guardrails, err := ParseGuardrailConfigs(configs)
	require.NoError(t, err)
	assert.Len(t, guardrails, 3)

	assert.Equal(t, guardrail.GuardrailTypeScope, guardrails[0].Type())
	assert.Equal(t, guardrail.GuardrailTypeRate, guardrails[1].Type())
	assert.Equal(t, guardrail.GuardrailTypeTool, guardrails[2].Type())
}

func TestParseGuardrailConfigsWithError(t *testing.T) {
	configs := []GuardrailConfig{
		{
			Type: "scope",
			Config: map[string]any{
				"allowed_domains": []any{"example.com"},
			},
		},
		{
			Type: "invalid_type",
			Config: map[string]any{
				"foo": "bar",
			},
		},
	}

	guardrails, err := ParseGuardrailConfigs(configs)
	assert.Error(t, err)
	assert.Nil(t, guardrails)
	assert.Contains(t, err.Error(), "unsupported guardrail type")
}

func TestValidateGuardrailConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      GuardrailConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "empty type",
			config: GuardrailConfig{
				Type:   "",
				Config: map[string]any{},
			},
			expectError: true,
			errorMsg:    "guardrail type is required",
		},
		{
			name: "unknown type",
			config: GuardrailConfig{
				Type:   "unknown",
				Config: map[string]any{},
			},
			expectError: true,
			errorMsg:    "unsupported guardrail type",
		},
		{
			name: "nil config",
			config: GuardrailConfig{
				Type:   "scope",
				Config: nil,
			},
			expectError: true,
			errorMsg:    "config is required",
		},
		{
			name: "valid scope config",
			config: GuardrailConfig{
				Type: "scope",
				Config: map[string]any{
					"allowed_domains": []any{"example.com"},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGuardrailConfig(tt.config)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateRateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]any
		expectError bool
		errorMsg    string
	}{
		{
			name: "missing max_requests",
			config: map[string]any{
				"window": "1m",
			},
			expectError: true,
			errorMsg:    "max_requests is required",
		},
		{
			name: "missing window",
			config: map[string]any{
				"max_requests": 100,
			},
			expectError: true,
			errorMsg:    "window is required",
		},
		{
			name: "negative max_requests",
			config: map[string]any{
				"max_requests": -10,
				"window":       "1m",
			},
			expectError: true,
			errorMsg:    "max_requests must be positive",
		},
		{
			name: "invalid window format",
			config: map[string]any{
				"max_requests": 100,
				"window":       "invalid",
			},
			expectError: true,
			errorMsg:    "invalid window duration",
		},
		{
			name: "valid config",
			config: map[string]any{
				"max_requests": 100,
				"window":       "1m",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRateConfig(tt.config)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateScopeConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]any
		expectError bool
		errorMsg    string
	}{
		{
			name:        "empty config",
			config:      map[string]any{},
			expectError: false,
		},
		{
			name: "valid config",
			config: map[string]any{
				"allowed_domains": []any{"example.com"},
				"blocked_paths":   []any{"/admin/*"},
			},
			expectError: false,
		},
		{
			name: "invalid allowed_domains type",
			config: map[string]any{
				"allowed_domains": "not an array",
			},
			expectError: true,
			errorMsg:    "allowed_domains must be an array",
		},
		{
			name: "invalid blocked_paths type",
			config: map[string]any{
				"blocked_paths": "not an array",
			},
			expectError: true,
			errorMsg:    "blocked_paths must be an array",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateScopeConfig(tt.config)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateToolConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]any
		expectError bool
		errorMsg    string
	}{
		{
			name:        "empty config",
			config:      map[string]any{},
			expectError: false,
		},
		{
			name: "valid config",
			config: map[string]any{
				"allowed_tools": []any{"http_request"},
				"blocked_tools": []any{"shell_execute"},
			},
			expectError: false,
		},
		{
			name: "invalid allowed_tools type",
			config: map[string]any{
				"allowed_tools": "not an array",
			},
			expectError: true,
			errorMsg:    "allowed_tools must be an array",
		},
		{
			name: "invalid blocked_tools type",
			config: map[string]any{
				"blocked_tools": "not an array",
			},
			expectError: true,
			errorMsg:    "blocked_tools must be an array",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateToolConfig(tt.config)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePIIConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]any
		expectError bool
		errorMsg    string
	}{
		{
			name:        "empty config",
			config:      map[string]any{},
			expectError: false,
		},
		{
			name: "valid config with action",
			config: map[string]any{
				"action":           "redact",
				"enabled_patterns": []any{"ssn", "email"},
			},
			expectError: false,
		},
		{
			name: "invalid action",
			config: map[string]any{
				"action": "invalid_action",
			},
			expectError: true,
			errorMsg:    "invalid action",
		},
		{
			name: "invalid enabled_patterns type",
			config: map[string]any{
				"enabled_patterns": "not an array",
			},
			expectError: true,
			errorMsg:    "enabled_patterns must be an array",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePIIConfig(tt.config)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateContentConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]any
		expectError bool
		errorMsg    string
	}{
		{
			name:        "missing patterns",
			config:      map[string]any{},
			expectError: true,
			errorMsg:    "patterns is required",
		},
		{
			name: "empty patterns array",
			config: map[string]any{
				"patterns": []any{},
			},
			expectError: true,
			errorMsg:    "at least one pattern is required",
		},
		{
			name: "patterns not an array",
			config: map[string]any{
				"patterns": "not an array",
			},
			expectError: true,
			errorMsg:    "patterns must be an array",
		},
		{
			name: "pattern missing pattern field",
			config: map[string]any{
				"patterns": []any{
					map[string]any{
						"action": "block",
					},
				},
			},
			expectError: true,
			errorMsg:    "must have a 'pattern' field",
		},
		{
			name: "valid config",
			config: map[string]any{
				"patterns": []any{
					map[string]any{
						"pattern": "password",
						"action":  "redact",
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateContentConfig(tt.config)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSupportedGuardrailTypes(t *testing.T) {
	types := SupportedGuardrailTypes()
	assert.Len(t, types, 5)
	assert.Contains(t, types, "scope")
	assert.Contains(t, types, "rate")
	assert.Contains(t, types, "tool")
	assert.Contains(t, types, "pii")
	assert.Contains(t, types, "content")
}

func TestDurationParsing(t *testing.T) {
	tests := []struct {
		name     string
		duration string
		expected time.Duration
	}{
		{"1 minute", "1m", time.Minute},
		{"30 seconds", "30s", 30 * time.Second},
		{"1 hour", "1h", time.Hour},
		{"mixed", "1m30s", time.Minute + 30*time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := GuardrailConfig{
				Type: "rate",
				Config: map[string]any{
					"max_requests": 100,
					"window":       tt.duration,
				},
			}

			g, err := ParseGuardrailConfig(config)
			require.NoError(t, err)
			require.NotNil(t, g)
		})
	}
}

func TestDefaultValues(t *testing.T) {
	t.Run("rate limiter default burst size", func(t *testing.T) {
		config := GuardrailConfig{
			Type: "rate",
			Config: map[string]any{
				"max_requests": 100,
				"window":       "1m",
				// burst_size not specified
			},
		}

		g, err := ParseGuardrailConfig(config)
		require.NoError(t, err)
		require.NotNil(t, g)
	})

	t.Run("pii detector default action", func(t *testing.T) {
		config := GuardrailConfig{
			Type: "pii",
			Config: map[string]any{
				"enabled_patterns": []any{"ssn"},
				// action not specified (should default to redact)
			},
		}

		g, err := ParseGuardrailConfig(config)
		require.NoError(t, err)
		require.NotNil(t, g)
	})
}

func TestInvalidConfigs(t *testing.T) {
	tests := []struct {
		name   string
		config GuardrailConfig
	}{
		{
			name: "invalid regex in content filter",
			config: GuardrailConfig{
				Type: "content",
				Config: map[string]any{
					"patterns": []any{
						map[string]any{
							"pattern": "[invalid regex",
							"action":  "block",
						},
					},
				},
			},
		},
		{
			name: "invalid regex in pii detector",
			config: GuardrailConfig{
				Type: "pii",
				Config: map[string]any{
					"custom_patterns": map[string]any{
						"bad_pattern": "[invalid",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := ParseGuardrailConfig(tt.config)
			assert.Error(t, err)
			assert.Nil(t, g)
		})
	}
}
