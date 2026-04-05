package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateProviderKeys_AllPresent(t *testing.T) {
	providers := map[string]ProviderConfig{
		"anthropic": {Type: "anthropic", APIKeyEnv: "ANTHROPIC_API_KEY"},
		"openai":    {Type: "openai", APIKeyEnv: "OPENAI_API_KEY"},
	}

	env := func(key string) string {
		switch key {
		case "ANTHROPIC_API_KEY":
			return "sk-ant-api03-valid-key-1234567890"
		case "OPENAI_API_KEY":
			return "sk-valid-openai-key-1234567890"
		default:
			return ""
		}
	}

	results := ValidateProviderKeys(providers, env)
	for _, r := range results {
		assert.NoError(t, r.Error, "provider %s should have no error", r.ProviderName)
		assert.True(t, r.Available, "provider %s should be available", r.ProviderName)
	}
}

func TestValidateProviderKeys_MissingEnvVar(t *testing.T) {
	providers := map[string]ProviderConfig{
		"anthropic": {Type: "anthropic", APIKeyEnv: "ANTHROPIC_API_KEY"},
	}

	env := func(key string) string { return "" }

	results := ValidateProviderKeys(providers, env)
	require.Len(t, results, 1)
	assert.Error(t, results[0].Error)
	assert.Contains(t, results[0].Error.Error(), "ANTHROPIC_API_KEY")
	assert.Contains(t, results[0].Error.Error(), "not set or is empty")
	assert.False(t, results[0].Available)
}

func TestValidateProviderKeys_PlaceholderDetected(t *testing.T) {
	providers := map[string]ProviderConfig{
		"openai": {Type: "openai", APIKeyEnv: "OPENAI_API_KEY"},
	}

	env := func(key string) string { return "sk-your-key-here" }

	results := ValidateProviderKeys(providers, env)
	require.Len(t, results, 1)
	assert.Error(t, results[0].Error)
	assert.Contains(t, results[0].Error.Error(), "placeholder")
}

func TestValidateProviderKeys_PrefixWarning(t *testing.T) {
	providers := map[string]ProviderConfig{
		"anthropic": {Type: "anthropic", APIKeyEnv: "ANTHROPIC_API_KEY"},
	}

	// Key doesn't start with sk-ant-
	env := func(key string) string { return "wrong-prefix-key-123" }

	results := ValidateProviderKeys(providers, env)
	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error) // Prefix mismatch is a warning, not error
	assert.True(t, results[0].Available)
	assert.Contains(t, results[0].Warning, "expected prefix")
}

func TestValidateProviderKeys_UnconfiguredProvider(t *testing.T) {
	providers := map[string]ProviderConfig{
		"gemini": {Type: "google"}, // No api_key_env
	}

	results := ValidateProviderKeys(providers, nil)
	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
	assert.False(t, results[0].Available) // Unconfigured but not an error
}

func TestValidateProviderKeys_BothApiKeyAndEnv(t *testing.T) {
	providers := map[string]ProviderConfig{
		"anthropic": {
			Type:      "anthropic",
			APIKey:    "inline-key",
			APIKeyEnv: "ANTHROPIC_API_KEY",
		},
	}

	env := func(key string) string { return "sk-ant-env-key-123" }

	results := ValidateProviderKeys(providers, env)
	require.Len(t, results, 1)
	assert.Contains(t, results[0].Warning, "both api_key and api_key_env")
	assert.True(t, results[0].Available)
}

func TestValidateProviderKeys_WhitespaceTrimming(t *testing.T) {
	providers := map[string]ProviderConfig{
		"openai": {Type: "openai", APIKeyEnv: "OPENAI_API_KEY"},
	}

	env := func(key string) string { return "  sk-valid-key-123  " }

	results := ValidateProviderKeys(providers, env)
	require.Len(t, results, 1)
	assert.True(t, results[0].Available)
	assert.Contains(t, results[0].Warning, "whitespace")
}

func TestValidateProviderKeys_MultipleErrors(t *testing.T) {
	providers := map[string]ProviderConfig{
		"anthropic": {Type: "anthropic", APIKeyEnv: "ANTHROPIC_API_KEY"},
		"openai":    {Type: "openai", APIKeyEnv: "OPENAI_API_KEY"},
		"gemini":    {Type: "google", APIKeyEnv: "GEMINI_API_KEY"},
	}

	env := func(key string) string { return "" } // All missing

	results := ValidateProviderKeys(providers, env)
	var errors []error
	for _, r := range results {
		if r.Error != nil {
			errors = append(errors, r.Error)
		}
	}
	// All three should have errors (all have api_key_env set but env is empty)
	assert.Len(t, errors, 3, "should report all three errors, not fail on first")
}

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
