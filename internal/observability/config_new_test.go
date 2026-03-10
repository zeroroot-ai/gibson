package observability

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestContentLoggingConfig_Integration demonstrates full workflow.
func TestContentLoggingConfig_Integration(t *testing.T) {
	// Create config with defaults
	cfg := DefaultContentLoggingConfig()
	assert.False(t, cfg.Enabled, "should be disabled by default")

	// Enable and compile patterns
	cfg.Enabled = true
	err := cfg.CompilePatterns()
	require.NoError(t, err)

	// Test redaction
	sensitive := "My api_key=sk-1234567890 and password=secret"
	redacted := cfg.Redact(sensitive)
	assert.Contains(t, redacted, "[REDACTED]")
	assert.NotContains(t, redacted, "sk-1234567890")

	// Test truncation
	longText := "This is a very long message that should be truncated"
	truncated := cfg.Truncate(longText, 10)
	assert.Contains(t, truncated, "... [truncated]")
	assert.True(t, len(truncated) < len(longText))

	// Validate configuration
	err = cfg.Validate()
	assert.NoError(t, err)
}

// TestOTLPConfig_Integration demonstrates full workflow.
func TestOTLPConfig_Integration(t *testing.T) {
	// Create config with defaults
	cfg := DefaultOTLPConfig()
	assert.Equal(t, 512, cfg.BatchSize)
	assert.True(t, cfg.RetryEnabled)

	// Customize config
	cfg.Endpoint = "http://localhost:4318"
	cfg.Compression = "gzip"
	cfg.Headers = map[string]string{
		"Authorization": "Bearer token123",
	}

	// Validate configuration
	err := cfg.Validate()
	assert.NoError(t, err)
}

// TestContentLoggingConfig_TruncateEdgeCases tests edge cases for truncation.
func TestContentLoggingConfig_TruncateEdgeCases(t *testing.T) {
	cfg := ContentLoggingConfig{}

	// Empty string
	assert.Equal(t, "", cfg.Truncate("", 10))

	// Single character string with maxLen 1
	assert.Equal(t, "x", cfg.Truncate("x", 1))

	// Multi-byte UTF-8 characters
	result := cfg.Truncate("世界你好世界你好", 3)
	assert.Equal(t, "世界你... [truncated]", result)
}

// TestOTLPConfig_EdgeCases tests edge cases for OTLP configuration.
func TestOTLPConfig_EdgeCases(t *testing.T) {
	// Minimum valid config
	cfg := OTLPConfig{
		Endpoint:     "http://localhost:4318",
		BatchSize:    1,
		BatchTimeout: 1 * time.Millisecond,
		RetryEnabled: false,
	}
	err := cfg.Validate()
	assert.NoError(t, err)

	// Zero retry intervals when retry is disabled (should be valid)
	cfg2 := OTLPConfig{
		Endpoint:             "http://localhost:4318",
		BatchSize:            100,
		BatchTimeout:         1 * time.Second,
		RetryEnabled:         false,
		RetryInitialInterval: 0,
		RetryMaxInterval:     0,
		RetryMaxElapsedTime:  0,
	}
	err = cfg2.Validate()
	assert.NoError(t, err)
}

// TestContentLoggingConfig_MultipleRedactions tests multiple pattern matches.
func TestContentLoggingConfig_MultipleRedactions(t *testing.T) {
	cfg := ContentLoggingConfig{
		RedactPatterns: []string{
			`api_key=\S+`,
			`password=\S+`,
			`token=\S+`,
		},
	}
	err := cfg.CompilePatterns()
	require.NoError(t, err)

	input := "Config: api_key=secret1 password=secret2 token=secret3"
	result := cfg.Redact(input)

	assert.Contains(t, result, "[REDACTED]")
	assert.NotContains(t, result, "secret1")
	assert.NotContains(t, result, "secret2")
	assert.NotContains(t, result, "secret3")
}

// TestContentLoggingConfig_ValidateComplexPatterns tests complex regex patterns.
func TestContentLoggingConfig_ValidateComplexPatterns(t *testing.T) {
	cfg := ContentLoggingConfig{
		MaxPromptLength:     10000,
		MaxCompletionLength: 10000,
		RedactPatterns: []string{
			`(?i)(api[_-]?key|password|secret|token|bearer)[=:\s]+\S+`, // Case-insensitive with alternation
			`\b\d{3}-\d{2}-\d{4}\b`,                                     // SSN pattern
			`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,      // Email pattern
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)

	// Compile and test
	err = cfg.CompilePatterns()
	require.NoError(t, err)

	testCases := []struct {
		input    string
		contains string
	}{
		{"API_KEY=secret", "[REDACTED]"},
		{"SSN: 123-45-6789", "[REDACTED]"},
		{"Contact: user@example.com", "[REDACTED]"},
	}

	for _, tc := range testCases {
		result := cfg.Redact(tc.input)
		assert.Contains(t, result, tc.contains, "Failed for input: %s", tc.input)
	}
}
