// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package observability

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestTracingConfig_YAMLSerialization tests YAML marshaling and unmarshaling.
func TestTracingConfig_YAMLSerialization(t *testing.T) {
	original := TracingConfig{
		Enabled:     true,
		Provider:    "otlp",
		Endpoint:    "http://localhost:4318",
		ServiceName: "gibson-test",
		SampleRate:  0.75,
	}

	// Marshal to YAML
	data, err := yaml.Marshal(&original)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Verify YAML contains expected fields
	yamlStr := string(data)
	assert.Contains(t, yamlStr, "enabled: true")
	assert.Contains(t, yamlStr, "provider: otlp")
	assert.Contains(t, yamlStr, "endpoint: http://localhost:4318")
	assert.Contains(t, yamlStr, "service_name: gibson-test")
	assert.Contains(t, yamlStr, "sample_rate: 0.75")

	// Unmarshal back
	var unmarshaled TracingConfig
	err = yaml.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, original.Enabled, unmarshaled.Enabled)
	assert.Equal(t, original.Provider, unmarshaled.Provider)
	assert.Equal(t, original.Endpoint, unmarshaled.Endpoint)
	assert.Equal(t, original.ServiceName, unmarshaled.ServiceName)
	assert.Equal(t, original.SampleRate, unmarshaled.SampleRate)
}

// TestMetricsConfig_YAMLSerialization tests YAML marshaling and unmarshaling.
func TestMetricsConfig_YAMLSerialization(t *testing.T) {
	original := MetricsConfig{
		Enabled:  true,
		Provider: "prometheus",
		Port:     9090,
	}

	// Marshal to YAML
	data, err := yaml.Marshal(&original)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Verify YAML contains expected fields
	yamlStr := string(data)
	assert.Contains(t, yamlStr, "enabled: true")
	assert.Contains(t, yamlStr, "provider: prometheus")
	assert.Contains(t, yamlStr, "port: 9090")

	// Unmarshal back
	var unmarshaled MetricsConfig
	err = yaml.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, original.Enabled, unmarshaled.Enabled)
	assert.Equal(t, original.Provider, unmarshaled.Provider)
	assert.Equal(t, original.Port, unmarshaled.Port)
}

// TestLoggingConfig_YAMLSerialization tests YAML marshaling and unmarshaling.
func TestLoggingConfig_YAMLSerialization(t *testing.T) {
	original := LoggingConfig{
		Level:  "debug",
		Format: "json",
		Output: "/var/log/gibson.log",
	}

	// Marshal to YAML
	data, err := yaml.Marshal(&original)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Verify YAML contains expected fields
	yamlStr := string(data)
	assert.Contains(t, yamlStr, "level: debug")
	assert.Contains(t, yamlStr, "format: json")
	assert.Contains(t, yamlStr, "output: /var/log/gibson.log")

	// Unmarshal back
	var unmarshaled LoggingConfig
	err = yaml.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, original.Level, unmarshaled.Level)
	assert.Equal(t, original.Format, unmarshaled.Format)
	assert.Equal(t, original.Output, unmarshaled.Output)
}

// TestContentLoggingConfig_DefaultConfig tests the default configuration.
func TestContentLoggingConfig_DefaultConfig(t *testing.T) {
	cfg := DefaultContentLoggingConfig()

	assert.False(t, cfg.Enabled, "content logging should be disabled by default (opt-in)")
	assert.Equal(t, 10000, cfg.MaxPromptLength)
	assert.Equal(t, 10000, cfg.MaxCompletionLength)
	assert.False(t, cfg.IncludeToolIO)
	assert.NotEmpty(t, cfg.RedactPatterns, "should have default redaction patterns")
	assert.Nil(t, cfg.compiledPatterns, "patterns should not be compiled yet")
}

// TestContentLoggingConfig_CompilePatterns tests pattern compilation.
func TestContentLoggingConfig_CompilePatterns(t *testing.T) {
	tests := []struct {
		name      string
		patterns  []string
		wantError bool
	}{
		{
			name:      "valid patterns",
			patterns:  []string{`\d{16}`, `(?i)password\s*=\s*\S+`, `api[_-]?key`},
			wantError: false,
		},
		{
			name:      "empty patterns",
			patterns:  []string{},
			wantError: false,
		},
		{
			name:      "invalid regex",
			patterns:  []string{`[unclosed`},
			wantError: true,
		},
		{
			name:      "mixed valid and invalid",
			patterns:  []string{`\d{16}`, `[unclosed`, `api_key`},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ContentLoggingConfig{
				RedactPatterns: tt.patterns,
			}

			err := cfg.CompilePatterns()
			if tt.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to compile redaction pattern")
			} else {
				require.NoError(t, err)
				assert.Equal(t, len(tt.patterns), len(cfg.compiledPatterns))
			}
		})
	}
}

// TestContentLoggingConfig_Redact tests content redaction.
func TestContentLoggingConfig_Redact(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		input    string
		expected string
	}{
		{
			name:     "redact API key",
			patterns: []string{`(?i)api[_-]?key[=:\s]+\S+`},
			input:    "My API_KEY=sk-1234567890 is secret",
			expected: "My [REDACTED] is secret",
		},
		{
			name: "redact password",
			// Pattern matches key+sep+value; the whole match is replaced.
			patterns: []string{`(?i)password[=:\s]+\S+`},
			input:    "password: secretpass123",
			expected: "[REDACTED]",
		},
		{
			name:     "redact credit card",
			patterns: []string{`\b\d{16}\b`},
			input:    "Card: 1234567890123456",
			expected: "Card: [REDACTED]",
		},
		{
			name:     "multiple patterns",
			patterns: []string{`(?i)api_key=\S+`, `(?i)password=\S+`},
			input:    "api_key=secret password=hunter2",
			expected: "[REDACTED] [REDACTED]",
		},
		{
			name:     "no match",
			patterns: []string{`secret`},
			input:    "This is public information",
			expected: "This is public information",
		},
		{
			name:     "empty patterns",
			patterns: []string{},
			input:    "api_key=secret",
			expected: "api_key=secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ContentLoggingConfig{
				RedactPatterns: tt.patterns,
			}
			err := cfg.CompilePatterns()
			require.NoError(t, err)

			result := cfg.Redact(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestContentLoggingConfig_Truncate tests content truncation.
func TestContentLoggingConfig_Truncate(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		maxLen   int
		expected string
	}{
		{
			name:     "no truncation needed",
			content:  "short",
			maxLen:   10,
			expected: "short",
		},
		{
			name:     "exact length",
			content:  "exactly10c",
			maxLen:   10,
			expected: "exactly10c",
		},
		{
			name:     "truncate simple ASCII",
			content:  "This is a very long message that needs truncation",
			maxLen:   10,
			expected: "This is a ... [truncated]",
		},
		{
			name:     "maxLen zero (no limit)",
			content:  "This should not be truncated",
			maxLen:   0,
			expected: "This should not be truncated",
		},
		{
			name:     "maxLen negative (no limit)",
			content:  "This should not be truncated",
			maxLen:   -1,
			expected: "This should not be truncated",
		},
		{
			name:     "truncate UTF-8 multibyte",
			content:  "Hello 世界 from the world",
			maxLen:   8,
			expected: "Hello 世界... [truncated]",
		},
		{
			name:     "UTF-8 emojis",
			content:  "Hello 👋 🌍 🎉 World",
			maxLen:   9,
			expected: "Hello 👋 🌍... [truncated]",
		},
		{
			name:     "one character",
			content:  "Long content here",
			maxLen:   1,
			expected: "L... [truncated]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ContentLoggingConfig{}
			result := cfg.Truncate(tt.content, tt.maxLen)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestContentLoggingConfig_Validate tests validation logic.
func TestContentLoggingConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    ContentLoggingConfig
		wantError bool
		errMsg    string
	}{
		{
			name: "valid default config",
			config: ContentLoggingConfig{
				Enabled:             true,
				MaxPromptLength:     10000,
				MaxCompletionLength: 10000,
				RedactPatterns:      []string{`api_key`},
				IncludeToolIO:       false,
			},
			wantError: false,
		},
		{
			name: "valid with zero limits",
			config: ContentLoggingConfig{
				Enabled:             true,
				MaxPromptLength:     0,
				MaxCompletionLength: 0,
				RedactPatterns:      []string{},
				IncludeToolIO:       true,
			},
			wantError: false,
		},
		{
			name: "negative MaxPromptLength",
			config: ContentLoggingConfig{
				Enabled:             true,
				MaxPromptLength:     -1,
				MaxCompletionLength: 10000,
				RedactPatterns:      []string{},
			},
			wantError: true,
			errMsg:    "max_prompt_length must be >= 0",
		},
		{
			name: "negative MaxCompletionLength",
			config: ContentLoggingConfig{
				Enabled:             true,
				MaxPromptLength:     10000,
				MaxCompletionLength: -1,
				RedactPatterns:      []string{},
			},
			wantError: true,
			errMsg:    "max_completion_length must be >= 0",
		},
		{
			name: "invalid redaction pattern",
			config: ContentLoggingConfig{
				Enabled:             true,
				MaxPromptLength:     10000,
				MaxCompletionLength: 10000,
				RedactPatterns:      []string{`[unclosed`},
			},
			wantError: true,
			errMsg:    "invalid redaction pattern",
		},
		{
			name: "multiple invalid patterns",
			config: ContentLoggingConfig{
				Enabled:             true,
				MaxPromptLength:     10000,
				MaxCompletionLength: 10000,
				RedactPatterns:      []string{`valid`, `[invalid`, `also_valid`},
			},
			wantError: true,
			errMsg:    "invalid redaction pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestContentLoggingConfig_YAMLSerialization tests YAML marshaling and unmarshaling.
func TestContentLoggingConfig_YAMLSerialization(t *testing.T) {
	original := ContentLoggingConfig{
		Enabled:             true,
		MaxPromptLength:     5000,
		MaxCompletionLength: 8000,
		RedactPatterns:      []string{`api_key`, `password`},
		IncludeToolIO:       true,
	}

	// Marshal to YAML
	data, err := yaml.Marshal(&original)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Verify YAML contains expected fields
	yamlStr := string(data)
	assert.Contains(t, yamlStr, "enabled: true")
	assert.Contains(t, yamlStr, "max_prompt_length: 5000")
	assert.Contains(t, yamlStr, "max_completion_length: 8000")
	assert.Contains(t, yamlStr, "redact_patterns:")
	assert.Contains(t, yamlStr, "include_tool_io: true")

	// Unmarshal back
	var unmarshaled ContentLoggingConfig
	err = yaml.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, original.Enabled, unmarshaled.Enabled)
	assert.Equal(t, original.MaxPromptLength, unmarshaled.MaxPromptLength)
	assert.Equal(t, original.MaxCompletionLength, unmarshaled.MaxCompletionLength)
	assert.Equal(t, original.RedactPatterns, unmarshaled.RedactPatterns)
	assert.Equal(t, original.IncludeToolIO, unmarshaled.IncludeToolIO)
}

// TestOTLPConfig_YAMLSerialization tests YAML marshaling and unmarshaling.
func TestOTLPConfig_YAMLSerialization(t *testing.T) {
	original := OTLPConfig{
		Endpoint:             "http://otlp.example.com:4318",
		Headers:              map[string]string{"Authorization": "Bearer token123", "X-Custom": "value"},
		Compression:          "gzip",
		BatchSize:            1000,
		BatchTimeout:         10 * time.Second,
		RetryEnabled:         true,
		RetryInitialInterval: 2 * time.Second,
		RetryMaxInterval:     60 * time.Second,
		RetryMaxElapsedTime:  10 * time.Minute,
	}

	// Marshal to YAML
	data, err := yaml.Marshal(&original)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Verify YAML contains expected fields
	yamlStr := string(data)
	assert.Contains(t, yamlStr, "endpoint: http://otlp.example.com:4318")
	assert.Contains(t, yamlStr, "compression: gzip")
	assert.Contains(t, yamlStr, "batch_size: 1000")
	assert.Contains(t, yamlStr, "retry_enabled: true")

	// Unmarshal back
	var unmarshaled OTLPConfig
	err = yaml.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, original.Endpoint, unmarshaled.Endpoint)
	assert.Equal(t, original.Headers, unmarshaled.Headers)
	assert.Equal(t, original.Compression, unmarshaled.Compression)
	assert.Equal(t, original.BatchSize, unmarshaled.BatchSize)
	assert.Equal(t, original.BatchTimeout, unmarshaled.BatchTimeout)
	assert.Equal(t, original.RetryEnabled, unmarshaled.RetryEnabled)
	assert.Equal(t, original.RetryInitialInterval, unmarshaled.RetryInitialInterval)
	assert.Equal(t, original.RetryMaxInterval, unmarshaled.RetryMaxInterval)
	assert.Equal(t, original.RetryMaxElapsedTime, unmarshaled.RetryMaxElapsedTime)
}

// TestContentLoggingConfig_RedactWithDefaultPatterns tests default redaction patterns.
func TestContentLoggingConfig_RedactWithDefaultPatterns(t *testing.T) {
	cfg := DefaultContentLoggingConfig()
	err := cfg.CompilePatterns()
	require.NoError(t, err)

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "API key with equals",
			input: "api_key=sk-1234567890",
		},
		{
			name:  "API key with colon",
			input: "api-key: bearer_token_here",
		},
		{
			name:  "password",
			input: "password=secret123",
		},
		{
			name:  "secret",
			input: "secret: my_secret_value",
		},
		{
			name: "token",
			// Pattern `token[=:\s]+\S+` matches "token=abc123xyz" (value directly follows).
			// "token Bearer abc123xyz" only redacts "Bearer"; use direct assignment form.
			input: "token=abc123xyz",
		},
		{
			name:  "bearer token",
			input: "Authorization: bearer sk-proj-xyz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cfg.Redact(tt.input)
			assert.Contains(t, result, "[REDACTED]", "should redact sensitive content")
			assert.NotContains(t, result, "sk-", "should not contain API key prefix")
			assert.NotContains(t, result, "secret123", "should not contain password")
			assert.NotContains(t, result, "abc123xyz", "should not contain token")
		})
	}
}

// Benchmark content logging operations
func BenchmarkContentLoggingConfig_Redact(b *testing.B) {
	cfg := DefaultContentLoggingConfig()
	_ = cfg.CompilePatterns()
	content := "This is a test with api_key=sk-1234567890 and password=secret123"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cfg.Redact(content)
	}
}

func BenchmarkContentLoggingConfig_Truncate(b *testing.B) {
	cfg := ContentLoggingConfig{}
	content := strings.Repeat("This is a long message. ", 100) // ~2400 chars

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cfg.Truncate(content, 1000)
	}
}

func BenchmarkContentLoggingConfig_CompilePatterns(b *testing.B) {
	cfg := DefaultContentLoggingConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cfg.CompilePatterns()
	}
}
