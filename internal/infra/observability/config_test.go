// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package observability

import (
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

func BenchmarkContentLoggingConfig_CompilePatterns(b *testing.B) {
	cfg := DefaultContentLoggingConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cfg.CompilePatterns()
	}
}
