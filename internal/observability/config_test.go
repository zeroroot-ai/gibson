package observability

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestTracingConfig_Validate tests TracingConfig validation logic.
func TestTracingConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    TracingConfig
		wantError bool
		errMsg    string
	}{
		{
			name: "invalid jaeger config - no longer supported",
			config: TracingConfig{
				Enabled:     true,
				Provider:    "jaeger",
				Endpoint:    "http://localhost:14268",
				ServiceName: "gibson-test",
				SampleRate:  1.0,
			},
			wantError: true,
			errMsg:    "invalid tracing provider",
		},
		{
			name: "valid otlp config",
			config: TracingConfig{
				Enabled:     true,
				Provider:    "otlp",
				Endpoint:    "http://localhost:4318",
				ServiceName: "gibson",
				SampleRate:  0.5,
			},
			wantError: false,
		},
		{
			name: "valid zipkin config",
			config: TracingConfig{
				Enabled:     true,
				Provider:    "zipkin",
				Endpoint:    "http://localhost:9411",
				ServiceName: "gibson",
				SampleRate:  0.0,
			},
			wantError: false,
		},
		{
			name: "disabled config always valid",
			config: TracingConfig{
				Enabled:     false,
				Provider:    "invalid",
				Endpoint:    "",
				ServiceName: "",
				SampleRate:  2.0,
			},
			wantError: false,
		},
		{
			name: "invalid provider",
			config: TracingConfig{
				Enabled:     true,
				Provider:    "datadog",
				Endpoint:    "http://localhost:8126",
				ServiceName: "gibson",
				SampleRate:  1.0,
			},
			wantError: true,
			errMsg:    "invalid tracing provider",
		},
		{
			name: "sample rate too low",
			config: TracingConfig{
				Enabled:     true,
				Provider:    "otlp",
				Endpoint:    "http://localhost:4318",
				ServiceName: "gibson",
				SampleRate:  -0.1,
			},
			wantError: true,
			errMsg:    "invalid sample rate",
		},
		{
			name: "sample rate too high",
			config: TracingConfig{
				Enabled:     true,
				Provider:    "otlp",
				Endpoint:    "http://localhost:4318",
				ServiceName: "gibson",
				SampleRate:  1.5,
			},
			wantError: true,
			errMsg:    "invalid sample rate",
		},
		{
			name: "missing endpoint",
			config: TracingConfig{
				Enabled:     true,
				Provider:    "otlp",
				Endpoint:    "",
				ServiceName: "gibson",
				SampleRate:  1.0,
			},
			wantError: true,
			errMsg:    "endpoint is required",
		},
		{
			name: "missing service name",
			config: TracingConfig{
				Enabled:     true,
				Provider:    "otlp",
				Endpoint:    "http://localhost:4318",
				ServiceName: "",
				SampleRate:  1.0,
			},
			wantError: true,
			errMsg:    "service name is required",
		},
		{
			name: "case insensitive provider",
			config: TracingConfig{
				Enabled:     true,
				Provider:    "OTLP",
				Endpoint:    "http://localhost:4318",
				ServiceName: "gibson",
				SampleRate:  1.0,
			},
			wantError: false,
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

// TestLangfuseConfig_Validate tests LangfuseConfig validation logic.
func TestLangfuseConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    LangfuseConfig
		wantError bool
		errMsg    string
	}{
		{
			name: "valid config",
			config: LangfuseConfig{
				PublicKey: "pk-lf-1234567890",
				SecretKey: "sk-lf-0987654321",
				Host:      "https://cloud.langfuse.com",
			},
			wantError: false,
		},
		{
			name: "missing public key",
			config: LangfuseConfig{
				PublicKey: "",
				SecretKey: "sk-lf-0987654321",
				Host:      "https://cloud.langfuse.com",
			},
			wantError: true,
			errMsg:    "public key is required",
		},
		{
			name: "missing secret key",
			config: LangfuseConfig{
				PublicKey: "pk-lf-1234567890",
				SecretKey: "",
				Host:      "https://cloud.langfuse.com",
			},
			wantError: true,
			errMsg:    "secret key is required",
		},
		{
			name: "missing host",
			config: LangfuseConfig{
				PublicKey: "pk-lf-1234567890",
				SecretKey: "sk-lf-0987654321",
				Host:      "",
			},
			wantError: true,
			errMsg:    "host is required",
		},
		{
			name: "all fields empty",
			config: LangfuseConfig{
				PublicKey: "",
				SecretKey: "",
				Host:      "",
			},
			wantError: true,
			errMsg:    "public key is required",
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

// TestMetricsConfig_Validate tests MetricsConfig validation logic.
func TestMetricsConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    MetricsConfig
		wantError bool
		errMsg    string
	}{
		{
			name: "valid prometheus config",
			config: MetricsConfig{
				Enabled:  true,
				Provider: "prometheus",
				Port:     9090,
			},
			wantError: false,
		},
		{
			name: "valid otlp config",
			config: MetricsConfig{
				Enabled:  true,
				Provider: "otlp",
				Port:     4318,
			},
			wantError: false,
		},
		{
			name: "disabled config always valid",
			config: MetricsConfig{
				Enabled:  false,
				Provider: "invalid",
				Port:     0,
			},
			wantError: false,
		},
		{
			name: "invalid provider",
			config: MetricsConfig{
				Enabled:  true,
				Provider: "statsd",
				Port:     8125,
			},
			wantError: true,
			errMsg:    "invalid metrics provider",
		},
		{
			name: "port too low",
			config: MetricsConfig{
				Enabled:  true,
				Provider: "prometheus",
				Port:     0,
			},
			wantError: true,
			errMsg:    "invalid port",
		},
		{
			name: "port too high",
			config: MetricsConfig{
				Enabled:  true,
				Provider: "prometheus",
				Port:     65536,
			},
			wantError: true,
			errMsg:    "invalid port",
		},
		{
			name: "minimum valid port",
			config: MetricsConfig{
				Enabled:  true,
				Provider: "prometheus",
				Port:     1,
			},
			wantError: false,
		},
		{
			name: "maximum valid port",
			config: MetricsConfig{
				Enabled:  true,
				Provider: "prometheus",
				Port:     65535,
			},
			wantError: false,
		},
		{
			name: "case insensitive provider",
			config: MetricsConfig{
				Enabled:  true,
				Provider: "PROMETHEUS",
				Port:     9090,
			},
			wantError: false,
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

// TestLoggingConfig_Validate tests LoggingConfig validation logic.
func TestLoggingConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    LoggingConfig
		wantError bool
		errMsg    string
	}{
		{
			name: "valid json to stdout",
			config: LoggingConfig{
				Level:  "info",
				Format: "json",
				Output: "stdout",
			},
			wantError: false,
		},
		{
			name: "valid text to stderr",
			config: LoggingConfig{
				Level:  "debug",
				Format: "text",
				Output: "stderr",
			},
			wantError: false,
		},
		{
			name: "valid file output",
			config: LoggingConfig{
				Level:  "warn",
				Format: "json",
				Output: "/var/log/gibson.log",
			},
			wantError: false,
		},
		{
			name: "all valid log levels",
			config: LoggingConfig{
				Level:  "error",
				Format: "json",
				Output: "stdout",
			},
			wantError: false,
		},
		{
			name: "fatal level",
			config: LoggingConfig{
				Level:  "fatal",
				Format: "json",
				Output: "stdout",
			},
			wantError: false,
		},
		{
			name: "invalid log level",
			config: LoggingConfig{
				Level:  "trace",
				Format: "json",
				Output: "stdout",
			},
			wantError: true,
			errMsg:    "invalid log level",
		},
		{
			name: "invalid format",
			config: LoggingConfig{
				Level:  "info",
				Format: "xml",
				Output: "stdout",
			},
			wantError: true,
			errMsg:    "invalid log format",
		},
		{
			name: "empty output",
			config: LoggingConfig{
				Level:  "info",
				Format: "json",
				Output: "",
			},
			wantError: true,
			errMsg:    "output is required",
		},
		{
			name: "invalid output (relative path)",
			config: LoggingConfig{
				Level:  "info",
				Format: "json",
				Output: "logs/gibson.log",
			},
			wantError: true,
			errMsg:    "invalid log output",
		},
		{
			name: "case insensitive level",
			config: LoggingConfig{
				Level:  "INFO",
				Format: "json",
				Output: "stdout",
			},
			wantError: false,
		},
		{
			name: "case insensitive format",
			config: LoggingConfig{
				Level:  "info",
				Format: "JSON",
				Output: "stdout",
			},
			wantError: false,
		},
		{
			name: "case insensitive output",
			config: LoggingConfig{
				Level:  "info",
				Format: "json",
				Output: "STDOUT",
			},
			wantError: false,
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

// TestLangfuseConfig_YAMLSerialization tests YAML marshaling and unmarshaling.
func TestLangfuseConfig_YAMLSerialization(t *testing.T) {
	original := LangfuseConfig{
		PublicKey: "pk-lf-test-key",
		SecretKey: "sk-lf-secret-key",
		Host:      "https://cloud.langfuse.com",
	}

	// Marshal to YAML
	data, err := yaml.Marshal(&original)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Verify YAML contains expected fields
	yamlStr := string(data)
	assert.Contains(t, yamlStr, "public_key: pk-lf-test-key")
	assert.Contains(t, yamlStr, "secret_key: sk-lf-secret-key")
	assert.Contains(t, yamlStr, "host: https://cloud.langfuse.com")

	// Unmarshal back
	var unmarshaled LangfuseConfig
	err = yaml.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, original.PublicKey, unmarshaled.PublicKey)
	assert.Equal(t, original.SecretKey, unmarshaled.SecretKey)
	assert.Equal(t, original.Host, unmarshaled.Host)
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

// TestYAMLDeserialization_CompleteConfig tests unmarshaling a complete YAML config.
func TestYAMLDeserialization_CompleteConfig(t *testing.T) {
	yamlContent := `
tracing:
  enabled: true
  provider: otlp
  endpoint: http://localhost:4318
  service_name: gibson
  sample_rate: 0.5

langfuse:
  public_key: pk-lf-abc123
  secret_key: sk-lf-xyz789
  host: https://cloud.langfuse.com

metrics:
  enabled: true
  provider: prometheus
  port: 9090

logging:
  level: info
  format: json
  output: stdout
`

	// Parse as a composite struct
	type ObservabilityConfig struct {
		Tracing  TracingConfig  `yaml:"tracing"`
		Langfuse LangfuseConfig `yaml:"langfuse"`
		Metrics  MetricsConfig  `yaml:"metrics"`
		Logging  LoggingConfig  `yaml:"logging"`
	}

	var config ObservabilityConfig
	err := yaml.Unmarshal([]byte(yamlContent), &config)
	require.NoError(t, err)

	// Validate tracing
	assert.True(t, config.Tracing.Enabled)
	assert.Equal(t, "otlp", config.Tracing.Provider)
	assert.Equal(t, "http://localhost:4318", config.Tracing.Endpoint)
	assert.Equal(t, "gibson", config.Tracing.ServiceName)
	assert.Equal(t, 0.5, config.Tracing.SampleRate)
	assert.NoError(t, config.Tracing.Validate())

	// Validate langfuse
	assert.Equal(t, "pk-lf-abc123", config.Langfuse.PublicKey)
	assert.Equal(t, "sk-lf-xyz789", config.Langfuse.SecretKey)
	assert.Equal(t, "https://cloud.langfuse.com", config.Langfuse.Host)
	assert.NoError(t, config.Langfuse.Validate())

	// Validate metrics
	assert.True(t, config.Metrics.Enabled)
	assert.Equal(t, "prometheus", config.Metrics.Provider)
	assert.Equal(t, 9090, config.Metrics.Port)
	assert.NoError(t, config.Metrics.Validate())

	// Validate logging
	assert.Equal(t, "info", config.Logging.Level)
	assert.Equal(t, "json", config.Logging.Format)
	assert.Equal(t, "stdout", config.Logging.Output)
	assert.NoError(t, config.Logging.Validate())
}

// TestYAMLDeserialization_InvalidConfig tests unmarshaling with invalid values.
func TestYAMLDeserialization_InvalidConfig(t *testing.T) {
	tests := []struct {
		name         string
		yaml         string
		validateFunc func(*testing.T, interface{})
	}{
		{
			name: "invalid tracing provider",
			yaml: `
enabled: true
provider: invalid-provider
endpoint: http://localhost:4318
service_name: gibson
sample_rate: 1.0
`,
			validateFunc: func(t *testing.T, v interface{}) {
				config := v.(*TracingConfig)
				err := config.Validate()
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid tracing provider")
			},
		},
		{
			name: "invalid sample rate",
			yaml: `
enabled: true
provider: otlp
endpoint: http://localhost:4318
service_name: gibson
sample_rate: 1.5
`,
			validateFunc: func(t *testing.T, v interface{}) {
				config := v.(*TracingConfig)
				err := config.Validate()
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid sample rate")
			},
		},
		{
			name: "invalid metrics port",
			yaml: `
enabled: true
provider: prometheus
port: 99999
`,
			validateFunc: func(t *testing.T, v interface{}) {
				config := v.(*MetricsConfig)
				err := config.Validate()
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid port")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Determine config type based on YAML content
			if strings.Contains(tt.yaml, "sample_rate") {
				var config TracingConfig
				err := yaml.Unmarshal([]byte(tt.yaml), &config)
				require.NoError(t, err)
				tt.validateFunc(t, &config)
			} else if strings.Contains(tt.yaml, "port") {
				var config MetricsConfig
				err := yaml.Unmarshal([]byte(tt.yaml), &config)
				require.NoError(t, err)
				tt.validateFunc(t, &config)
			}
		})
	}
}

// Benchmark validation performance
func BenchmarkTracingConfig_Validate(b *testing.B) {
	config := TracingConfig{
		Enabled:     true,
		Provider:    "otlp",
		Endpoint:    "http://localhost:4318",
		ServiceName: "gibson",
		SampleRate:  1.0,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = config.Validate()
	}
}

func BenchmarkMetricsConfig_Validate(b *testing.B) {
	config := MetricsConfig{
		Enabled:  true,
		Provider: "prometheus",
		Port:     9090,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = config.Validate()
	}
}

func BenchmarkLoggingConfig_Validate(b *testing.B) {
	config := LoggingConfig{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = config.Validate()
	}
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
			name:     "redact password",
			patterns: []string{`(?i)password[=:\s]+\S+`},
			input:    "password: secretpass123",
			expected: "password: [REDACTED]",
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

// TestOTLPConfig_DefaultConfig tests the default configuration.
func TestOTLPConfig_DefaultConfig(t *testing.T) {
	cfg := DefaultOTLPConfig()

	assert.Equal(t, 512, cfg.BatchSize)
	assert.Equal(t, 5*time.Second, cfg.BatchTimeout)
	assert.True(t, cfg.RetryEnabled)
	assert.Equal(t, 1*time.Second, cfg.RetryInitialInterval)
	assert.Equal(t, 30*time.Second, cfg.RetryMaxInterval)
	assert.Equal(t, 5*time.Minute, cfg.RetryMaxElapsedTime)
	assert.NotNil(t, cfg.Headers)
	assert.Empty(t, cfg.Headers)
}

// TestOTLPConfig_Validate tests validation logic.
func TestOTLPConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    OTLPConfig
		wantError bool
		errMsg    string
	}{
		{
			name: "valid default config",
			config: OTLPConfig{
				Endpoint:             "http://localhost:4318",
				BatchSize:            512,
				BatchTimeout:         5 * time.Second,
				RetryEnabled:         true,
				RetryInitialInterval: 1 * time.Second,
				RetryMaxInterval:     30 * time.Second,
				RetryMaxElapsedTime:  5 * time.Minute,
			},
			wantError: false,
		},
		{
			name: "valid with gzip compression",
			config: OTLPConfig{
				Endpoint:     "http://localhost:4318",
				Compression:  "gzip",
				BatchSize:    100,
				BatchTimeout: 1 * time.Second,
				RetryEnabled: false,
			},
			wantError: false,
		},
		{
			name: "valid with none compression",
			config: OTLPConfig{
				Endpoint:     "http://localhost:4318",
				Compression:  "none",
				BatchSize:    100,
				BatchTimeout: 1 * time.Second,
				RetryEnabled: false,
			},
			wantError: false,
		},
		{
			name: "valid with empty compression",
			config: OTLPConfig{
				Endpoint:     "http://localhost:4318",
				Compression:  "",
				BatchSize:    100,
				BatchTimeout: 1 * time.Second,
				RetryEnabled: false,
			},
			wantError: false,
		},
		{
			name: "invalid compression",
			config: OTLPConfig{
				Endpoint:     "http://localhost:4318",
				Compression:  "brotli",
				BatchSize:    100,
				BatchTimeout: 1 * time.Second,
			},
			wantError: true,
			errMsg:    "invalid compression",
		},
		{
			name: "zero batch size",
			config: OTLPConfig{
				Endpoint:     "http://localhost:4318",
				BatchSize:    0,
				BatchTimeout: 1 * time.Second,
			},
			wantError: true,
			errMsg:    "batch_size must be > 0",
		},
		{
			name: "negative batch size",
			config: OTLPConfig{
				Endpoint:     "http://localhost:4318",
				BatchSize:    -1,
				BatchTimeout: 1 * time.Second,
			},
			wantError: true,
			errMsg:    "batch_size must be > 0",
		},
		{
			name: "zero batch timeout",
			config: OTLPConfig{
				Endpoint:     "http://localhost:4318",
				BatchSize:    100,
				BatchTimeout: 0,
			},
			wantError: true,
			errMsg:    "batch_timeout must be > 0",
		},
		{
			name: "negative batch timeout",
			config: OTLPConfig{
				Endpoint:     "http://localhost:4318",
				BatchSize:    100,
				BatchTimeout: -1 * time.Second,
			},
			wantError: true,
			errMsg:    "batch_timeout must be > 0",
		},
		{
			name: "negative retry initial interval",
			config: OTLPConfig{
				Endpoint:             "http://localhost:4318",
				BatchSize:            100,
				BatchTimeout:         1 * time.Second,
				RetryEnabled:         true,
				RetryInitialInterval: -1 * time.Second,
				RetryMaxInterval:     30 * time.Second,
				RetryMaxElapsedTime:  5 * time.Minute,
			},
			wantError: true,
			errMsg:    "retry_initial_interval must be >= 0",
		},
		{
			name: "negative retry max interval",
			config: OTLPConfig{
				Endpoint:             "http://localhost:4318",
				BatchSize:            100,
				BatchTimeout:         1 * time.Second,
				RetryEnabled:         true,
				RetryInitialInterval: 1 * time.Second,
				RetryMaxInterval:     -30 * time.Second,
				RetryMaxElapsedTime:  5 * time.Minute,
			},
			wantError: true,
			errMsg:    "retry_max_interval must be >= 0",
		},
		{
			name: "initial interval greater than max interval",
			config: OTLPConfig{
				Endpoint:             "http://localhost:4318",
				BatchSize:            100,
				BatchTimeout:         1 * time.Second,
				RetryEnabled:         true,
				RetryInitialInterval: 60 * time.Second,
				RetryMaxInterval:     30 * time.Second,
				RetryMaxElapsedTime:  5 * time.Minute,
			},
			wantError: true,
			errMsg:    "retry_initial_interval",
		},
		{
			name: "negative retry max elapsed time",
			config: OTLPConfig{
				Endpoint:             "http://localhost:4318",
				BatchSize:            100,
				BatchTimeout:         1 * time.Second,
				RetryEnabled:         true,
				RetryInitialInterval: 1 * time.Second,
				RetryMaxInterval:     30 * time.Second,
				RetryMaxElapsedTime:  -5 * time.Minute,
			},
			wantError: true,
			errMsg:    "retry_max_elapsed_time must be >= 0",
		},
		{
			name: "retry disabled - no retry validation",
			config: OTLPConfig{
				Endpoint:             "http://localhost:4318",
				BatchSize:            100,
				BatchTimeout:         1 * time.Second,
				RetryEnabled:         false,
				RetryInitialInterval: -1 * time.Second, // Invalid but ignored
				RetryMaxInterval:     -30 * time.Second,
				RetryMaxElapsedTime:  -5 * time.Minute,
			},
			wantError: false,
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
			name:  "token",
			input: "token Bearer abc123xyz",
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

func BenchmarkOTLPConfig_Validate(b *testing.B) {
	cfg := DefaultOTLPConfig()
	cfg.Endpoint = "http://localhost:4318"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cfg.Validate()
	}
}
