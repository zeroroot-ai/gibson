package observability

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// TracingConfig contains distributed tracing configuration for observability.
// Supports multiple tracing providers with configurable sampling rates and TLS.
type TracingConfig struct {
	Enabled      bool    `yaml:"enabled" mapstructure:"enabled"`
	Provider     string  `yaml:"provider" mapstructure:"provider"`
	Endpoint     string  `yaml:"endpoint" mapstructure:"endpoint"`
	ServiceName  string  `yaml:"service_name" mapstructure:"service_name"`
	SampleRate   float64 `yaml:"sample_rate" mapstructure:"sample_rate"`
	TLSCertFile  string  `yaml:"tls_cert_file" mapstructure:"tls_cert_file"` // Client TLS certificate file
	TLSKeyFile   string  `yaml:"tls_key_file" mapstructure:"tls_key_file"`   // Client TLS key file
	InsecureMode bool    `yaml:"insecure_mode" mapstructure:"insecure_mode"` // Disable TLS verification (unsafe)
}

// Validate validates the TracingConfig fields.
// Returns an error if Provider is invalid (must be otlp, zipkin, langfuse, or noop),
// or if SampleRate is out of range (must be between 0.0 and 1.0).
func (c *TracingConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	// Validate provider
	validProviders := []string{"otlp", "zipkin", "langfuse", "noop"}
	provider := strings.ToLower(c.Provider)
	isValid := false
	for _, valid := range validProviders {
		if provider == valid {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid tracing provider: %s (must be one of: %s)", c.Provider, strings.Join(validProviders, ", "))
	}

	// Validate sample rate
	if c.SampleRate < 0.0 || c.SampleRate > 1.0 {
		return fmt.Errorf("invalid sample rate: %f (must be between 0.0 and 1.0)", c.SampleRate)
	}

	// Validate endpoint is not empty (except for noop provider)
	if provider != "noop" && c.Endpoint == "" {
		return fmt.Errorf("endpoint is required when tracing is enabled")
	}

	// Validate service name is not empty (except for noop provider)
	if provider != "noop" && c.ServiceName == "" {
		return fmt.Errorf("service name is required when tracing is enabled")
	}

	return nil
}

// LangfuseConfig contains Langfuse LLM observability configuration.
// Langfuse provides tracing and monitoring for LLM applications.
type LangfuseConfig struct {
	PublicKey string `yaml:"public_key" mapstructure:"public_key"`
	SecretKey string `yaml:"secret_key" mapstructure:"secret_key"`
	Host      string `yaml:"host" mapstructure:"host"`
}

// Validate validates the LangfuseConfig fields.
// Returns an error if any required field is empty.
func (c *LangfuseConfig) Validate() error {
	if c.PublicKey == "" {
		return fmt.Errorf("public key is required")
	}
	if c.SecretKey == "" {
		return fmt.Errorf("secret key is required")
	}
	if c.Host == "" {
		return fmt.Errorf("host is required")
	}
	return nil
}

// MetricsConfig contains metrics export configuration.
// Supports multiple metrics providers with configurable ports.
type MetricsConfig struct {
	Enabled  bool   `yaml:"enabled" mapstructure:"enabled"`
	Provider string `yaml:"provider" mapstructure:"provider"`
	Port     int    `yaml:"port" mapstructure:"port"`
}

// Validate validates the MetricsConfig fields.
// Returns an error if Provider is invalid (must be prometheus or otlp),
// or if Port is out of valid range (1-65535).
func (c *MetricsConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	// Validate provider
	validProviders := []string{"prometheus", "otlp"}
	provider := strings.ToLower(c.Provider)
	isValid := false
	for _, valid := range validProviders {
		if provider == valid {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid metrics provider: %s (must be one of: %s)", c.Provider, strings.Join(validProviders, ", "))
	}

	// Validate port range
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port: %d (must be between 1 and 65535)", c.Port)
	}

	return nil
}

// LoggingConfig contains structured logging configuration.
// Supports multiple log levels, formats, and output destinations.
type LoggingConfig struct {
	Level  string `yaml:"level" mapstructure:"level"`
	Format string `yaml:"format" mapstructure:"format"`
	Output string `yaml:"output" mapstructure:"output"`
}

// Validate validates the LoggingConfig fields.
// Returns an error if Level is invalid (must be debug, info, warn, error, or fatal),
// or if Format is invalid (must be json or text),
// or if Output is invalid (must be stdout, stderr, or a file path).
func (c *LoggingConfig) Validate() error {
	// Validate level
	validLevels := []string{"debug", "info", "warn", "error", "fatal"}
	level := strings.ToLower(c.Level)
	isValid := false
	for _, valid := range validLevels {
		if level == valid {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid log level: %s (must be one of: %s)", c.Level, strings.Join(validLevels, ", "))
	}

	// Validate format
	validFormats := []string{"json", "text"}
	format := strings.ToLower(c.Format)
	isValid = false
	for _, valid := range validFormats {
		if format == valid {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid log format: %s (must be one of: %s)", c.Format, strings.Join(validFormats, ", "))
	}

	// Validate output (stdout, stderr, or file path)
	if c.Output == "" {
		return fmt.Errorf("output is required")
	}
	output := strings.ToLower(c.Output)
	if output != "stdout" && output != "stderr" && !strings.HasPrefix(c.Output, "/") {
		return fmt.Errorf("invalid log output: %s (must be 'stdout', 'stderr', or an absolute file path)", c.Output)
	}

	return nil
}

// Config configures the unified logger.
// This is used for runtime logger configuration, separate from the YAML-based
// LoggingConfig which is used for daemon configuration.
type Config struct {
	// Level is the minimum log level (debug, info, warn, error)
	Level slog.Level

	// Output is where logs are written (default: os.Stdout)
	Output io.Writer

	// RedactSensitive enables automatic redaction of sensitive fields
	RedactSensitive bool

	// MaxContentLength truncates large string values (0 = no limit)
	MaxContentLength int

	// Component is the default component name
	Component string
}

// DefaultConfig returns the default logger configuration.
// This provides sensible defaults for production use:
//   - Info level logging (balances verbosity and noise)
//   - Output to stdout (Kubernetes-friendly)
//   - Redaction enabled (protects sensitive data)
//   - Content truncated at 500 chars (prevents log bloat)
//   - Component set to "gibson" (can be overridden with WithComponent)
func DefaultConfig() Config {
	return Config{
		Level:            slog.LevelInfo,
		Output:           os.Stdout,
		RedactSensitive:  true,
		MaxContentLength: 500,
		Component:        "gibson",
	}
}

// ConfigFromEnv returns a logger configuration initialized from environment variables.
// It starts with DefaultConfig() and applies environment-based overrides.
//
// Environment variables:
//   - GIBSON_LOG_LEVEL: Set log level (debug, info, warn, error)
//     - Case-insensitive
//     - Invalid values default to Info
//     - Example: export GIBSON_LOG_LEVEL=debug
//
// Example:
//
//	// With GIBSON_LOG_LEVEL=debug
//	cfg := ConfigFromEnv()
//	// cfg.Level will be slog.LevelDebug
//
//	// With GIBSON_LOG_LEVEL=invalid
//	cfg := ConfigFromEnv()
//	// cfg.Level will be slog.LevelInfo (default)
func ConfigFromEnv() Config {
	cfg := DefaultConfig()

	// Read GIBSON_LOG_LEVEL environment variable
	if levelStr := os.Getenv("GIBSON_LOG_LEVEL"); levelStr != "" {
		// Parse level (case-insensitive)
		switch strings.ToLower(levelStr) {
		case "debug":
			cfg.Level = slog.LevelDebug
		case "info":
			cfg.Level = slog.LevelInfo
		case "warn":
			cfg.Level = slog.LevelWarn
		case "error":
			cfg.Level = slog.LevelError
		default:
			// Invalid value - keep default (Info)
			// Note: We can't log this error since we're configuring the logger
			cfg.Level = slog.LevelInfo
		}
	}

	return cfg
}
