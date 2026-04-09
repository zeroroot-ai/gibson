package observability

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
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
//   - Case-insensitive
//   - Invalid values default to Info
//   - Example: export GIBSON_LOG_LEVEL=debug
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

// ContentLoggingConfig contains configuration for logging LLM conversation content.
// This includes prompts, completions, and tool interactions with security features
// like redaction and truncation to protect sensitive data and prevent log bloat.
type ContentLoggingConfig struct {
	// Enabled determines whether content logging is active.
	// Default is false for security (opt-in model).
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`

	// MaxPromptLength is the maximum number of characters to log for prompts.
	// Content exceeding this will be truncated. Default is 10000.
	// Set to 0 for no limit (not recommended in production).
	MaxPromptLength int `yaml:"max_prompt_length" mapstructure:"max_prompt_length"`

	// MaxCompletionLength is the maximum number of characters to log for completions.
	// Content exceeding this will be truncated. Default is 10000.
	// Set to 0 for no limit (not recommended in production).
	MaxCompletionLength int `yaml:"max_completion_length" mapstructure:"max_completion_length"`

	// RedactPatterns contains regex patterns for redacting sensitive information.
	// Matches are replaced with [REDACTED]. Default includes patterns for API keys,
	// passwords, secrets, tokens, and bearer tokens.
	RedactPatterns []string `yaml:"redact_patterns" mapstructure:"redact_patterns"`

	// IncludeToolIO determines whether tool input and output are logged.
	// Default is false to reduce log volume and potential sensitive data exposure.
	IncludeToolIO bool `yaml:"include_tool_io" mapstructure:"include_tool_io"`

	// compiledPatterns holds the compiled regex patterns from RedactPatterns.
	// This field is not exported and is populated by CompilePatterns().
	compiledPatterns []*regexp.Regexp
}

// DefaultContentLoggingConfig returns a ContentLoggingConfig with safe defaults.
// All sensitive features are disabled by default (opt-in security model):
//   - Content logging disabled (must be explicitly enabled)
//   - Reasonable truncation limits to prevent log bloat (10000 chars)
//   - Common redaction patterns for API keys, passwords, secrets, tokens
//   - Tool I/O logging disabled to reduce volume
//
// Example:
//
//	cfg := DefaultContentLoggingConfig()
//	cfg.Enabled = true  // Opt-in to content logging
//	if err := cfg.CompilePatterns(); err != nil {
//	    log.Fatal(err)
//	}
func DefaultContentLoggingConfig() ContentLoggingConfig {
	return ContentLoggingConfig{
		Enabled:             false,
		MaxPromptLength:     10000,
		MaxCompletionLength: 10000,
		RedactPatterns: []string{
			// Match API keys, passwords, secrets, tokens with various formats
			`(?i)(api[_-]?key|password|secret|token|bearer)[=:\s]+\S+`,
		},
		IncludeToolIO:    false,
		compiledPatterns: nil,
	}
}

// CompilePatterns compiles the RedactPatterns into internal compiled regex patterns.
// This must be called after configuration is loaded and before using Redact().
// Returns an error if any pattern fails to compile.
//
// Example:
//
//	cfg := DefaultContentLoggingConfig()
//	cfg.RedactPatterns = append(cfg.RedactPatterns, `\d{16}`) // Credit card numbers
//	if err := cfg.CompilePatterns(); err != nil {
//	    return fmt.Errorf("failed to compile redaction patterns: %w", err)
//	}
func (c *ContentLoggingConfig) CompilePatterns() error {
	c.compiledPatterns = make([]*regexp.Regexp, 0, len(c.RedactPatterns))

	for i, pattern := range c.RedactPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile redaction pattern %d (%q): %w", i, pattern, err)
		}
		c.compiledPatterns = append(c.compiledPatterns, re)
	}

	return nil
}

// Redact applies all compiled redaction patterns to the given content.
// Each match is replaced with [REDACTED]. CompilePatterns() must be called
// before using this method.
//
// Example:
//
//	cfg := DefaultContentLoggingConfig()
//	cfg.CompilePatterns()
//	safe := cfg.Redact("My API key is: sk-1234567890")
//	// safe == "My API key is: [REDACTED]"
func (c *ContentLoggingConfig) Redact(content string) string {
	result := content
	for _, pattern := range c.compiledPatterns {
		result = pattern.ReplaceAllString(result, "[REDACTED]")
	}
	return result
}

// Truncate truncates content to maxLen characters and appends "... [truncated]".
// If content length is <= maxLen or maxLen <= 0, returns content unchanged.
// Handles UTF-8 properly by not cutting in the middle of multi-byte runes.
//
// Example:
//
//	cfg := DefaultContentLoggingConfig()
//	result := cfg.Truncate("This is a very long message", 10)
//	// result == "This is a ... [truncated]"
//
//	result = cfg.Truncate("Short", 10)
//	// result == "Short"
//
//	result = cfg.Truncate("Long message", 0)
//	// result == "Long message" (no limit)
func (c *ContentLoggingConfig) Truncate(content string, maxLen int) string {
	// No truncation if maxLen is 0 or negative
	if maxLen <= 0 {
		return content
	}

	// No truncation needed if content is short enough
	if utf8.RuneCountInString(content) <= maxLen {
		return content
	}

	// Truncate at rune boundary to handle UTF-8 properly
	runes := []rune(content)
	if len(runes) <= maxLen {
		return content
	}

	return string(runes[:maxLen]) + "... [truncated]"
}

// Validate validates the ContentLoggingConfig fields.
// Returns an error if:
//   - MaxPromptLength is negative
//   - MaxCompletionLength is negative
//   - RedactPatterns contains invalid regex patterns
func (c *ContentLoggingConfig) Validate() error {
	if c.MaxPromptLength < 0 {
		return fmt.Errorf("max_prompt_length must be >= 0, got %d", c.MaxPromptLength)
	}

	if c.MaxCompletionLength < 0 {
		return fmt.Errorf("max_completion_length must be >= 0, got %d", c.MaxCompletionLength)
	}

	// Validate that all patterns compile
	for i, pattern := range c.RedactPatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid redaction pattern %d (%q): %w", i, pattern, err)
		}
	}

	return nil
}

// OTLPConfig contains extended OTLP (OpenTelemetry Protocol) configuration.
// This includes endpoint settings, batching, compression, and retry policies
// for exporting observability data to OTLP-compatible backends.
type OTLPConfig struct {
	// Endpoint is the OTLP receiver endpoint URL.
	// Example: "http://localhost:4318" or "https://otlp.example.com:4317"
	Endpoint string `yaml:"endpoint" mapstructure:"endpoint"`

	// Headers contains additional HTTP headers to send with OTLP requests.
	// Commonly used for authentication tokens or custom metadata.
	// Example: {"Authorization": "Bearer token123", "X-Custom": "value"}
	Headers map[string]string `yaml:"headers" mapstructure:"headers"`

	// Compression specifies the compression algorithm to use.
	// Valid values: "gzip", "none". Default is empty (no compression).
	Compression string `yaml:"compression" mapstructure:"compression"`

	// BatchSize is the maximum number of events to batch before sending.
	// Default is 512. Higher values reduce network overhead but increase latency.
	BatchSize int `yaml:"batch_size" mapstructure:"batch_size"`

	// BatchTimeout is the maximum time to wait before sending a partial batch.
	// Default is 5 seconds. Ensures events are sent even if BatchSize isn't reached.
	BatchTimeout time.Duration `yaml:"batch_timeout" mapstructure:"batch_timeout"`

	// RetryEnabled determines whether failed exports should be retried.
	// Default is true. Recommended for production to handle transient failures.
	RetryEnabled bool `yaml:"retry_enabled" mapstructure:"retry_enabled"`

	// RetryInitialInterval is the initial backoff duration for retry attempts.
	// Default is 1 second. Subsequent retries use exponential backoff.
	RetryInitialInterval time.Duration `yaml:"retry_initial_interval" mapstructure:"retry_initial_interval"`

	// RetryMaxInterval is the maximum backoff duration between retry attempts.
	// Default is 30 seconds. Prevents excessive wait times.
	RetryMaxInterval time.Duration `yaml:"retry_max_interval" mapstructure:"retry_max_interval"`

	// RetryMaxElapsedTime is the maximum total time to spend retrying.
	// Default is 5 minutes. After this time, the export is abandoned.
	RetryMaxElapsedTime time.Duration `yaml:"retry_max_elapsed_time" mapstructure:"retry_max_elapsed_time"`
}

// DefaultOTLPConfig returns an OTLPConfig with sensible production defaults:
//   - Batch size of 512 events (balances throughput and latency)
//   - Batch timeout of 5 seconds (ensures timely delivery)
//   - Retry enabled with exponential backoff (1s initial, 30s max)
//   - Total retry time of 5 minutes (handles extended outages)
//   - No compression (can be enabled if network bandwidth is limited)
//
// Example:
//
//	cfg := DefaultOTLPConfig()
//	cfg.Endpoint = "http://localhost:4318"
//	cfg.Compression = "gzip"
//	if err := cfg.Validate(); err != nil {
//	    log.Fatal(err)
//	}
func DefaultOTLPConfig() OTLPConfig {
	return OTLPConfig{
		BatchSize:            512,
		BatchTimeout:         5 * time.Second,
		RetryEnabled:         true,
		RetryInitialInterval: 1 * time.Second,
		RetryMaxInterval:     30 * time.Second,
		RetryMaxElapsedTime:  5 * time.Minute,
		Headers:              make(map[string]string),
	}
}

// Validate validates the OTLPConfig fields.
// Returns an error if:
//   - Compression is not "gzip", "none", or empty
//   - BatchSize is <= 0
//   - BatchTimeout is <= 0
//   - Retry intervals are invalid (initial > max, negative values)
//   - RetryMaxElapsedTime is negative
func (c *OTLPConfig) Validate() error {
	// Validate compression
	if c.Compression != "" && c.Compression != "gzip" && c.Compression != "none" {
		return fmt.Errorf("invalid compression: %s (must be 'gzip', 'none', or empty)", c.Compression)
	}

	// Validate batch size
	if c.BatchSize <= 0 {
		return fmt.Errorf("batch_size must be > 0, got %d", c.BatchSize)
	}

	// Validate batch timeout
	if c.BatchTimeout <= 0 {
		return fmt.Errorf("batch_timeout must be > 0, got %v", c.BatchTimeout)
	}

	// Validate retry configuration
	if c.RetryEnabled {
		if c.RetryInitialInterval < 0 {
			return fmt.Errorf("retry_initial_interval must be >= 0, got %v", c.RetryInitialInterval)
		}

		if c.RetryMaxInterval < 0 {
			return fmt.Errorf("retry_max_interval must be >= 0, got %v", c.RetryMaxInterval)
		}

		if c.RetryInitialInterval > c.RetryMaxInterval {
			return fmt.Errorf("retry_initial_interval (%v) must be <= retry_max_interval (%v)",
				c.RetryInitialInterval, c.RetryMaxInterval)
		}

		if c.RetryMaxElapsedTime < 0 {
			return fmt.Errorf("retry_max_elapsed_time must be >= 0, got %v", c.RetryMaxElapsedTime)
		}
	}

	return nil
}
