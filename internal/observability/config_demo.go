//go:build ignore

package observability

// This file contains example usage of ContentLoggingConfig and OTLPConfig.
// It demonstrates the API and is excluded from builds via build tags.

import (
	"fmt"
	"log"
	"time"
)

func ExampleContentLoggingConfig() {
	// Create configuration with safe defaults
	cfg := DefaultContentLoggingConfig()
	fmt.Printf("Content logging enabled: %v\n", cfg.Enabled)
	fmt.Printf("Max prompt length: %d\n", cfg.MaxPromptLength)
	fmt.Printf("Include tool I/O: %v\n", cfg.IncludeToolIO)

	// Enable content logging
	cfg.Enabled = true

	// Add custom redaction pattern
	cfg.RedactPatterns = append(cfg.RedactPatterns, `\b\d{16}\b`) // Credit card numbers

	// Compile patterns before use
	if err := cfg.CompilePatterns(); err != nil {
		log.Fatal(err)
	}

	// Redact sensitive content
	sensitive := "My API key is api_key=sk-1234567890 and card 1234567890123456"
	redacted := cfg.Redact(sensitive)
	fmt.Printf("Original: %s\n", sensitive)
	fmt.Printf("Redacted: %s\n", redacted)

	// Truncate long content
	longPrompt := "This is a very long prompt that exceeds the maximum length..."
	truncated := cfg.Truncate(longPrompt, 20)
	fmt.Printf("Truncated: %s\n", truncated)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}

	// Output:
	// Content logging enabled: false
	// Max prompt length: 10000
	// Include tool I/O: false
	// Original: My API key is api_key=sk-1234567890 and card 1234567890123456
	// Redacted: My API key is [REDACTED] and card [REDACTED]
	// Truncated: This is a very long... [truncated]
}

func ExampleOTLPConfig() {
	// Create configuration with production defaults
	cfg := DefaultOTLPConfig()
	fmt.Printf("Batch size: %d\n", cfg.BatchSize)
	fmt.Printf("Batch timeout: %v\n", cfg.BatchTimeout)
	fmt.Printf("Retry enabled: %v\n", cfg.RetryEnabled)
	fmt.Printf("Retry initial interval: %v\n", cfg.RetryInitialInterval)
	fmt.Printf("Retry max interval: %v\n", cfg.RetryMaxInterval)

	// Customize for your environment
	cfg.Endpoint = "http://otel-collector:4318"
	cfg.Compression = "gzip"
	cfg.Headers = map[string]string{
		"Authorization": "Bearer YOUR_TOKEN",
		"X-Tenant-ID":   "customer-123",
	}

	// Adjust batching for high-throughput scenarios
	cfg.BatchSize = 1000
	cfg.BatchTimeout = 10 * time.Second

	// Configure retry behavior
	cfg.RetryInitialInterval = 500 * time.Millisecond
	cfg.RetryMaxInterval = 1 * time.Minute
	cfg.RetryMaxElapsedTime = 10 * time.Minute

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("OTLP endpoint: %s\n", cfg.Endpoint)
	fmt.Printf("Compression: %s\n", cfg.Compression)

	// Output:
	// Batch size: 512
	// Batch timeout: 5s
	// Retry enabled: true
	// Retry initial interval: 1s
	// Retry max interval: 30s
	// OTLP endpoint: http://otel-collector:4318
	// Compression: gzip
}

func ExampleContentLoggingConfig_WithYAML() {
	// Example YAML configuration:
	//
	// content_logging:
	//   enabled: true
	//   max_prompt_length: 5000
	//   max_completion_length: 5000
	//   redact_patterns:
	//     - "(?i)(api[_-]?key|password|secret|token|bearer)[=:\\s]+\\S+"
	//     - "\\b\\d{16}\\b"
	//     - "\\b\\d{3}-\\d{2}-\\d{4}\\b"
	//   include_tool_io: false

	fmt.Println("See YAML example in comments")
	// Output:
	// See YAML example in comments
}

func ExampleOTLPConfig_WithYAML() {
	// Example YAML configuration:
	//
	// otlp:
	//   endpoint: "http://otel-collector:4318"
	//   headers:
	//     Authorization: "Bearer token123"
	//     X-Tenant-ID: "customer-123"
	//   compression: "gzip"
	//   batch_size: 1000
	//   batch_timeout: 10s
	//   retry_enabled: true
	//   retry_initial_interval: 1s
	//   retry_max_interval: 30s
	//   retry_max_elapsed_time: 5m

	fmt.Println("See YAML example in comments")
	// Output:
	// See YAML example in comments
}
