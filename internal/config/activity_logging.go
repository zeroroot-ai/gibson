package config

import (
	"os"
	"strconv"
)

// ActivityLoggingConfig configures the activity stream logger.
// Activity logging provides real-time structured logging of agent decisions,
// LLM interactions, and tool executions for observability in Grafana/Loki.
type ActivityLoggingConfig struct {
	// Enabled controls whether activity logging is active
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// Level sets the verbosity level (quiet, normal, verbose, debug)
	Level string `mapstructure:"level" yaml:"level"`

	// MaxContentLength is the maximum characters for content fields before truncation
	MaxContentLength int `mapstructure:"max_content_length" yaml:"max_content_length"`

	// Output specifies where to write events (stdout, file, both)
	Output string `mapstructure:"output" yaml:"output"`

	// FilePath is the file path when output includes "file"
	FilePath string `mapstructure:"file_path" yaml:"file_path"`

	// BufferSize is the event buffer size for async writes
	BufferSize int `mapstructure:"buffer_size" yaml:"buffer_size"`

	// IncludeLangfuseURLs adds Langfuse deep links to events
	IncludeLangfuseURLs bool `mapstructure:"include_langfuse_urls" yaml:"include_langfuse_urls"`
}

// ApplyEnvironmentOverrides checks for environment variables and overrides
// the config values if they are set.
//
// Supported environment variables:
//   - GIBSON_ACTIVITY_LOG_ENABLED: overrides Enabled (default: true)
//   - GIBSON_ACTIVITY_LOG_LEVEL: overrides Level (default: normal)
//   - GIBSON_ACTIVITY_LOG_MAX_CONTENT: overrides MaxContentLength (default: 500)
//   - GIBSON_ACTIVITY_LOG_OUTPUT: overrides Output (default: stdout)
//   - GIBSON_ACTIVITY_LOG_FILE: overrides FilePath (default: "")
func (c *ActivityLoggingConfig) ApplyEnvironmentOverrides() {
	if enabled := os.Getenv("GIBSON_ACTIVITY_LOG_ENABLED"); enabled != "" {
		if val, err := strconv.ParseBool(enabled); err == nil {
			c.Enabled = val
		}
	}

	if level := os.Getenv("GIBSON_ACTIVITY_LOG_LEVEL"); level != "" {
		c.Level = level
	}

	if maxContent := os.Getenv("GIBSON_ACTIVITY_LOG_MAX_CONTENT"); maxContent != "" {
		if val, err := strconv.Atoi(maxContent); err == nil {
			c.MaxContentLength = val
		}
	}

	if output := os.Getenv("GIBSON_ACTIVITY_LOG_OUTPUT"); output != "" {
		c.Output = output
	}

	if filePath := os.Getenv("GIBSON_ACTIVITY_LOG_FILE"); filePath != "" {
		c.FilePath = filePath
	}
}
