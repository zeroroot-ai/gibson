package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-playground/validator/v10"
)

// ConfigValidator validates configuration values.
type ConfigValidator interface {
	Validate(cfg *Config) error
}

// validatorImpl implements ConfigValidator using go-playground/validator.
type validatorImpl struct {
	validate *validator.Validate
}

// NewValidator creates a new ConfigValidator instance.
func NewValidator() ConfigValidator {
	return &validatorImpl{
		validate: validator.New(),
	}
}

// Validate validates the configuration and returns detailed error messages.
func (v *validatorImpl) Validate(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("configuration is nil")
	}

	// Perform struct tag validation first
	err := v.validate.Struct(cfg)
	if err != nil {
		// Convert validation errors to detailed messages
		validationErrs, ok := err.(validator.ValidationErrors)
		if !ok {
			return fmt.Errorf("validation error: %w", err)
		}

		var errorMessages []string
		for _, e := range validationErrs {
			errorMessages = append(errorMessages, formatValidationError(e))
		}

		return fmt.Errorf("configuration validation failed:\n  - %s", strings.Join(errorMessages, "\n  - "))
	}

	// Custom validation for RegistrationConfig
	if cfg.Registration.Enabled {
		if cfg.Registration.Port < 1024 || cfg.Registration.Port > 65535 {
			return fmt.Errorf("configuration validation failed:\n  - registration.port must be between 1024 and 65535 when enabled (got: %d)", cfg.Registration.Port)
		}
	}

	// Custom validation for ActivityLoggingConfig
	if err := validateActivityLogging(&cfg.ActivityLogging); err != nil {
		return err
	}

	return nil
}

// validateActivityLogging validates the activity logging configuration.
func validateActivityLogging(cfg *ActivityLoggingConfig) error {
	var errors []string

	// Validate level is valid
	validLevels := map[string]bool{
		"quiet":   true,
		"normal":  true,
		"verbose": true,
		"debug":   true,
	}
	if !validLevels[cfg.Level] {
		errors = append(errors, fmt.Sprintf("activity_logging.level must be one of [quiet, normal, verbose, debug] (got: %s)", cfg.Level))
	}

	// Validate max_content_length is positive
	if cfg.MaxContentLength <= 0 {
		errors = append(errors, fmt.Sprintf("activity_logging.max_content_length must be positive (got: %d)", cfg.MaxContentLength))
	}

	// Validate output is valid
	validOutputs := map[string]bool{
		"stdout": true,
		"file":   true,
		"both":   true,
	}
	if !validOutputs[cfg.Output] {
		errors = append(errors, fmt.Sprintf("activity_logging.output must be one of [stdout, file, both] (got: %s)", cfg.Output))
	}

	// Validate file_path is set when output includes file
	if (cfg.Output == "file" || cfg.Output == "both") && cfg.FilePath == "" {
		errors = append(errors, "activity_logging.file_path must be set when output is 'file' or 'both'")
	}

	// Validate buffer_size is positive
	if cfg.BufferSize <= 0 {
		errors = append(errors, fmt.Sprintf("activity_logging.buffer_size must be positive (got: %d)", cfg.BufferSize))
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}

// formatValidationError formats a single validation error with field path and details.
func formatValidationError(e validator.FieldError) string {
	fieldPath := formatFieldPath(e.Namespace())

	switch e.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", fieldPath)
	case "min":
		return fmt.Sprintf("%s must be at least %s (got: %v)", fieldPath, e.Param(), e.Value())
	case "max":
		return fmt.Sprintf("%s must be at most %s (got: %v)", fieldPath, e.Param(), e.Value())
	case "oneof":
		return fmt.Sprintf("%s must be one of [%s] (got: %v)", fieldPath, e.Param(), e.Value())
	case "url":
		return fmt.Sprintf("%s must be a valid URL (got: %v)", fieldPath, e.Value())
	case "filepath":
		return fmt.Sprintf("%s must be a valid file path (got: %v)", fieldPath, e.Value())
	default:
		return fmt.Sprintf("%s failed validation '%s' (got: %v)", fieldPath, e.Tag(), e.Value())
	}
}

// formatFieldPath converts validator namespace to a more readable field path.
// Example: "Config.Core.ParallelLimit" -> "core.parallel_limit"
func formatFieldPath(namespace string) string {
	// Remove the root struct name
	parts := strings.Split(namespace, ".")
	if len(parts) <= 1 {
		return namespace
	}

	// Skip the first part (struct name) and convert to lowercase with underscores
	result := make([]string, 0, len(parts)-1)
	for i := 1; i < len(parts); i++ {
		result = append(result, camelToSnake(parts[i]))
	}

	return strings.Join(result, ".")
}

// camelToSnake converts CamelCase to snake_case.
func camelToSnake(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteRune('_')
		}
		result.WriteRune(r)
	}
	return strings.ToLower(result.String())
}

// PlaceholderPatterns are values that indicate a copy-paste error or template value.
// The validation function checks for these patterns (case-insensitive).
var PlaceholderPatterns = []string{
	"sk-your-key-here",
	"<your-api-key>",
	"<your-",
	"CHANGE_ME",
	"changeme",
	"TODO",
	"xxx",
	"your-key-here",
	"replace-me",
	"INSERT_KEY_HERE",
}

// ProviderKeyPrefixes maps provider types to their expected API key prefixes.
// Used for advisory warnings only -- providers may change key formats.
var ProviderKeyPrefixes = map[string]string{
	"anthropic": "sk-ant-",
	"openai":    "sk-",
}

// IsPlaceholderValue checks if a string matches known placeholder patterns.
func IsPlaceholderValue(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, pattern := range PlaceholderPatterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// ProviderValidationResult contains the result of validating a single provider.
type ProviderValidationResult struct {
	ProviderName string
	EnvVar       string
	Available    bool   // true if key is present and valid
	Error        error  // non-nil if fatal validation error
	Warning      string // non-empty if advisory warning
}

// ValidateProviderKeys checks that all configured provider API key environment
// variables are set and contain valid-looking values. The env parameter allows
// injection of a custom environment lookup function for testing.
//
// Returns a slice of results (one per provider). The function reports ALL errors,
// not just the first.
func ValidateProviderKeys(providers map[string]ProviderConfig, env func(string) string) []ProviderValidationResult {
	if env == nil {
		env = os.Getenv
	}

	var results []ProviderValidationResult

	for name, provider := range providers {
		result := validateSingleProvider(name, provider, env)
		results = append(results, result)
	}

	return results
}

// validateSingleProvider validates a single provider's API key configuration.
func validateSingleProvider(name string, provider ProviderConfig, env func(string) string) ProviderValidationResult {
	result := ProviderValidationResult{
		ProviderName: name,
		EnvVar:       provider.APIKeyEnv,
	}

	// Case 1: Both api_key and api_key_env are set
	if provider.APIKey != "" && provider.APIKeyEnv != "" {
		result.Warning = fmt.Sprintf(
			"provider %q: both api_key and api_key_env are set, using api_key_env",
			name)
	}

	// Case 2: api_key_env is empty -- provider is unconfigured (acceptable)
	if provider.APIKeyEnv == "" {
		if provider.APIKey == "" {
			// Fully unconfigured provider
			result.Available = false
			return result
		}
		// Has inline api_key but no api_key_env
		result.Available = true
		return result
	}

	// Case 3: api_key_env is set -- validate the env var exists
	value := env(provider.APIKeyEnv)
	if value == "" {
		result.Error = fmt.Errorf(
			"provider %q: environment variable %q is not set or is empty",
			name, provider.APIKeyEnv)
		result.Available = false
		return result
	}

	// Trim whitespace
	trimmed := strings.TrimSpace(value)
	if trimmed != value {
		result.Warning = fmt.Sprintf(
			"provider %q: API key in %q has leading/trailing whitespace (trimmed)",
			name, provider.APIKeyEnv)
	}

	// Check for placeholder values
	if IsPlaceholderValue(trimmed) {
		result.Error = fmt.Errorf(
			"provider %q: API key appears to be a placeholder value",
			name)
		result.Available = false
		return result
	}

	// Check known prefix (advisory warning only)
	providerType := provider.Type
	if providerType == "" {
		providerType = name // fall back to provider name
	}
	if expectedPrefix, ok := ProviderKeyPrefixes[providerType]; ok {
		if !strings.HasPrefix(trimmed, expectedPrefix) {
			if result.Warning != "" {
				result.Warning += "; "
			}
			result.Warning += fmt.Sprintf(
				"provider %q: API key does not match expected prefix %q, verify the key is correct",
				name, expectedPrefix)
		}
	}

	result.Available = true
	return result
}

// maskKey returns a masked version of an API key for diagnostic output.
// Never used in standard logging.
func maskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:6] + "...****"
}
