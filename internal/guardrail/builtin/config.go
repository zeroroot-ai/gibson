package builtin

import (
	"fmt"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/zeroroot-ai/gibson/internal/guardrail"
)

// GuardrailConfig represents a guardrail configuration from YAML
type GuardrailConfig struct {
	Type   string         `yaml:"type" json:"type"`
	Name   string         `yaml:"name,omitempty" json:"name,omitempty"`
	Config map[string]any `yaml:"config" json:"config"`
}

// ParseGuardrailConfigs creates Guardrail instances from configurations
func ParseGuardrailConfigs(configs []GuardrailConfig) ([]guardrail.Guardrail, error) {
	guardrails := make([]guardrail.Guardrail, 0, len(configs))

	for i, config := range configs {
		g, err := ParseGuardrailConfig(config)
		if err != nil {
			return nil, fmt.Errorf("failed to parse guardrail config at index %d: %w", i, err)
		}
		guardrails = append(guardrails, g)
	}

	return guardrails, nil
}

// ParseGuardrailConfig creates a single Guardrail from configuration
func ParseGuardrailConfig(config GuardrailConfig) (guardrail.Guardrail, error) {
	// Validate first
	if err := ValidateGuardrailConfig(config); err != nil {
		return nil, err
	}

	switch config.Type {
	case "scope":
		return parseScopeConfig(config)
	case "rate":
		return parseRateConfig(config)
	case "tool":
		return parseToolConfig(config)
	case "pii":
		return parsePIIConfig(config)
	case "content":
		return parseContentConfig(config)
	default:
		return nil, fmt.Errorf("unknown guardrail type: %s", config.Type)
	}
}

// parseScopeConfig parses a scope validator configuration
func parseScopeConfig(config GuardrailConfig) (guardrail.Guardrail, error) {
	var scopeConfig ScopeValidatorConfig

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:     &scopeConfig,
		TagName:    "mapstructure",
		DecodeHook: mapstructure.StringToTimeDurationHookFunc(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create decoder: %w", err)
	}

	if err := decoder.Decode(config.Config); err != nil {
		return nil, fmt.Errorf("failed to decode scope config: %w", err)
	}

	return NewScopeValidator(scopeConfig), nil
}

// parseRateConfig parses a rate limiter configuration
func parseRateConfig(config GuardrailConfig) (guardrail.Guardrail, error) {
	// Create a temporary struct to handle duration parsing
	type tempRateConfig struct {
		MaxRequests int    `mapstructure:"max_requests"`
		Window      string `mapstructure:"window"`
		BurstSize   int    `mapstructure:"burst_size"`
		PerTarget   bool   `mapstructure:"per_target"`
	}

	var temp tempRateConfig

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  &temp,
		TagName: "mapstructure",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create decoder: %w", err)
	}

	if err := decoder.Decode(config.Config); err != nil {
		return nil, fmt.Errorf("failed to decode rate config: %w", err)
	}

	// Parse window duration
	window, err := time.ParseDuration(temp.Window)
	if err != nil {
		return nil, fmt.Errorf("invalid window duration '%s': %w", temp.Window, err)
	}

	// Create the actual config
	rateConfig := RateLimiterConfig{
		MaxRequests: temp.MaxRequests,
		Window:      window,
		BurstSize:   temp.BurstSize,
		PerTarget:   temp.PerTarget,
	}

	return NewRateLimiter(rateConfig), nil
}

// parseToolConfig parses a tool restriction configuration
func parseToolConfig(config GuardrailConfig) (guardrail.Guardrail, error) {
	var toolConfig ToolRestrictionConfig

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  &toolConfig,
		TagName: "mapstructure",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create decoder: %w", err)
	}

	if err := decoder.Decode(config.Config); err != nil {
		return nil, fmt.Errorf("failed to decode tool config: %w", err)
	}

	return NewToolRestriction(toolConfig), nil
}

// parsePIIConfig parses a PII detector configuration
func parsePIIConfig(config GuardrailConfig) (guardrail.Guardrail, error) {
	// Create a temporary struct to handle action parsing
	type tempPIIConfig struct {
		Action          string            `mapstructure:"action"`
		EnabledPatterns []string          `mapstructure:"enabled_patterns"`
		CustomPatterns  map[string]string `mapstructure:"custom_patterns"`
	}

	var temp tempPIIConfig

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  &temp,
		TagName: "mapstructure",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create decoder: %w", err)
	}

	if err := decoder.Decode(config.Config); err != nil {
		return nil, fmt.Errorf("failed to decode pii config: %w", err)
	}

	// Convert action string to GuardrailAction
	piiConfig := PIIDetectorConfig{
		Action:          guardrail.GuardrailAction(temp.Action),
		EnabledPatterns: temp.EnabledPatterns,
		CustomPatterns:  temp.CustomPatterns,
	}

	return NewPIIDetector(piiConfig)
}

// parseContentConfig parses a content filter configuration
func parseContentConfig(config GuardrailConfig) (guardrail.Guardrail, error) {
	// Create a temporary struct to handle pattern parsing
	type tempContentPattern struct {
		Pattern string `mapstructure:"pattern"`
		Action  string `mapstructure:"action"`
		Replace string `mapstructure:"replace"`
	}

	type tempContentConfig struct {
		Patterns      []tempContentPattern `mapstructure:"patterns"`
		DefaultAction string               `mapstructure:"default_action"`
	}

	var temp tempContentConfig

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  &temp,
		TagName: "mapstructure",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create decoder: %w", err)
	}

	if err := decoder.Decode(config.Config); err != nil {
		return nil, fmt.Errorf("failed to decode content config: %w", err)
	}

	// Convert to actual config
	patterns := make([]ContentPattern, len(temp.Patterns))
	for i, p := range temp.Patterns {
		patterns[i] = ContentPattern{
			Pattern: p.Pattern,
			Action:  guardrail.GuardrailAction(p.Action),
			Replace: p.Replace,
		}
	}

	contentConfig := ContentFilterConfig{
		Patterns:      patterns,
		DefaultAction: guardrail.GuardrailAction(temp.DefaultAction),
	}

	return NewContentFilter(contentConfig)
}

// ValidateGuardrailConfig validates a guardrail configuration
func ValidateGuardrailConfig(config GuardrailConfig) error {
	// Check that type is not empty
	if config.Type == "" {
		return fmt.Errorf("guardrail type is required")
	}

	// Check that type is supported
	supportedTypes := map[string]bool{
		"scope":   true,
		"rate":    true,
		"tool":    true,
		"pii":     true,
		"content": true,
	}

	if !supportedTypes[config.Type] {
		return fmt.Errorf("unsupported guardrail type: %s (supported types: %v)", config.Type, SupportedGuardrailTypes())
	}

	// Check that config is not nil
	if config.Config == nil {
		return fmt.Errorf("config is required for guardrail type %s", config.Type)
	}

	// Type-specific validation
	switch config.Type {
	case "rate":
		return validateRateConfig(config.Config)
	case "scope":
		return validateScopeConfig(config.Config)
	case "tool":
		return validateToolConfig(config.Config)
	case "pii":
		return validatePIIConfig(config.Config)
	case "content":
		return validateContentConfig(config.Config)
	}

	return nil
}

// validateRateConfig validates rate limiter configuration
func validateRateConfig(config map[string]any) error {
	maxRequests, ok := config["max_requests"]
	if !ok {
		return fmt.Errorf("max_requests is required for rate limiter")
	}

	// Check that max_requests is a positive number
	var maxReq int
	switch v := maxRequests.(type) {
	case int:
		maxReq = v
	case float64:
		maxReq = int(v)
	default:
		return fmt.Errorf("max_requests must be a number")
	}

	if maxReq <= 0 {
		return fmt.Errorf("max_requests must be positive")
	}

	window, ok := config["window"]
	if !ok {
		return fmt.Errorf("window is required for rate limiter")
	}

	// Check that window is a valid duration string
	windowStr, ok := window.(string)
	if !ok {
		return fmt.Errorf("window must be a duration string (e.g., '1m', '30s')")
	}

	if _, err := time.ParseDuration(windowStr); err != nil {
		return fmt.Errorf("invalid window duration: %w", err)
	}

	return nil
}

// validateScopeConfig validates scope validator configuration
func validateScopeConfig(config map[string]any) error {
	// Scope config is optional, can be empty
	// But if provided, allowed_domains and blocked_paths should be arrays
	if allowedDomains, ok := config["allowed_domains"]; ok {
		if _, ok := allowedDomains.([]interface{}); !ok {
			return fmt.Errorf("allowed_domains must be an array")
		}
	}

	if blockedPaths, ok := config["blocked_paths"]; ok {
		if _, ok := blockedPaths.([]interface{}); !ok {
			return fmt.Errorf("blocked_paths must be an array")
		}
	}

	return nil
}

// validateToolConfig validates tool restriction configuration
func validateToolConfig(config map[string]any) error {
	// Tool config is optional, can be empty
	// But if provided, allowed_tools and blocked_tools should be arrays
	if allowedTools, ok := config["allowed_tools"]; ok {
		if _, ok := allowedTools.([]interface{}); !ok {
			return fmt.Errorf("allowed_tools must be an array")
		}
	}

	if blockedTools, ok := config["blocked_tools"]; ok {
		if _, ok := blockedTools.([]interface{}); !ok {
			return fmt.Errorf("blocked_tools must be an array")
		}
	}

	return nil
}

// validatePIIConfig validates PII detector configuration
func validatePIIConfig(config map[string]any) error {
	// Action is optional (defaults to redact)
	if action, ok := config["action"]; ok {
		actionStr, ok := action.(string)
		if !ok {
			return fmt.Errorf("action must be a string")
		}

		validActions := map[string]bool{
			"allow":  true,
			"block":  true,
			"redact": true,
			"warn":   true,
		}

		if !validActions[actionStr] {
			return fmt.Errorf("invalid action: %s (valid actions: allow, block, redact, warn)", actionStr)
		}
	}

	// enabled_patterns is optional
	if enabledPatterns, ok := config["enabled_patterns"]; ok {
		if _, ok := enabledPatterns.([]interface{}); !ok {
			return fmt.Errorf("enabled_patterns must be an array")
		}
	}

	return nil
}

// validateContentConfig validates content filter configuration
func validateContentConfig(config map[string]any) error {
	patterns, ok := config["patterns"]
	if !ok {
		return fmt.Errorf("patterns is required for content filter")
	}

	patternsSlice, ok := patterns.([]interface{})
	if !ok {
		return fmt.Errorf("patterns must be an array")
	}

	if len(patternsSlice) == 0 {
		return fmt.Errorf("at least one pattern is required for content filter")
	}

	// Validate each pattern
	for i, p := range patternsSlice {
		patternMap, ok := p.(map[string]interface{})
		if !ok {
			return fmt.Errorf("pattern at index %d must be an object", i)
		}

		// Check that pattern field exists
		if _, ok := patternMap["pattern"]; !ok {
			return fmt.Errorf("pattern at index %d must have a 'pattern' field", i)
		}
	}

	return nil
}

// SupportedGuardrailTypes returns the list of supported guardrail types
func SupportedGuardrailTypes() []string {
	return []string{"scope", "rate", "tool", "pii", "content"}
}
