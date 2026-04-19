package llm

import (
	"fmt"
	"strings"

	"github.com/zero-day-ai/gibson/internal/types"
)

// ProviderType represents the type of LLM provider.
type ProviderType string

const (
	ProviderAnthropic   ProviderType = "anthropic"
	ProviderOpenAI      ProviderType = "openai"
	ProviderGoogle      ProviderType = "google"
	ProviderOllama      ProviderType = "ollama"
	ProviderBedrock     ProviderType = "bedrock"
	ProviderCloudflare  ProviderType = "cloudflare"
	ProviderCohere      ProviderType = "cohere"
	ProviderHuggingFace ProviderType = "huggingface"
	ProviderLlamafile   ProviderType = "llamafile"
	ProviderMistral     ProviderType = "mistral"
	ProviderCustom      ProviderType = "custom"
)

// SupportedProviderTypes returns every ProviderType the platform can construct,
// in a deterministic order. This is the single source of truth for the factory
// switch, config validator, and the GetSupportedProviders introspection RPC.
func SupportedProviderTypes() []ProviderType {
	return []ProviderType{
		ProviderAnthropic,
		ProviderOpenAI,
		ProviderGoogle,
		ProviderOllama,
		ProviderBedrock,
		ProviderCloudflare,
		ProviderCohere,
		ProviderHuggingFace,
		ProviderLlamafile,
		ProviderMistral,
		ProviderCustom,
	}
}

// selfHostedProviderTypes lists providers that do not require an API key at
// construction time (the endpoint is operator-controlled).
var selfHostedProviderTypes = map[ProviderType]bool{
	ProviderOllama:    true,
	ProviderLlamafile: true,
}

// IsSelfHosted reports whether the provider runs on operator-controlled
// infrastructure and therefore does not require an API key at config time.
func (p ProviderType) IsSelfHosted() bool {
	return selfHostedProviderTypes[p]
}

// LLMConfig contains the root LLM provider configuration.
// It specifies which provider to use by default and provides
// detailed configuration for each available provider.
type LLMConfig struct {
	DefaultProvider string                    `mapstructure:"default_provider" yaml:"default_provider" validate:"required"`
	Providers       map[string]ProviderConfig `mapstructure:"providers" yaml:"providers" validate:"required,dive"`
}

// Validate performs validation on the LLMConfig.
// It ensures that the default provider exists in the providers map
// and that all provider configurations are valid.
func (c *LLMConfig) Validate() error {
	if c.DefaultProvider == "" {
		return types.NewError(types.CONFIG_VALIDATION_FAILED, "default_provider cannot be empty")
	}

	if c.Providers == nil || len(c.Providers) == 0 {
		return types.NewError(types.CONFIG_VALIDATION_FAILED, "providers map cannot be empty")
	}

	// Validate that default provider exists
	if _, exists := c.Providers[c.DefaultProvider]; !exists {
		return types.NewError(
			types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("default_provider '%s' not found in providers map", c.DefaultProvider),
		)
	}

	// Validate each provider configuration
	for name, provider := range c.Providers {
		if err := provider.Validate(); err != nil {
			return types.WrapError(
				types.CONFIG_VALIDATION_FAILED,
				fmt.Sprintf("provider '%s' validation failed", name),
				err,
			)
		}
	}

	return nil
}

// ProviderConfig contains configuration for a specific LLM provider.
// It includes authentication credentials, API endpoints, available models,
// and provider-specific options.
type ProviderConfig struct {
	Type         ProviderType           `mapstructure:"type" yaml:"type" validate:"required,oneof=anthropic openai google ollama bedrock cloudflare cohere huggingface llamafile mistral custom"`
	APIKey       string                 `mapstructure:"api_key" yaml:"api_key"`
	BaseURL      string                 `mapstructure:"base_url" yaml:"base_url"`
	DefaultModel string                 `mapstructure:"default_model" yaml:"default_model" validate:"required"`
	Models       map[string]ModelConfig `mapstructure:"models" yaml:"models" validate:"dive"`
	Options      map[string]interface{} `mapstructure:"options" yaml:"options"`
	RateLimits   RateLimitConfig        `mapstructure:"rate_limits" yaml:"rate_limits"`
	// Extra carries provider-specific credentials (e.g. aws_access_key_id,
	// watsonx_project_id, ernie_secret_key) that do not fit the typed fields
	// above. Keys are provider-defined; values are treated as secrets and
	// redacted by the observability layer.
	Extra map[string]string `mapstructure:"extra" yaml:"extra"`
}

// Validate performs validation on the ProviderConfig.
// It ensures all required fields are present and that the default model
// exists in the models map if models are specified.
func (p *ProviderConfig) Validate() error {
	if p.Type == "" {
		return types.NewError(types.CONFIG_VALIDATION_FAILED, "provider type cannot be empty")
	}

	// Validate provider type against the full supported set
	validTypes := make(map[ProviderType]bool, len(SupportedProviderTypes()))
	for _, t := range SupportedProviderTypes() {
		validTypes[t] = true
	}
	if !validTypes[p.Type] {
		names := make([]string, 0, len(SupportedProviderTypes()))
		for _, t := range SupportedProviderTypes() {
			names = append(names, string(t))
		}
		return types.NewError(
			types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("invalid provider type '%s', must be one of: %s", p.Type, strings.Join(names, ", ")),
		)
	}

	// APIKey is required for hosted providers but optional for self-hosted ones
	// (ollama, llamafile) where the endpoint is operator-controlled.
	if p.APIKey == "" && !p.Type.IsSelfHosted() {
		return types.NewError(types.CONFIG_VALIDATION_FAILED, "api_key cannot be empty")
	}

	if p.DefaultModel == "" {
		return types.NewError(types.CONFIG_VALIDATION_FAILED, "default_model cannot be empty")
	}

	// If models are specified, validate that default model exists
	if p.Models != nil && len(p.Models) > 0 {
		if _, exists := p.Models[p.DefaultModel]; !exists {
			return types.NewError(
				types.CONFIG_VALIDATION_FAILED,
				fmt.Sprintf("default_model '%s' not found in models map", p.DefaultModel),
			)
		}

		// Validate each model configuration
		for modelName, model := range p.Models {
			if err := model.Validate(); err != nil {
				return types.WrapError(
					types.CONFIG_VALIDATION_FAILED,
					fmt.Sprintf("model '%s' validation failed", modelName),
					err,
				)
			}
		}
	}

	return nil
}

// ModelFeature represents capabilities that a model may support.
type ModelFeature string

const (
	FeatureChat       ModelFeature = "chat"
	FeatureCompletion ModelFeature = "completion"
	FeatureVision     ModelFeature = "vision"
	FeatureTools      ModelFeature = "tools"
	FeatureStreaming  ModelFeature = "streaming"
	FeatureJSON       ModelFeature = "json"
)

// ModelConfig contains configuration and metadata for a specific model.
// It defines the model's capabilities, context limits, and pricing information.
type ModelConfig struct {
	ContextWindow int            `mapstructure:"context_window" yaml:"context_window" validate:"min=1"`
	MaxOutput     int            `mapstructure:"max_output" yaml:"max_output" validate:"min=1"`
	Features      []ModelFeature `mapstructure:"features" yaml:"features"`
	PricingInput  float64        `mapstructure:"pricing_input" yaml:"pricing_input" validate:"min=0"`
	PricingOutput float64        `mapstructure:"pricing_output" yaml:"pricing_output" validate:"min=0"`
}

// Validate performs validation on the ModelConfig.
// It ensures that context window and max output are positive values,
// and that pricing information is non-negative.
func (m *ModelConfig) Validate() error {
	if m.ContextWindow <= 0 {
		return types.NewError(
			types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("context_window must be greater than 0, got %d", m.ContextWindow),
		)
	}

	if m.MaxOutput <= 0 {
		return types.NewError(
			types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("max_output must be greater than 0, got %d", m.MaxOutput),
		)
	}

	if m.MaxOutput > m.ContextWindow {
		return types.NewError(
			types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("max_output (%d) cannot exceed context_window (%d)", m.MaxOutput, m.ContextWindow),
		)
	}

	if m.PricingInput < 0 {
		return types.NewError(
			types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("pricing_input must be non-negative, got %f", m.PricingInput),
		)
	}

	if m.PricingOutput < 0 {
		return types.NewError(
			types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("pricing_output must be non-negative, got %f", m.PricingOutput),
		)
	}

	// Validate features if specified
	if m.Features != nil && len(m.Features) > 0 {
		validFeatures := map[ModelFeature]bool{
			FeatureChat:       true,
			FeatureCompletion: true,
			FeatureVision:     true,
			FeatureTools:      true,
			FeatureStreaming:  true,
			FeatureJSON:       true,
		}

		for _, feature := range m.Features {
			if !validFeatures[feature] {
				return types.NewError(
					types.CONFIG_VALIDATION_FAILED,
					fmt.Sprintf("invalid feature '%s'", feature),
				)
			}
		}
	}

	return nil
}

// HasFeature checks if the model supports a specific feature.
func (m *ModelConfig) HasFeature(feature ModelFeature) bool {
	if m.Features == nil {
		return false
	}
	for _, f := range m.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// GetBaseURL returns the base URL for a provider, with defaults for known providers.
func (p *ProviderConfig) GetBaseURL() string {
	if p.BaseURL != "" {
		return p.BaseURL
	}

	// Return default base URLs for known providers
	switch p.Type {
	case ProviderAnthropic:
		return "https://api.anthropic.com"
	case ProviderOpenAI:
		return "https://api.openai.com/v1"
	case ProviderGoogle:
		return "https://generativelanguage.googleapis.com/v1beta"
	default:
		return ""
	}
}

// GetModel returns the configuration for a specific model.
// If the model is not found in the Models map, it returns nil.
func (p *ProviderConfig) GetModel(modelName string) *ModelConfig {
	if p.Models == nil {
		return nil
	}
	if model, exists := p.Models[modelName]; exists {
		return &model
	}
	return nil
}

// NormalizeProviderName normalizes provider names to lowercase for consistent lookup.
func NormalizeProviderName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// NormalizeModelName normalizes model names to lowercase for consistent lookup.
func NormalizeModelName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
