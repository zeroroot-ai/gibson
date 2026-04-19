package providers

import (
	"fmt"
	"strings"

	"github.com/zero-day-ai/gibson/internal/llm"
)

// NewProvider constructs an LLMProvider for the given ProviderConfig.Type.
// Every ProviderType in llm.SupportedProviderTypes() must have a matching case
// in this switch — the factory_coverage_test enforces that invariant.
func NewProvider(cfg llm.ProviderConfig) (llm.LLMProvider, error) {
	switch cfg.Type {
	case llm.ProviderAnthropic:
		return NewAnthropicProvider(cfg)
	case llm.ProviderOpenAI:
		return NewOpenAIProvider(cfg)
	case llm.ProviderGoogle:
		return NewGoogleProvider(cfg)
	case llm.ProviderOllama:
		return NewOllamaProvider(cfg)
	case llm.ProviderBedrock:
		return NewBedrockProvider(cfg)
	case llm.ProviderCloudflare:
		return NewCloudflareProvider(cfg)
	case llm.ProviderCohere:
		return NewCohereProvider(cfg)
	case llm.ProviderHuggingFace:
		return NewHuggingFaceProvider(cfg)
	case llm.ProviderLlamafile:
		return NewLlamafileProvider(cfg)
	case llm.ProviderMistral:
		return NewMistralProvider(cfg)
	case llm.ProviderCustom:
		// Custom is a deliberate escape hatch for operators wiring a provider
		// the daemon doesn't know about. Construction is their responsibility;
		// the factory refuses to pretend it understands the type.
		return nil, llm.NewInvalidInputError("factory",
			"ProviderCustom cannot be constructed by the factory; build the provider directly")
	case "mock":
		return NewMockProvider([]string{"Mock response"}), nil
	default:
		return nil, llm.NewInvalidInputError("factory",
			fmt.Sprintf("unknown provider type %q; supported: %s", cfg.Type, supportedTypesList()))
	}
}

// supportedTypesList returns the enum as a comma-separated list for error messages.
func supportedTypesList() string {
	types := llm.SupportedProviderTypes()
	names := make([]string, 0, len(types))
	for _, t := range types {
		names = append(names, string(t))
	}
	return strings.Join(names, ", ")
}
