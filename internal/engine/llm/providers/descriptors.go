package providers

import (
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/llm/providers/catalogue"
)

// ProviderDescriptor is the Go-side, proto-free form of what the daemon's
// GetSupportedProviders admin RPC returns. It is the source of truth for
// provider capability metadata consumed by the dashboard Settings > Providers
// form.
//
// When the admin RPC is wired (follow-up to spec 21), its proto message
// type `gibson.tenant.v1.ProviderRecord` should be a 1:1 mapping
// of this struct.
type ProviderDescriptor struct {
	// Type is the ProviderType constant (e.g. "bedrock").
	Type llm.ProviderType

	// DisplayName is the human-facing label shown in the dashboard dropdown.
	DisplayName string

	// DocsURL points at the upstream provider's credential/setup docs.
	DocsURL string

	// SelfHosted mirrors ProviderType.IsSelfHosted() — surfaced here so the
	// dashboard can omit the "Test connection" button for providers that
	// don't have a public API to probe.
	SelfHosted bool

	// Credentials is the form schema — one entry per input field.
	Credentials []llm.CredentialField

	// DefaultModels is the catalogue the provider would report from Models();
	// populated here so the dashboard can render a model picker without
	// constructing the provider.
	DefaultModels []llm.ModelInfo
}

// catalogueModels converts the catalogue's Model entries for a given provider
// type into the llm.ModelInfo slice used by ProviderDescriptor.DefaultModels.
// It sources data from the embedded provider-catalogue.yaml via catalogue.Load()
// rather than constructing a runtime provider instance.
func catalogueModels(providerType string) []llm.ModelInfo {
	entries := catalogue.ModelsFor(providerType)
	if len(entries) == 0 {
		return nil
	}
	out := make([]llm.ModelInfo, 0, len(entries))
	for _, e := range entries {
		out = append(out, llm.ModelInfo{
			Name:          e.ID,
			ContextWindow: e.ContextWindow,
			Features:      e.Capabilities,
		})
	}
	return out
}

// SupportedProviderDescriptors returns the full list of provider descriptors
// in the same deterministic order as llm.SupportedProviderTypes(). This is
// the function the future admin RPC handler will call.
func SupportedProviderDescriptors() []ProviderDescriptor {
	out := make([]ProviderDescriptor, 0, len(llm.SupportedProviderTypes()))
	for _, t := range llm.SupportedProviderTypes() {
		if d, ok := providerDescriptor(t); ok {
			out = append(out, d)
		}
	}
	return out
}

// providerDescriptor returns the static descriptor for a given ProviderType,
// or (zero, false) when the type has no descriptor registered — ProviderCustom
// is intentionally excluded because its shape is operator-defined.
func providerDescriptor(t llm.ProviderType) (ProviderDescriptor, bool) {
	switch t {
	case llm.ProviderAnthropic:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "Anthropic (Claude)",
			DocsURL:     "https://docs.anthropic.com/",
			Credentials: []llm.CredentialField{
				{Key: "api_key", Label: "Anthropic API Key", Required: true, Secret: true},
			},
			DefaultModels: catalogueModels("anthropic"),
		}, true
	case llm.ProviderOpenAI:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "OpenAI (GPT)",
			DocsURL:     "https://platform.openai.com/docs",
			Credentials: []llm.CredentialField{
				{Key: "api_key", Label: "OpenAI API Key", Required: true, Secret: true},
				{Key: "base_url", Label: "Base URL (optional)", Placeholder: "https://api.openai.com/v1"},
			},
			DefaultModels: catalogueModels("openai"),
		}, true
	case llm.ProviderGoogle:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "Google Gemini",
			DocsURL:     "https://ai.google.dev/",
			Credentials: []llm.CredentialField{
				{Key: "api_key", Label: "Google API Key", Required: true, Secret: true},
			},
			DefaultModels: catalogueModels("google"),
		}, true
	case llm.ProviderOllama:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "Ollama",
			DocsURL:     "https://ollama.com/",
			SelfHosted:  true,
			Credentials: []llm.CredentialField{
				{Key: "base_url", Label: "Server URL", Placeholder: "http://localhost:11434", Help: "Where your Ollama server is reachable."},
			},
			DefaultModels: catalogueModels("ollama"),
		}, true
	case llm.ProviderBedrock:
		return ProviderDescriptor{
			Type:          t,
			DisplayName:   "AWS Bedrock",
			DocsURL:       "https://docs.aws.amazon.com/bedrock/",
			Credentials:   BedrockCredentialSchema(),
			DefaultModels: catalogueModels("bedrock"),
		}, true
	case llm.ProviderCloudflare:
		return ProviderDescriptor{
			Type:          t,
			DisplayName:   "Cloudflare Workers AI",
			DocsURL:       "https://developers.cloudflare.com/workers-ai/",
			Credentials:   CloudflareCredentialSchema(),
			DefaultModels: catalogueModels("cloudflare"),
		}, true
	case llm.ProviderCohere:
		return ProviderDescriptor{
			Type:          t,
			DisplayName:   "Cohere",
			DocsURL:       "https://docs.cohere.com/",
			Credentials:   CohereCredentialSchema(),
			DefaultModels: catalogueModels("cohere"),
		}, true
	case llm.ProviderHuggingFace:
		return ProviderDescriptor{
			Type:          t,
			DisplayName:   "HuggingFace Inference",
			DocsURL:       "https://huggingface.co/docs/api-inference/",
			Credentials:   HuggingFaceCredentialSchema(),
			DefaultModels: catalogueModels("huggingface"),
		}, true
	case llm.ProviderLlamafile:
		return ProviderDescriptor{
			Type:          t,
			DisplayName:   "Llamafile",
			DocsURL:       "https://github.com/Mozilla-Ocho/llamafile",
			SelfHosted:    true,
			Credentials:   LlamafileCredentialSchema(),
			DefaultModels: catalogueModels("llamafile"),
		}, true
	case llm.ProviderMistral:
		return ProviderDescriptor{
			Type:          t,
			DisplayName:   "Mistral",
			DocsURL:       "https://docs.mistral.ai/",
			Credentials:   MistralCredentialSchema(),
			DefaultModels: catalogueModels("mistral"),
		}, true
	case llm.ProviderVoyage:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "Voyage AI",
			DocsURL:     "https://docs.voyageai.com/",
			Credentials: []llm.CredentialField{
				{Key: "api_key", Label: "Voyage API Key", Required: true, Secret: true},
			},
			DefaultModels: catalogueModels("voyage"),
		}, true
	case llm.ProviderOpenAICompatible:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "OpenAI-compatible endpoint",
			DocsURL:     "https://platform.openai.com/docs/api-reference/embeddings",
			SelfHosted:  true,
			Credentials: []llm.CredentialField{
				{Key: "base_url", Label: "Endpoint URL", Required: true, Placeholder: "http://embedder:8080", Help: "URL of the OpenAI-compatible /v1/embeddings endpoint."},
				{Key: "api_key", Label: "API Key (optional)", Secret: true, Help: "Leave empty if the endpoint does not require authentication."},
			},
			DefaultModels: catalogueModels("openai-compatible"),
		}, true
	case llm.ProviderTEI:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "HuggingFace TEI (native)",
			DocsURL:     "https://huggingface.co/docs/text-embeddings-inference",
			SelfHosted:  true,
			Credentials: []llm.CredentialField{
				{Key: "base_url", Label: "TEI URL", Required: true, Placeholder: "http://tei:8080", Help: "Base URL of the HuggingFace Text-Embeddings-Inference server."},
			},
			DefaultModels: catalogueModels("tei"),
		}, true
	case llm.ProviderCustom:
		// Custom is intentionally excluded — the descriptor surface is for
		// known providers the dashboard can render a form for.
		return ProviderDescriptor{}, false
	}
	return ProviderDescriptor{}, false
}
