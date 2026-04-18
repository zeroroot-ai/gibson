package providers

import (
	"github.com/zero-day-ai/gibson/internal/llm"
)

// ProviderDescriptor is the Go-side, proto-free form of what the daemon's
// GetSupportedProviders admin RPC returns. It is the source of truth for
// provider capability metadata consumed by the dashboard Settings > Providers
// form.
//
// When the admin RPC is wired (follow-up to spec 21), its proto message
// type `gibson.daemon.admin.v1.ProviderDescriptor` should be a 1:1 mapping
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
		}, true
	case llm.ProviderGoogle:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "Google Gemini",
			DocsURL:     "https://ai.google.dev/",
			Credentials: []llm.CredentialField{
				{Key: "api_key", Label: "Google API Key", Required: true, Secret: true},
			},
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
		}, true
	case llm.ProviderBedrock:
		p := &BedrockProvider{}
		models, _ := p.Models(nil)
		return ProviderDescriptor{
			Type:          t,
			DisplayName:   "AWS Bedrock",
			DocsURL:       "https://docs.aws.amazon.com/bedrock/",
			Credentials:   BedrockCredentialSchema(),
			DefaultModels: models,
		}, true
	case llm.ProviderCloudflare:
		p := &CloudflareProvider{}
		models, _ := p.Models(nil)
		return ProviderDescriptor{
			Type:          t,
			DisplayName:   "Cloudflare Workers AI",
			DocsURL:       "https://developers.cloudflare.com/workers-ai/",
			Credentials:   CloudflareCredentialSchema(),
			DefaultModels: models,
		}, true
	case llm.ProviderCohere:
		p := &CohereProvider{}
		models, _ := p.Models(nil)
		return ProviderDescriptor{
			Type:          t,
			DisplayName:   "Cohere",
			DocsURL:       "https://docs.cohere.com/",
			Credentials:   CohereCredentialSchema(),
			DefaultModels: models,
		}, true
	case llm.ProviderErnie:
		p := &ErnieProvider{}
		models, _ := p.Models(nil)
		return ProviderDescriptor{
			Type:          t,
			DisplayName:   "Baidu ERNIE",
			DocsURL:       "https://cloud.baidu.com/doc/WENXINWORKSHOP/",
			Credentials:   ErnieCredentialSchema(),
			DefaultModels: models,
		}, true
	case llm.ProviderHuggingFace:
		p := &HuggingFaceProvider{}
		models, _ := p.Models(nil)
		return ProviderDescriptor{
			Type:          t,
			DisplayName:   "HuggingFace Inference",
			DocsURL:       "https://huggingface.co/docs/api-inference/",
			Credentials:   HuggingFaceCredentialSchema(),
			DefaultModels: models,
		}, true
	case llm.ProviderLlamafile:
		p := &LlamafileProvider{}
		models, _ := p.Models(nil)
		return ProviderDescriptor{
			Type:          t,
			DisplayName:   "Llamafile",
			DocsURL:       "https://github.com/Mozilla-Ocho/llamafile",
			SelfHosted:    true,
			Credentials:   LlamafileCredentialSchema(),
			DefaultModels: models,
		}, true
	case llm.ProviderLocal:
		p := &LocalProvider{}
		models, _ := p.Models(nil)
		return ProviderDescriptor{
			Type:          t,
			DisplayName:   "Local (subprocess)",
			DocsURL:       "",
			SelfHosted:    true,
			Credentials:   LocalCredentialSchema(),
			DefaultModels: models,
		}, true
	case llm.ProviderMaritaca:
		p := &MaritacaProvider{}
		models, _ := p.Models(nil)
		return ProviderDescriptor{
			Type:          t,
			DisplayName:   "Maritaca AI",
			DocsURL:       "https://docs.maritaca.ai/",
			Credentials:   MaritacaCredentialSchema(),
			DefaultModels: models,
		}, true
	case llm.ProviderMistral:
		p := &MistralProvider{}
		models, _ := p.Models(nil)
		return ProviderDescriptor{
			Type:          t,
			DisplayName:   "Mistral",
			DocsURL:       "https://docs.mistral.ai/",
			Credentials:   MistralCredentialSchema(),
			DefaultModels: models,
		}, true
	case llm.ProviderWatsonX:
		p := &WatsonXProvider{}
		models, _ := p.Models(nil)
		return ProviderDescriptor{
			Type:          t,
			DisplayName:   "IBM WatsonX",
			DocsURL:       "https://www.ibm.com/products/watsonx-ai",
			Credentials:   WatsonXCredentialSchema(),
			DefaultModels: models,
		}, true
	case llm.ProviderCustom:
		// Custom is intentionally excluded — the descriptor surface is for
		// known providers the dashboard can render a form for.
		return ProviderDescriptor{}, false
	}
	return ProviderDescriptor{}, false
}
