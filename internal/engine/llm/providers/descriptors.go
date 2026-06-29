package providers

import (
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/llm/providers/catalogue"
	"github.com/zeroroot-ai/gibson/internal/engine/memory/embedder"
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

	// EmbeddingModels is the static catalogue of EMBEDDING models this provider
	// type offers (E11 BYO-embedder). Empty for provider types the daemon has
	// no embedder backend for. A non-empty list is what makes a provider
	// advertise CAPABILITY_EMBEDDING.
	EmbeddingModels []EmbeddingModelInfo
}

// EmbeddingModelInfo describes one embedding model a provider offers, carrying
// the output vector dimension the dashboard needs to pin the tenant's vector
// index. Dimensions are resolved from embedder.DimensionForModel (the single
// source of truth) so this table never drifts from the indexer.
type EmbeddingModelInfo struct {
	Name       string
	Dimensions int
}

// embeddingModelCatalogue lists the embedding models each provider type offers.
// Only provider types with an embedder backend appear here (E11 BYO-embedder:
// the embedder.Kind* set — openai, bedrock, cohere — mapped back to their chat
// ProviderType). Embedding-only backends with no chat provider (voyage, TEI,
// generic openai-compatible) are intentionally absent: GetSupportedProviders
// enumerates chat provider types, so surfacing those needs a separate surface
// (tracked as a #1012 follow-up). Dimensions are NOT listed here — they are
// resolved from embedder.DimensionForModel so the two cannot diverge.
var embeddingModelCatalogue = map[llm.ProviderType][]string{
	llm.ProviderOpenAI:  {"text-embedding-3-small", "text-embedding-3-large", "text-embedding-ada-002"},
	llm.ProviderBedrock: {"amazon.titan-embed-text-v1", "amazon.titan-embed-text-v2:0"},
	llm.ProviderCohere:  {"embed-english-v3.0", "embed-multilingual-v3.0"},
}

// embeddingModelsFor returns the embedding-model catalogue for a provider type,
// resolving each model's output dimension from embedder.DimensionForModel.
// A model absent from the dimension table yields a zero dimension; the
// descriptors test asserts every catalogued model is known, failing loud on
// drift rather than letting a 0-dimension reach the index.
func embeddingModelsFor(t llm.ProviderType) []EmbeddingModelInfo {
	names := embeddingModelCatalogue[t]
	if len(names) == 0 {
		return nil
	}
	out := make([]EmbeddingModelInfo, 0, len(names))
	for _, name := range names {
		dim, _ := embedder.DimensionForModel(name)
		out = append(out, EmbeddingModelInfo{Name: name, Dimensions: dim})
	}
	return out
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
			// Inject the embedding catalogue centrally so each provider case
			// stays focused on its credential/chat shape.
			d.EmbeddingModels = embeddingModelsFor(d.Type)
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
	case llm.ProviderCustom:
		// Custom is intentionally excluded — the descriptor surface is for
		// known providers the dashboard can render a form for.
		return ProviderDescriptor{}, false
	}
	return ProviderDescriptor{}, false
}
