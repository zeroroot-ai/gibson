// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providerconfig

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
	Type ProviderType

	// DisplayName is the human-facing label shown in the dashboard dropdown.
	DisplayName string

	// DocsURL points at the upstream provider's credential/setup docs.
	DocsURL string

	// SelfHosted mirrors ProviderType.IsSelfHosted() — surfaced here so the
	// dashboard can omit the "Test connection" button for providers that
	// don't have a public API to probe.
	SelfHosted bool

	// Credentials is the form schema — one entry per input field.
	Credentials []CredentialField
}

// SupportedProviderDescriptors returns the full list of provider descriptors
// in the same deterministic order as SupportedProviderTypes(). This is
// the function the future admin RPC handler will call.
func SupportedProviderDescriptors() []ProviderDescriptor {
	out := make([]ProviderDescriptor, 0, len(SupportedProviderTypes()))
	for _, t := range SupportedProviderTypes() {
		if d, ok := providerDescriptor(t); ok {
			out = append(out, d)
		}
	}
	return out
}

// providerDescriptor returns the static descriptor for a given ProviderType,
// or (zero, false) when the type has no descriptor registered — ProviderCustom
// is intentionally excluded because its shape is operator-defined.
func providerDescriptor(t ProviderType) (ProviderDescriptor, bool) {
	switch t {
	case ProviderAnthropic:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "Anthropic (Claude)",
			DocsURL:     "https://docs.anthropic.com/",
			Credentials: []CredentialField{
				{Key: "api_key", Label: "Anthropic API Key", Required: true, Secret: true, Type: FieldPassword},
			},
		}, true
	case ProviderOpenAI:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "OpenAI (GPT)",
			DocsURL:     "https://platform.openai.com/docs",
			Credentials: []CredentialField{
				{Key: "api_key", Label: "OpenAI API Key", Required: true, Secret: true, Type: FieldPassword},
				{Key: "base_url", Label: "Base URL (optional)", Placeholder: "https://api.openai.com/v1", Type: FieldURL},
			},
		}, true
	case ProviderGoogle:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "Google Gemini",
			DocsURL:     "https://ai.google.dev/",
			Credentials: []CredentialField{
				{Key: "api_key", Label: "Google API Key", Required: true, Secret: true, Type: FieldPassword},
			},
		}, true
	case ProviderOllama:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "Ollama",
			DocsURL:     "https://ollama.com/",
			SelfHosted:  true,
			Credentials: []CredentialField{
				{Key: "base_url", Label: "Server URL", Placeholder: "http://localhost:11434", Help: "Where your Ollama server is reachable.", Type: FieldURL},
			},
		}, true
	case ProviderBedrock:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "AWS Bedrock",
			DocsURL:     "https://docs.aws.amazon.com/bedrock/",
			Credentials: BedrockCredentialSchema(),
		}, true
	case ProviderVertex:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "Google Vertex (Claude)",
			DocsURL:     "https://cloud.google.com/vertex-ai/generative-ai/docs/partner-models/claude",
			Credentials: VertexCredentialSchema(),
		}, true
	case ProviderFoundry:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "Microsoft Foundry (Claude)",
			DocsURL:     "https://learn.microsoft.com/azure/ai-foundry/",
			Credentials: FoundryCredentialSchema(),
		}, true
	case ProviderCloudflare:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "Cloudflare Workers AI",
			DocsURL:     "https://developers.cloudflare.com/workers-ai/",
			Credentials: CloudflareCredentialSchema(),
		}, true
	case ProviderCohere:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "Cohere",
			DocsURL:     "https://docs.cohere.com/",
			Credentials: CohereCredentialSchema(),
		}, true
	case ProviderHuggingFace:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "HuggingFace Inference",
			DocsURL:     "https://huggingface.co/docs/api-inference/",
			Credentials: HuggingFaceCredentialSchema(),
		}, true
	case ProviderLlamafile:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "Llamafile",
			DocsURL:     "https://github.com/Mozilla-Ocho/llamafile",
			SelfHosted:  true,
			Credentials: LlamafileCredentialSchema(),
		}, true
	case ProviderMistral:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "Mistral",
			DocsURL:     "https://docs.mistral.ai/",
			Credentials: MistralCredentialSchema(),
		}, true
	case ProviderVoyage:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "Voyage AI",
			DocsURL:     "https://docs.voyageai.com/",
			Credentials: []CredentialField{
				{Key: "api_key", Label: "Voyage API Key", Required: true, Secret: true, Type: FieldPassword},
			},
		}, true
	case ProviderOpenAICompatible:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "OpenAI-compatible endpoint",
			DocsURL:     "https://platform.openai.com/docs/api-reference/embeddings",
			SelfHosted:  true,
			Credentials: []CredentialField{
				{Key: "base_url", Label: "Endpoint URL", Required: true, Placeholder: "http://embedder:8080", Help: "URL of the OpenAI-compatible /v1/embeddings endpoint.", Type: FieldURL},
				{Key: "api_key", Label: "API Key (optional)", Secret: true, Help: "Leave empty if the endpoint does not require authentication.", Type: FieldPassword},
			},
		}, true
	case ProviderTEI:
		return ProviderDescriptor{
			Type:        t,
			DisplayName: "HuggingFace TEI (native)",
			DocsURL:     "https://huggingface.co/docs/text-embeddings-inference",
			SelfHosted:  true,
			Credentials: []CredentialField{
				{Key: "base_url", Label: "TEI URL", Required: true, Placeholder: "http://tei:8080", Help: "Base URL of the HuggingFace Text-Embeddings-Inference server.", Type: FieldURL},
			},
		}, true
	case ProviderCustom:
		// Custom is intentionally excluded — the descriptor surface is for
		// known providers the dashboard can render a form for.
		return ProviderDescriptor{}, false
	}
	return ProviderDescriptor{}, false
}

// BedrockCredentialSchema is the exported static schema used by the
// introspection RPC so the handler can build its descriptor table without
// instantiating a provider.
func BedrockCredentialSchema() []CredentialField {
	return []CredentialField{
		{Key: "aws_region", Label: "AWS Region", Placeholder: "us-east-1", Help: "Defaults to AWS_REGION env or us-east-1.", Type: FieldRegion},
		{Key: "aws_access_key_id", Label: "AWS Access Key ID", Required: true, Secret: true, Help: "The access key of your own AWS account. The daemon never uses its own AWS credentials.", Type: FieldPassword},
		{Key: "aws_secret_access_key", Label: "AWS Secret Access Key", Required: true, Secret: true, Type: FieldPassword},
		{Key: "aws_session_token", Label: "AWS Session Token", Secret: true, Help: "Only required for temporary credentials.", Type: FieldPassword},
	}
}

func MistralCredentialSchema() []CredentialField {
	return []CredentialField{
		{Key: "api_key", Label: "Mistral API Key", Required: true, Secret: true, Type: FieldPassword},
		{Key: "base_url", Label: "Endpoint (optional)", Placeholder: "https://api.mistral.ai/v1", Type: FieldURL},
	}
}

// VertexCredentialSchema is the form schema for a Google Vertex provider.
func VertexCredentialSchema() []CredentialField {
	return []CredentialField{
		{Key: "vertex_project_id", Label: "Google Cloud Project ID", Required: true, Help: "The project the Vertex models are served from.", Type: FieldText},
		{Key: "vertex_region", Label: "Vertex Region", Required: true, Placeholder: "us-east5", Type: FieldRegion},
		{Key: "google_application_credentials_json", Label: "Service Account JSON", Required: true, Secret: true, Help: "The whole service-account key document. It is written to a file inside the sandbox, never on the daemon.", Type: FieldPassword},
	}
}

// FoundryCredentialSchema is the form schema for a Microsoft Foundry provider.
func FoundryCredentialSchema() []CredentialField {
	return []CredentialField{
		{Key: "foundry_api_key", Label: "Foundry API Key", Required: true, Secret: true, Type: FieldPassword},
		{Key: "foundry_resource", Label: "Foundry Resource Name", Required: true, Help: "The resource that serves the endpoint, e.g. my-resource in my-resource.services.ai.azure.com.", Type: FieldText},
	}
}

func CloudflareCredentialSchema() []CredentialField {
	return []CredentialField{
		{Key: "cloudflare_account_id", Label: "Cloudflare Account ID", Required: true, Secret: true, Placeholder: "ab12...", Type: FieldPassword},
		{Key: "api_key", Label: "Cloudflare API Token", Required: true, Secret: true, Help: "API token with Workers AI permission.", Type: FieldPassword},
		{Key: "base_url", Label: "Server URL (optional)", Placeholder: "https://api.cloudflare.com/client/v4/accounts/<id>/ai/v1", Type: FieldURL},
	}
}

func CohereCredentialSchema() []CredentialField {
	return []CredentialField{
		{Key: "api_key", Label: "Cohere API Key", Required: true, Secret: true, Type: FieldPassword},
		{Key: "base_url", Label: "Base URL (optional)", Placeholder: "https://api.cohere.com/compatibility/v1", Type: FieldURL},
	}
}

func HuggingFaceCredentialSchema() []CredentialField {
	return []CredentialField{
		{Key: "api_key", Label: "HuggingFace API Token", Required: true, Secret: true, Placeholder: "hf_...", Type: FieldPassword},
		{Key: "base_url", Label: "TGI Endpoint (optional)", Placeholder: "https://your-tgi.example/v1", Help: "Leave empty to use the public HuggingFace Inference API.", Type: FieldURL},
	}
}

func LlamafileCredentialSchema() []CredentialField {
	return []CredentialField{
		// Llamafile is self-hosted — no credentials required. The only field
		// we surface is default_model so operators can label their deployment.
	}
}
