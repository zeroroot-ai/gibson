// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providerconfig

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
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

	// Third-party inference routes for Anthropic's models (ADR-0119).
	// The Claude Code terms name exactly these three as the
	// permitted 3P credentials, so they are provider types a tenant
	// configures, not options on the anthropic provider: each carries its own
	// credential set and the launcher injects a different variable block for
	// each. ProviderBedrock above is the first of the three.

	// ProviderVertex is Anthropic's models on Google Vertex.
	ProviderVertex ProviderType = "vertex"
	// ProviderFoundry is Anthropic's models on Microsoft Foundry.
	ProviderFoundry ProviderType = "foundry"

	// Embedding-only provider types (E11 BYO-embedder, ADR-0059).
	// These types are valid for ProviderConfigInput when the CAPABILITY_EMBEDDING
	// capability is declared; they cannot serve chat completions and
	// providers.NewProvider returns ErrEmbeddingOnlyProvider for them.

	// ProviderVoyage is the Voyage AI embeddings API.
	ProviderVoyage ProviderType = "voyage"
	// ProviderOpenAICompatible is a generic OpenAI-compatible /v1/embeddings
	// endpoint — e.g. a self-hosted TEI server in OpenAI-compat mode.
	ProviderOpenAICompatible ProviderType = "openai-compatible"
	// ProviderTEI is HuggingFace Text-Embeddings-Inference's native /embed
	// endpoint (non-OpenAI-compatible mode).
	ProviderTEI ProviderType = "tei"
)

// SupportedProviderTypes returns every ProviderType the platform supports,
// in a deterministic order. This is the single source of truth for the factory
// switch, config validator, and the GetSupportedProviders introspection RPC.
//
// Chat-capable providers (anthropic, openai, google, …) can be constructed via
// providers.NewProvider. Embedding-only providers (voyage, openai-compatible,
// tei) are valid in ProviderConfigInput when CAPABILITY_EMBEDDING is declared
// but return ErrEmbeddingOnlyProvider from providers.NewProvider — they are
// consumed via the embedder.NewFromProvider path instead.
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
		ProviderVertex,
		ProviderFoundry,
		ProviderCustom,
		// Embedding-only (E11 BYO-embedder):
		ProviderVoyage,
		ProviderOpenAICompatible,
		ProviderTEI,
	}
}

// selfHostedProviderTypes lists providers that do not require an API key at
// construction time (the endpoint is operator-controlled).
var selfHostedProviderTypes = map[ProviderType]bool{
	ProviderOllama:           true,
	ProviderLlamafile:        true,
	ProviderOpenAICompatible: true,
	ProviderTEI:              true,
}

// IsSelfHosted reports whether the provider runs on operator-controlled
// infrastructure and therefore does not require an API key at config time.
func (p ProviderType) IsSelfHosted() bool {
	return selfHostedProviderTypes[p]
}

// CredentialField describes a single credential input for a provider type.
// Providers expose a slice of these via CredentialSchema() so the daemon's
// GetSupportedProviders RPC can hand the dashboard a machine-readable form
// spec — no hard-coded frontend dropdowns, no drift between daemon and UI.
type CredentialField struct {
	// Key is the cfg.Extra map key the resolver will read. For the canonical
	// fields APIKey and BaseURL, use "api_key" / "base_url" — the daemon
	// handler maps those back to the typed ProviderConfig fields.
	Key string

	// Label is the human-facing form label.
	Label string

	// Required flags the field as mandatory for successful construction.
	Required bool

	// Secret tells the dashboard to render a password input and mask in logs.
	Secret bool

	// Placeholder is an example value shown in the empty input.
	Placeholder string

	// Help is a short description rendered beneath the field.
	Help string

	// Type is the input kind of the field (gibson#701). Each field sets one;
	// TestEveryCredentialFieldHasAType fails on a field with none.
	Type CredentialFieldType
}

// CredentialFieldType is the input kind of a credential field. The daemon
// maps it to the CredentialFieldType enum of the provider proto, so the
// dashboard builds its form from it.
type CredentialFieldType string

// The input kinds of a credential field.
const (
	FieldText     CredentialFieldType = "text"
	FieldPassword CredentialFieldType = "password"
	FieldURL      CredentialFieldType = "url"
	FieldRegion   CredentialFieldType = "region"
	FieldBool     CredentialFieldType = "bool"
)

// CustomHeadersKey is the credential field of an Anthropic provider that
// carries extra request headers. The format is the one of the variable
// ANTHROPIC_CUSTOM_HEADERS of Claude Code: one "Name: Value" pair on each line.
// The daemon client and the sandbox variable read this one field.
const CustomHeadersKey = "custom_headers"

// WorkspaceHeader is the one header that the field may carry. An organization
// user key works only with it.
const WorkspaceHeader = "anthropic-workspace-id"

// ErrInvalidCustomHeaders is returned for a value that is not on the allowlist.
// The message never holds the value.
var ErrInvalidCustomHeaders = errors.New("invalid custom_headers")

var workspaceIDPattern = regexp.MustCompile(`^wrkspc_[A-Za-z0-9]{1,64}$`)

// ParseCustomHeaders reads and checks the value of the field. It accepts the
// header anthropic-workspace-id only, once, with a value of the form
// wrkspc_<letters and digits>. Any other name, a repeated name, a line with no
// colon and any other value shape is refused.
func ParseCustomHeaders(raw string) (http.Header, error) {
	h := http.Header{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || name == "" {
			return nil, fmt.Errorf("%w: each line must be \"Name: Value\"", ErrInvalidCustomHeaders)
		}
		if !strings.EqualFold(name, WorkspaceHeader) {
			return nil, fmt.Errorf("%w: only the header %s is accepted", ErrInvalidCustomHeaders, WorkspaceHeader)
		}
		if !workspaceIDPattern.MatchString(value) {
			return nil, fmt.Errorf("%w: the value of %s must look like wrkspc_ followed by letters and digits", ErrInvalidCustomHeaders, WorkspaceHeader)
		}
		if h.Get(WorkspaceHeader) != "" {
			return nil, fmt.Errorf("%w: the header %s is given twice", ErrInvalidCustomHeaders, WorkspaceHeader)
		}
		h.Set(WorkspaceHeader, value)
	}
	return h, nil
}

// CanonicalCustomHeaders checks the value and returns it in one fixed form, so
// the stored value, and the sandbox that reads it, hold nothing but the checked
// header. An empty value returns an empty value.
func CanonicalCustomHeaders(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	h, err := ParseCustomHeaders(raw)
	if err != nil {
		return "", err
	}
	if id := h.Get(WorkspaceHeader); id != "" {
		return WorkspaceHeader + ": " + id, nil
	}
	return "", nil
}
