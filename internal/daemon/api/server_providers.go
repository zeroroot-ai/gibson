package api

import (
	"context"

	"github.com/zero-day-ai/gibson/internal/llm/providers"
)

// GetSupportedProviders returns the full list of LLM provider types the
// daemon can construct with their credential schemas and default model
// catalogues, so the dashboard can render its Settings > Providers form
// without a hard-coded provider list.
//
// Authorisation: enforced by the FGA interceptor via the RPC registry.
// This RPC is read-only, touches no network, and returns in microseconds —
// the descriptor table is built at process init from static provider
// metadata (see internal/llm/providers/descriptors.go).
func (s *DaemonServer) GetSupportedProviders(_ context.Context, _ *GetSupportedProvidersRequest) (*GetSupportedProvidersResponse, error) {
	descs := providers.SupportedProviderDescriptors()
	out := make([]*ProviderDescriptor, 0, len(descs))
	for _, d := range descs {
		out = append(out, toProtoProviderDescriptor(d))
	}
	return &GetSupportedProvidersResponse{Providers: out}, nil
}

// toProtoProviderDescriptor converts the internal Go descriptor to the
// generated proto message. The shape matches 1:1 — this is boilerplate.
func toProtoProviderDescriptor(d providers.ProviderDescriptor) *ProviderDescriptor {
	creds := make([]*CredentialField, 0, len(d.Credentials))
	for _, f := range d.Credentials {
		creds = append(creds, &CredentialField{
			Key:         f.Key,
			Label:       f.Label,
			Required:    f.Required,
			Secret:      f.Secret,
			Placeholder: f.Placeholder,
			Help:        f.Help,
		})
	}
	models := make([]*ModelDescriptor, 0, len(d.DefaultModels))
	for _, m := range d.DefaultModels {
		models = append(models, &ModelDescriptor{
			Name:          m.Name,
			ContextWindow: int32(m.ContextWindow),
			MaxOutput:     int32(m.MaxOutput),
			Features:      append([]string(nil), m.Features...),
		})
	}
	return &ProviderDescriptor{
		Type:          string(d.Type),
		DisplayName:   d.DisplayName,
		DocsUrl:       d.DocsURL,
		SelfHosted:    d.SelfHosted,
		Credentials:   creds,
		DefaultModels: models,
	}
}
