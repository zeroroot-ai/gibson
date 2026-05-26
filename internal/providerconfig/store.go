package providerconfig

import (
	"context"
	"fmt"
	"strings"

	"github.com/zero-day-ai/gibson/internal/llm"
)

// ProviderConfigStore is the daemon's single source of truth for
// tenant-configured LLM providers. Credentials flow through the secrets broker;
// reads return masked values via AsRecord; Resolve returns the decrypted
// credential for the ExecuteLLM/StreamLLM execution path only.
type ProviderConfigStore interface {
	// List returns all provider configs for the given tenant, with credentials masked.
	List(ctx context.Context, tenantID string) ([]*ProviderConfig, error)

	// Get returns the named provider config for the given tenant, with credentials masked.
	Get(ctx context.Context, tenantID string, name string) (*ProviderConfig, error)

	// Create persists a new provider config. Returns ErrAlreadyExists if a config
	// with the same name already exists for this tenant. Returns ErrUnsupportedType
	// if the provider type is not in llm.SupportedProviderTypes().
	Create(ctx context.Context, tenantID string, input *ProviderConfigInput) (*ProviderConfig, error)

	// Update replaces the named provider config. Returns ErrNotFound if no config
	// with that name exists for the tenant.
	Update(ctx context.Context, tenantID string, name string, input *ProviderConfigInput) (*ProviderConfig, error)

	// Delete removes the named provider config. Returns ErrNotFound if it does not exist.
	Delete(ctx context.Context, tenantID string, name string) error

	// GetDefault returns the provider config marked as default for the tenant.
	// Returns ErrNotFound if no default has been set.
	GetDefault(ctx context.Context, tenantID string) (*ProviderConfig, error)

	// SetDefault marks the named provider as the tenant's default. Returns ErrNotFound
	// if no provider with that name exists for the tenant.
	SetDefault(ctx context.Context, tenantID string, name string) error

	// Resolve returns the decrypted config for the execution path.
	//
	// SECURITY CONTRACT: Caller MUST NOT log or persist the returned Credentials
	// map. The decrypted credential must not escape the calling handler's stack frame.
	Resolve(ctx context.Context, tenantID string, name string) (*DecryptedConfig, error)
}

func validateType(t llm.ProviderType) error {
	for _, supported := range llm.SupportedProviderTypes() {
		if t == supported {
			return nil
		}
	}
	return fmt.Errorf("%w: %q (supported: %s)", ErrUnsupportedType, t, joinTypes(llm.SupportedProviderTypes()))
}

func joinTypes(types []llm.ProviderType) string {
	ss := make([]string, len(types))
	for i, t := range types {
		ss[i] = string(t)
	}
	return strings.Join(ss, ", ")
}
