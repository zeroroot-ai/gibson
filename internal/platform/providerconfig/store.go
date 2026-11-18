// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providerconfig

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
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
	// if the provider type is not in SupportedProviderTypes().
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

// ErrInvalidName is returned when the name of a provider record is not a valid
// Kubernetes name. The tenant operator uses the name in the name of a
// ModelProvider and of the objects that it renders, and in labels.
var ErrInvalidName = errors.New("invalid provider name")

// validateName refuses a name that is not a DNS-1123 label: lower case letters,
// digits and '-', start and end with a letter or digit, 63 characters at most.
func validateName(name string) error {
	if errs := validation.IsDNS1123Label(name); len(errs) > 0 {
		return fmt.Errorf("%w: %q must be a valid Kubernetes name (%s)", ErrInvalidName, name, strings.Join(errs, "; "))
	}
	return nil
}

func validateType(t ProviderType) error {
	for _, supported := range SupportedProviderTypes() {
		if t == supported {
			return nil
		}
	}
	return fmt.Errorf("%w: %q (supported: %s)", ErrUnsupportedType, t, joinTypes(SupportedProviderTypes()))
}

// checkCredentials validates the credential fields that carry more than a
// secret. The field custom_headers belongs to the anthropic type only, and its
// value must pass the allowlist. It returns a copy of the input that holds the
// value in its canonical form, so the store and the sandbox that reads it hold
// a checked value and nothing else.
func checkCredentials(input *ProviderConfigInput) (*ProviderConfigInput, error) {
	raw, present := input.Credentials[CustomHeadersKey]
	if !present {
		return input, nil
	}
	if input.Type != ProviderAnthropic {
		return nil, fmt.Errorf("%w: the field %s is for the anthropic type only", ErrInvalidCredentials, CustomHeadersKey)
	}
	canonical, err := CanonicalCustomHeaders(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCredentials, err)
	}
	out := *input
	out.Credentials = make(map[string]string, len(input.Credentials))
	for k, v := range input.Credentials {
		out.Credentials[k] = v
	}
	if canonical == "" {
		delete(out.Credentials, CustomHeadersKey)
	} else {
		out.Credentials[CustomHeadersKey] = canonical
	}
	return &out, nil
}

func joinTypes(types []ProviderType) string {
	ss := make([]string, len(types))
	for i, t := range types {
		ss[i] = string(t)
	}
	return strings.Join(ss, ", ")
}
