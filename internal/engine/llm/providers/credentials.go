// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// resolveCredential returns the credential value for the named field. The tenant
// provider resolver has already populated cfg.APIKey/cfg.Extra from the secrets
// broker (see tenantprovider.decryptedToLLMConfig), so the chain is:
//
//  1. cfg.Extra[extraKey]  (only when extraKey != "")
//  2. cfg.APIKey           (only when extraKey == "" — typed field mode)
//
// There is no third source. The daemon's own environment is never a
// credential: the platform holds no LLM key of its own, and a provider config
// that carries no credential is rejected rather than constructed on whatever
// the pod happens to carry. (The GIBSON_DEV_ENV_FALLBACK escape hatch that
// used to sit here is gone with the platform LLM path, 2026-09-10.)
//
// If required is true and both sources are empty, resolveCredential returns an
// llm.AuthError naming the missing field so operators can diagnose the
// misconfiguration without the provider making a network call. Callers MUST
// pass the provider name exactly as the provider's Name() method reports, so
// error strings line up with log/trace attributes.
//
// SECURITY: never log the returned value.
func resolveCredential(
	cfg llm.ProviderConfig,
	provider string,
	extraKey string,
	required bool,
) (string, error) {
	if extraKey != "" {
		if v := cfg.Extra[extraKey]; v != "" {
			return v, nil
		}
	} else if cfg.APIKey != "" {
		return cfg.APIKey, nil
	}

	if !required {
		return "", nil
	}

	return "", fmt.Errorf("resolve %s credential: %w",
		provider, llm.NewAuthError(provider, fmt.Errorf("missing credential: %s", describeCredentialSource(extraKey))))
}

// describeCredentialSource builds a human-readable pointer to where the
// missing credential comes from: the tenant's provider configuration, which
// the resolver hands over as cfg.Extra (typed fields) or cfg.APIKey.
func describeCredentialSource(extraKey string) string {
	if extraKey != "" {
		return fmt.Sprintf("set cfg.Extra[%q] in the tenant's provider configuration", extraKey)
	}
	return "set cfg.APIKey in the tenant's provider configuration"
}
