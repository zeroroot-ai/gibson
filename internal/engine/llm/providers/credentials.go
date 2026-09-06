// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"fmt"
	"os"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// resolveCredential returns the credential value for the named field. The tenant
// provider resolver has already populated cfg.APIKey/cfg.Extra from the secrets
// broker (see tenantprovider.decryptedToLLMConfig), so the chain is:
//
//  1. cfg.Extra[extraKey]  (only when extraKey != "")
//  2. cfg.APIKey           (only when extraKey == "" — typed field mode)
//  3. os.Getenv(envVar)    (only when envVar != "" AND GIBSON_DEV_ENV_FALLBACK is
//     "true"; a dev/Kind-only escape hatch, never set in production Helm charts).
//
// If required is true and all sources are empty, resolveCredential returns an
// llm.AuthError naming the missing field and env var so operators can diagnose
// the misconfiguration without the provider making a network call. Callers MUST
// pass the provider name exactly as the provider's Name() method reports, so
// error strings line up with log/trace attributes.
//
// SECURITY: never log the returned value.
func resolveCredential(
	cfg llm.ProviderConfig,
	provider string,
	extraKey string,
	envVar string,
	required bool,
) (string, error) {
	// 1. cfg.Extra[extraKey] or cfg.APIKey.
	if extraKey != "" {
		if v := cfg.Extra[extraKey]; v != "" {
			return v, nil
		}
	} else if cfg.APIKey != "" {
		return cfg.APIKey, nil
	}

	// 2. Environment-variable fallback — only in dev overlays.
	if v := devEnvCredential(envVar); v != "" {
		return v, nil
	}

	if !required {
		return "", nil
	}
	hint := describeCredentialSource(extraKey, envVar)
	return "", llm.NewAuthError(provider, fmt.Errorf("missing credential: %s", hint))
}

// describeCredentialSource builds a human-readable pointer to where the
// missing credential could come from.
func describeCredentialSource(extraKey, envVar string) string {
	switch {
	case extraKey != "" && envVar != "":
		return fmt.Sprintf("set cfg.Extra[%q] or env %s", extraKey, envVar)
	case extraKey != "":
		return fmt.Sprintf("set cfg.Extra[%q]", extraKey)
	case envVar != "":
		return fmt.Sprintf("set cfg.APIKey or env %s", envVar)
	default:
		return "set cfg.APIKey"
	}
}

// redactCredentialKeys returns the canonical list of cfg.Extra keys carrying
// provider credentials. The observability layer consumes this to populate
// its log-attribute redaction allowlist so no credential ever appears in a
// structured log line. Keep this list in sync with every provider's
// CredentialSchema().
func redactCredentialKeys() []string {
	return []string{
		// Generic
		"api_key",
		"base_url", // not a secret, but we redact to be conservative in logs

		// AWS Bedrock
		"aws_access_key_id",
		"aws_secret_access_key",
		"aws_session_token",
		"aws_region",

		// Cloudflare Workers AI
		"cloudflare_account_id",
		"cloudflare_api_token",

		// HuggingFace
		"huggingface_api_token",

		// Mistral / Cohere share the generic api_key field but also expose typed
		// env-var-equivalent keys in case operators want to store them in
		// cfg.Extra alongside multi-provider configs.
		"mistral_api_key",
		"cohere_api_key",
	}
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// devEnvFallbackEnabled returns true when the GIBSON_DEV_ENV_FALLBACK environment
// variable is set to "true". This flag is intended for dev/Kind overlays only —
// NEVER set in production. When disabled, env-var credential fallback is skipped
// and the broker is the authoritative source.
func devEnvFallbackEnabled() bool {
	return os.Getenv("GIBSON_DEV_ENV_FALLBACK") == "true"
}

// devEnvCredential returns the value of envVar, but only when the dev env-var
// fallback is explicitly enabled. It returns "" for an empty envVar or whenever
// the gate is off.
//
// This is the ONLY sanctioned way for a provider constructor to read a
// credential from the daemon's own environment. Reading os.Getenv directly
// would let a tenant provider row that carries no credential of its own
// construct successfully on the daemon's ambient key and then register as if
// the credential were the tenant's — a silent substitution with no error and
// no log. Every provider constructor must route env-var credential lookups
// through here so the gate cannot be bypassed.
//
// Non-credential environment inputs (for example AWS_REGION) are not covered
// by this gate and may be read directly.
//
// SECURITY: never log the returned value.
func devEnvCredential(envVar string) string {
	if envVar == "" || !devEnvFallbackEnabled() {
		return ""
	}
	return os.Getenv(envVar)
}
