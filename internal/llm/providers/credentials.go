package providers

import (
	"fmt"
	"os"

	"github.com/zero-day-ai/gibson/internal/llm"
)

// resolveCredential returns the first non-empty value found in this order:
//
//  1. cfg.Extra[extraKey]  (only when extraKey != "")
//  2. cfg.APIKey           (only when extraKey == "" — typed field mode)
//  3. os.Getenv(envVar)    (only when envVar != "")
//
// If required is true and all sources are empty, resolveCredential returns
// an llm.AuthError naming the missing field and env var so operators can
// diagnose the misconfiguration without the provider making a network call.
//
// Callers MUST pass the provider name exactly as the provider's Name() method
// reports, so error strings line up with log/trace attributes.
func resolveCredential(
	cfg llm.ProviderConfig,
	provider string,
	extraKey string,
	envVar string,
	required bool,
) (string, error) {
	if extraKey != "" {
		if v := cfg.Extra[extraKey]; v != "" {
			return v, nil
		}
	} else if cfg.APIKey != "" {
		return cfg.APIKey, nil
	}
	if envVar != "" {
		if v := os.Getenv(envVar); v != "" {
			return v, nil
		}
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

		// ERNIE
		"ernie_access_key",
		"ernie_secret_key",

		// HuggingFace
		"huggingface_api_token",

		// WatsonX
		"watsonx_api_key",
		"watsonx_project_id",

		// Mistral / Cohere / Maritaca share the generic api_key field but also
		// expose typed env-var-equivalent keys in case operators want to store
		// them in cfg.Extra alongside multi-provider configs.
		"mistral_api_key",
		"cohere_api_key",
		"maritaca_api_key",
	}
}
