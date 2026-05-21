package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/secrets"
	sdksecrets "github.com/zero-day-ai/platform-clients/secrets"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// resolveCredential returns the credential value for the named field using the
// following priority chain:
//
//  1. Broker-first: if service is non-nil, call
//     service.Resolve(ctx, "provider_config:"+provider+":"+name)
//     where name is extraKey (or "api_key" when extraKey is "").
//     On success, unmarshal the returned JSON blob and extract the value.
//     On ErrNotFound, continue to the next source.
//
//  2. cfg.Extra[extraKey]  (only when extraKey != "")
//
//  3. cfg.APIKey           (only when extraKey == "" — typed field mode)
//
//  4. os.Getenv(envVar)    (only when envVar != "" AND GIBSON_DEV_ENV_FALLBACK is "true").
//     Env-var fallback is intentionally disabled in production — the broker is the
//     authoritative source. Set GIBSON_DEV_ENV_FALLBACK=true in dev/Kind overlays
//     only; this value is never set in production Helm charts.
//
// If required is true and all sources are empty, resolveCredential returns an
// llm.AuthError naming the missing field and env var so operators can diagnose
// the misconfiguration without the provider making a network call.
//
// Callers MUST pass the provider name exactly as the provider's Name() method
// reports, so error strings line up with log/trace attributes.
//
// SECURITY: never log the returned value.
//
// Phase 10 (secrets-broker, Task 28): broker-first lookup added. The previous
// cfg.Extra / cfg.APIKey / env chain is preserved as the fallback.
// Per-provider in-process credential caches should be invalidated on
// secret_rotated events whose name starts with "provider_config:" — the
// rotation subscription is wired in Task 29 (Phase 11).
func resolveCredential(
	ctx context.Context,
	service *secrets.Service,
	cfg llm.ProviderConfig,
	provider string,
	extraKey string,
	envVar string,
	required bool,
) (string, error) {
	// Determine the broker key name: use extraKey if set, otherwise "api_key".
	brokerField := extraKey
	if brokerField == "" {
		brokerField = "api_key"
	}
	brokerKey := "provider_config:" + provider + ":" + brokerField

	// 1. Broker-first lookup.
	if service != nil {
		brokerVal, brokerErr := service.Resolve(ctx, brokerKey)
		if brokerErr == nil && len(brokerVal) > 0 {
			// The broker returns an opaque byte slice. Attempt JSON unmarshal
			// assuming the value is a JSON string or a JSON object with a
			// "value" or "api_key" field. If it's a plain string, use it
			// directly.
			if extracted := extractCredentialFromJSON(brokerVal, brokerField); extracted != "" {
				return extracted, nil
			}
			// Fallback: treat raw bytes as the credential value.
			return string(brokerVal), nil
		}
		// Only continue on not-found; surface other errors.
		if brokerErr != nil && !isBrokerNotFound(brokerErr) {
			return "", llm.NewAuthError(provider, fmt.Errorf("broker credential lookup for %q: %w", brokerKey, brokerErr))
		}
		// ErrNotFound or ErrUnsupported: fall through to local sources.
	}

	// 2. cfg.Extra[extraKey] or cfg.APIKey.
	if extraKey != "" {
		if v := cfg.Extra[extraKey]; v != "" {
			return v, nil
		}
	} else if cfg.APIKey != "" {
		return cfg.APIKey, nil
	}

	// 3. Environment-variable fallback — only in dev overlays.
	if envVar != "" && devEnvFallbackEnabled() {
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

// isBrokerNotFound reports whether err represents a "not found" response from
// secrets.Service (i.e., the credential does not exist in the broker — not an
// infrastructure failure).
func isBrokerNotFound(err error) bool {
	if err == nil {
		return false
	}
	if st, ok := status.FromError(err); ok {
		return st.Code() == codes.NotFound
	}
	// Check for wrapped sentinel errors from the SDK.
	for e := err; e != nil; {
		if e == sdksecrets.ErrNotFound {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		if u, ok := e.(unwrapper); ok {
			e = u.Unwrap()
		} else {
			break
		}
	}
	return false
}

// providerConfigBlob is the JSON shape stored in the broker under
// "provider_config:{provider}:{field}" keys. The "value" field holds the
// credential plaintext. This struct is used only for deserialization;
// it is never logged or serialized back.
type providerConfigBlob struct {
	Value  string `json:"value"`
	APIKey string `json:"api_key"`
}

// extractCredentialFromJSON attempts to extract a credential value from raw
// broker bytes. It first tries to unmarshal the bytes as a providerConfigBlob
// (JSON object with "value" or "api_key" field); if that fails or yields an
// empty string, it returns "" to signal the caller should use raw bytes.
// SECURITY: never log the extracted value.
func extractCredentialFromJSON(raw []byte, preferField string) string {
	var blob providerConfigBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		return "" // not JSON; caller uses raw bytes directly
	}
	if preferField == "api_key" || preferField == "" {
		if blob.APIKey != "" {
			return blob.APIKey
		}
	}
	return blob.Value
}
