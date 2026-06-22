// Package providerconfig is the daemon's single source of truth for
// tenant-configured LLM providers. Credentials are encrypted at rest via the
// crypto.AESGCMEncryptor + crypto.KeyProvider pipeline (the same primitive that
// protects plugin credentials). Reads return masked credential values via
// AsRecord; Resolve returns the decrypted credential for the
// ExecuteLLM/StreamLLM execution path only.
package providerconfig

import (
	"errors"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Sentinel errors returned by ProviderConfigStore.
var (
	// ErrNotFound is returned when a provider config with the given name does not exist.
	ErrNotFound = errors.New("provider config not found")

	// ErrAlreadyExists is returned when creating a provider config whose name
	// is already in use within the same tenant.
	ErrAlreadyExists = errors.New("provider config already exists")

	// ErrUnsupportedType is returned when the requested ProviderType is not in
	// llm.SupportedProviderTypes().
	ErrUnsupportedType = errors.New("unsupported provider type")

	// ErrKeyProviderUnset is returned by NewStore when kp is nil, and returned
	// by write operations at runtime when no KeyProvider was configured.
	ErrKeyProviderUnset = errors.New("key provider is not configured — set security.key_provider in gibson.yaml")
)

// ProviderConfig is the read-side representation of a provider configuration.
// Credentials are always masked in this struct; use DecryptedConfig (via Resolve)
// for the execution path.
type ProviderConfig struct {
	ID           types.ID
	TenantID     string
	Name         string
	Type         llm.ProviderType
	DefaultModel string
	IsDefault    bool
	Enabled      bool
	// CredentialsMasked is the credential map with values masked as "****<last4>"
	// (or "****" for values shorter than 8 characters). Computed at read time,
	// never stored. Empty string values are passed through as empty strings.
	CredentialsMasked map[string]string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// DecryptedConfig embeds ProviderConfig and adds the plaintext credential map.
// This type is for the execution path only (ExecuteLLM / StreamLLM).
//
// SECURITY CONTRACT: callers MUST NOT log, persist, or cache the Credentials
// map or any value within it. The decrypted credential lives in daemon process
// memory for the duration of a single handler invocation only.
type DecryptedConfig struct {
	ProviderConfig
	Credentials map[string]string // plaintext — execution-path only
}

// ProviderConfigInput is the write-side representation used for Create and Update.
// Credentials are plaintext on the way in; the store encrypts immediately before
// persisting to Redis.
type ProviderConfigInput struct {
	Name         string
	Type         llm.ProviderType
	DefaultModel string
	Credentials  map[string]string // plaintext — encrypted before storage
	SetAsDefault bool
	Enabled      bool
}

// AsRecord computes the masked credential map for cfg and returns a copy of cfg
// with CredentialsMasked populated. The mask format is:
//   - Empty string → empty string (no masking)
//   - Value with len < 8 → "****" (fully masked)
//   - Value with len >= 8 → "****" + last 4 characters
//
// Masking is deterministic per-value so the dashboard can detect "no change"
// across update forms by comparing masked values.
func AsRecord(cfg *ProviderConfig, plainCredentials map[string]string) *ProviderConfig {
	copy := *cfg
	masked := make(map[string]string, len(plainCredentials))
	for k, v := range plainCredentials {
		masked[k] = maskCredential(v)
	}
	copy.CredentialsMasked = masked
	return &copy
}

// maskCredential applies the platform masking policy to a single credential value.
func maskCredential(v string) string {
	if v == "" {
		return ""
	}
	if len(v) < 8 {
		return "****"
	}
	return "****" + v[len(v)-4:]
}
