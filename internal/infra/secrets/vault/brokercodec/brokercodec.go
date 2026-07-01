// Package brokercodec is the single source of truth for mapping a tenant's
// broker configuration onto the Vault provider's on-disk config blob.
//
// Two callers persist per-tenant broker config rows into the platform
// `tenant_secrets_broker_config` table, and the daemon deserialises them at
// per-tenant provider construction time:
//
//   - the daemon's TenantAdminService (SetBrokerConfig / ProbeBrokerConfig),
//     which maps a dashboard-supplied wire CandidateConfig, and
//   - the tenant-operator's provisioning saga (WriteTenantBrokerConfig),
//     which maps its operator-side configuration.
//
// Before this package existed the two callers hand-rolled divergent JSON:
// the daemon emitted flat keys (`namespace_or_path`, `mount`, `auth_method`,
// flat `vault_token`), while the provider config (`vault.Config`) expects
// `namespace` / `path_prefix` / `kv_mount` and a NESTED `auth{...}` object.
// BYO Vault therefore deserialised with an empty auth block and failed to
// probe (H2 — gibson#1105, same class as tenant-operator#144). Routing both
// callers through Encode here guarantees byte-identical blobs for the same
// logical config, so the writer/reader shapes can never drift again.
//
// The blob this package emits is exactly `json.Marshal(vault.Config)`; the
// daemon's VaultFactory unmarshals the same shape back into a vault.Config.
package brokercodec

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets/vault"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ProviderName is the secrets.Registry factory name both Vault modes resolve
// to. Hosted vs BYO is not a distinct backend factory — it is a vault.Config
// distinction (namespace mode vs path-prefix mode). The broker-config row's
// provider column carries this string for either mode.
const ProviderName = "vault"

// DefaultPathPrefix returns the tenant-scoped default KV path prefix used for
// BYO (path-prefix) mode when the caller supplies none. OSS Vault / OpenBao
// CE has no namespaces, so tenant isolation on a customer's own Vault comes
// from this prefix. The value matches vault.Provider.kvPath's path-prefix
// layout ("tenant/<tenant_id>/<name>").
func DefaultPathPrefix(tenant auth.TenantID) string {
	return "tenant/" + tenant.String()
}

// Fields is the mode-independent logical broker configuration both callers
// supply. It is the single definition of how a tenant broker config maps
// onto vault.Config's field names and nested auth shape.
type Fields struct {
	// Hosted selects namespace mode (true — the platform-managed OpenBao
	// broker) vs path-prefix / BYO mode (false — a customer's own Vault).
	Hosted bool

	// Address is the Vault server URL. Required for BYO; for Hosted the
	// daemon supplies the platform address, so it may be empty here.
	Address string

	// NamespaceOrPath is the tenant namespace (Hosted) or the KV path prefix
	// (BYO). In BYO mode an empty value defaults to DefaultPathPrefix(Tenant).
	NamespaceOrPath string

	// KVMount is the KV v2 mount path. Empty defers to vault.Config's default.
	KVMount string

	// Auth is the nested authentication configuration.
	Auth vault.AuthConfig

	// Tenant scopes the BYO default path prefix. Required in BYO mode when
	// NamespaceOrPath is empty; ignored in Hosted mode.
	Tenant auth.TenantID
}

// VaultConfig projects the logical Fields onto the concrete vault.Config the
// provider factory consumes. It is the one place mode → (namespace |
// path_prefix) is decided.
func (f Fields) VaultConfig() vault.Config {
	cfg := vault.Config{
		Address: f.Address,
		KVMount: f.KVMount,
		Auth:    f.Auth,
	}
	if f.Hosted {
		// Namespace mode: isolation is the per-tenant Vault namespace.
		cfg.Namespace = f.NamespaceOrPath
		return cfg
	}
	// Path-prefix mode (BYO): isolation is a per-tenant KV path prefix.
	prefix := f.NamespaceOrPath
	if prefix == "" {
		prefix = DefaultPathPrefix(f.Tenant)
	}
	cfg.PathPrefix = prefix
	return cfg
}

// Encode is the canonical blob encoder shared by the daemon and the operator.
// It returns the registry provider name and the JSON blob to persist.
func Encode(f Fields) (provider string, blob []byte, err error) {
	b, err := json.Marshal(f.VaultConfig())
	if err != nil {
		return "", nil, fmt.Errorf("brokercodec: marshal vault config: %w", err)
	}
	return ProviderName, b, nil
}

// Decode parses a persisted blob back into a vault.Config. An empty blob
// yields a zero Config (not an error) so callers can treat "no row" and
// "empty row" uniformly.
func Decode(blob []byte) (vault.Config, error) {
	var cfg vault.Config
	if len(blob) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(blob, &cfg); err != nil {
		return vault.Config{}, fmt.Errorf("brokercodec: config blob not valid JSON: %w", err)
	}
	return cfg, nil
}

// EncodeCandidate maps a dashboard-supplied wire CandidateConfig onto the
// canonical vault.Config blob. tenant is used to derive the BYO default path
// prefix when the candidate supplies none.
func EncodeCandidate(c *tenantv1.CandidateConfig, tenant auth.TenantID) (provider string, blob []byte, err error) {
	f, err := fieldsFromCandidate(c, tenant)
	if err != nil {
		return "", nil, err
	}
	return Encode(f)
}

// fieldsFromCandidate maps the wire CandidateConfig field-by-field onto the
// logical Fields, translating the proto's flat auth fields into the nested
// vault.AuthConfig shape. The candidate carries only token / AppRole auth
// (the two methods the dashboard offers); JWT / role auth is operator-side.
func fieldsFromCandidate(c *tenantv1.CandidateConfig, tenant auth.TenantID) (Fields, error) {
	if c == nil {
		return Fields{}, errors.New("brokercodec: nil candidate")
	}
	hosted, err := providerIsHosted(c.GetProvider())
	if err != nil {
		return Fields{}, err
	}
	return Fields{
		Hosted:          hosted,
		Address:         c.GetAddress(),
		NamespaceOrPath: c.GetNamespaceOrPath(),
		KVMount:         c.GetMount(),
		Auth: vault.AuthConfig{
			Method:          vault.AuthMethod(c.GetAuthMethod()),
			Token:           string(c.GetVaultToken()),
			AppRoleID:       c.GetApproleRoleId(),
			AppRoleSecretID: string(c.GetApproleSecretId()),
		},
		Tenant: tenant,
	}, nil
}

// providerIsHosted maps the proto enum to a mode. Only the two Vault variants
// are supported; every other value (UNSPECIFIED, the reserved retired
// backends) is rejected.
func providerIsHosted(p tenantv1.BrokerProvider) (bool, error) {
	switch p {
	case tenantv1.BrokerProvider_BROKER_PROVIDER_VAULT_HOSTED:
		return true, nil
	case tenantv1.BrokerProvider_BROKER_PROVIDER_VAULT_BYO:
		return false, nil
	case tenantv1.BrokerProvider_BROKER_PROVIDER_UNSPECIFIED:
		return false, errors.New("brokercodec: broker provider is unspecified")
	default:
		return false, fmt.Errorf("brokercodec: unsupported broker provider %v", p)
	}
}

// sensitiveAuthKeys are the wire-facing names of sensitive fields the
// dashboard renders "(configured)" placeholders for. They are never returned
// by value — Redact only reports their presence.
const (
	sensitiveVaultToken      = "vault_token"
	sensitiveAppRoleSecretID = "approle_secret_id"
)

// Redact parses a persisted vault.Config blob and produces the dashboard-safe
// RedactedConfig. Sensitive auth material is NEVER included; only its presence
// is reported via sensitive_fields_set. The active mode (Hosted vs BYO) is
// derived from the blob shape: a path_prefix (with no namespace) is BYO;
// anything else is Hosted.
func Redact(blob []byte) (*tenantv1.RedactedConfig, error) {
	cfg, err := Decode(blob)
	if err != nil {
		return nil, err
	}

	provider := tenantv1.BrokerProvider_BROKER_PROVIDER_VAULT_HOSTED
	nsOrPath := cfg.Namespace
	if cfg.PathPrefix != "" && cfg.Namespace == "" {
		provider = tenantv1.BrokerProvider_BROKER_PROVIDER_VAULT_BYO
		nsOrPath = cfg.PathPrefix
	}

	out := &tenantv1.RedactedConfig{
		Provider:        provider,
		Address:         cfg.Address,
		NamespaceOrPath: nsOrPath,
		Mount:           cfg.KVMount,
		AuthMethod:      string(cfg.Auth.Method),
	}
	if cfg.Auth.Token != "" {
		out.SensitiveFieldsSet = append(out.SensitiveFieldsSet, sensitiveVaultToken)
	}
	if cfg.Auth.AppRoleSecretID != "" {
		out.SensitiveFieldsSet = append(out.SensitiveFieldsSet, sensitiveAppRoleSecretID)
	}
	return out, nil
}
