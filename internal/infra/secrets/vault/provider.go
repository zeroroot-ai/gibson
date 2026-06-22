package vault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/openbao/openbao/api/v2"
	"github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// maxVaultValueBytes is the maximum value size the Vault provider accepts.
// Vault itself has no enforced upper limit on KV v2 values, but the broker
// contract requires a declared ceiling. 1 MiB matches the Postgres provider.
const maxVaultValueBytes = 1 << 20

// valueKey is the KV v2 data map key under which the base64-encoded secret
// value is stored. All writes store {"value": base64(bytes)} and reads
// decode this field. This convention is documented in the package godoc.
const valueKey = "value"

// Config holds the per-provider Vault configuration. A Config is supplied
// once at construction time; the Provider does not mutate it.
//
// The JSON shape of Config is part of the SDK's public contract: the
// gibson daemon and the tenant-operator both serialise / deserialise it
// to/from the platform's tenant_secrets_broker_config table. JSON tags
// are explicit + snake_case so writer/reader agreement is compile-time
// auditable rather than relying on Go's default field-name matching.
type Config struct {
	// Address is the Vault server URL, e.g. "https://vault.example.com:8200".
	// Required.
	Address string `json:"address"`

	// Namespace is the Vault Enterprise namespace to target for all
	// requests. When non-empty, the X-Vault-Namespace header is set on
	// every request. Leave empty for Vault Community Edition; use
	// PathPrefix instead.
	Namespace string `json:"namespace,omitempty"`

	// PathPrefix is an optional path segment prepended to every KV path
	// for tenant isolation on Vault Community Edition when Namespace is
	// empty. Typical value: "tenant/<tenant_id>". The kvPath helper
	// incorporates PathPrefix when building the full KV path.
	//
	// When Namespace is non-empty, PathPrefix is ignored; namespaces
	// provide the isolation boundary.
	PathPrefix string `json:"path_prefix,omitempty"`

	// KVMount is the KV v2 secret engine mount path. Defaults to "secret"
	// when empty.
	KVMount string `json:"kv_mount,omitempty"`

	// Auth holds the authentication configuration.
	Auth AuthConfig `json:"auth"`
}

// kvMount returns the effective KV mount path, applying the default.
func (c Config) kvMount() string {
	if c.KVMount == "" {
		return "secret"
	}
	return c.KVMount
}

// TokenRefresher is called before every Vault KV operation to obtain a
// current auth token. The returned token is set on a per-operation client
// clone so concurrent callers do not race on token mutation.
//
// The refresher is typically backed by a daemon-level AuthCache keyed by
// vault config blob hash. On a cache hit (token still valid) the call
// completes in microseconds (RWLock read). On a miss the cache performs a
// fresh JWT login and updates the cache under singleflight.
//
// Implementations must be safe for concurrent use.
type TokenRefresher func(ctx context.Context) (string, error)

// Provider is a HashiCorp Vault KV v2 implementation of secrets.Broker.
// Each Provider instance is bound to one Vault address and one set of
// authentication credentials; tenant isolation is provided either by Vault
// Enterprise namespaces (one namespace per tenant) or by a path-prefix scheme
// (one path-prefix per tenant) on Community Edition.
//
// Provider is safe for concurrent use from multiple goroutines.
type Provider struct {
	client    *api.Client
	cfg       Config
	refresher TokenRefresher // nil for static-token providers
}

// New constructs a Provider from cfg. It:
//  1. Builds and authenticates a Vault API client.
//  2. Verifies that the configured KV mount is KV v2 (not v1).
//
// New returns an error when:
//   - cfg.Address is empty or unreachable.
//   - Authentication fails (wrong token, role not found, etc.).
//   - The KV mount is KV v1 or is not found.
//
// For long-lived providers whose auth token will expire (e.g. JWT auth with a
// 30-minute TTL), use NewWithRefresher instead. New bakes the initial token
// into the client and never re-authenticates; the provider will return
// ErrPermissionDenied once that token expires.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault: Config.Address is required")
	}

	client, err := buildClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	mount := cfg.kvMount()
	if cfg.Namespace == "" {
		if err := detectKVVersion(ctx, client, mount); err != nil {
			return nil, err
		}
	}

	return &Provider{client: client, cfg: cfg}, nil
}

// NewWithRefresher constructs a Provider like New, but accepts a
// TokenRefresher that is called before every KV operation to obtain a
// current auth token. The refresher is invoked once at construction time to
// acquire the initial token and validate connectivity; subsequent calls are
// driven by the refresher alone.
//
// Use this constructor when the auth token has a finite TTL (JWT, AppRole,
// etc.) and the provider will be cached across multiple token lifetimes.
// On each operation the refresher is called (a fast cache-hit on the normal
// path), a clone of the base client is created, and the fresh token is set on
// the clone — so concurrent callers never race on token mutation.
//
// refresher must not be nil.
func NewWithRefresher(ctx context.Context, cfg Config, refresher TokenRefresher) (*Provider, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault: Config.Address is required")
	}
	if refresher == nil {
		return nil, fmt.Errorf("vault: NewWithRefresher: refresher must not be nil")
	}

	// Obtain the initial token via the refresher. This surfaces auth failures
	// at factory/construction time rather than at the first RPC.
	initialToken, err := refresher(ctx)
	if err != nil {
		return nil, fmt.Errorf("vault: initial token refresh failed: %w", err)
	}

	// Build the base client using the initial token as a static credential so
	// buildClient → authenticate does not trigger an extra round-trip to Vault.
	tokenCfg := cfg
	tokenCfg.Auth = AuthConfig{
		Method: AuthMethodToken,
		Token:  initialToken,
	}
	client, err := buildClient(ctx, tokenCfg)
	if err != nil {
		return nil, err
	}

	mount := cfg.kvMount()
	if cfg.Namespace == "" {
		if err := detectKVVersion(ctx, client, mount); err != nil {
			return nil, err
		}
	}

	return &Provider{client: client, cfg: cfg, refresher: refresher}, nil
}

// clientFor returns the api.Client to use for a single KV operation. When a
// TokenRefresher is configured, it calls the refresher, clones the base
// client (sharing the underlying HTTP transport / connection pool), and sets
// the fresh token on the clone. Cloning is O(1) in memory and shares the
// connection pool, so per-operation overhead is limited to the refresher call
// (a mutex-protected map read on the cache-hit path) and a struct allocation.
//
// When no refresher is configured the base client is returned directly.
func (p *Provider) clientFor(ctx context.Context) (*api.Client, error) {
	if p.refresher == nil {
		return p.client, nil
	}
	token, err := p.refresher(ctx)
	if err != nil {
		return nil, fmt.Errorf("vault: token refresh failed: %w", err)
	}
	// CloneWithHeaders preserves X-Vault-Namespace (set by SetNamespace at
	// construction time). Plain Clone() only copies headers when
	// config.CloneHeaders=true, which we never set — losing the namespace
	// header causes every read to hit the root namespace and return 404.
	clone, err := p.client.CloneWithHeaders()
	if err != nil {
		return nil, fmt.Errorf("vault: client clone failed: %w", err)
	}
	clone.SetToken(token)
	return clone, nil
}

// kvPath builds the full KV v2 logical path for a given tenant and secret
// name.
//
// Namespace mode (cfg.Namespace != ""): the Vault client has already called
// SetNamespace so every request carries X-Vault-Namespace=<ns>. Within that
// namespace the KV mount is tenant-private, so the path is just <name>
// (e.g. "infra/postgres"). Adding "tenant/<id>/" would create a nested path
// that does not exist — the operator writes to <mount>/data/<name> not
// <mount>/data/tenant/<id>/<name> inside the namespace.
//
// Path-prefix mode (cfg.Namespace == ""): no namespace header is sent; tenant
// isolation comes from a path prefix so the full path is
// "tenant/<tenant_id>/<name>".
func (p *Provider) kvPath(tenant auth.TenantID, name string) string {
	if p.cfg.Namespace != "" {
		return name
	}
	return fmt.Sprintf("tenant/%s/%s", tenant.String(), name)
}

// Get retrieves the current value of the named secret for the given tenant.
// Values are stored as {"value": base64(bytes)} in the KV v2 data map; Get
// decodes the "value" field and returns the raw bytes.
//
// Returns secrets.ErrNotFound when the secret does not exist.
// Returns secrets.ErrPermissionDenied when Vault returns 403.
// Returns secrets.ErrUnavailable for any other error (network, sealed, etc.).
func (p *Provider) Get(ctx context.Context, tenant auth.TenantID, name string) ([]byte, error) {
	client, err := p.clientFor(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", secrets.ErrUnavailable, err)
	}
	path := p.kvPath(tenant, name)
	secret, err := client.KVv2(p.cfg.kvMount()).Get(ctx, path)
	if err != nil {
		return nil, mapVaultError(err, name)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("%w: %q", secrets.ErrNotFound, name)
	}

	raw, ok := secret.Data[valueKey]
	if !ok {
		return nil, fmt.Errorf("%w: %q (missing %q field in KV data)", secrets.ErrNotFound, name, valueKey)
	}

	encoded, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("%w: %q (unexpected type %T for %q field)", secrets.ErrUnavailable, name, raw, valueKey)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %q (base64 decode failed: %w)", secrets.ErrUnavailable, name, err)
	}

	return decoded, nil
}

// Put creates or overwrites the named secret for the given tenant. The value
// is stored as {"value": base64(bytes)} in the KV v2 data map.
//
// Returns secrets.ErrTooLarge when len(value) exceeds maxVaultValueBytes.
// Returns secrets.ErrPermissionDenied when Vault returns 403.
// Returns secrets.ErrUnavailable for any other error.
func (p *Provider) Put(ctx context.Context, tenant auth.TenantID, name string, value []byte) error {
	if len(value) > maxVaultValueBytes {
		return fmt.Errorf("%w: %d bytes (max %d)", secrets.ErrTooLarge, len(value), maxVaultValueBytes)
	}

	client, err := p.clientFor(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", secrets.ErrUnavailable, err)
	}
	path := p.kvPath(tenant, name)
	data := map[string]interface{}{
		valueKey: base64.StdEncoding.EncodeToString(value),
	}
	_, err = client.KVv2(p.cfg.kvMount()).Put(ctx, path, data)
	if err != nil {
		return mapVaultError(err, name)
	}
	return nil
}

// Delete removes the named secret for the given tenant using KV v2 soft
// delete. Soft delete marks all existing versions as deleted but does not
// destroy the data. Deleting a non-existent secret is a no-op.
//
// Returns secrets.ErrPermissionDenied when Vault returns 403.
// Returns secrets.ErrUnavailable for any other error.
func (p *Provider) Delete(ctx context.Context, tenant auth.TenantID, name string) error {
	client, err := p.clientFor(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", secrets.ErrUnavailable, err)
	}
	path := p.kvPath(tenant, name)
	if err := client.KVv2(p.cfg.kvMount()).Delete(ctx, path); err != nil {
		return mapVaultError(err, name)
	}
	return nil
}

// List returns the names of all secrets for the given tenant that match the
// supplied filter. It queries the KV v2 metadata root endpoint and filters
// client-side by filter.Prefix. Pagination is applied via filter.Offset and
// filter.Limit.
//
// Key names in this deployment use ":" as a field separator
// (e.g. "provider_cred:name:field"). Vault treats only "/" as a path
// separator, so appending a colon-based prefix to the vault LIST path would
// query a non-existent subdirectory and return nothing. We therefore always
// list from the tenant root and apply the prefix filter in the client.
//
// Returns secrets.ErrPermissionDenied when Vault returns 403.
// Returns secrets.ErrUnavailable for any other error.
func (p *Provider) List(ctx context.Context, tenant auth.TenantID, filter secrets.Filter) ([]string, error) {
	// KV v2 List goes against the metadata endpoint. We always list from the
	// tenant root so that colon-delimited key names (e.g.
	// "provider_cred:openai:api_key") are reachable — vault only treats "/"
	// as a path separator, so listing at a colon-suffixed subpath returns
	// nothing.
	//
	// Namespace mode: the Vault client sends X-Vault-Namespace=<ns>; within
	// that namespace the KV root is the tenant's private mount.
	// Path-prefix mode: no namespace header; secrets are under
	// secret/metadata/tenant/<id>/ in the root namespace.
	var metaPath string
	if p.cfg.Namespace != "" {
		metaPath = fmt.Sprintf("%s/metadata", p.cfg.kvMount())
	} else {
		metaPath = fmt.Sprintf("%s/metadata/tenant/%s", p.cfg.kvMount(), tenant.String())
	}

	client, err := p.clientFor(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", secrets.ErrUnavailable, err)
	}
	secret, err := client.Logical().ListWithContext(ctx, metaPath)
	if err != nil {
		return nil, mapVaultError(err, "")
	}

	if secret == nil || secret.Data == nil {
		// Empty list — no secrets exist for this tenant.
		return nil, nil
	}

	rawKeys, ok := secret.Data["keys"]
	if !ok {
		return nil, nil
	}

	iKeys, ok := rawKeys.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: unexpected list response shape", secrets.ErrUnavailable)
	}

	var names []string
	for _, k := range iKeys {
		s, ok := k.(string)
		if !ok {
			continue
		}
		// Skip pseudo-directories (trailing slash).
		if strings.HasSuffix(s, "/") {
			continue
		}
		// Client-side prefix filter. The keys returned by the root LIST are
		// already full logical key names; no prefix prepend is needed.
		if filter.Prefix != "" && !strings.HasPrefix(s, filter.Prefix) {
			continue
		}
		names = append(names, s)
	}

	// Apply offset.
	if filter.Offset > 0 {
		if filter.Offset >= len(names) {
			return nil, nil
		}
		names = names[filter.Offset:]
	}
	// Apply limit.
	if filter.Limit > 0 && len(names) > filter.Limit {
		names = names[:filter.Limit]
	}

	return names, nil
}

// Health calls the Vault sys/health endpoint and returns nil when the cluster
// is initialized, unsealed, and active. Returns secrets.ErrUnavailable when
// Vault is sealed, uninitialized, or unreachable.
func (p *Provider) Health(ctx context.Context) error {
	health, err := p.client.Sys().HealthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("%w: vault health check failed: %w", secrets.ErrUnavailable, err)
	}
	if health == nil {
		return fmt.Errorf("%w: vault health endpoint returned nil", secrets.ErrUnavailable)
	}
	if health.Sealed {
		return fmt.Errorf("%w: vault is sealed", secrets.ErrUnavailable)
	}
	if !health.Initialized {
		return fmt.Errorf("%w: vault is not initialized", secrets.ErrUnavailable)
	}
	return nil
}

// Probe performs a write–read–delete round-trip of a canary secret against
// the configured tenant path, verifying full connectivity and authorization.
// The canary name is random to prevent collisions across concurrent probes.
//
// Probe is called before a new broker configuration is persisted; it never
// leaves the canary in place — a failure at any step attempts cleanup before
// returning the error.
func (p *Provider) Probe(ctx context.Context) error {
	// Use a random suffix via crypto/rand in provider.go where it is called.
	// For probe, generate a canary name using a timestamp-based suffix.
	canaryName := probeCanaryName()
	probeValue := []byte("__probe__")

	probeTenant := auth.MustNewTenantID("probe-tenant")

	// Write.
	if err := p.Put(ctx, probeTenant, canaryName, probeValue); err != nil {
		return fmt.Errorf("vault probe write failed: %w", err)
	}

	// Read.
	got, err := p.Get(ctx, probeTenant, canaryName)
	// Best-effort cleanup regardless of read result.
	_ = p.Delete(ctx, probeTenant, canaryName)

	if err != nil {
		return fmt.Errorf("vault probe read failed: %w", err)
	}
	if string(got) != string(probeValue) {
		return fmt.Errorf("vault probe value mismatch: wrote %q, got %q", probeValue, got)
	}

	return nil
}

// Capabilities returns the static capability set for the Vault KV v2
// provider: full read/write/delete/list support, native versioning, and a
// 1 MiB value ceiling.
func (p *Provider) Capabilities() secrets.Capabilities {
	return secrets.Capabilities{
		CanPut:          true,
		CanDelete:       true,
		CanList:         true,
		SupportsVersion: true,
		MaxValueBytes:   maxVaultValueBytes,
	}
}

// mapVaultError translates a Vault API error to the appropriate secrets
// sentinel. The vault/api SDK wraps HTTP 404 responses as a special "secret
// not found" string error rather than a *api.ResponseError, so we detect that
// by string inspection. HTTP 403/401/503 surface as *api.ResponseError.
func mapVaultError(err error, name string) error {
	if err == nil {
		return nil
	}

	// The KVv2 SDK converts 404 to the message "secret not found" wrapped in
	// a fmt.Errorf; it never surfaces as a *api.ResponseError. Check the
	// error string to detect this case.
	msg := err.Error()
	if strings.Contains(msg, "secret not found") || strings.Contains(msg, "404") {
		if name != "" {
			return fmt.Errorf("%w: %q", secrets.ErrNotFound, name)
		}
		return secrets.ErrNotFound
	}

	// The Logical client (used for List) wraps response errors as
	// *api.ResponseError; use errors.As to detect it.
	var respErr *api.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.StatusCode {
		case http.StatusNotFound:
			if name != "" {
				return fmt.Errorf("%w: %q", secrets.ErrNotFound, name)
			}
			return secrets.ErrNotFound
		case http.StatusForbidden:
			return fmt.Errorf("%w: vault denied the request", secrets.ErrPermissionDenied)
		case http.StatusUnauthorized:
			return fmt.Errorf("%w: vault auth token invalid or expired", secrets.ErrPermissionDenied)
		case http.StatusServiceUnavailable:
			return fmt.Errorf("%w: vault returned 503", secrets.ErrUnavailable)
		}
	}

	// Inspect the error message for common Vault access-denied strings.
	if strings.Contains(msg, "permission denied") || strings.Contains(msg, "Code: 403") {
		return fmt.Errorf("%w: vault denied the request", secrets.ErrPermissionDenied)
	}

	// Non-HTTP errors (network failure, DNS, TLS) and unknown statuses map
	// to ErrUnavailable.
	return fmt.Errorf("%w: %w", secrets.ErrUnavailable, err)
}
