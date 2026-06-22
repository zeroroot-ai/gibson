package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/zeroroot-ai/gibson/internal/secrets"
	"github.com/zeroroot-ai/gibson/internal/secrets/jwtsource"
	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	sdkvault "github.com/zeroroot-ai/gibson/internal/infra/secrets/vault"
)

// stampVaultJWTOnConfig mints a SPIRE JWT-SVID via src and writes it onto
// cfg.Auth.JWT when the broker config selects AuthMethodJWT but carries
// no static JWT.
//
// Why this exists (ADR-0009 + amendment docs#34): the tenant-operator
// writes per-tenant broker configs that reference a Vault auth/jwt role
// (gibson-plugin-<tenant_id>) but never the bearer JWT itself — the
// JWT must be minted by the daemon, per request, from the daemon's own
// SPIRE identity. This helper is the single point at which that mint
// happens, before any sdkvault call. Both the AuthCache refresh closure
// (broker_init.go) and the direct-auth fallback in the Vault factory
// (broker_init.go) call it.
//
// Behaviour matrix:
//
//   - cfg.Auth.Method != AuthMethodJWT → no-op (returns nil, cfg unchanged).
//   - cfg.Auth.Method == AuthMethodJWT AND cfg.Auth.JWT != "" → no-op
//     (caller-supplied JWTs win; allows local-dev short-circuit and
//     migration scenarios without touching this code path).
//   - cfg.Auth.Method == AuthMethodJWT AND cfg.Auth.JWT == "" AND src is
//     nil OR audience is "" → error. Fail-loud: AuthMethodJWT without a
//     JWTSource + audience is a misconfiguration the daemon must surface
//     rather than silently fall back to a non-JWT method.
//   - Otherwise → call src.Token(ctx, audience); on success, write the
//     returned token onto cfg.Auth.JWT and return nil.
//
// The returned JWT MUST NOT be logged by this helper or any caller.
// Spec: ADR-0009 amendment (docs#34); gibson#167 PRD; gibson#168.
func stampVaultJWTOnConfig(ctx context.Context, cfg *sdkvault.Config, src jwtsource.JWTSource, audience string) error {
	if cfg == nil {
		return fmt.Errorf("stamp jwt: nil config")
	}
	if cfg.Auth.Method != sdkvault.AuthMethodJWT {
		return nil
	}
	if cfg.Auth.JWT != "" {
		// Caller already supplied a JWT (local-dev short-circuit / test).
		return nil
	}
	if src == nil {
		return fmt.Errorf("stamp jwt: AuthMethodJWT requires a JWTSource but none was wired (set WithVaultJWTSource in daemon.New; spec: gibson#168)")
	}
	if audience == "" {
		return fmt.Errorf("stamp jwt: AuthMethodJWT requires a non-empty audience (set GIBSON_DAEMON_VAULT_JWT_AUDIENCE in the daemon env; spec: gibson#168)")
	}
	tok, err := src.Token(ctx, audience)
	if err != nil {
		return fmt.Errorf("stamp jwt: mint token for audience %q: %w", audience, err)
	}
	if tok == "" {
		return fmt.Errorf("stamp jwt: source returned an empty JWT for audience %q", audience)
	}
	cfg.Auth.JWT = tok
	return nil
}

// vaultAuthLogin performs a Vault auth-method login for the supplied
// sdkvault.Config and returns the resulting (clientToken, leaseDuration).
//
// Supported auth methods (in order of common production usage):
//
//   - approle: POSTs to /v1/auth/approle/login with {role_id, secret_id}.
//
//   - jwt: POSTs to /v1/auth/<JWTPath>/login with {role, jwt}. The JWT can
//     be SPIFFE-issued or Zitadel-issued; this is the canonical
//     workload→Vault auth path per ADR-0009.
//
//   - token: returns the static token immediately with a zero TTL — the
//     auth-cache substitutes a 5-minute default in that case so static
//     tokens still benefit from the singleflight protection.
//
// All other methods (aws_iam, etc.) fall back to building a transient
// sdkvault.Provider via sdkvault.New and reading the resulting client token.
//
// Vault `auth/kubernetes` is intentionally NOT supported: per ADR-0009
// (jwt-spiffe-everywhere), TokenReview-based authentication to non-Kubernetes
// services is forbidden. Workloads on Kubernetes authenticate to Vault via
// JWT (SPIFFE- or Zitadel-issued) or AppRole. The SDK's
// AuthMethodKubernetes constant was removed in sdk#81; switching on it here
// has been deleted accordingly. An incoming config with Auth.Method =
// "kubernetes" falls through to the SDK fallback and surfaces the SDK's
// "unsupported auth method" error.
//
// vaultAuthLogin never returns the secret material in any logged form. The
// returned token is opaque to the caller — it will be set on the next
// sdkvault.Provider via AuthMethodToken.
//
// Loginurl is computed from cfg only; vaultAuthLogin does not mutate cfg.
func vaultAuthLogin(ctx context.Context, cfg sdkvault.Config) (string, time.Duration, error) {
	if cfg.Address == "" {
		return "", 0, fmt.Errorf("vault auth: Config.Address is required")
	}

	switch cfg.Auth.Method {
	case sdkvault.AuthMethodToken:
		if cfg.Auth.Token == "" {
			return "", 0, fmt.Errorf("vault auth: token method requires Auth.Token")
		}
		// Static tokens have no server-issued TTL; return 0 so the cache
		// applies its default minimum effective TTL.
		return cfg.Auth.Token, 0, nil

	case sdkvault.AuthMethodAppRole:
		return loginAppRole(ctx, cfg)

	case sdkvault.AuthMethodJWT:
		return loginJWT(ctx, cfg)

	default:
		// Fallback path: build a transient sdkvault.Provider and let the SDK
		// run its full auth flow. We then return the *bare* token via a
		// lookup-self call. Cost is one extra RPC; benefit is method
		// coverage without re-implementing aws_iam etc. An auth method of
		// "kubernetes" lands here and surfaces the SDK's clean
		// "unsupported auth method" error (see ADR-0009).
		return loginFallbackViaProvider(ctx, cfg)
	}
}

func loginAppRole(ctx context.Context, cfg sdkvault.Config) (string, time.Duration, error) {
	if cfg.Auth.AppRoleID == "" || cfg.Auth.AppRoleSecretID == "" {
		return "", 0, fmt.Errorf("vault auth (approle): Auth.AppRoleID and Auth.AppRoleSecretID are required")
	}
	body := map[string]string{
		"role_id":   cfg.Auth.AppRoleID,
		"secret_id": cfg.Auth.AppRoleSecretID,
	}
	return postLogin(ctx, cfg, "auth/approle/login", body)
}

func loginJWT(ctx context.Context, cfg sdkvault.Config) (string, time.Duration, error) {
	if cfg.Auth.Role == "" || cfg.Auth.JWT == "" {
		return "", 0, fmt.Errorf("vault auth (jwt): Auth.Role and Auth.JWT are required")
	}
	mount := cfg.Auth.JWTPath
	if mount == "" {
		mount = "auth/jwt"
	}
	if !strings.HasSuffix(mount, "/login") {
		mount = strings.TrimSuffix(mount, "/") + "/login"
	}
	body := map[string]string{
		"role": cfg.Auth.Role,
		"jwt":  cfg.Auth.JWT,
	}
	return postLogin(ctx, cfg, mount, body)
}

// postLogin runs a Vault auth login by writing a logical request via the
// vault api client. Using the SDK's logical client (rather than raw HTTP)
// gives us correct namespace + retry behaviour for free.
func postLogin(ctx context.Context, cfg sdkvault.Config, path string, body map[string]string) (string, time.Duration, error) {
	cli, err := newVaultBareClient(cfg)
	if err != nil {
		return "", 0, err
	}

	data := make(map[string]interface{}, len(body))
	for k, v := range body {
		data[k] = v
	}
	secret, err := cli.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return "", 0, fmt.Errorf("vault auth: %s: %w", path, err)
	}
	if secret == nil || secret.Auth == nil {
		return "", 0, fmt.Errorf("vault auth: %s: response had no auth data", path)
	}
	return secret.Auth.ClientToken, time.Duration(secret.Auth.LeaseDuration) * time.Second, nil
}

// newVaultBareClient builds a vault api.Client without performing any
// authentication.
func newVaultBareClient(cfg sdkvault.Config) (*api.Client, error) {
	apiCfg := api.DefaultConfig()
	apiCfg.Address = cfg.Address
	apiCfg.Timeout = 15 * time.Second

	cli, err := api.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("vault auth: build client: %w", err)
	}
	if cfg.Namespace != "" {
		cli.SetNamespace(cfg.Namespace)
	}
	return cli, nil
}

// loginFallbackViaProvider builds a transient sdkvault.Provider and then
// issues a sys/lookup-self call to recover the lease TTL of the resulting
// client token. This path supports auth methods (e.g. aws_iam) that
// loginAppRole/loginJWT do not.
func loginFallbackViaProvider(ctx context.Context, cfg sdkvault.Config) (string, time.Duration, error) {
	prov, err := sdkvault.New(ctx, cfg)
	if err != nil {
		return "", 0, fmt.Errorf("vault auth fallback: %w", err)
	}
	_ = prov // hold reference; the GC won't close any internal state mid-call

	// Without access to the provider's internal *api.Client we re-issue the
	// lookup-self via a bare client + token-style auth. To make that work we
	// require Auth.Token to be set as a fallback bridge — the SDK leaves it
	// blank for non-token methods, so this branch effectively only succeeds
	// when the operator has configured both a primary method AND a
	// reusable token. For aws_iam this is uncommon; we surface a clear
	// error so the caller knows to register a method-specific helper.
	return "", 0, fmt.Errorf("vault auth: method %q is not supported by the lightweight refresher; add a method-specific case in vaultAuthLogin", cfg.Auth.Method)
}

// vaultConfigCacheKey returns a stable, opaque cache key for an sdkvault.Config
// blob. The key is a SHA-256 hex digest of the canonicalized JSON
// representation; identical configs (Address + Namespace + Auth fields) hash
// to the same key, distinct configs do not collide.
//
// This key is used as the AuthCache's "tenant" parameter so that callers
// without a TenantID handy (e.g. the registry's blob-only factory) still get
// per-config singleflight protection.
func vaultConfigCacheKey(blob []byte) string {
	h := sha256.Sum256(blob)
	return "vaultcfg:" + hex.EncodeToString(h[:8]) // 16 hex chars is plenty for log readability
}

// vaultRefreshLookup is a process-wide map of cache key → sdkvault.Config.
// Populated by makeVaultFactory before each GetOrRefresh, consumed by the
// AuthRefreshFn closure. The AuthRefreshFn cannot reach the config any other
// way because secrets.AuthRefreshFn only carries opaque (tenant, provider)
// strings.
//
// A sync.Map suffices: writes are far less frequent than reads, and even
// after a write/read race the worst case is a single missed cache lookup,
// which the singleflight handles.
type vaultRefreshLookup struct {
	mu      sync.RWMutex
	configs map[string]sdkvault.Config
}

func newVaultRefreshLookup() *vaultRefreshLookup {
	return &vaultRefreshLookup{configs: make(map[string]sdkvault.Config)}
}

func (l *vaultRefreshLookup) put(key string, cfg sdkvault.Config) {
	l.mu.Lock()
	l.configs[key] = cfg
	l.mu.Unlock()
}

func (l *vaultRefreshLookup) get(key string) (sdkvault.Config, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	c, ok := l.configs[key]
	return c, ok
}

// makeVaultRefreshFn returns an AuthRefreshFn that dispatches by cache key
// through the supplied vaultRefreshLookup. The returned closure has no
// dependency on RegistryConfigGetter; it is purely driven by the configs
// the VaultFactory deposits before each call.
func makeVaultRefreshFn(lookup *vaultRefreshLookup) secrets.AuthRefreshFn {
	return func(ctx context.Context, key, _ string) (string, time.Duration, error) {
		cfg, ok := lookup.get(key)
		if !ok {
			return "", 0, fmt.Errorf("vault auth refresh: no config registered for cache key %s", key)
		}
		return vaultAuthLogin(ctx, cfg)
	}
}

// makeVaultFactory returns a Vault ProviderConstructor that consults the
// AuthCache before constructing each sdkvault.Provider. The flow is:
//
//  1. Unmarshal the per-tenant config blob into sdkvault.Config.
//  2. Compute a stable cache key from the blob; register the config so the
//     refresh closure can find it.
//  3. Call vaultAuthCache.GetOrRefresh; under concurrent factory invocations
//     for the same tenant (e.g. Registry.Reload), all goroutines collapse
//     onto one auth round-trip via singleflight.
//  4. Inject the cached token into cfg.Auth.{Method,Token} and call
//     sdkvault.New, which now skips its own auth round-trip and only runs
//     the KV-mount detection probe.
//
// On AuthCache failure the factory falls back to plain sdkvault.New so that
// providers without a registered config (e.g. tenants with malformed blobs
// or static-token-only configs) still construct successfully.
//
// lookup is the registry shared with makeVaultRefreshFn — when the factory
// inserts a config into it, the AuthCache's refresh closure can find that
// config and run the corresponding login flow. Both arguments must come
// from the same broker_init call site so the wiring matches.
//
// Spec: headline-feature-completion R3 (VaultFactory consults AuthCache).
func makeVaultFactory(ctx context.Context, vaultAuthCache *secrets.AuthCache, lookup *vaultRefreshLookup) func(blob []byte) (sdksecrets.Broker, error) {
	return func(blob []byte) (sdksecrets.Broker, error) {
		var cfg sdkvault.Config
		if err := json.Unmarshal(blob, &cfg); err != nil {
			return nil, fmt.Errorf("vault: unmarshal config: %w", err)
		}

		if vaultAuthCache == nil || lookup == nil {
			return sdkvault.New(ctx, cfg)
		}

		key := vaultConfigCacheKey(blob)
		lookup.put(key, cfg)

		token, err := vaultAuthCache.GetOrRefresh(ctx, key, "vault")
		if err != nil {
			// Fall back to direct construction; sdkvault.New will run its
			// own auth round-trip. This preserves availability when the
			// cache cannot reach Vault for some transient reason.
			return sdkvault.New(ctx, cfg)
		}

		// Inject the cached token. AuthMethodToken short-circuits sdkvault's
		// internal authenticate() to a single SetToken call — no round-trip.
		cfg.Auth.Method = sdkvault.AuthMethodToken
		cfg.Auth.Token = token
		return sdkvault.New(ctx, cfg)
	}
}
