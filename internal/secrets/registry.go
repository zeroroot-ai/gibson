package secrets

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/zero-day-ai/sdk/auth"
	sdksecrets "github.com/zero-day-ai/platform-clients/secrets"
)

// ProviderConstructor is a function that builds a SecretsBroker from the raw
// JSON config blob stored in the tenant's broker config row. The Postgres
// constructor is a special case — it takes no config blob and returns a
// pre-shared instance (see Registry.postgresFactory).
type ProviderConstructor func(configBlob []byte) (sdksecrets.Broker, error)

// RegistryConfigGetter is the narrow interface Registry needs from the config
// store. The concrete implementation is *ConfigStore; tests may substitute a
// fake.
type RegistryConfigGetter interface {
	Get(ctx context.Context, tenant auth.TenantID) (BrokerConfig, error)
}

// Registry resolves a tenant to its configured SecretsBroker instance.
// Each provider instance is constructed once (lazily, on first For call) and
// cached for the lifetime of the daemon process or until Reload is called.
//
// Default fallback: when no broker configuration row exists for a tenant, the
// Postgres provider is returned (backward-compatible behaviour for tenants
// that pre-date the broker abstraction).
//
// Registry is safe for concurrent use. The internal cache uses a sync.RWMutex
// with a double-check pattern on construction to prevent redundant
// construction under concurrent calls.
type Registry struct {
	configStore  RegistryConfigGetter
	constructors map[string]ProviderConstructor

	// postgresProvider is the pre-constructed Postgres provider used as the
	// default fallback. It is shared across all tenants (the Postgres
	// provider is stateless beyond its ConnAcquirer callback).
	postgresProvider sdksecrets.Broker

	mu    sync.RWMutex
	cache map[auth.TenantID]sdksecrets.Broker
}

// RegistryConfig carries the factory functions used to construct provider
// instances from per-tenant config blobs. Each field except PostgresProvider
// takes the raw JSON blob stored in tenant_secrets_broker_config.config.
//
// PostgresProvider is a ready-to-use instance (no per-tenant config; the
// Postgres provider receives its ConnAcquirer at construction time in daemon
// wiring). The other four factories receive the decrypted JSON blob and must
// return a fully-initialized provider or an error.
type RegistryConfig struct {
	// PostgresProvider is the pre-constructed default-fallback Postgres
	// provider. Must be non-nil.
	PostgresProvider sdksecrets.Broker

	// VaultFactory constructs a Vault provider from the tenant's JSON config
	// blob. May be nil if vault is not supported in this deployment (unusual
	// — all five providers compile into every binary).
	VaultFactory ProviderConstructor

	// AWSSMFactory constructs an AWS Secrets Manager provider.
	AWSSMFactory ProviderConstructor

	// GCPSMFactory constructs a GCP Secret Manager provider.
	GCPSMFactory ProviderConstructor

	// AzureKVFactory constructs an Azure Key Vault provider.
	AzureKVFactory ProviderConstructor
}

// NewRegistry constructs a Registry. configStore is used to read per-tenant
// broker configurations; cfg supplies provider factories. All fields of cfg
// except the optional cloud provider factories must be non-nil.
func NewRegistry(configStore RegistryConfigGetter, cfg RegistryConfig) (*Registry, error) {
	if configStore == nil {
		return nil, errors.New("registry: ConfigStore must not be nil")
	}
	if cfg.PostgresProvider == nil {
		return nil, errors.New("registry: PostgresProvider must not be nil")
	}

	constructors := map[string]ProviderConstructor{
		"postgres": func(_ []byte) (sdksecrets.Broker, error) {
			return cfg.PostgresProvider, nil
		},
	}
	if cfg.VaultFactory != nil {
		constructors["vault"] = cfg.VaultFactory
	}
	if cfg.AWSSMFactory != nil {
		constructors["awssm"] = cfg.AWSSMFactory
	}
	if cfg.GCPSMFactory != nil {
		constructors["gcpsm"] = cfg.GCPSMFactory
	}
	if cfg.AzureKVFactory != nil {
		constructors["azurekv"] = cfg.AzureKVFactory
	}

	return &Registry{
		configStore:      configStore,
		constructors:     constructors,
		postgresProvider: cfg.PostgresProvider,
		cache:            make(map[auth.TenantID]sdksecrets.Broker),
	}, nil
}

// For returns the SecretsBroker configured for the given tenant. If no
// broker configuration row exists, the Postgres provider is returned as the
// default fallback (backward-compatible with pre-spec tenants).
//
// Constructed providers are cached; subsequent calls for the same tenant
// return the cached instance without re-reading the config store.
func (r *Registry) For(ctx context.Context, tenant auth.TenantID) (sdksecrets.Broker, error) {
	// Fast path: check the read-locked cache.
	r.mu.RLock()
	if broker, ok := r.cache[tenant]; ok {
		r.mu.RUnlock()
		return broker, nil
	}
	r.mu.RUnlock()

	// Slow path: read config, construct, and cache — with a double-check
	// to prevent redundant construction under concurrent calls for the
	// same new tenant.
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring the write lock.
	if broker, ok := r.cache[tenant]; ok {
		return broker, nil
	}

	broker, err := r.buildProvider(ctx, tenant)
	if err != nil {
		return nil, err
	}

	r.cache[tenant] = broker
	return broker, nil
}

// Reload invalidates the cached provider for the given tenant. The next call
// to For for this tenant will re-read the config store and reconstruct the
// provider. Reload is called when a broker configuration change event is
// received (e.g., via the component callback stream wired in daemon.go).
func (r *Registry) Reload(_ context.Context, tenant auth.TenantID) {
	r.mu.Lock()
	delete(r.cache, tenant)
	r.mu.Unlock()
}

// Health returns a map of each cached tenant to the result of calling
// Health() on its provider. Uncached tenants (never accessed since daemon
// start or since last Reload) are not included. A nil error value means the
// provider is healthy.
func (r *Registry) Health(ctx context.Context) map[auth.TenantID]error {
	r.mu.RLock()
	snapshot := make(map[auth.TenantID]sdksecrets.Broker, len(r.cache))
	for k, v := range r.cache {
		snapshot[k] = v
	}
	r.mu.RUnlock()

	result := make(map[auth.TenantID]error, len(snapshot))
	for tenant, broker := range snapshot {
		result[tenant] = broker.Health(ctx)
	}
	return result
}

// registeredConstructors returns the keys of a ProviderConstructor map as a
// slice, for use in error messages.
func registeredConstructors(m map[string]ProviderConstructor) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	return names
}

// buildProvider reads the tenant's broker config and constructs the
// appropriate provider. Must be called with r.mu write-locked (or from
// code that is otherwise the sole writer, e.g. during construction).
//
// When no broker config row exists for the tenant, this used to fall back
// to r.postgresProvider for backward-compatibility with pre-spec tenants.
// That fallback caused an infinite-recursion-style deadlock: the Postgres
// provider's ConnAcquirer is wired to the per-tenant data-plane pool
// (`pool.For`), and `pool.For` itself resolves Postgres credentials via
// THIS registry — so when the registry returns the fallback Postgres
// provider for an unprovisioned tenant, the secrets resolution chain
// loops until it hits the gRPC timeout (60s). End user impact was that
// every authenticated list call from the dashboard timed out for any
// tenant whose data-plane saga had not run. See gibson#101.
//
// The fix is to surface ErrBrokerConfigNotFound to the caller as a
// well-typed "not provisioned" condition. Daemon handlers map it to
// gRPC FailedPrecondition with a clear message; operators can then
// drive the tenant-operator's provisioning saga (or, in dev,
// hand-seed a row via the admin RPCs). The postgresProvider field is
// kept on Registry so an explicit `provider="postgres"` config row
// still works for tenants that opt into Postgres-backed secrets.
func (r *Registry) buildProvider(ctx context.Context, tenant auth.TenantID) (sdksecrets.Broker, error) {
	cfg, err := r.configStore.Get(ctx, tenant)
	if err != nil {
		if errors.Is(err, ErrBrokerConfigNotFound) {
			return nil, fmt.Errorf(
				"registry: tenant %s has no broker config row in "+
					"tenant_secrets_broker_config; data-plane has not "+
					"been provisioned (gibson#101): %w",
				tenant, err)
		}
		return nil, fmt.Errorf("registry: read broker config for tenant %s: %w", tenant, err)
	}

	constructor, ok := r.constructors[cfg.Provider]
	if !ok {
		return nil, fmt.Errorf("registry: unknown provider %q for tenant %s (registered: %v)",
			cfg.Provider, tenant, registeredConstructors(r.constructors))
	}

	broker, err := constructor(cfg.ConfigBlob)
	if err != nil {
		return nil, fmt.Errorf("registry: construct provider %q for tenant %s: %w", cfg.Provider, tenant, err)
	}
	return broker, nil
}
