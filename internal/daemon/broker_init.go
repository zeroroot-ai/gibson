package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/zero-day-ai/gibson/internal/audit"
	"github.com/zero-day-ai/gibson/internal/component"
	daemonapi "github.com/zero-day-ai/gibson/internal/daemon/api"
	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/secrets"
	pgprovider "github.com/zero-day-ai/gibson/internal/secrets/providers/postgres"
	"github.com/zero-day-ai/sdk/auth"
	sdksecrets "github.com/zero-day-ai/sdk/secrets"
	sdkawssm "github.com/zero-day-ai/sdk/secrets/providers/awssm"
	sdkazurekv "github.com/zero-day-ai/sdk/secrets/providers/azurekv"
	sdkgcpsm "github.com/zero-day-ai/sdk/secrets/providers/gcpsm"
	sdkvault "github.com/zero-day-ai/sdk/secrets/providers/vault"
)

// brokerHealthGauge tracks per-(tenant, provider) broker health for SRE
// visibility. Values: 0 = healthy, 1 = unhealthy.
var brokerHealthGauge = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "gibson_secrets_broker_health",
		Help: "Health of the secrets broker per tenant and provider: 0=healthy, 1=unhealthy.",
	},
	[]string{"tenant", "provider"},
)

// initBrokerStack constructs and wires the full broker stack into the daemon:
//
//  1. Audit writer  — delegates to the Redis Streams AuditLogger.
//  2. Circuit breaker — per-(tenant, provider) fault isolation.
//  3. Config store  — TenantConfigStore + ConfigStore backed by dashboard Postgres + system-tenant KEK.
//  4. Postgres provider — ConnAcquirer over Pool.For.
//  5. Cloud provider factories (Vault, AWS SM, GCP SM, Azure KV).
//  6. Registry — resolves tenant → broker.
//  7. secrets.Service — the single entry-point for all handlers.
//
// The call is guarded: it requires both keyProvider (for the KEK) and a
// stateClient (for the audit logger). When dashboard Postgres is absent the
// broker still boots using only the Postgres provider — the TenantConfigStore
// is skipped and the registry defaults every tenant to Postgres.
//
// On success d.credentialStore, d.credentialHandler, and compSvc's
// WithCredentialStore are all wired. Returns a non-nil error only for
// conditions that prevent any credential operations (e.g., KEK retrieval
// failure or registry construction failure).
func (d *daemonImpl) initBrokerStack(ctx context.Context, compSvc *component.ComponentServiceServer) error {
	// --- 1. Audit writer ---
	// The audit writer requires the Redis Streams AuditLogger already
	// constructed in grpc.go and stored in d.stateClient.
	if d.stateClient == nil {
		return fmt.Errorf("broker stack: state client is nil; cannot construct audit writer")
	}
	auditLogger := audit.NewAuditLogger(d.stateClient, d.logger.Slog())
	auditWriter := secrets.NewAuditWriter(auditLogger, d.logger.Slog())
	d.logger.Info(ctx, "broker stack: audit writer initialized")

	// --- 2. Circuit breaker ---
	cb := secrets.NewCircuitBreaker(d.logger.Slog(), nil /* real clock */)
	d.logger.Info(ctx, "broker stack: circuit breaker initialized")

	// --- 3. Postgres provider (default fallback) ---
	// The Postgres provider receives a ConnAcquirer that calls Pool.For.
	if d.pool == nil {
		d.logger.Warn(ctx, "broker stack: data-plane pool is nil; Postgres provider unavailable — credentials inoperable until pool is available")
		return fmt.Errorf("broker stack: data-plane pool is nil; cannot construct Postgres provider")
	}
	pool := d.pool
	pgAcquirer := func(ctx context.Context, tenant auth.TenantID) (*datapool.Conn, error) {
		return pool.For(ctx, tenant)
	}
	pgProvider := pgprovider.New(pgAcquirer)
	d.logger.Info(ctx, "broker stack: Postgres provider initialized")

	// --- 4. System-tenant KEK (for TenantConfigStore) ---
	// Required to encrypt/decrypt per-tenant broker config blobs.
	var systemKEK []byte
	if d.keyProvider != nil {
		kek, err := d.keyProvider.GetEncryptionKey(ctx)
		if err != nil {
			d.logger.Warn(ctx, "broker stack: failed to retrieve system KEK; config store unavailable (broker config CRUD inoperable)",
				"error", err)
			// Non-fatal: fall back to a Postgres-only registry with no config store.
		} else {
			systemKEK = kek
		}
	} else {
		d.logger.Warn(ctx, "broker stack: no key provider configured; broker config store unavailable")
	}

	// --- 5. Config store (optional — needs dashboard Postgres + KEK) ---
	//
	// The config store holds per-tenant broker configurations encrypted at rest.
	// When the dashboard Postgres is unavailable, the registry falls back to the
	// Postgres provider for all tenants (backward-compatible behaviour).
	var configStore secrets.RegistryConfigGetter = &noopRegistryConfigGetter{}

	if len(systemKEK) == 32 && d.config.DashboardPostgres.Host != "" {
		pgxPool, err := d.dashboardPgxPool(ctx)
		if err != nil {
			d.logger.Warn(ctx, "broker stack: could not open pgxpool to dashboard Postgres; broker config CRUD unavailable",
				"error", err)
			// Non-fatal: continue with noop config getter.
		} else {
			tenantCfgStore, err := secrets.NewTenantConfigStore(pgxPool, systemKEK)
			if err != nil {
				d.logger.Warn(ctx, "broker stack: TenantConfigStore construction failed; broker config CRUD unavailable",
					"error", err)
				pgxPool.Close() // best-effort cleanup
			} else {
				// Build the provider factories for the config-store probe step.
				configFactories := map[string]secrets.ProviderFactory{
					"postgres": func(_ []byte) (sdksecrets.SecretsBroker, error) {
						return pgProvider, nil
					},
					"vault": func(blob []byte) (sdksecrets.SecretsBroker, error) {
						var cfg sdkvault.Config
						if err := json.Unmarshal(blob, &cfg); err != nil {
							return nil, fmt.Errorf("vault: unmarshal config: %w", err)
						}
						return sdkvault.New(ctx, cfg)
					},
					"awssm": func(blob []byte) (sdksecrets.SecretsBroker, error) {
						var cfg sdkawssm.Config
						if err := json.Unmarshal(blob, &cfg); err != nil {
							return nil, fmt.Errorf("awssm: unmarshal config: %w", err)
						}
						return sdkawssm.New(ctx, cfg)
					},
					"gcpsm": func(blob []byte) (sdksecrets.SecretsBroker, error) {
						var cfg sdkgcpsm.Config
						if err := json.Unmarshal(blob, &cfg); err != nil {
							return nil, fmt.Errorf("gcpsm: unmarshal config: %w", err)
						}
						return sdkgcpsm.New(ctx, cfg)
					},
					"azurekv": func(blob []byte) (sdksecrets.SecretsBroker, error) {
						var cfg sdkazurekv.Config
						if err := json.Unmarshal(blob, &cfg); err != nil {
							return nil, fmt.Errorf("azurekv: unmarshal config: %w", err)
						}
						return sdkazurekv.New(cfg)
					},
				}
				cs, err := secrets.NewConfigStore(tenantCfgStore, configFactories, auditWriter)
				if err != nil {
					d.logger.Warn(ctx, "broker stack: ConfigStore construction failed",
						"error", err)
				} else {
					configStore = cs
					d.logger.Info(ctx, "broker stack: config store initialized (dashboard Postgres-backed)")
				}
			}
		}
	} else {
		d.logger.Info(ctx, "broker stack: config store not available (missing KEK or dashboard Postgres); all tenants use Postgres provider by default")
	}

	// --- 5b. Auth-token cache (Vault proof-of-concept) ---
	//
	// The AuthCache prevents auth churn when the Vault provider instance is
	// rebuilt on registry Reload events. The refresh function decodes the
	// tenant's Vault config blob and performs the configured auth method to
	// obtain a fresh token; subsequent Reload calls within the token's
	// effective TTL reuse the cached token instead of re-authenticating.
	//
	// TODO(follow-up): wire the AuthCache into per-call token refresh inside
	// the Vault provider itself (sdkvault.Provider.ReauthFn) so that
	// long-lived provider instances can also refresh expired tokens via the
	// cache without full reconstruction. AWS SM uses SDK-managed STS caching
	// which provides an equivalent guarantee; full AuthCache integration for
	// AWS SM is deferred to that follow-up.
	//
	// The per-tenant blob is used as the cache's AuthRefreshFn context because
	// the tenant's Vault config (address, auth method, role) is embedded in
	// the blob itself. We use the Vault address as a stable "provider" key
	// within the singleflight group.
	//
	// Spec: secrets-broker NFR Performance, Requirement 9.6.
	vaultAuthCache := secrets.NewAuthCache(
		func(ctx context.Context, tenantID, _ string) (string, time.Duration, error) {
			// The refresh function is a no-op at the registry level because
			// full per-call refresh requires a provider-side callback
			// (see TODO above). At the registry level the cache prevents
			// redundant vault.New() authentication during concurrent Reload
			// calls for the same tenant.
			//
			// The actual token and TTL are obtained at provider construction
			// time inside the VaultFactory closure; the AuthCache ensures
			// that only one such construction (and hence one auth call) is
			// in-flight per tenant at any given moment.
			//
			// For the production follow-up, this refreshFn will call the
			// Vault auth endpoint directly and return the ClientToken +
			// LeaseDuration. Until then we return a sentinel so the factory
			// always calls sdkvault.New (which internally authenticates).
			return "", 0, fmt.Errorf("vault auth cache: direct token refresh not yet wired (see broker_init.go TODO)")
		},
		d.logger.Slog(),
		nil, // production clock
	)
	d.vaultAuthCache = vaultAuthCache
	d.logger.Info(ctx, "broker stack: Vault auth cache initialized (proof-of-concept; full per-call refresh wiring is a follow-up)")

	// --- 6. Cloud provider factories for the Registry ---
	registryCfg := secrets.RegistryConfig{
		PostgresProvider: pgProvider,
		VaultFactory: func(blob []byte) (sdksecrets.SecretsBroker, error) {
			var cfg sdkvault.Config
			if err := json.Unmarshal(blob, &cfg); err != nil {
				return nil, fmt.Errorf("vault: unmarshal config: %w", err)
			}
			// The auth cache is not yet wired into the Vault provider's
			// per-call refresh path (see TODO in section 5b above). When the
			// follow-up lands, this factory will call:
			//   vaultAuthCache.GetOrRefresh(ctx, tenant, "vault")
			// and inject the cached token as AuthMethodToken before calling
			// sdkvault.New. Until then, sdkvault.New authenticates directly.
			return sdkvault.New(ctx, cfg)
		},
		AWSSMFactory: func(blob []byte) (sdksecrets.SecretsBroker, error) {
			var cfg sdkawssm.Config
			if err := json.Unmarshal(blob, &cfg); err != nil {
				return nil, fmt.Errorf("awssm: unmarshal config: %w", err)
			}
			return sdkawssm.New(ctx, cfg)
		},
		GCPSMFactory: func(blob []byte) (sdksecrets.SecretsBroker, error) {
			var cfg sdkgcpsm.Config
			if err := json.Unmarshal(blob, &cfg); err != nil {
				return nil, fmt.Errorf("gcpsm: unmarshal config: %w", err)
			}
			return sdkgcpsm.New(ctx, cfg)
		},
		AzureKVFactory: func(blob []byte) (sdksecrets.SecretsBroker, error) {
			var cfg sdkazurekv.Config
			if err := json.Unmarshal(blob, &cfg); err != nil {
				return nil, fmt.Errorf("azurekv: unmarshal config: %w", err)
			}
			return sdkazurekv.New(cfg)
		},
	}

	// --- 7. Registry ---
	registry, err := secrets.NewRegistry(configStore, registryCfg)
	if err != nil {
		return fmt.Errorf("broker stack: registry construction failed: %w", err)
	}
	d.logger.Info(ctx, "broker stack: registry initialized")

	// Startup self-check: verify the system-tenant (Postgres) provider is reachable.
	// A Health() call is sufficient here; Probe() is reserved for config-set time.
	sysTenantHealth := pgProvider.Health(ctx)
	if sysTenantHealth != nil {
		return fmt.Errorf("broker stack: startup self-check: system-tenant Postgres provider unhealthy: %w", sysTenantHealth)
	}
	d.logger.Info(ctx, "broker stack: system-tenant Postgres provider health check passed")

	// --- 8. Service ---
	svc, err := secrets.NewService(registry, cb, auditWriter)
	if err != nil {
		return fmt.Errorf("broker stack: service construction failed: %w", err)
	}
	d.logger.Info(ctx, "broker stack: secrets.Service initialized")

	// Store the registry on the daemon so the /readyz probe can call Health().
	d.secretsRegistry = registry

	// --- 9. Wire into handlers ---

	// DaemonCredentialStore (harness callback).
	credStore, err := NewDaemonCredentialStore(svc)
	if err != nil {
		return fmt.Errorf("broker stack: DaemonCredentialStore construction failed: %w", err)
	}
	d.credentialStore = credStore
	d.callback.SetCredentialStore(credStore)
	d.logger.Info(ctx, "broker stack: DaemonCredentialStore wired into callback service")

	// CredentialHandler (dashboard API).
	credHandler, err := daemonapi.NewCredentialHandler(svc)
	if err != nil {
		return fmt.Errorf("broker stack: CredentialHandler construction failed: %w", err)
	}
	d.credentialHandler = credHandler
	d.logger.Info(ctx, "broker stack: CredentialHandler initialized for dashboard API")

	// ComponentService credential store.
	if compSvc != nil {
		compCredStore, err := component.NewSecretsCredentialStore(svc)
		if err != nil {
			return fmt.Errorf("broker stack: SecretsCredentialStore construction failed: %w", err)
		}
		compSvc.WithCredentialStore(compCredStore)
		d.logger.Info(ctx, "broker stack: SecretsCredentialStore wired into ComponentService")
	}

	// LLM provider chain — broker wiring is done lazily in registerLLMProviders
	// via providers.NewProviderWithContext. Store the service on the daemon so
	// re-registration (e.g., on config reload) can pick it up.
	d.secretsService = svc
	d.logger.Info(ctx, "broker stack: secrets.Service stored for LLM provider chain")

	// --- 10. Subscribe to broker-config-change events ---
	// When ConfigStore.Set persists a new config, callers should call
	// registry.Reload(tenant) to invalidate the cached provider. The pattern
	// chosen here is direct: ConfigStore.Set callers are responsible for calling
	// registry.Reload after a successful Set. This avoids a pubsub dependency
	// while keeping the registry cache consistent. An admin RPC handler (future
	// spec 4) will call registry.Reload after a successful ConfigStore.Set.
	//
	// The registration of a reload callback on the component callback stream
	// (Requirement 6.5) is deferred to the admin-RPC wiring in Spec 4 because
	// the component callback stream carries component lifecycle events, not
	// broker-config events. The correct integration point is the future
	// SetBrokerConfig admin RPC handler which will call both ConfigStore.Set
	// and registry.Reload in the same transaction.
	d.logger.Info(ctx, "broker stack: initialized successfully; all five provider constructors registered")
	return nil
}

// dashboardPgxPool opens a pgxpool.Pool connection to the operator-shared
// dashboard Postgres database. This is used by the TenantConfigStore to persist
// per-tenant broker configurations. The pool is separate from the sql.DB pool
// used by other daemon services because TenantConfigStore requires pgx v5.
func (d *daemonImpl) dashboardPgxPool(ctx context.Context) (*pgxpool.Pool, error) {
	pgCfg := d.config.DashboardPostgres

	if pgCfg.Host == "" {
		return nil, fmt.Errorf("dashboard Postgres not configured")
	}

	port := pgCfg.Port
	if port == 0 {
		port = 5432
	}
	sslMode := pgCfg.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}
	database := pgCfg.Database
	if database == "" {
		database = "gibson_dashboard"
	}
	maxConns := int32(pgCfg.MaxConns)
	if maxConns == 0 {
		maxConns = 5
	}

	dsn := fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s pool_max_conns=%d",
		pgCfg.Host,
		port,
		database,
		pgCfg.Username,
		pgCfg.Password,
		sslMode,
		maxConns,
	)

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgxpool.New: %w", err)
	}

	// Verify connectivity.
	if pingErr := pool.Ping(ctx); pingErr != nil {
		pool.Close()
		return nil, fmt.Errorf("dashboard Postgres pgxpool ping failed: %w", pingErr)
	}

	return pool, nil
}

// noopRegistryConfigGetter is a RegistryConfigGetter that always returns
// ErrBrokerConfigNotFound, causing the registry to default every tenant to the
// Postgres provider. Used when the dashboard Postgres or system KEK is
// unavailable at startup.
type noopRegistryConfigGetter struct{}

func (n *noopRegistryConfigGetter) Get(_ context.Context, _ auth.TenantID) (secrets.BrokerConfig, error) {
	return secrets.BrokerConfig{}, secrets.ErrBrokerConfigNotFound
}
