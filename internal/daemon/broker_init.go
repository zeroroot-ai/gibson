package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/zeroroot-ai/gibson/internal/audit"
	"github.com/zeroroot-ai/gibson/internal/component"
	daemonapi "github.com/zeroroot-ai/gibson/internal/daemon/api"
	"github.com/zeroroot-ai/gibson/internal/secrets"
	"github.com/zeroroot-ai/gibson/internal/secrets/configstore"
	"github.com/zeroroot-ai/gibson/internal/secrets/jwtsource"
	"github.com/zeroroot-ai/gibson/internal/infra/resilience"
	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	sdkawssm "github.com/zeroroot-ai/gibson/internal/infra/secrets/awssm"
	sdkazurekv "github.com/zeroroot-ai/gibson/internal/infra/secrets/azurekv"
	sdkgcpsm "github.com/zeroroot-ai/gibson/internal/infra/secrets/gcpsm"
	sdkvault "github.com/zeroroot-ai/gibson/internal/infra/secrets/vault"
	"github.com/zeroroot-ai/sdk/auth"
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
//  4. Cloud provider factories (Vault, AWS SM, GCP SM, Azure KV).
//  5. Registry — resolves tenant → broker.
//  6. secrets.Service — the single entry-point for all handlers.
//
// The call is guarded: it requires both keyProvider (for the KEK) and a
// stateClient (for the audit logger). When dashboard Postgres is absent the
// TenantConfigStore is skipped and broker config CRUD is inoperable.
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
	auditLogger := audit.NewAuditLogger(ctx, d.stateClient, d.logger.Slog())
	auditWriter := secrets.NewAuditWriter(auditLogger, d.logger.Slog())
	d.brokerAuditWriter = auditWriter
	d.logger.Info(ctx, "broker stack: audit writer initialized")

	// --- 2. Circuit breaker ---
	cb := secrets.NewGobreakerExecutor(resilience.DefaultCircuitConfig())
	d.logger.Info(ctx, "broker stack: circuit breaker initialized")

	// --- 2b. JWT source cache (gibson#321) ---
	//
	// Wrap d.vaultJWTSource in a JWTCache so the background goroutine keeps
	// the SPIRE JWT-SVID warm, and per-tenant Vault auth round-trips read
	// directly from the cache without blocking on the SPIRE Workload API.
	//
	// Skip caching when the source is DisabledJWTSource (no real SPIRE
	// socket configured): Start() would succeed trivially but the source
	// always errors anyway, so no value is gained.
	if _, isDisabled := d.vaultJWTSource.(jwtsource.DisabledJWTSource); !isDisabled {
		cache := jwtsource.NewJWTCache(d.vaultJWTSource, d.vaultJWTAudience, d.logger.Slog())
		if err := cache.Start(ctx); err != nil {
			return fmt.Errorf("broker stack: JWT source cache: %w", err)
		}
		d.vaultJWTCache = cache
		d.vaultJWTSource = cache
		d.logger.Info(ctx, "broker stack: JWT source cache started",
			"audience", d.vaultJWTAudience,
		)
	} else {
		d.logger.Info(ctx, "broker stack: JWT source is disabled; skipping cache (no SPIRE source configured)")
	}

	// --- 3. System-tenant KEK (for TenantConfigStore) ---
	// Required to encrypt/decrypt per-tenant broker config blobs.
	var systemKEK []byte
	if d.keyProvider != nil {
		kek, err := d.keyProvider.GetEncryptionKey(ctx)
		if err != nil {
			d.logger.Warn(ctx, "broker stack: failed to retrieve system KEK; config store unavailable (broker config CRUD inoperable)",
				"error", err)
			// Non-fatal: continue with noop config getter; broker config CRUD inoperable.
		} else {
			systemKEK = kek
		}
	} else {
		d.logger.Warn(ctx, "broker stack: no key provider configured; broker config store unavailable")
	}

	// --- 4. Config store (optional — needs dashboard Postgres + KEK) ---
	//
	// The config store holds per-tenant broker configurations encrypted at rest.
	// When the dashboard Postgres is unavailable, broker config CRUD is inoperable
	// and the daemon cannot resolve any tenant's secrets provider.
	var configStore secrets.RegistryConfigGetter = &noopRegistryConfigGetter{}

	if len(systemKEK) == 32 && d.config.PlatformPostgres.Host != "" {
		pgxPool, err := d.dashboardPgxPool(ctx)
		if err != nil {
			d.logger.Warn(ctx, "broker stack: could not open pgxpool to dashboard Postgres; broker config CRUD unavailable",
				"error", err)
			// Non-fatal: continue with noop config getter.
		} else {
			tenantCfgStore, err := configstore.NewStore(pgxPool, systemKEK)
			if err != nil {
				d.logger.Warn(ctx, "broker stack: TenantConfigStore construction failed; broker config CRUD unavailable",
					"error", err)
				pgxPool.Close() // best-effort cleanup
			} else {
				// Build the provider factories for the config-store probe step.
				configFactories := map[string]secrets.ProviderFactory{
					"vault": func(blob []byte) (sdksecrets.Broker, error) {
						var cfg sdkvault.Config
						if err := json.Unmarshal(blob, &cfg); err != nil {
							return nil, fmt.Errorf("vault: unmarshal config: %w", err)
						}
						return sdkvault.New(ctx, cfg)
					},
					"awssm": func(blob []byte) (sdksecrets.Broker, error) {
						var cfg sdkawssm.Config
						if err := json.Unmarshal(blob, &cfg); err != nil {
							return nil, fmt.Errorf("awssm: unmarshal config: %w", err)
						}
						return sdkawssm.New(ctx, cfg)
					},
					"gcpsm": func(blob []byte) (sdksecrets.Broker, error) {
						var cfg sdkgcpsm.Config
						if err := json.Unmarshal(blob, &cfg); err != nil {
							return nil, fmt.Errorf("gcpsm: unmarshal config: %w", err)
						}
						return sdkgcpsm.New(ctx, cfg)
					},
					"azurekv": func(blob []byte) (sdksecrets.Broker, error) {
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
					d.configStore = cs
					d.brokerFactories = configFactories
					d.logger.Info(ctx, "broker stack: config store initialized (dashboard Postgres-backed)")
				}
			}
		}
	} else {
		d.logger.Info(ctx, "broker stack: config store not available (missing KEK or dashboard Postgres); broker config CRUD inoperable")
	}

	// --- 4b. Auth-token cache (Vault) ---
	//
	// The AuthCache prevents auth churn when the Vault provider instance is
	// rebuilt on registry Reload events. Both the factory (constructor) and
	// the refresh closure cooperate via a process-wide vaultRefreshLookup
	// keyed by a stable hash of the per-tenant Vault config blob. The
	// factory deposits the unmarshalled `sdkvault.Config` under the hash
	// key before calling `GetOrRefresh`; the refresh closure retrieves it,
	// mints a SPIRE JWT-SVID if the auth method requires one, and performs
	// the Vault login.
	//
	// This replaces an earlier design where the factory used
	// `cfg.Namespace` (e.g. "tenant-<id>") as the cache key and the
	// refresh closure tried to parse the same string as a TenantID and
	// look up the broker_config row in Postgres. That conflated two
	// different identifiers — the SaaS rendered template
	// "tenant-{tenant_id}" is NOT the tenant_id used to key the
	// `tenant_secrets_broker_config` table. Result: every authenticated
	// RPC after a fresh signup got `configstore: broker config not found`
	// and the circuit breaker opened (gibson#262).
	//
	// The blob-hash key sidesteps the problem entirely: identical configs
	// (same Address + Namespace + Auth) hash to the same key — exactly
	// what AuthCache needs for singleflight coalescing — and the refresh
	// closure no longer queries the config store at all because the
	// factory already supplied the live config via the lookup.
	//
	// Spec: vault-refresh-and-plugin-runtime Window 1, Requirement 1;
	// ADR-0009 (JWT-SPIFFE-everywhere); gibson#262 (regression close).
	vaultLookup := newVaultRefreshLookup()
	vaultAuthCache := secrets.NewAuthCache(
		func(ctx context.Context, key, _ string) (string, time.Duration, error) {
			cfg, ok := vaultLookup.get(key)
			if !ok {
				return "", 0, &sdkvault.VaultRefreshError{
					TenantID: key,
					Cause:    fmt.Errorf("vault refresh: no config registered for cache key %s", key),
				}
			}
			// JWT-SVID mint step (ADR-0009 + amendment docs#34) — no-op
			// for non-JWT auth methods.
			if err := stampVaultJWTOnConfig(ctx, &cfg, d.vaultJWTSource, d.vaultJWTAudience); err != nil {
				return "", 0, &sdkvault.VaultRefreshError{
					TenantID: key,
					Method:   cfg.Auth.Method,
					Cause:    err,
				}
			}
			freshToken, ttl, err := sdkvault.RefreshToken(ctx, cfg)
			if err != nil {
				return "", 0, &sdkvault.VaultRefreshError{
					TenantID: key,
					Method:   cfg.Auth.Method,
					Cause:    err,
				}
			}
			// Hash-only logging — raw token MUST NOT appear in any log
			// field.
			tokenHash := sha256.Sum256([]byte(freshToken))
			d.logger.Info(ctx, "vault.token.refreshed",
				"cache_key", key,
				"lease_duration_seconds", ttl.Seconds(),
				"token_hash", fmt.Sprintf("%x", tokenHash),
			)
			return freshToken, ttl, nil
		},
		d.logger.Slog(),
		nil, // production clock
	)
	d.vaultAuthCache = vaultAuthCache
	d.logger.Info(ctx, "broker stack: Vault auth cache initialized")

	// --- 5. Cloud provider factories for the Registry ---
	registryCfg := secrets.RegistryConfig{
		VaultFactory: func(blob []byte) (sdksecrets.Broker, error) {
			var cfg sdkvault.Config
			if err := json.Unmarshal(blob, &cfg); err != nil {
				return nil, fmt.Errorf("vault: unmarshal config: %w", err)
			}
			// Deposit the live config under a blob-hash key so the
			// refresh closure can find it without needing to consult
			// configStore. Coalesces concurrent factory invocations for
			// the same tenant onto a single auth round-trip via the
			// AuthCache's singleflight.
			key := vaultConfigCacheKey(blob)
			vaultLookup.put(key, cfg)
			// Per-operation token refresh: each KV call gets a fresh token
			// from AuthCache (cache-hit path: RWLock read + ~1 alloc).
			// Eliminates the stale-token circuit-open failure that occurs
			// when a static token cached in the provider expires mid-lifetime
			// (gibson#301).
			refresher := func(rCtx context.Context) (string, error) {
				return vaultAuthCache.GetOrRefresh(rCtx, key, "vault")
			}
			return sdkvault.NewWithRefresher(ctx, cfg, refresher)
		},
		AWSSMFactory: func(blob []byte) (sdksecrets.Broker, error) {
			var cfg sdkawssm.Config
			if err := json.Unmarshal(blob, &cfg); err != nil {
				return nil, fmt.Errorf("awssm: unmarshal config: %w", err)
			}
			return sdkawssm.New(ctx, cfg)
		},
		GCPSMFactory: func(blob []byte) (sdksecrets.Broker, error) {
			var cfg sdkgcpsm.Config
			if err := json.Unmarshal(blob, &cfg); err != nil {
				return nil, fmt.Errorf("gcpsm: unmarshal config: %w", err)
			}
			return sdkgcpsm.New(ctx, cfg)
		},
		AzureKVFactory: func(blob []byte) (sdksecrets.Broker, error) {
			var cfg sdkazurekv.Config
			if err := json.Unmarshal(blob, &cfg); err != nil {
				return nil, fmt.Errorf("azurekv: unmarshal config: %w", err)
			}
			return sdkazurekv.New(cfg)
		},
	}

	// --- 6. Registry ---
	registry, err := secrets.NewRegistry(configStore, registryCfg)
	if err != nil {
		return fmt.Errorf("broker stack: registry construction failed: %w", err)
	}
	d.logger.Info(ctx, "broker stack: registry initialized")

	// --- 7. Service ---
	svc, err := secrets.NewService(registry, cb, auditWriter)
	if err != nil {
		return fmt.Errorf("broker stack: service construction failed: %w", err)
	}
	d.logger.Info(ctx, "broker stack: secrets.Service initialized")

	// Store the registry on the daemon so the /readyz probe can call Health().
	d.secretsRegistry = registry

	// --- 8. Wire into handlers ---

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

	// --- 9. Subscribe to broker-config-change events ---
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
	d.logger.Info(ctx, "broker stack: initialized successfully; four cloud provider constructors registered")
	return nil
}

// dashboardPgxPool opens a pgxpool.Pool connection to the operator-shared
// dashboard Postgres database. This is used by the TenantConfigStore to persist
// per-tenant broker configurations. The pool is separate from the sql.DB pool
// used by other daemon services because TenantConfigStore requires pgx v5.
func (d *daemonImpl) dashboardPgxPool(ctx context.Context) (*pgxpool.Pool, error) {
	pgCfg := d.config.PlatformPostgres

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
// ErrBrokerConfigNotFound. Used when the dashboard Postgres or system KEK is
// unavailable at startup, rendering broker config CRUD inoperable.
type noopRegistryConfigGetter struct{}

func (n *noopRegistryConfigGetter) Get(_ context.Context, _ auth.TenantID) (secrets.BrokerConfig, error) {
	return secrets.BrokerConfig{}, secrets.ErrBrokerConfigNotFound
}
