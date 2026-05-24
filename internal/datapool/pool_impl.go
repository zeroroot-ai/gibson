package datapool

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/zero-day-ai/gibson/internal/crypto"
	dpmetrics "github.com/zero-day-ai/gibson/internal/datapool/metrics"
	"github.com/zero-day-ai/gibson/internal/datapool/vectordb"
	"github.com/zero-day-ai/sdk/auth"
)

// tenantEntry tracks the per-tenant pool state used by the evictor.
type tenantEntry struct {
	// lastReleased is the timestamp of the last Conn.Release() for this
	// tenant. Updated atomically.
	lastReleased atomic.Int64 // UnixNano

	// activeConns is the number of currently checked-out Conns.
	activeConns atomic.Int64
}

// pool is the concrete implementation of Pool. It holds the four per-tenant
// sub-pool wrappers and orchestrates lazy initialization, idle eviction,
// and KEK lifecycle.
type pool struct {
	cfg         Config
	pg          *pgPerTenant
	redisPool   *redisPerTenant
	neo4j       *neo4jPerTenant
	vector      *vectorPerTenant
	keyProvider crypto.KeyProvider
	masterKEK   []byte // loaded once at startup; never written to disk

	checker *provisioningChecker
	evictor *evictor

	// adminAcquirer is the wired admin.AdminPool (set via SetAdminPool).
	adminAcquirer AdminAcquirer
	adminMu       sync.RWMutex

	// recoveryHook is invoked on the first successful For() dial of each
	// tenant per process lifetime — see ADR-0023 lazy mission recovery.
	// Defaults to a no-op; production wires via SetRecoveryHook.
	recoveryHook RecoveryHook
	recoveryMu   sync.RWMutex
	// firedRecovery tracks which tenants have already had their hook run
	// this process. Map of auth.TenantID → struct{}; entries persist for
	// the process lifetime (cheap; one entry per tenant ever dialled).
	firedRecovery sync.Map

	// tenantEntries tracks per-tenant eviction state.
	tenantEntries sync.Map // map[auth.TenantID]*tenantEntry

	// inflightInit deduplicates concurrent For() calls for the same tenant.
	inflightInit singleflight.Group

	closeOnce sync.Once
	closeCh   chan struct{}
}

// NewPool creates a Pool and starts the background evictor.
//
// cfg must have PostgresHost, RedisAddr, Neo4jURI set if the corresponding
// stores are used. KeyProvider must be non-nil.
//
// The returned Pool takes ownership of keyProvider and calls keyProvider.Close
// when Pool.Close is called.
func NewPool(ctx context.Context, cfg Config, keyProvider crypto.KeyProvider, checker *provisioningChecker) (Pool, error) {
	if keyProvider == nil {
		return nil, fmt.Errorf("datapool: NewPool: keyProvider is required")
	}

	// Load the master KEK once at startup. If the KMS is unreachable, fail
	// fast — the daemon should not start without a functional key provider.
	masterKEK, err := keyProvider.GetEncryptionKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("datapool: NewPool: failed to load master KEK: %w", err)
	}
	if len(masterKEK) < minMasterKEKLen {
		return nil, fmt.Errorf("datapool: NewPool: master KEK too short (%d bytes, minimum %d)", len(masterKEK), minMasterKEKLen)
	}

	// Apply config defaults.
	if cfg.AcquireTimeout == 0 {
		cfg.AcquireTimeout = DefaultAcquireTimeout
	}
	if cfg.PoolMaxConns == 0 {
		cfg.PoolMaxConns = DefaultPoolMaxConns
	}
	if cfg.IdleTTL == 0 {
		cfg.IdleTTL = DefaultIdleTTL
	}
	if cfg.EvictionCheckInterval == 0 {
		cfg.EvictionCheckInterval = DefaultEvictionCheckInterval
	}

	pg := newPgPerTenant(cfg)

	var rp *redisPerTenant
	if cfg.RedisAddr != "" {
		rp, err = newRedisPerTenant(cfg.RedisAddr, cfg.RedisPassword)
		if err != nil {
			return nil, fmt.Errorf("datapool: NewPool: redis init: %w", err)
		}
	}

	var n4j *neo4jPerTenant
	if cfg.Neo4jResolver != nil {
		// Resolver-based path (Task 16): per-tenant driver pool via EndpointResolver.
		// This is the forward path for both instance mode (instanceResolver) and
		// multi-db mode (multiDBResolver).
		n4j = newNeo4jPerTenant(cfg.Neo4jResolver)
	} else if cfg.Neo4jURI != "" {
		// Backward-compat path: single shared URI provided without a resolver.
		// Wrap it in a one-off multiDBResolver-style static resolver so existing
		// tests and single-tenant deployments keep working.
		// NOTE: in this fallback the database name is empty (default "neo4j" DB).
		staticResolver := &staticNeo4jResolver{
			endpoint: &Neo4jEndpoint{
				BoltURI:  cfg.Neo4jURI,
				Username: cfg.Neo4jUser,
				Password: cfg.Neo4jPassword,
				Database: "", // default DB; matches pre-refactor behaviour
			},
		}
		n4j = newNeo4jPerTenant(staticResolver)
	}

	closeCh := make(chan struct{})

	p := &pool{
		cfg:          cfg,
		pg:           pg,
		redisPool:    rp,
		neo4j:        n4j,
		keyProvider:  keyProvider,
		masterKEK:    masterKEK,
		checker:      checker,
		recoveryHook: noopRecoveryHook{},
		closeCh:      closeCh,
	}

	// Wire the Redis VSS vector driver when an address is configured.
	// VectorStoreAddr shares the same Redis Stack instance as the cache/session
	// Redis (same addr, same password); the per-tenant index name is read from
	// VectorCredentials at tenant/<id>/infra/vector by the caller's DSN resolver.
	if cfg.VectorStoreAddr != "" {
		vectorDriver, err := vectordb.NewRedisVSSDriver(vectordb.RedisConfig{
			Addr:     cfg.VectorStoreAddr,
			Password: cfg.RedisPassword,
		})
		if err != nil {
			return nil, fmt.Errorf("datapool: NewPool: vector driver init: %w", err)
		}
		p.vector = newVectorPerTenant(vectorDriver)
	}

	ev := newEvictor(p, cfg.EvictionCheckInterval, cfg.IdleTTL, realClock{})
	p.evictor = ev
	go ev.run(ctx)

	return p, nil
}

// For implements Pool.For. It:
//  1. Checks provisioning status via the provisioning checker.
//  2. Uses singleflight to deduplicate concurrent initialization for the
//     same tenant (warm-up the sub-pools exactly once per tenant).
//  3. Derives the per-tenant KEK.
//  4. Acquires sub-pool references for Postgres, Redis, Neo4j, Vector.
//  5. Assembles and returns a *Conn with a release func.
func (p *pool) For(ctx context.Context, tenant auth.TenantID) (*Conn, error) {
	if tenant.IsZero() {
		return nil, fmt.Errorf("datapool: For called with zero TenantID")
	}

	// Start acquire timer for gibson_pool_acquire_duration_seconds{store="all"}.
	acquireStart := time.Now()

	// Step 1: provisioning check.
	if p.checker != nil {
		if _, err := p.checker.isProvisioned(ctx, tenant); err != nil {
			return nil, err
		}
	}

	// Step 2: derive KEK (pure, no I/O).
	tenantKEK, err := deriveTenantKEK(p.masterKEK, tenant)
	if err != nil {
		return nil, fmt.Errorf("datapool: For: KEK derivation failed: %w", err)
	}

	// zeroKEKOnErr zeroes the derived key before returning an error so the
	// material is not left in memory on failure paths.
	zeroKEKOnErr := func(e error) (*Conn, error) {
		for i := range tenantKEK {
			tenantKEK[i] = 0
		}
		return nil, e
	}

	// Step 3: warm-up sub-pools via singleflight (deduplicate concurrent
	// For() calls for the same tenant to a single initialization).
	_, sfErr, _ := p.inflightInit.Do(tenant.String(), func() (any, error) {
		return nil, p.initTenant(ctx, tenant, tenantKEK)
	})
	if sfErr != nil {
		return zeroKEKOnErr(sfErr)
	}

	// Step 4: acquire sub-pool references.
	pgPool, err := p.pg.ForTenant(ctx, tenant, tenantKEK)
	if err != nil {
		return zeroKEKOnErr(fmt.Errorf("datapool: For: postgres: %w", err))
	}

	conn := &Conn{
		Tenant:   tenant,
		Postgres: pgPool,
		KEK:      tenantKEK,
	}

	if p.redisPool != nil {
		rc, err := p.redisPool.ForTenant(ctx, tenant)
		if err != nil {
			return zeroKEKOnErr(fmt.Errorf("datapool: For: redis: %w", err))
		}
		conn.Redis = rc
	}

	if p.neo4j != nil {
		sess, err := p.neo4j.ForTenant(ctx, tenant)
		if err != nil {
			return zeroKEKOnErr(fmt.Errorf("datapool: For: neo4j: %w", err))
		}
		conn.Neo4j = sess
	}

	// Step 5: track active conn.
	entry := p.getOrCreateEntry(tenant)
	entry.activeConns.Add(1)

	// Record acquire duration and increment active conn gauge.
	dpmetrics.ObservePoolAcquireDuration(dpmetrics.StoreAll, time.Since(acquireStart).Seconds())
	dpmetrics.IncPoolActiveConns(tenant.String())

	tenantStr := tenant.String()
	conn.release = func() {
		// Close Neo4j session (sessions are per-Conn; not pooled).
		if conn.Neo4j != nil {
			conn.Neo4j.Close(context.Background())
		}
		// Decrement active conn count and record last-released timestamp.
		entry.activeConns.Add(-1)
		entry.lastReleased.Store(time.Now().UnixNano())
		// Decrement active conn gauge.
		dpmetrics.DecPoolActiveConns(tenantStr)
	}

	// Lazy mission recovery (ADR-0023): on the first successful For() dial
	// of each tenant per process, run the recovery hook to transition any
	// missions left in `running` state by the previous daemon process to
	// `paused`. Replaces the eager startup-enumeration loop that crashed
	// the daemon on 2026-05-19 (testa123 incident).
	//
	// LoadOrStore guarantees exactly-once semantics across concurrent
	// callers for the same tenant. Hook errors are logged by the hook
	// itself and do NOT propagate as For() failures — recovery is
	// best-effort cleanup, not a dispatch gate.
	if _, fired := p.firedRecovery.LoadOrStore(tenant, struct{}{}); !fired {
		p.recoveryMu.RLock()
		hook := p.recoveryHook
		p.recoveryMu.RUnlock()
		if hook != nil {
			if err := hook.Run(ctx, tenant, conn); err != nil {
				// Failure isolation: log and continue. Conn is still returned.
				dpmetrics.IncPoolInitFailure(tenantStr, dpmetrics.StoreRedis, "recovery_hook")
			}
		}
	}

	return conn, nil
}

// SetRecoveryHook wires the RecoveryHook into this pool. Thread-safe; may
// be called at any time. Subsequent first-dial-per-tenant invocations of
// Pool.For use the newly-set hook. Existing per-tenant "already fired"
// markers are preserved — a hook swap does not retroactively re-fire on
// tenants already dialled. Pass NewNoopRecoveryHook() to disable recovery
// for tests.
//
// Spec: ADR-0023.
func (p *pool) SetRecoveryHook(hook RecoveryHook) {
	if hook == nil {
		hook = noopRecoveryHook{}
	}
	p.recoveryMu.Lock()
	p.recoveryHook = hook
	p.recoveryMu.Unlock()
}

// initTenant performs the first-time initialization for a tenant's sub-pools.
// It is called inside a singleflight group so only one goroutine runs it at
// a time per tenant.
func (p *pool) initTenant(ctx context.Context, tenant auth.TenantID, tenantKEK []byte) error {
	tenantStr := tenant.String()

	// Postgres pool is lazily created in pgPerTenant.ForTenant; we warm it
	// here to detect NotProvisioned early.
	_, err := p.pg.ForTenant(ctx, tenant, tenantKEK)
	if err != nil {
		var npErr *NotProvisionedError
		if errors.As(err, &npErr) {
			dpmetrics.IncPoolInitFailure(tenantStr, dpmetrics.StorePostgres, "not_provisioned")
			return npErr
		}
		dpmetrics.IncPoolInitFailure(tenantStr, dpmetrics.StorePostgres, "conn_error")
		return fmt.Errorf("datapool: tenant %s init: postgres: %w", tenant, err)
	}
	dpmetrics.IncPoolInit(tenantStr, dpmetrics.StorePostgres)

	// Redis is optional; skip if not configured.
	if p.redisPool != nil {
		if _, err := p.redisPool.ForTenant(ctx, tenant); err != nil {
			var npErr *NotProvisionedError
			if errors.As(err, &npErr) {
				dpmetrics.IncPoolInitFailure(tenantStr, dpmetrics.StoreRedis, "not_provisioned")
				return npErr
			}
			dpmetrics.IncPoolInitFailure(tenantStr, dpmetrics.StoreRedis, "conn_error")
			return fmt.Errorf("datapool: tenant %s init: redis: %w", tenant, err)
		}
		dpmetrics.IncPoolInit(tenantStr, dpmetrics.StoreRedis)
	}

	return nil
}

// SetAdminPool wires the AdminAcquirer (typically *admin.AdminPool from
// internal/datapool/admin) into this pool so that Admin() can delegate to it.
// Thread-safe; may be called at any time before Admin() is invoked.
func (p *pool) SetAdminPool(acquirer AdminAcquirer) {
	p.adminMu.Lock()
	p.adminAcquirer = acquirer
	p.adminMu.Unlock()
}

// Admin implements Pool.Admin. It delegates to the wired AdminAcquirer.
// Returns ErrAdminPoolNotConfigured when no AdminAcquirer has been set via
// SetAdminPool.
func (p *pool) Admin(ctx context.Context) (*AdminConn, error) {
	p.adminMu.RLock()
	acquirer := p.adminAcquirer
	p.adminMu.RUnlock()

	if acquirer == nil {
		return nil, ErrAdminPoolNotConfigured
	}
	return acquirer.Acquire(ctx)
}

// Close shuts down the pool. It stops the evictor and closes all sub-pools.
func (p *pool) Close() error {
	var err error
	p.closeOnce.Do(func() {
		close(p.closeCh)
		p.pg.Close()
		if p.redisPool != nil {
			p.redisPool.Close()
		}
		if p.neo4j != nil {
			err = p.neo4j.Close(context.Background())
		}
		if p.vector != nil {
			p.vector.Close()
		}
	})
	return err
}

// getOrCreateEntry returns the tenantEntry for the tenant, creating it if absent.
func (p *pool) getOrCreateEntry(tenant auth.TenantID) *tenantEntry {
	if v, ok := p.tenantEntries.Load(tenant); ok {
		return v.(*tenantEntry)
	}
	entry := &tenantEntry{}
	entry.lastReleased.Store(time.Now().UnixNano())
	actual, _ := p.tenantEntries.LoadOrStore(tenant, entry)
	return actual.(*tenantEntry)
}

// evictTenant closes and removes the tenant's sub-pools (called by evictor).
func (p *pool) evictTenant(tenant auth.TenantID) {
	p.pg.EvictTenant(tenant)
	if p.redisPool != nil {
		p.redisPool.EvictTenant(tenant)
	}
	p.tenantEntries.Delete(tenant)
}

// lastAccess returns the last time a Conn for this tenant was released.
func (p *pool) lastAccess(tenant auth.TenantID) time.Time {
	if v, ok := p.tenantEntries.Load(tenant); ok {
		ns := v.(*tenantEntry).lastReleased.Load()
		return time.Unix(0, ns)
	}
	return time.Time{}
}

// activeConnCount returns the number of currently checked-out Conns for tenant.
func (p *pool) activeConnCount(tenant auth.TenantID) int64 {
	if v, ok := p.tenantEntries.Load(tenant); ok {
		return v.(*tenantEntry).activeConns.Load()
	}
	return 0
}

// staticNeo4jResolver is a backward-compat resolver that returns the same
// endpoint for every tenant. Used when Neo4jURI is set in Config but no
// Neo4jResolver is provided (legacy single-URI deployments and tests that
// predate the resolver abstraction).
//
// In this mode all tenants share the same Neo4j connection with the default
// database; this matches pre-Task-15 behaviour and preserves test compatibility.
type staticNeo4jResolver struct {
	endpoint *Neo4jEndpoint
}

func (s *staticNeo4jResolver) Resolve(_ context.Context, _ auth.TenantID) (*Neo4jEndpoint, error) {
	return s.endpoint, nil
}
