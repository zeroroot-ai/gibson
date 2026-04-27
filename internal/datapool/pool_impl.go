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
		rp, err = newRedisPerTenant(cfg.RedisAddr)
		if err != nil {
			return nil, fmt.Errorf("datapool: NewPool: redis init: %w", err)
		}
	}

	var n4j *neo4jPerTenant
	if cfg.Neo4jURI != "" {
		n4j, err = newNeo4jPerTenant(cfg.Neo4jURI, cfg.Neo4jUser, cfg.Neo4jPassword)
		if err != nil {
			return nil, fmt.Errorf("datapool: NewPool: neo4j init: %w", err)
		}
	}

	closeCh := make(chan struct{})

	p := &pool{
		cfg:         cfg,
		pg:          pg,
		redisPool:   rp,
		neo4j:       n4j,
		keyProvider: keyProvider,
		masterKEK:   masterKEK,
		checker:     checker,
		closeCh:     closeCh,
	}

	// For now, the vector driver is nil (B2 TODO stub). Wired when Phase B2 is
	// fully implemented with a real Qdrant driver.
	// p.vector = newVectorPerTenant(driver)

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

	conn.release = func() {
		// Close Neo4j session (sessions are per-Conn; not pooled).
		if conn.Neo4j != nil {
			conn.Neo4j.Close(context.Background())
		}
		// Decrement active conn count and record last-released timestamp.
		entry.activeConns.Add(-1)
		entry.lastReleased.Store(time.Now().UnixNano())
	}

	return conn, nil
}

// initTenant performs the first-time initialization for a tenant's sub-pools.
// It is called inside a singleflight group so only one goroutine runs it at
// a time per tenant.
func (p *pool) initTenant(ctx context.Context, tenant auth.TenantID, tenantKEK []byte) error {
	// Postgres pool is lazily created in pgPerTenant.ForTenant; we warm it
	// here to detect NotProvisioned early.
	_, err := p.pg.ForTenant(ctx, tenant, tenantKEK)
	if err != nil {
		var npErr *NotProvisionedError
		if errors.As(err, &npErr) {
			return npErr
		}
		return fmt.Errorf("datapool: tenant %s init: postgres: %w", tenant, err)
	}

	// Redis is optional; skip if not configured.
	if p.redisPool != nil {
		if _, err := p.redisPool.ForTenant(ctx, tenant); err != nil {
			var npErr *NotProvisionedError
			if errors.As(err, &npErr) {
				return npErr
			}
			return fmt.Errorf("datapool: tenant %s init: redis: %w", tenant, err)
		}
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
