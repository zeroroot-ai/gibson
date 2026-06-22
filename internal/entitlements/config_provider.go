package entitlements

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"
)

// configProvider is the OSS default Provider: it derives Limits from
// admin-set quota config stored in the platform Postgres `tenant_quotas`
// row. It reads ONLY the bare limit columns — it does not look at, depend
// on, or expose the plan_id column or any payment state. The plan_id column
// is written by the commercial operator path (gibson#798/E4) for the billing
// page's benefit; the OSS runtime is blind to it.
//
// Absence of a row, or a daemon started without a platform DB, means
// "unlimited on every dimension" — the permissive OSS default.
type configProvider struct {
	db       *sql.DB
	cacheTTL time.Duration

	mu    sync.RWMutex
	cache map[string]limitsCacheEntry
}

type limitsCacheEntry struct {
	limits   Limits
	expireAt time.Time
}

// DefaultProviderTTL is the in-process cache lifetime for a config-driven
// limits read. Matches the pre-seam QuotaManager cache window.
const DefaultProviderTTL = 60 * time.Second

// NewConfigProvider constructs the OSS default Provider backed by the
// platform Postgres pool. db may be nil (dev/kind without a platform DB), in
// which case every tenant is unlimited. The returned provider is safe for
// concurrent use.
func NewConfigProvider(db *sql.DB) Provider {
	return &configProvider{
		db:       db,
		cacheTTL: DefaultProviderTTL,
		cache:    make(map[string]limitsCacheEntry),
	}
}

// Limits implements Provider. It serves a cached value when fresh, otherwise
// reads the admin-set quota row. A missing row or nil DB yields the zero
// (unlimited) Limits value with no error.
func (p *configProvider) Limits(ctx context.Context, tenantID string) (Limits, error) {
	if tenantID == "" {
		return Limits{}, fmt.Errorf("entitlements: tenant must not be empty")
	}

	p.mu.RLock()
	if e, ok := p.cache[tenantID]; ok && time.Now().Before(e.expireAt) {
		p.mu.RUnlock()
		return e.limits, nil
	}
	p.mu.RUnlock()

	if p.db == nil {
		return Limits{}, nil
	}

	lim, err := p.read(ctx, tenantID)
	if err != nil {
		return Limits{}, err
	}
	p.mu.Lock()
	p.cache[tenantID] = limitsCacheEntry{limits: lim, expireAt: time.Now().Add(p.cacheTTL)}
	p.mu.Unlock()
	return lim, nil
}

// read performs the SELECT against tenant_quotas. A missing row returns the
// zero (unlimited) Limits value with no error.
func (p *configProvider) read(ctx context.Context, tenantID string) (Limits, error) {
	const q = `
		SELECT concurrent_missions, concurrent_agents, concurrent_connectors
		FROM tenant_quotas
		WHERE tenant_id = $1
	`
	var lim Limits
	err := p.db.QueryRowContext(ctx, q, tenantID).Scan(
		&lim.ConcurrentMissions,
		&lim.ConcurrentAgents,
		&lim.ConcurrentConnectors,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Limits{}, nil
	}
	if err != nil {
		return Limits{}, fmt.Errorf("entitlements: read tenant_quotas for %s: %w", tenantID, err)
	}
	return lim, nil
}

// Invalidate drops the cached Limits for one tenant so the next read
// reflects a just-written quota change immediately.
func (p *configProvider) Invalidate(tenantID string) {
	p.mu.Lock()
	delete(p.cache, tenantID)
	p.mu.Unlock()
}

// Prime seeds the cache for a tenant. Used by tests (and any future
// push-based limits source) to install limits without a DB round-trip.
func (p *configProvider) Prime(tenantID string, lim Limits) {
	p.mu.Lock()
	if p.cache == nil {
		p.cache = make(map[string]limitsCacheEntry)
	}
	p.cache[tenantID] = limitsCacheEntry{limits: lim, expireAt: time.Now().Add(p.cacheTTL)}
	p.mu.Unlock()
}

// Invalidator is the optional cache-control surface a Provider may expose so
// callers that have just written limits can force a fresh read. The OSS
// configProvider satisfies it; the UnlimitedProvider does not (nothing to
// invalidate).
type Invalidator interface {
	Invalidate(tenantID string)
}
