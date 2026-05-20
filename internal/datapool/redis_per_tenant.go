package datapool

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	redis "github.com/redis/go-redis/v9"
	pcpools "github.com/zero-day-ai/platform-clients/pools"
	"github.com/zero-day-ai/sdk/auth"

	pdataplane "github.com/zero-day-ai/gibson/pkg/platform/dataplane"
)

// redisProductionOpts are the required connection lifecycle settings for
// per-tenant Redis clients, enforced via platform-clients/pools so that the
// daemon uses the same validated defaults as every other platform service.
//
// Values:
//   - PoolSize: 10 connections per tenant (matches DefaultPoolMaxConns).
//   - DialTimeout: 5 s — connection establishment timeout.
//   - ReadTimeout: 3 s — per-command socket read timeout.
//   - WriteTimeout: 3 s — per-command socket write timeout.
//   - ConnMaxLifetime: 30 m — connections older than this are recycled.
//
// Spec: zero-day-ai/.github#101 audit P1 (missing ConnMaxLifetime).
var redisProductionOpts = pcpools.RedisOptions{
	PoolSize:        10,
	DialTimeout:     5 * time.Second,
	ReadTimeout:     3 * time.Second,
	WriteTimeout:    3 * time.Second,
	ConnMaxLifetime: 30 * time.Minute,
}

// redisMasterIndexKey is the hash key in db 0 that maps tenant ID →
// logical DB index. Written by the tenant-operator on tenant provision.
// Sourced from the canonical platform/dataplane constant so the daemon
// and the operator cannot drift on this key (the historical bug:
// operator wrote "tenant_db_index", daemon read "tenant:index"). Spec
// tenant-provisioning-unification Requirement 1.4.
var redisMasterIndexKey = pdataplane.RedisIndexHashKey

// redisDB0 is the master index database. Never returned to handler code.
const redisDB0 = 0

// redisPerTenant manages per-tenant *redis.Client instances. Each tenant
// gets a client bound to their dedicated logical DB (resolved from the master
// index in db 0).
//
// The admin client (db 0) is held internally for index lookups; it is never
// returned to handler code.
type redisPerTenant struct {
	mu          sync.Mutex
	clients     map[auth.TenantID]*redis.Client
	dbIndexes   map[auth.TenantID]int // in-process cache: tenant → db index
	adminClient *redis.Client         // db 0 only — for master index lookups
	addr        string
	closed      bool
}

func newRedisPerTenant(addr string) (*redisPerTenant, error) {
	if addr == "" {
		return nil, fmt.Errorf("datapool: redis: addr is required")
	}
	adminClient := redis.NewClient(&redis.Options{
		Addr:            addr,
		DB:              redisDB0,
		PoolSize:        redisProductionOpts.PoolSize,
		DialTimeout:     redisProductionOpts.DialTimeout,
		ReadTimeout:     redisProductionOpts.ReadTimeout,
		WriteTimeout:    redisProductionOpts.WriteTimeout,
		ConnMaxLifetime: redisProductionOpts.ConnMaxLifetime,
	})
	return &redisPerTenant{
		clients:     make(map[auth.TenantID]*redis.Client),
		dbIndexes:   make(map[auth.TenantID]int),
		adminClient: adminClient,
		addr:        addr,
	}, nil
}

// ForTenant returns a *redis.Client bound to the tenant's logical DB. The
// DB index is resolved from the master index (db 0) on first call and cached
// in-process thereafter.
//
// Returns *NotProvisionedError if the tenant has no entry in the master index.
// Never returns a client pointing at db 0.
func (r *redisPerTenant) ForTenant(ctx context.Context, tenant auth.TenantID) (*redis.Client, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, fmt.Errorf("datapool: redis: pool is closed")
	}
	if client, ok := r.clients[tenant]; ok {
		r.mu.Unlock()
		return client, nil
	}
	r.mu.Unlock()

	// Resolve DB index from master index.
	dbIndex, err := r.resolveDBIndex(ctx, tenant)
	if err != nil {
		return nil, err
	}

	// Guard: never hand out a client that points at the master index DB.
	if dbIndex == redisDB0 {
		return nil, &NotProvisionedError{
			Tenant: tenant.String(),
			Reason: "tenant mapped to master index db 0, which is reserved",
		}
	}

	// Apply required connection lifecycle settings enforced by platform-clients/pools.
	// ConnMaxLifetime is required; omitting it leaves connections open indefinitely
	// (audit finding P1, zero-day-ai/.github#101).
	client := redis.NewClient(&redis.Options{
		Addr:            r.addr,
		DB:              dbIndex,
		PoolSize:        redisProductionOpts.PoolSize,
		DialTimeout:     redisProductionOpts.DialTimeout,
		ReadTimeout:     redisProductionOpts.ReadTimeout,
		WriteTimeout:    redisProductionOpts.WriteTimeout,
		ConnMaxLifetime: redisProductionOpts.ConnMaxLifetime,
	})

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		client.Close()
		return nil, fmt.Errorf("datapool: redis: pool closed during init")
	}
	// Double-check after lock.
	if existing, ok := r.clients[tenant]; ok {
		client.Close()
		return existing, nil
	}
	r.clients[tenant] = client
	return client, nil
}

// resolveDBIndex looks up the tenant's logical DB index from the master
// index. The result is cached in-process after the first lookup.
func (r *redisPerTenant) resolveDBIndex(ctx context.Context, tenant auth.TenantID) (int, error) {
	r.mu.Lock()
	if idx, ok := r.dbIndexes[tenant]; ok {
		r.mu.Unlock()
		return idx, nil
	}
	r.mu.Unlock()

	// HGET gibson:tenant:index <tenantID>
	val, err := r.adminClient.HGet(ctx, redisMasterIndexKey, tenant.String()).Result()
	if err == redis.Nil {
		return 0, &NotProvisionedError{
			Tenant: tenant.String(),
			Reason: "no logical DB index found in Redis master index (gibson:tenant:index)",
		}
	}
	if err != nil {
		return 0, fmt.Errorf("datapool: redis: master index lookup for tenant %s failed: %w", tenant, err)
	}

	idx, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("datapool: redis: invalid DB index %q for tenant %s: %w", val, tenant, err)
	}

	r.mu.Lock()
	r.dbIndexes[tenant] = idx
	r.mu.Unlock()

	return idx, nil
}

// EvictTenant closes and removes the tenant's client if present.
func (r *redisPerTenant) EvictTenant(tenant auth.TenantID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if client, ok := r.clients[tenant]; ok {
		client.Close()
		delete(r.clients, tenant)
	}
	delete(r.dbIndexes, tenant)
}

// Close closes all tenant clients and the admin client.
func (r *redisPerTenant) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	for id, client := range r.clients {
		client.Close()
		delete(r.clients, id)
	}
	if r.adminClient != nil {
		r.adminClient.Close()
	}
}
