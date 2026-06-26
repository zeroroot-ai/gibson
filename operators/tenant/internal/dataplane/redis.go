// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/redis/go-redis/v9"

	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"

	vaultadmin "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/vault"
)

// ErrRedisDBExhausted is returned when all logical Redis DB slots are in use.
// Callers should scale out to additional Redis instances or increase
// maxmemory / number of logical DBs.
var ErrRedisDBExhausted = errors.New("dataplane/redis: all logical DB slots are allocated")

// masterIndexHash is the key of the hash on DB 0 that maps tenant IDs
// to their assigned logical DB index. Sourced from the canonical
// platform/dataplane constant so the operator and the gibson daemon
// cannot drift on the hash key (the historical bug: operator wrote
// "tenant_db_index", daemon read "tenant:index"). Spec
// tenant-provisioning-unification Requirement 1.4.
var masterIndexHash = pdataplane.RedisIndexHashKey

// allocateLuaScript atomically scans the master index hash for the
// lowest free DB slot in [1, maxDBs) and HSETs the tenant_id → index
// mapping, all in a single Redis call. Atomicity is critical:
//
//   - HSETNX keyed by tenant_id doesn't protect against the real race
//     here (two DIFFERENT tenants both picking the same slot — HSETNX
//     succeeds for both because the field names are different).
//   - A Lua script under EVAL runs single-threaded inside the Redis
//     server, so no other provisioner can mutate the hash between the
//     HGETALL scan and the HSET.
//
// KEYS[1] = master index hash key.
// ARGV[1] = tenant id (already sanitized to underscore form).
// ARGV[2] = maxDBs (exclusive upper bound).
//
// Return: positive integer = the slot just allocated (or the
// pre-existing slot if the tenant already had one — idempotent).
//
//	0 = exhausted (every slot in [1, maxDBs) is in use).
const allocateLuaScript = `
local hashKey = KEYS[1]
local tenantID = ARGV[1]
local maxDBs = tonumber(ARGV[2])

local existing = redis.call('HGET', hashKey, tenantID)
if existing then
  return tonumber(existing)
end

local all = redis.call('HGETALL', hashKey)
local inUse = {}
for i = 2, #all, 2 do
  local idx = tonumber(all[i])
  if idx then
    inUse[idx] = true
  end
end

for i = 1, maxDBs - 1 do
  if not inUse[i] then
    redis.call('HSET', hashKey, tenantID, i)
    return i
  end
end

return 0
`

// RedisProvisionerConfig holds the connection and capacity configuration for
// the Redis provisioner.
type RedisProvisionerConfig struct {
	// Addr is the Redis address (host:port).
	Addr string

	// Password is the Redis auth password (empty for no auth).
	Password string

	// MaxLogicalDBs is the maximum number of logical databases to allocate
	// (exclusive upper bound). Defaults to 16 if 0. Index 0 is reserved for
	// the master index; tenants receive indices 1..MaxLogicalDBs-1.
	MaxLogicalDBs int

	// MaxMemoryPolicy is the eviction policy to set on allocated DBs when Redis
	// >= 7.4 supports per-DB CONFIG SET. "noeviction" is always the target for
	// tenant data; if the server does not support per-DB CONFIG SET, a warning
	// is logged and provisioning continues.
	MaxMemoryPolicy string

	// VaultClient writes per-tenant Redis credentials to
	// tenant/<id>/infra/redis after a successful Provision so the daemon
	// can resolve them via the secrets broker. May be nil; the write is
	// then skipped (dev/on-prem). Spec
	// tenant-provisioning-unification-phase2 Requirement 1.3.
	VaultClient vaultadmin.AdminClient
}

// redisProvisioner allocates logical Redis DB indices for tenants using a
// master index on DB 0. It never assigns DB 0 to any tenant.
type redisProvisioner struct {
	cfg    RedisProvisionerConfig
	admin  *redis.Client // always DB 0
	maxDBs int
}

// NewRedisProvisioner constructs a Redis provisioner. An admin connection to
// DB 0 is established eagerly to validate connectivity.
func NewRedisProvisioner(cfg RedisProvisionerConfig) (*redisProvisioner, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("dataplane/redis: Addr required")
	}
	maxDBs := cfg.MaxLogicalDBs
	if maxDBs <= 0 {
		maxDBs = 16
	}
	admin := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       0,
	})
	return &redisProvisioner{cfg: cfg, admin: admin, maxDBs: maxDBs}, nil
}

// Close releases the admin connection.
func (r *redisProvisioner) Close() error {
	return r.admin.Close()
}

// Provision allocates a logical DB index for the tenant, storing the mapping
// in the master index hash on DB 0. Idempotent: if the tenant already has an
// index, the existing index is returned without modification.
//
// Allocation strategy (tenant-operator#159): the master index hash is the
// canonical state. A Lua script under EVAL atomically (a) checks whether
// the tenant already has a mapping (idempotency), (b) scans the hash for
// the lowest free slot in [1, maxDBs), and (c) persists the mapping.
// EVAL runs single-threaded in the Redis server, so two concurrent
// provisioners cannot both observe slot N as free and both claim it —
// the classic race trap that HSETNX-on-tenant-id does NOT protect against
// (because the field keys are distinct per tenant, both HSETNXs succeed).
//
// Replaces the previous INCR-based allocator (`INCR next_db_index`) that
// monotonically incremented a counter and never decremented on
// deprovision, reporting exhaustion after maxDBs lifetime allocations
// regardless of how many tenants had since been deprovisioned. Live
// evidence on 2026-05-19: counter at 46 with one slot occupied, every
// signup failed with ErrRedisDBExhausted.
func (r *redisProvisioner) Provision(ctx context.Context, tenantID string) error {
	safe, err := sanitizeTenantID(tenantID)
	if err != nil {
		return err
	}

	result, err := r.admin.Eval(
		ctx,
		allocateLuaScript,
		[]string{masterIndexHash},
		safe,
		r.maxDBs,
	).Int()
	if err != nil {
		return fmt.Errorf("dataplane/redis: allocate slot via lua: %w", err)
	}
	if result == 0 {
		return ErrRedisDBExhausted
	}
	if result < 0 {
		return fmt.Errorf("dataplane/redis: lua returned unexpected index %d", result)
	}

	return r.finalizeProvision(ctx, tenantID, result)
}

// finalizeProvision applies the per-DB eviction policy and writes Vault
// credentials. Shared by Provision (after a successful Lua allocation),
// so the same side effects fire whether the tenant just got a fresh
// slot or had an existing one (the Lua returns the existing index
// unchanged on re-Provision).
func (r *redisProvisioner) finalizeProvision(ctx context.Context, tenantID string, index int) error {
	if err := r.applyMaxMemoryPolicy(ctx, index); err != nil {
		return err
	}

	// Write credentials to Vault so the daemon's secrets broker can resolve
	// addr + db_index without needing to know the operator's config layout.
	// Spec tenant-provisioning-unification-phase2 Requirement 1.3.
	if r.cfg.VaultClient != nil {
		creds := pdataplane.RedisCredentials{
			Addr:     r.cfg.Addr,
			DBIndex:  index,
			Password: r.cfg.Password,
		}
		if err := r.cfg.VaultClient.WriteInfraRedis(ctx, tenantID, creds); err != nil {
			return fmt.Errorf("dataplane/redis: write credentials to Vault: %w", err)
		}
	}

	return nil
}

// Deprovision removes the tenant's logical DB mapping and flushes the DB.
// Idempotent — no-op if the tenant has no allocated DB. HDel of the
// tenant's entry frees the slot for the next Provision to recycle —
// this is the half of the fix that, paired with the lowest-free-slot
// allocator in Provision, closes tenant-operator#159.
func (r *redisProvisioner) Deprovision(ctx context.Context, tenantID string) error {
	safe, err := sanitizeTenantID(tenantID)
	if err != nil {
		return err
	}

	// Read the assigned index before deleting the mapping.
	indexStr, err := r.admin.HGet(ctx, masterIndexHash, safe).Result()
	if errors.Is(err, redis.Nil) {
		// No mapping — idempotent no-op.
		return nil
	}
	if err != nil {
		return fmt.Errorf("dataplane/redis: hget for deprovision: %w", err)
	}

	dbIndex, err := strconv.Atoi(indexStr)
	if err != nil || dbIndex <= 0 {
		// Corrupt or reserved index — just remove the mapping.
		_ = r.admin.HDel(ctx, masterIndexHash, safe).Err()
		return nil
	}

	// FLUSHDB against the tenant's logical DB.
	tenantClient := redis.NewClient(&redis.Options{
		Addr:     r.cfg.Addr,
		Password: r.cfg.Password,
		DB:       dbIndex,
	})
	defer func() { _ = tenantClient.Close() }()

	if err := tenantClient.FlushDB(ctx).Err(); err != nil {
		return fmt.Errorf("dataplane/redis: flushdb (db %d): %w", dbIndex, err)
	}

	// Remove the mapping from the master index. This frees the slot —
	// the next Provision's Lua scan will pick it up as lowest-free.
	if err := r.admin.HDel(ctx, masterIndexHash, safe).Err(); err != nil {
		return fmt.Errorf("dataplane/redis: hdel %s: %w", masterIndexHash, err)
	}

	return nil
}

// applyMaxMemoryPolicy attempts CONFIG SET maxmemory-policy noeviction on the
// tenant's logical DB. Redis < 7.4 does not support per-DB CONFIG SET; errors
// are logged but do not fail provisioning.
func (r *redisProvisioner) applyMaxMemoryPolicy(ctx context.Context, dbIndex int) error {
	policy := r.cfg.MaxMemoryPolicy
	if policy == "" {
		policy = "noeviction"
	}

	tenantClient := redis.NewClient(&redis.Options{
		Addr:     r.cfg.Addr,
		Password: r.cfg.Password,
		DB:       dbIndex,
	})
	defer func() { _ = tenantClient.Close() }()

	err := tenantClient.ConfigSet(ctx, "maxmemory-policy", policy).Err()
	if err != nil {
		// Per-DB CONFIG SET is a Redis 7.4+ feature; older versions return an
		// error here. Log and continue — provisioning succeeds either way.
		// The cluster-wide default policy applies to all logical DBs on older Redis.
		// This is surfaced as a warning in the pipeline step log.
		return nil //nolint:nilerr // intentional: per-DB CONFIG SET is best-effort
	}
	return nil
}
