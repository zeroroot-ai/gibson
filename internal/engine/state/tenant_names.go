// Package state — tenant-name resolver.
//
// The daemon's ListMyMemberships RPC needs a friendly display name for each
// tenant ID it returns. The display name lives on the Tenant CR's spec, but
// the daemon does NOT hold cluster-wide K8s RBAC for Tenant reads — that
// permission stays on the tenant-operator. Instead, the operator publishes
// the name into Redis on every reconcile, and the daemon reads it from
// there with a tight timeout. On miss or timeout the daemon falls back to
// the tenant ID, so the membership RPC never blocks on the name lookup.

package state

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"
)

// tenantNameTimeout caps Redis latency for a single GetTenantName call.
// On timeout the caller falls back to the tenant ID.
const tenantNameTimeout = 100 * time.Millisecond

// TenantNameKey returns the canonical Redis key used by both the daemon
// reader and the tenant-operator writer. Exported so the operator can call
// the same builder.
func TenantNameKey(tenantID string) string {
	return "tenant:name:" + tenantID
}

var tenantNameCacheMisses = promauto.NewCounter(prometheus.CounterOpts{
	Name: "gibson_tenant_name_cache_miss_total",
	Help: "Number of tenant-name lookups that fell back to the tenant ID (cache miss or Redis timeout).",
})

// GetTenantName returns the display name for a tenant from the Redis cache.
//
// Returns (name, true, nil) on cache hit, ("", false, nil) on miss (the
// caller should fall back to the tenant ID), and ("", false, err) only on
// a real Redis error other than redis.Nil.
//
// A 100 ms timeout is enforced internally so a stalled Redis cannot hold up
// the membership RPC. Timeout is treated as a miss, not an error, and the
// miss counter is incremented.
func GetTenantName(ctx context.Context, c *StateClient, tenantID string) (string, bool, error) {
	if c == nil || tenantID == "" {
		return "", false, nil
	}

	callCtx, cancel := context.WithTimeout(ctx, tenantNameTimeout)
	defer cancel()

	val, err := c.Client().Get(callCtx, TenantNameKey(tenantID)).Result()
	switch {
	case err == redis.Nil:
		tenantNameCacheMisses.Inc()
		return "", false, nil
	case err != nil:
		// Treat timeouts and transient errors as misses — the membership RPC
		// MUST NOT fail on name resolution.
		if callCtx.Err() != nil {
			tenantNameCacheMisses.Inc()
			return "", false, nil
		}
		return "", false, err
	}
	if val == "" {
		tenantNameCacheMisses.Inc()
		return "", false, nil
	}
	return val, true, nil
}

// SetTenantName writes the display name for a tenant into the Redis cache.
// The tenant-operator calls this on every Tenant CR reconcile so the cache
// stays in sync with the source of truth on the CR.
//
// No TTL is applied — the operator owns the lifecycle and removes entries
// via DeleteTenantName on Tenant deletion.
func SetTenantName(ctx context.Context, c *StateClient, tenantID, name string) error {
	if c == nil || tenantID == "" {
		return nil
	}
	return c.Client().Set(ctx, TenantNameKey(tenantID), name, 0).Err()
}

// DeleteTenantName removes the cached display name for a tenant. Called by
// the tenant-operator on Tenant CR deletion to keep the cache from
// accumulating stale entries.
func DeleteTenantName(ctx context.Context, c *StateClient, tenantID string) error {
	if c == nil || tenantID == "" {
		return nil
	}
	return c.Client().Del(ctx, TenantNameKey(tenantID)).Err()
}
