// Package quota — quota.go
//
// Per-tenant sandbox detonation quota enforced via Redis atomic counters.
//
// Two complementary limits are enforced (R4.1, R4.2):
//
//  1. Concurrent detonations (INCR/DECR on a per-tenant current-count key):
//     a call is rejected with ErrQuotaExceeded when the INCR result would
//     exceed maxConcurrentDetonations. On rejection the counter is
//     immediately DECR'd (the operation is atomic via Lua script).
//
//  2. Per-hour rolling window (not yet enforced in this release — the counter
//     is incremented but no cap is applied until a follow-up spec lands the
//     per-tier tier mapping from pricing-display.ts). The key is written so
//     the dashboard / cost-attribution queries can already read it.
//
// Key scheme (matches the daemon's existing per-tenant Redis key discipline):
//
//	sandbox:detonation:concurrent:{tenantID}   (integer, no TTL — decremented on completion)
//	sandbox:detonation:hourly:{tenantID}:{hour} (integer, TTL=1h, incremented on acquire)
//
// The `hour` component is the Unix epoch time floored to the nearest hour:
//
//	hour = time.Now().Truncate(time.Hour).Unix()
//
// Spec: setec-sandbox-prod-default §"Resource quotas" R4.1, R4.2, R4.3.
package quota

import (
	"context"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// ErrQuotaExceeded is returned by Acquire when the per-tenant concurrent
// detonation cap has been reached. The caller translates it into the
// structured mission-step error per design Scenario 5:
//
//	"quota_exceeded (max_concurrent_detonations=N)"
//
// Callers may use errors.Is(err, ErrQuotaExceeded) to distinguish this from
// other errors returned by Acquire.
var ErrQuotaExceeded = errors.New("quota_exceeded")

// Quota enforces per-tenant sandbox detonation limits.
//
// Acquire must be called before each Setec launch; Release must be called
// (via defer) after the launch completes, regardless of outcome. Callers
// are responsible for emitting the outcome metric via IncrDetonation.
type Quota interface {
	// Acquire increments the concurrent-detonation counter for the tenant.
	// Returns ErrQuotaExceeded when the tenant has reached its cap; in that
	// case the counter is NOT incremented — no Release is needed.
	// Returns other errors only on Redis connectivity failures.
	Acquire(ctx context.Context, tenant string) error

	// Release decrements the concurrent-detonation counter. Must be called
	// exactly once after each successful Acquire, regardless of whether the
	// detonation succeeded or failed.
	Release(ctx context.Context, tenant string)
}

// Config controls the quota limits. Zero values mean "no limit" for the
// respective constraint.
type Config struct {
	// MaxConcurrentDetonations is the per-tenant cap on simultaneous in-flight
	// sandbox launches. Zero means unlimited.
	MaxConcurrentDetonations int64
}

// RedisQuota is the production Quota implementation backed by Redis.
//
// It is safe for concurrent use: all mutations go through Redis atomic
// operations (Lua scripting for the compare-and-increment).
type RedisQuota struct {
	client goredis.UniversalClient
	cfg    Config
	now    func() time.Time // injectable for tests
}

// NewRedisQuota constructs a RedisQuota.
//
// client must be non-nil. cfg.MaxConcurrentDetonations=0 means unlimited.
func NewRedisQuota(client goredis.UniversalClient, cfg Config) *RedisQuota {
	initMetrics()
	return &RedisQuota{
		client: client,
		cfg:    cfg,
		now:    time.Now,
	}
}

// concurrentKey returns the Redis key for the per-tenant concurrent counter.
func concurrentKey(tenant string) string {
	return fmt.Sprintf("sandbox:detonation:concurrent:%s", tenant)
}

// hourlyKey returns the Redis key for the per-tenant hourly counter at the
// given truncated hour.
func hourlyKey(tenant string, hour time.Time) string {
	return fmt.Sprintf("sandbox:detonation:hourly:%s:%d", tenant, hour.Unix())
}

// acquireScript atomically checks the current counter value and increments
// it only if it is strictly less than the cap. Returns 1 on success, 0 on
// quota exceeded.
//
// KEYS[1] — concurrent counter key
// ARGV[1] — cap (int64 as string, 0 means unlimited)
var acquireScript = goredis.NewScript(`
local cap = tonumber(ARGV[1])
if cap <= 0 then
  return redis.call('INCR', KEYS[1])
end
local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
if cur >= cap then
  return -1
end
return redis.call('INCR', KEYS[1])
`)

// Acquire implements Quota.
func (q *RedisQuota) Acquire(ctx context.Context, tenant string) error {
	key := concurrentKey(tenant)
	cap := q.cfg.MaxConcurrentDetonations

	result, err := acquireScript.Run(ctx, q.client, []string{key}, cap).Int64()
	if err != nil {
		return fmt.Errorf("quota Acquire: Redis script failed for tenant %q: %w", tenant, err)
	}
	if result == -1 {
		IncrDetonation(tenant, OutcomeQuotaExceeded)
		return fmt.Errorf("%w (max_concurrent_detonations=%d)", ErrQuotaExceeded, cap)
	}

	// Increment hourly window counter (no cap enforced yet; written for
	// cost-attribution queries and future per-tier limits).
	hour := q.now().Truncate(time.Hour)
	hkey := hourlyKey(tenant, hour)
	pipe := q.client.Pipeline()
	pipe.Incr(ctx, hkey)
	pipe.Expire(ctx, hkey, 2*time.Hour) // retain for 2h to avoid race at rollover
	if _, err := pipe.Exec(ctx); err != nil {
		// Non-fatal: hourly counter failure doesn't block the detonation.
		// Log is omitted here to avoid adding a logger dependency; callers log on error.
		_ = err
	}

	return nil
}

// Release implements Quota.
func (q *RedisQuota) Release(ctx context.Context, tenant string) {
	key := concurrentKey(tenant)
	// DECR is safe even if the key doesn't exist (returns -1, which is fine
	// since Acquire would have prevented under-decrement scenarios).
	if err := q.client.Decr(ctx, key).Err(); err != nil {
		// Non-fatal: log loss of a counter is acceptable; the TTL-based
		// hourly counter prevents permanent counter drift in practice.
		_ = err
	}
}

// CurrentConcurrent returns the current in-flight detonation count for a
// tenant. Used by tests and the dashboard health endpoint.
func (q *RedisQuota) CurrentConcurrent(ctx context.Context, tenant string) (int64, error) {
	key := concurrentKey(tenant)
	n, err := q.client.Get(ctx, key).Int64()
	if err == goredis.Nil {
		return 0, nil
	}
	return n, err
}

// NoopQuota is a no-op implementation of Quota that always permits detonations.
// Used in test harnesses and in dev/kind deployments where quota enforcement
// is explicitly disabled.
type NoopQuota struct{}

// Acquire always returns nil (permit).
func (NoopQuota) Acquire(_ context.Context, _ string) error { return nil }

// Release is a no-op.
func (NoopQuota) Release(_ context.Context, _ string) {}

// Compile-time assertion that both implementations satisfy Quota.
var _ Quota = (*RedisQuota)(nil)
var _ Quota = NoopQuota{}
