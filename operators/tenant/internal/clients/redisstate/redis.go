// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package redisstate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/infra/pools"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/metrics"
)

// RedisClient implements Client against a Redis Stack instance.
type RedisClient struct {
	rdb             *pools.CircuitRedisClient
	deleteBatchSize int
	deleteSleep     time.Duration
}

// NewRedisClient constructs a Redis-backed client using pools.NewRedis so all
// pool parameters are explicitly set (P1 finding: zero pool config).
func NewRedisClient(cfg Config) (*RedisClient, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("redisstate: Addr required: %w", clients.ErrInvalidInput)
	}
	rdb, err := pools.NewRedis(pools.RedisOptions{
		Addr:            cfg.Addr,
		Password:        cfg.Password,
		DB:              cfg.DB,
		PoolSize:        10,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
		ConnMaxLifetime: 30 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("redisstate: %w", err)
	}
	batch := cfg.DeleteBatchSize
	if batch <= 0 {
		batch = 1000
	}
	sleep := cfg.DeleteSleep
	if sleep <= 0 {
		sleep = 100 * time.Millisecond
	}
	return &RedisClient{rdb: rdb, deleteBatchSize: batch, deleteSleep: sleep}, nil
}

// InitTenantKeyspace implements Client.
func (c *RedisClient) InitTenantKeyspace(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("redisstate: tenantID required: %w", clients.ErrInvalidInput)
	}
	start := time.Now()
	key := fmt.Sprintf("tenant:%s:initialized", tenantID)
	err := mapRedisError(c.rdb.Unwrap().Set(ctx, key, time.Now().UTC().Format(time.RFC3339), 0).Err())
	metrics.ObserveSubsystemCall("redis", "InitTenantKeyspace", start, err)
	return err
}

// Exists implements Client.
func (c *RedisClient) Exists(ctx context.Context, tenantID string) (bool, error) {
	if tenantID == "" {
		return false, fmt.Errorf("redisstate: tenantID required: %w", clients.ErrInvalidInput)
	}
	start := time.Now()
	key := fmt.Sprintf("tenant:%s:initialized", tenantID)
	n, err := c.rdb.Unwrap().Exists(ctx, key).Result()
	mapped := mapRedisError(err)
	metrics.ObserveSubsystemCall("redis", "Exists", start, mapped)
	if mapped != nil {
		return false, mapped
	}
	return n > 0, nil
}

// DeleteTenantKeyspace implements Client. Uses SCAN with rate limiting.
func (c *RedisClient) DeleteTenantKeyspace(ctx context.Context, tenantID string) (int64, error) {
	if tenantID == "" {
		return 0, fmt.Errorf("redisstate: tenantID required: %w", clients.ErrInvalidInput)
	}
	start := time.Now()
	pattern := fmt.Sprintf("tenant:%s:*", tenantID)
	var cursor uint64
	var total int64
	for {
		keys, next, err := c.rdb.Unwrap().Scan(ctx, cursor, pattern, int64(c.deleteBatchSize)).Result()
		if err != nil {
			mapped := mapRedisError(err)
			metrics.ObserveSubsystemCall("redis", "DeleteTenantKeyspace", start, mapped)
			return total, mapped
		}
		if len(keys) > 0 {
			if err := c.rdb.Unwrap().Del(ctx, keys...).Err(); err != nil {
				mapped := mapRedisError(err)
				metrics.ObserveSubsystemCall("redis", "DeleteTenantKeyspace", start, mapped)
				return total, mapped
			}
			total += int64(len(keys))
		}
		cursor = next
		if cursor == 0 {
			break
		}
		// Rate limit between batches so we don't starve other Redis traffic.
		select {
		case <-ctx.Done():
			metrics.ObserveSubsystemCall("redis", "DeleteTenantKeyspace", start, ctx.Err())
			return total, ctx.Err()
		case <-time.After(c.deleteSleep):
		}
	}
	metrics.ObserveSubsystemCall("redis", "DeleteTenantKeyspace", start, nil)
	return total, nil
}

// Ping implements Client. Sends a PING command and returns an error if Redis
// is unreachable.
func (c *RedisClient) Ping(ctx context.Context) error {
	if err := c.rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redisstate: ping: %w", mapRedisError(err))
	}
	return nil
}

// tenantNameKey is the canonical key the daemon's GetTenantName reader
// consumes. Keep in sync with core/gibson/internal/state/tenant_names.go.
func tenantNameKey(tenantID string) string {
	return "tenant:name:" + tenantID
}

// PublishTenantName implements Client. Writes the friendly display name for
// a tenant into the cache the daemon's ListMyMemberships handler reads.
// Idempotent — safe to call on every reconcile.
func (c *RedisClient) PublishTenantName(ctx context.Context, tenantID, name string) error {
	if tenantID == "" {
		return fmt.Errorf("redisstate: tenantID required: %w", clients.ErrInvalidInput)
	}
	start := time.Now()
	err := mapRedisError(c.rdb.Unwrap().Set(ctx, tenantNameKey(tenantID), name, 0).Err())
	metrics.ObserveSubsystemCall("redis", "PublishTenantName", start, err)
	return err
}

// DeleteTenantName implements Client. Removes the tenant-name cache entry.
func (c *RedisClient) DeleteTenantName(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("redisstate: tenantID required: %w", clients.ErrInvalidInput)
	}
	start := time.Now()
	err := mapRedisError(c.rdb.Unwrap().Del(ctx, tenantNameKey(tenantID)).Err())
	metrics.ObserveSubsystemCall("redis", "DeleteTenantName", start, err)
	return err
}

func mapRedisError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, redis.Nil) {
		return fmt.Errorf("%w", clients.ErrNotFound)
	}
	// Network / I/O errors are transient.
	return fmt.Errorf("redis: %v: %w", err, clients.ErrUnreachable)
}
