package daemon

import (
	"context"
	"errors"
	"log/slog"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/idempotency"
)

// redisIdemBackend wraps *goredis.Client to satisfy the idempotency package's
// redisBackend interface. It lives here (internal/daemon is on the raw-store
// allowlist) rather than in internal/idempotency, keeping the idempotency
// package free of the raw redis client import per database-per-tenant-data-plane
// Requirement 16.1.
type redisIdemBackend struct {
	c *goredis.Client
}

func (r *redisIdemBackend) GetBytes(ctx context.Context, key string) ([]byte, error) {
	b, err := r.c.Get(ctx, key).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, nil
	}
	return b, err
}

func (r *redisIdemBackend) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	return r.c.SetNX(ctx, key, value, ttl).Result()
}

func (r *redisIdemBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return r.c.Set(ctx, key, value, ttl).Err()
}

// NewRedisIdempotencyStore creates an idempotency.RedisStore backed by c.
func NewRedisIdempotencyStore(c *goredis.Client, logger *slog.Logger) *idempotency.RedisStore {
	return idempotency.NewRedisStore(&redisIdemBackend{c: c}, logger)
}
