// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package signupprogress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/infra/pools"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/metrics"
)

// RedisClient implements Client against a Redis instance. The wire
// encoding is JSON to match the dashboard's `setJSON`/`getJSON` helpers.
type RedisClient struct {
	rdb       *redis.Client
	ttl       time.Duration
	keyPrefix string
}

// NewRedisClient constructs a Redis-backed Client. Redis is required
// infrastructure (one-code-path epic / deploy#199): an empty cfg.Addr
// returns an error instead of the previous (nil, nil) sentinel — the
// operator's main wiring exits 1 on the error and never reaches a
// degraded "no Redis" state.
//
// The caller is responsible for calling Close when shutting down.
func NewRedisClient(cfg Config) (*RedisClient, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("signupprogress: Addr is empty — Redis is required infrastructure (one-code-path epic / deploy#199)")
	}
	rdb, err := pools.NewRedis(pools.RedisOptions{
		Addr:            cfg.Addr,
		Password:        cfg.Password,
		DB:              cfg.DB,
		PoolSize:        5,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
		ConnMaxLifetime: 30 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("signupprogress: %w", err)
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}
	return &RedisClient{
		rdb:       rdb.Unwrap(),
		ttl:       ttl,
		keyPrefix: prefix,
	}, nil
}

// NewRedisClientFromRedis is a test-friendly constructor that wraps an
// existing *redis.Client (e.g., from miniredis or a docker-spawned Vault
// container's sidecar Redis). Production code should use NewRedisClient.
func NewRedisClientFromRedis(rdb *redis.Client, ttl time.Duration, keyPrefix string) *RedisClient {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if keyPrefix == "" {
		keyPrefix = DefaultKeyPrefix
	}
	return &RedisClient{
		rdb:       rdb,
		ttl:       ttl,
		keyPrefix: keyPrefix,
	}
}

// Close terminates the underlying Redis connection. Safe to call on a
// nil client (returns nil) so the operator's shutdown path can call it
// unconditionally regardless of degraded-mode wiring.
func (c *RedisClient) Close() error {
	if c == nil || c.rdb == nil {
		return nil
	}
	return c.rdb.Close()
}

// Advance implements Client.
func (c *RedisClient) Advance(ctx context.Context, attemptID string, step Step) error {
	if attemptID == "" {
		return nil
	}
	return c.publish(ctx, attemptID, Progress{
		Step:          step,
		StepStartedAt: time.Now().UnixMilli(),
		TerminalState: TerminalNone,
	})
}

// Complete implements Client.
func (c *RedisClient) Complete(ctx context.Context, attemptID string, step Step) error {
	if attemptID == "" {
		return nil
	}
	return c.publish(ctx, attemptID, Progress{
		Step:          step,
		StepStartedAt: time.Now().UnixMilli(),
		TerminalState: TerminalOK,
	})
}

// Fail implements Client.
func (c *RedisClient) Fail(
	ctx context.Context,
	attemptID string,
	step Step,
	code FailureCode,
	userMessage string,
) error {
	if attemptID == "" {
		return nil
	}
	return c.publish(ctx, attemptID, Progress{
		Step:          step,
		StepStartedAt: time.Now().UnixMilli(),
		TerminalState: TerminalFailed,
		Error: &ProgressError{
			Code:        code,
			UserMessage: userMessage,
		},
	})
}

// Ping implements Client.
func (c *RedisClient) Ping(ctx context.Context) error {
	if err := c.rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("signupprogress: ping: %w", mapRedisError(err))
	}
	return nil
}

func (c *RedisClient) publish(ctx context.Context, attemptID string, p Progress) error {
	start := time.Now()
	raw, err := json.Marshal(p)
	if err != nil {
		// Marshal failures are programming errors — we control the input.
		err = fmt.Errorf("signupprogress: marshal: %w", err)
		metrics.ObserveSubsystemCall("signupprogress", "publish", start, err)
		return err
	}
	key := c.keyPrefix + attemptID
	err = mapRedisError(c.rdb.Set(ctx, key, raw, c.ttl).Err())
	metrics.ObserveSubsystemCall("signupprogress", "publish", start, err)
	return err
}

func mapRedisError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, redis.Nil) {
		return fmt.Errorf("%w", clients.ErrNotFound)
	}
	return fmt.Errorf("redis: %v: %w", err, clients.ErrUnreachable)
}

// The NoopClient type was deleted in the one-code-path epic (deploy#199):
// Redis is now required infrastructure, so the operator exits 1 at boot
// when REDIS_ADDR is unset rather than injecting a silent no-op. Callers
// no longer need nil-check or fallback; the SignupProgress field on
// ProvisionDeps is guaranteed non-nil per the operator's startup gate.
