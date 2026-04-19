// Package ratelimit provides a Redis-backed sliding-window tenant rate limiter
// for daemon execution RPCs (ExecuteLLM, StreamLLM, TestProvider).
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrRateLimited is returned when a tenant has exceeded the configured request
// rate for a given RPC. The caller should surface this as codes.ResourceExhausted.
var ErrRateLimited = errors.New("rate limit exceeded")

// RateLimit configures the allowed request volume for a single named RPC.
type RateLimit struct {
	// RequestsPerMinute is the maximum number of requests a tenant may make
	// to this RPC within any 60-second sliding window.
	RequestsPerMinute int
}

// DefaultLimits returns the production defaults applied when no explicit
// configuration is provided.
func DefaultLimits() map[string]RateLimit {
	return map[string]RateLimit{
		"ExecuteLLM":   {RequestsPerMinute: 1000},
		"StreamLLM":    {RequestsPerMinute: 1000},
		"TestProvider": {RequestsPerMinute: 10},
	}
}

// TenantLimiter checks whether a tenant may proceed with an RPC call.
type TenantLimiter interface {
	// Check returns nil if the request is within the tenant's rate limit for
	// the named RPC, or ErrRateLimited if the bucket is full.
	// An empty tenantID or rpcName is treated as always-allowed so that the
	// limiter degrades gracefully when context metadata is missing.
	Check(ctx context.Context, tenantID, rpcName string) error
}

// redisTenantLimiter implements TenantLimiter using a simple sliding-window
// approach: one Redis INCR + EXPIRE per minute-epoch bucket, keyed by
// (tenant, rpc, minute). This over-counts at bucket boundaries (it is not a
// true sliding window), but is simple, lock-free, and accurate enough for
// protecting expensive LLM execution RPCs.
type redisTenantLimiter struct {
	client redis.UniversalClient
	limits map[string]RateLimit
}

// Ensure redisTenantLimiter satisfies TenantLimiter at compile time.
var _ TenantLimiter = (*redisTenantLimiter)(nil)

// NewRedisLimiter constructs a TenantLimiter backed by the given Redis client.
//
// limits is a map from RPC name (e.g. "ExecuteLLM") to RateLimit. RPCs not
// present in the map are always allowed. If limits is nil the defaults from
// DefaultLimits() are used.
func NewRedisLimiter(client redis.UniversalClient, limits map[string]RateLimit) TenantLimiter {
	if limits == nil {
		limits = DefaultLimits()
	}
	return &redisTenantLimiter{
		client: client,
		limits: limits,
	}
}

// Check increments the per-(tenant, rpc, minute) counter in Redis and returns
// ErrRateLimited if the new count exceeds the configured limit.
//
// The bucket key is:
//
//	ratelimit:<tenantID>:<rpcName>:<minute-epoch>
//
// where minute-epoch is time.Now().Unix()/60. The key is given a 120-second
// TTL (two minute-buckets) so Redis reclaims it automatically.
func (l *redisTenantLimiter) Check(ctx context.Context, tenantID, rpcName string) error {
	// Degrade gracefully for un-identified traffic rather than panicking.
	if tenantID == "" || rpcName == "" {
		return nil
	}

	limit, ok := l.limits[rpcName]
	if !ok {
		// No limit configured for this RPC — allow.
		return nil
	}
	if limit.RequestsPerMinute <= 0 {
		// Explicitly zero/negative means "unlimited".
		return nil
	}

	minuteEpoch := time.Now().Unix() / 60
	key := fmt.Sprintf("ratelimit:%s:%s:%d", tenantID, rpcName, minuteEpoch)

	// Pipeline INCR + EXPIRE so both are sent in a single RTT.
	var incrCmd *redis.IntCmd
	_, err := l.client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		incrCmd = pipe.Incr(ctx, key)
		// 120-second TTL: covers the current bucket plus the next, ensuring
		// old counters are reaped even if the daemon restarts mid-minute.
		pipe.Expire(ctx, key, 120*time.Second)
		return nil
	})
	if err != nil {
		// On Redis failure allow the request through rather than hard-blocking
		// all traffic. Log-worthy but not fatal to the user.
		return nil
	}

	count := incrCmd.Val()
	if count > int64(limit.RequestsPerMinute) {
		return fmt.Errorf("%w: tenant %q exceeded %d requests/minute for %s",
			ErrRateLimited, tenantID, limit.RequestsPerMinute, rpcName)
	}

	return nil
}
