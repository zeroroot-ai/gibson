// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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

// Window is a generic "at most Max events per Period" budget, keyed by an
// arbitrary string rather than a tenant.
//
// TenantLimiter's minute-epoch bucket cannot express this: the pre-tenant
// signup surface needs hour and day budgets, and a fixed epoch bucket of that
// size lets a caller spend two full budgets back to back across the boundary —
// at a 24h bucket that is a two-day burst in one second. Window is enforced by
// a real sliding window (a Redis sorted set of event timestamps) so the budget
// holds at every instant, not just per calendar bucket.
type Window struct {
	// Max is the number of events permitted within any Period-long span.
	Max int
	// Period is the width of the sliding window.
	Period time.Duration
}

// Limiter is the key-addressed sliding-window budget used by pre-tenant
// surfaces (signup verification request / redeem / complete), where there is
// no tenant to key on and the natural keys are an email, an IP, or a global
// circuit breaker.
//
// Check returns ErrRateLimited when the budget is spent. Unlike TenantLimiter,
// implementations MUST return a non-nil error when the backing store is
// unreachable rather than allowing the request: the surfaces behind this
// interface are unauthenticated, so a Redis outage must not silently remove
// every limit protecting them. Callers fail the request closed.
//
// Two obligations on implementations, both load-bearing for callers that hold
// several budgets at once:
//
//   - Check MUST consume nothing when it returns ErrRateLimited. A refused
//     request that still charges the budget lets refused traffic hold the
//     window open indefinitely, so the budget never returns.
//   - Peek MUST consume nothing at all. It is how a caller decides a whole
//     request before charging any single budget for it.
type Limiter interface {
	Peek(ctx context.Context, key string, w Window) error
	Check(ctx context.Context, key string, w Window) error
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
