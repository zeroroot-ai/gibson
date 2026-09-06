// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package ratelimit — window_limiter.go
//
// A genuine sliding-window Limiter over Redis, for the pre-tenant surfaces
// (self-serve signup) where the budget periods are hours and days rather than
// minutes.
package ratelimit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrLimiterUnavailable is returned when the backing store cannot be reached.
//
// It is a distinct error from ErrRateLimited because the caller's response
// differs — "you asked too often" versus "we cannot tell, so no" — but both
// reject the request. The unauthenticated surfaces behind this limiter must
// never fall open on a Redis outage.
var ErrLimiterUnavailable = errors.New("rate limiter unavailable")

// windowScript is the whole budget decision, evaluated server-side in one
// atomic step: evict what has aged out, count what remains, and record this
// event ONLY if the count leaves room for it.
//
// Two properties depend on it being one script rather than a pipeline.
//
// Admission and recording cannot separate. A pipeline that counts and then
// records unconditionally charges every request, including the ones it turns
// away. That is not a stricter limiter, it is a broken one: a caller who keeps
// asking after being refused keeps refreshing the window, so the window never
// drains and the budget never returns. Against a shared bucket that turns a
// single refused source into an outage for everyone; against a per-address
// bucket it holds one chosen address out of signup for as long as the traffic
// continues. A refused request must cost nothing.
//
// And the count-then-add pair cannot interleave. Two callers who both read
// count == max-1 in separate round trips would both be admitted. Inside the
// script Redis runs the whole thing before anything else touches the key.
//
// ARGV: now(ns), cutoff(ns), max, ttl(ms), member, consume("1"|"0").
// Returns 1 when admitted, 0 when over budget.
var windowScript = redis.NewScript(`
local now    = tonumber(ARGV[1])
local cutoff = tonumber(ARGV[2])
local max    = tonumber(ARGV[3])
local ttl    = tonumber(ARGV[4])

redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
if redis.call('ZCARD', KEYS[1]) >= max then
  return 0
end
if ARGV[6] == '1' then
  redis.call('ZADD', KEYS[1], now, ARGV[5])
  redis.call('PEXPIRE', KEYS[1], ttl)
end
return 1
`)

// windowLimiter implements Limiter with one Redis sorted set per key, holding
// one member per admitted event scored by its arrival time in nanoseconds.
type windowLimiter struct {
	client redis.UniversalClient
	now    func() time.Time
}

var _ Limiter = (*windowLimiter)(nil)

// NewWindowLimiter builds a sliding-window Limiter over the given client.
// A nil client yields a limiter that reports ErrLimiterUnavailable for every
// check — callers reject rather than proceed unlimited.
func NewWindowLimiter(client redis.UniversalClient) Limiter {
	return &windowLimiter{client: client}
}

// Peek reports whether the budget for key currently has room, consuming
// nothing.
//
// It exists so a caller holding several budgets can decide the whole request
// before charging any of them. Without it the only way to test the last budget
// is to have already spent the earlier ones — which means a request that is
// about to be refused has already drawn down a bucket other people share.
func (l *windowLimiter) Peek(ctx context.Context, key string, w Window) error {
	return l.eval(ctx, key, w, false)
}

// Check consumes one unit of the budget for key, or returns ErrRateLimited and
// consumes nothing.
//
// A zero or negative Max means "closed": no request is admitted. That is the
// safe reading of a misconfigured budget on an unauthenticated surface, and it
// is the opposite of TenantLimiter's "zero means unlimited", which is safe only
// because that limiter guards authenticated traffic.
func (l *windowLimiter) Check(ctx context.Context, key string, w Window) error {
	return l.eval(ctx, key, w, true)
}

func (l *windowLimiter) eval(ctx context.Context, key string, w Window, consume bool) error {
	if l == nil || l.client == nil {
		return ErrLimiterUnavailable
	}
	if key == "" {
		return ErrLimiterUnavailable
	}
	if w.Max <= 0 || w.Period <= 0 {
		return fmt.Errorf("%w: key %q has no budget configured", ErrRateLimited, key)
	}

	now := time.Now()
	if l.now != nil {
		now = l.now()
	}
	consumeArg := "0"
	if consume {
		consumeArg = "1"
	}

	admitted, err := windowScript.Run(ctx, l.client,
		[]string{"ratelimit:window:" + key},
		now.UnixNano(),
		now.Add(-w.Period).UnixNano(),
		w.Max,
		(w.Period + time.Second).Milliseconds(),
		eventMember(now),
		consumeArg,
	).Int64()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLimiterUnavailable, err)
	}
	if admitted != 1 {
		return fmt.Errorf("%w: key %q exceeded %d per %s", ErrRateLimited, key, w.Max, w.Period)
	}
	return nil
}

// eventMember builds a unique sorted-set member for one event.
//
// The timestamp alone is not unique: two events landing in the same nanosecond
// collapse into a single set member and the spend is silently undercounted. The
// random suffix makes each event its own member; the score stays the timestamp,
// which is what the window is measured against.
func eventMember(now time.Time) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A failed read must not make members collide on a constant. Fall back
		// to the nanosecond alone.
		return strconv.FormatInt(now.UnixNano(), 10)
	}
	return fmt.Sprintf("%d-%s", now.UnixNano(), hex.EncodeToString(b[:]))
}
