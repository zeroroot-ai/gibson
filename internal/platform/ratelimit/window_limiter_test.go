// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ratelimit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/platform/ratelimit"
)

// TestWindowLimiter_AdmitsUpToMax — the Nth request inside a window is allowed
// and the N+1th is not.
func TestWindowLimiter_AdmitsUpToMax(t *testing.T) {
	client := newTestClient(t)
	limiter := ratelimit.NewWindowLimiter(client)
	ctx := context.Background()
	w := ratelimit.Window{Max: 3, Period: time.Hour}

	for i := range 3 {
		require.NoError(t, limiter.Check(ctx, "sv:email:abc", w), "call %d should be admitted", i+1)
	}
	err := limiter.Check(ctx, "sv:email:abc", w)
	assert.ErrorIs(t, err, ratelimit.ErrRateLimited)
}

// TestWindowLimiter_KeysAreIndependent — one address exhausting its budget must
// not lock out another.
func TestWindowLimiter_KeysAreIndependent(t *testing.T) {
	client := newTestClient(t)
	limiter := ratelimit.NewWindowLimiter(client)
	ctx := context.Background()
	w := ratelimit.Window{Max: 1, Period: time.Hour}

	require.NoError(t, limiter.Check(ctx, "sv:email:a", w))
	require.ErrorIs(t, limiter.Check(ctx, "sv:email:a", w), ratelimit.ErrRateLimited)
	require.NoError(t, limiter.Check(ctx, "sv:email:b", w), "a different key must have its own budget")
}

// TestWindowLimiter_SlidesRatherThanResettingOnABoundary is why this limiter
// exists rather than reusing the minute-epoch bucket.
//
// A fixed-bucket limiter lets a caller spend a full budget at the end of one
// bucket and another immediately after the boundary — at a 24h bucket that is
// two days of allowance in one second. A sliding window releases capacity only
// as individual events age out.
func TestWindowLimiter_SlidesRatherThanResettingOnABoundary(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	limiter := ratelimit.NewWindowLimiter(client)
	ctx := context.Background()
	w := ratelimit.Window{Max: 2, Period: 2 * time.Second}

	require.NoError(t, limiter.Check(ctx, "sv:ip:x", w))
	require.NoError(t, limiter.Check(ctx, "sv:ip:x", w))
	require.ErrorIs(t, limiter.Check(ctx, "sv:ip:x", w), ratelimit.ErrRateLimited)

	// Wait for the recorded events to age past the window; capacity returns
	// because those events left it, not because a clock boundary passed.
	time.Sleep(2100 * time.Millisecond)
	assert.NoError(t, limiter.Check(ctx, "sv:ip:x", w), "capacity should return once events age out")
}

// TestWindowLimiter_ARefusedRequestCostsNothing is the regression test for the
// limiter that could be held open forever.
//
// The old implementation recorded the event before comparing the count, so a
// request it refused still landed in the window. Traffic that keeps arriving
// after being refused therefore keeps refreshing the window, and the budget
// never returns — a permanent lockout driven entirely by requests that were
// already denied.
//
// The assertion is the one that fails on the old code: after a long burst of
// refusals, capacity comes back on schedule, because refusals were never
// recorded.
func TestWindowLimiter_ARefusedRequestCostsNothing(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	limiter := ratelimit.NewWindowLimiter(client)
	ctx := context.Background()
	w := ratelimit.Window{Max: 2, Period: 2 * time.Second}

	require.NoError(t, limiter.Check(ctx, "sv:ip:x", w))
	require.NoError(t, limiter.Check(ctx, "sv:ip:x", w))

	// Sustained traffic against an already-exhausted key. Every one of these is
	// refused; none of them may extend the window.
	deadline := time.Now().Add(1500 * time.Millisecond)
	refused := 0
	for time.Now().Before(deadline) {
		if errors.Is(limiter.Check(ctx, "sv:ip:x", w), ratelimit.ErrRateLimited) {
			refused++
		}
	}
	require.Positive(t, refused, "the burst should have been refused")

	// The two ADMITTED events are now ~1.5s old. Wait out the rest of their
	// window; if refusals had been recorded, the newest would be milliseconds
	// old and the key would still be full.
	time.Sleep(700 * time.Millisecond)
	assert.NoError(t, limiter.Check(ctx, "sv:ip:x", w),
		"capacity must return once the ADMITTED events age out; refused requests must not hold the window open")
}

// TestWindowLimiter_PeekDoesNotConsume — Peek exists so a caller holding
// several budgets can decide the whole request before charging any of them.
// A Peek that consumed would defeat the purpose.
func TestWindowLimiter_PeekDoesNotConsume(t *testing.T) {
	client := newTestClient(t)
	limiter := ratelimit.NewWindowLimiter(client)
	ctx := context.Background()
	w := ratelimit.Window{Max: 1, Period: time.Hour}

	for i := range 50 {
		require.NoError(t, limiter.Peek(ctx, "sv:global", w), "peek %d must not spend budget", i)
	}
	require.NoError(t, limiter.Check(ctx, "sv:global", w), "the single unit must still be available")
	assert.ErrorIs(t, limiter.Peek(ctx, "sv:global", w), ratelimit.ErrRateLimited,
		"peek must report the budget as spent once it is")
}

// TestWindowLimiter_FailsClosedWithoutABackend is the property that separates
// this limiter from TenantLimiter.
//
// TenantLimiter guards authenticated traffic and allows on a Redis error.
// This one guards unauthenticated surfaces that send mail and create
// identities, so "we cannot count" must mean "no", not "sure".
func TestWindowLimiter_FailsClosedWithoutABackend(t *testing.T) {
	ctx := context.Background()
	w := ratelimit.Window{Max: 10, Period: time.Hour}

	t.Run("nil client", func(t *testing.T) {
		err := ratelimit.NewWindowLimiter(nil).Check(ctx, "sv:global", w)
		assert.ErrorIs(t, err, ratelimit.ErrLimiterUnavailable)
	})

	t.Run("empty key", func(t *testing.T) {
		client := newTestClient(t)
		limiter := ratelimit.NewWindowLimiter(client)
		err := limiter.Check(ctx, "", w)
		assert.ErrorIs(t, err, ratelimit.ErrLimiterUnavailable,
			"an empty key is a caller bug, not a budget verdict; it must not be treated as unlimited")
	})

	t.Run("unreachable redis", func(t *testing.T) {
		mr := miniredis.RunT(t)
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		limiter := ratelimit.NewWindowLimiter(client)
		mr.Close()

		err := limiter.Check(ctx, "sv:global", w)
		require.ErrorIs(t, err, ratelimit.ErrLimiterUnavailable)
		assert.NotErrorIs(t, err, ratelimit.ErrRateLimited,
			"an unreachable backend is a refusal to answer, not a budget verdict")
	})
}

// TestWindowLimiter_ZeroBudgetIsClosed — a misconfigured budget on an
// unauthenticated surface must deny, not wave everything through. This is the
// opposite of TenantLimiter's "zero means unlimited", which is only safe
// because that limiter guards authenticated traffic.
func TestWindowLimiter_ZeroBudgetIsClosed(t *testing.T) {
	client := newTestClient(t)
	limiter := ratelimit.NewWindowLimiter(client)
	ctx := context.Background()

	require.ErrorIs(t, limiter.Check(ctx, "sv:global", ratelimit.Window{Max: 0, Period: time.Hour}), ratelimit.ErrRateLimited)
	assert.ErrorIs(t, limiter.Check(ctx, "sv:global", ratelimit.Window{Max: 5}), ratelimit.ErrRateLimited)
}
