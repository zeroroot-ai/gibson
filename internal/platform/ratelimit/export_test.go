// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ratelimit

import (
	"time"

	"github.com/redis/go-redis/v9"
)

// NewRedisLimiterAt is NewRedisLimiter with a clock that the test controls. It
// is compiled only into tests.
func NewRedisLimiterAt(client redis.UniversalClient, limits map[string]RateLimit, now func() time.Time) TenantLimiter {
	l, ok := NewRedisLimiter(client, limits).(*redisTenantLimiter)
	if !ok {
		panic("NewRedisLimiter returned a limiter of another type")
	}
	l.now = now
	return l
}
