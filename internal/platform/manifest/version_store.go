// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package manifest

import (
	"context"

	"github.com/redis/go-redis/v9"
)

// RedisVersionClient narrows redis.UniversalClient to the Cmdables the
// VersionStore needs, so tests can wire miniredis (or a counting fake)
// without depending on the full UniversalClient surface.
type RedisVersionClient interface {
	Incr(ctx context.Context, key string) *redis.IntCmd
	Get(ctx context.Context, key string) *redis.StringCmd
}

type source int

const (
	sourceRedis source = iota
	sourceBump
)
