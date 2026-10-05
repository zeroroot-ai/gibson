// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package manifest

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultCurrentCacheTTL bounds how long a Current() read may be served
// from the in-memory cache before Redis is re-queried. Design.md calls
// for 1s so the Harness staleness interceptor (Task 13) can run without
// hitting Redis on every incoming Harness call.
const DefaultCurrentCacheTTL = time.Second

// versionKeyPrefix + tenantID = Redis key for the monotonic version
// counter. Kept in sync with design.md ("Redis keys" section).
const versionKeyPrefix = "tenant:"
const versionKeySuffix = ":manifest_version"

// RedisVersionClient narrows redis.UniversalClient to the Cmdables the
// VersionStore needs, so tests can wire miniredis (or a counting fake)
// without depending on the full UniversalClient surface.
type RedisVersionClient interface {
	Incr(ctx context.Context, key string) *redis.IntCmd
	Get(ctx context.Context, key string) *redis.StringCmd
}

// redisVersionStore implements VersionStore against Redis with an
// in-memory cache of Current reads. Safe for concurrent use.
type redisVersionStore struct {
	rdb      RedisVersionClient
	cacheTTL time.Duration
	cache    sync.Map // tenantID → cachedVersion
}

type cachedVersion struct {
	value      uint64
	fetchedAt  time.Time
	fetchedOK  bool
	lastSource source
}

type source int

const (
	sourceRedis source = iota
	sourceBump
)
