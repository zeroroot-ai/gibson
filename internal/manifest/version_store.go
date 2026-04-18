package manifest

import (
	"context"
	"fmt"
	"strconv"
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

// NewVersionStore constructs a VersionStore. cacheTTL <= 0 uses
// DefaultCurrentCacheTTL. Passing a RedisVersionClient (rather than the
// full UniversalClient) keeps tests mockable without reaching for the
// whole go-redis interface surface.
func NewVersionStore(rdb RedisVersionClient, cacheTTL time.Duration) VersionStore {
	if cacheTTL <= 0 {
		cacheTTL = DefaultCurrentCacheTTL
	}
	return &redisVersionStore{rdb: rdb, cacheTTL: cacheTTL}
}

// Bump atomically increments the tenant's counter. The fresh value is
// also cached so a subsequent Current() returns it immediately without
// a Redis round-trip.
func (s *redisVersionStore) Bump(ctx context.Context, tenantID string) (uint64, error) {
	if tenantID == "" {
		return 0, fmt.Errorf("manifest: Bump: empty tenantID")
	}
	key := versionKey(tenantID)
	v, err := s.rdb.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("manifest: Bump: INCR %s: %w", key, err)
	}
	if v < 0 {
		return 0, fmt.Errorf("manifest: Bump: negative counter from Redis (%d)", v)
	}
	uv := uint64(v)
	s.cache.Store(tenantID, cachedVersion{value: uv, fetchedAt: time.Now(), fetchedOK: true, lastSource: sourceBump})
	return uv, nil
}

// Current returns the tenant's current manifest version. Served from
// cache when the cached value is within cacheTTL, else refreshed from
// Redis. If Redis is down, a still-cached (even stale) value is NOT
// returned — errors propagate per design.md's "no silent fallback" rule.
func (s *redisVersionStore) Current(ctx context.Context, tenantID string) (uint64, error) {
	if tenantID == "" {
		return 0, fmt.Errorf("manifest: Current: empty tenantID")
	}
	now := time.Now()
	if cached, ok := s.cache.Load(tenantID); ok {
		cv := cached.(cachedVersion)
		if cv.fetchedOK && now.Sub(cv.fetchedAt) < s.cacheTTL {
			return cv.value, nil
		}
	}
	key := versionKey(tenantID)
	raw, err := s.rdb.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			// No writes have happened yet for this tenant — version 0 is
			// the well-defined starting state.
			s.cache.Store(tenantID, cachedVersion{value: 0, fetchedAt: now, fetchedOK: true, lastSource: sourceRedis})
			return 0, nil
		}
		return 0, fmt.Errorf("manifest: Current: GET %s: %w", key, err)
	}
	v, parseErr := strconv.ParseUint(raw, 10, 64)
	if parseErr != nil {
		return 0, fmt.Errorf("manifest: Current: parse %q: %w", raw, parseErr)
	}
	s.cache.Store(tenantID, cachedVersion{value: v, fetchedAt: now, fetchedOK: true, lastSource: sourceRedis})
	return v, nil
}

func versionKey(tenantID string) string {
	return versionKeyPrefix + tenantID + versionKeySuffix
}
