package idempotency

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// redisBackend is the minimal Redis command set the store needs.
// It is defined as an interface so callers in packages that are allowed to
// import the raw redis library (internal/daemon, internal/datapool) can supply
// the production *redis.Client via a thin adapter, while this package stays
// free of the raw client import.
//
// GetBytes must return (nil, nil) when the key is not found (translating the
// redis.Nil sentinel internally); store_redis.go does not inspect the error
// value for a redis-specific sentinel.
type redisBackend interface {
	// GetBytes returns the raw bytes stored at key.
	// Returns (nil, nil) on cache miss, (nil, err) on failure.
	GetBytes(ctx context.Context, key string) ([]byte, error)
	// SetNX sets key=value with TTL only when key does not exist.
	// Returns (true, nil) when planted, (false, nil) when key already existed.
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	// Set stores key=value with TTL unconditionally.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
}

// redisKeyPrefix is the Redis namespace under which all dedup entries
// live. Co-located with the daemon's other Redis namespaces (audit:,
// onboarding:, etc.).
const redisKeyPrefix = "idempotency:"

// pendingSentinel is the byte marker that distinguishes an in-flight
// execution from a real cached response. It is not valid proto.Marshal
// output for our cache-entry message so we can dispatch on it without
// ambiguity.
//
// Stored as a literal short ASCII string; the entry-message wire
// format always begins with a varint field tag, so the first byte is
// in {0x0a, 0x12, 0x1a, …}, never an ASCII letter.
var pendingSentinel = []byte("PENDING")

// RedisStore is the production Store. It uses a single Redis key per
// (tenant, method, key) triple, written under redisKeyPrefix. Both the
// cached response and the in-flight sentinel share the same key so a
// SET NX + subsequent overwriting SET is the entire critical section.
type RedisStore struct {
	client redisBackend
	logger *slog.Logger
	// pollInterval is the duration between polls when Get observes a
	// pending sentinel. Exposed for tests; production code should let
	// it default.
	pollInterval time.Duration
}

// NewRedisStore constructs a RedisStore. client must not be nil.
func NewRedisStore(client redisBackend, logger *slog.Logger) *RedisStore {
	if client == nil {
		panic("idempotency: NewRedisStore: redis client must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &RedisStore{
		client:       client,
		logger:       logger,
		pollInterval: 100 * time.Millisecond,
	}
}

// redisKey returns the canonical Redis key for the triple. Each
// component is wrapped so a colon embedded in the tenant or method
// (proto packages contain dots, not colons, but tenant IDs are
// caller-supplied) cannot collide with another triple.
//
// We strip newlines + nul bytes defensively; the upstream identity
// interceptor already validates these, but the dedup store is a
// trust boundary worth defending independently.
func redisKey(tenant, method, key string) string {
	clean := func(s string) string {
		s = strings.ReplaceAll(s, "\n", "")
		s = strings.ReplaceAll(s, "\r", "")
		s = strings.ReplaceAll(s, "\x00", "")
		return s
	}
	return fmt.Sprintf("%s%s:%s:%s", redisKeyPrefix, clean(tenant), clean(method), clean(key))
}

// Get implements Store.Get. On a "pending" sentinel it polls at
// pollInterval until either a real response appears, the sentinel
// expires, or MaxWaitForPending elapses.
func (s *RedisStore) Get(ctx context.Context, tenant, method, key string) (*CachedResponse, bool, error) {
	if tenant == "" || method == "" || key == "" {
		return nil, false, nil
	}
	rk := redisKey(tenant, method, key)

	deadline := time.Now().Add(MaxWaitForPending)
	for {
		raw, err := s.client.GetBytes(ctx, rk)
		if err != nil {
			return nil, false, fmt.Errorf("idempotency: redis GET failed: %w", err)
		}
		if raw == nil {
			return nil, false, nil
		}

		if isPendingSentinel(raw) {
			// Another caller is executing — brief poll for the real
			// response. On context cancel or wait timeout, give up and
			// fall back to re-execution.
			if time.Now().After(deadline) {
				s.logger.WarnContext(ctx, "idempotency: pending sentinel did not resolve within MaxWaitForPending; allowing re-execution",
					slog.String("tenant", tenant),
					slog.String("method", method),
				)
				return nil, false, nil
			}
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case <-time.After(s.pollInterval):
			}
			continue
		}

		cached, derr := decodeEntry(raw)
		if derr != nil {
			// Malformed entry. Treat as a miss and let the handler
			// re-execute; better than serving a corrupt cached
			// response to the caller.
			s.logger.WarnContext(ctx, "idempotency: cache entry decode failed; treating as miss",
				slog.String("tenant", tenant),
				slog.String("method", method),
				slog.String("error", derr.Error()),
			)
			return nil, false, nil
		}
		return cached, true, nil
	}
}

// MarkPending implements Store.MarkPending using Redis SET NX.
func (s *RedisStore) MarkPending(ctx context.Context, tenant, method, key string, pendingTTL time.Duration) (bool, error) {
	if tenant == "" || method == "" || key == "" {
		return false, nil
	}
	rk := redisKey(tenant, method, key)
	planted, err := s.client.SetNX(ctx, rk, pendingSentinel, pendingTTL)
	if err != nil {
		return false, fmt.Errorf("idempotency: redis SET NX failed: %w", err)
	}
	return planted, nil
}

// Set implements Store.Set. Always uses unconditional SET with TTL so
// the pending sentinel is overwritten in a single round trip.
func (s *RedisStore) Set(ctx context.Context, tenant, method, key string, cached *CachedResponse, ttl time.Duration) error {
	if tenant == "" || method == "" || key == "" {
		return nil
	}
	if cached == nil {
		return errors.New("idempotency: Set: cached response must not be nil")
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	raw, err := encodeEntry(cached)
	if err != nil {
		return fmt.Errorf("idempotency: cache entry marshal failed: %w", err)
	}
	if err := s.client.Set(ctx, redisKey(tenant, method, key), raw, ttl); err != nil {
		return fmt.Errorf("idempotency: redis SET failed: %w", err)
	}
	return nil
}

// isPendingSentinel returns true when raw matches the in-flight
// sentinel byte sequence. Allows the proto-encoded cache entry and
// the sentinel to coexist under the same key without collision.
func isPendingSentinel(raw []byte) bool {
	if len(raw) != len(pendingSentinel) {
		return false
	}
	for i := range pendingSentinel {
		if raw[i] != pendingSentinel[i] {
			return false
		}
	}
	return true
}
