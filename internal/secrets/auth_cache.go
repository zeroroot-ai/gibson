package secrets

// auth_cache.go — per-(tenant, provider) auth-token cache.
//
// Vault and AWS SM providers must re-authenticate periodically (Vault tokens
// have TTLs; STS AssumeRole credentials expire). Without caching, every
// Get call at high RPS would produce a corresponding auth call, causing
// upstream throttling and latency spikes.
//
// AuthCache implements a two-level defence:
//
//  1. A per-(tenant, provider) in-memory token entry with an effective TTL
//     equal to 80 % of the underlying token's issued TTL. Tokens are
//     considered valid until their effective expiry; stale entries trigger a
//     refresh via AuthRefreshFn.
//
//  2. golang.org/x/sync/singleflight collapses concurrent refresh calls for
//     the same (tenant, provider) key into a single in-flight RPC. Under a
//     1 000 RPS burst against a single tenant, at most one refresh call is
//     issued per TTL period (typically one per 60–3 600 seconds).
//
// Spec: secrets-broker NFR Performance, Requirement 9.6.

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/sync/singleflight"
)

// authCacheTTLFraction is the fraction of the underlying token's issued TTL
// that the cache uses as its effective TTL. Using 80 % gives a comfortable
// renewal margin before the token actually expires.
const authCacheTTLFraction = 0.80

// Prometheus metrics for the auth-token cache.
var (
	authCacheHitTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gibson_secrets_auth_cache_hit_total",
			Help: "Total number of auth-token cache hits, labeled by tenant and provider.",
		},
		[]string{"tenant", "provider"},
	)

	authCacheMissTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gibson_secrets_auth_cache_miss_total",
			Help: "Total number of auth-token cache misses (triggers a refresh), labeled by tenant and provider.",
		},
		[]string{"tenant", "provider"},
	)

	authCacheRefreshDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gibson_secrets_auth_cache_refresh_duration_seconds",
			Help:    "Duration of auth-token refresh calls in seconds, labeled by tenant and provider.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"tenant", "provider"},
	)
)

// AuthRefreshFn is the callback that the AuthCache invokes on a cache miss to
// obtain a new auth token and its TTL. The implementation is provider-specific:
//   - Vault: calls client.Auth().Login() and returns the ClientToken and
//     LeaseDuration as the TTL.
//   - AWS SM: calls sts.AssumeRole and returns the STS session credentials
//     encoded as a token string with the credentials' Expiration-derived TTL.
//
// The function must be concurrency-safe (it may be called from multiple
// goroutines, though singleflight ensures only one call per key is in-flight
// at any given time).
//
// token is the opaque string the provider will set on its underlying client
// (e.g. Vault's client.SetToken). ttl is the token's full issued lifetime;
// the cache will use 80 % of this value as the effective TTL.
type AuthRefreshFn func(ctx context.Context, tenant, provider string) (token string, ttl time.Duration, err error)

// authCacheKey is the composite map key for the per-(tenant, provider) cache.
type authCacheKey struct {
	tenant   string
	provider string
}

// authCacheEntry holds a single cached token and its effective expiry.
type authCacheEntry struct {
	token     string
	expiresAt time.Time
}

// isValid reports whether the entry is still within its effective TTL.
func (e *authCacheEntry) isValid(now time.Time) bool {
	return e.token != "" && now.Before(e.expiresAt)
}

// AuthCache is a concurrency-safe, per-(tenant, provider) cache for
// provider auth tokens. It uses singleflight to prevent thundering-herd auth
// on cache miss.
//
// AuthCache is safe for concurrent use from multiple goroutines.
type AuthCache struct {
	refreshFn AuthRefreshFn
	clock     func() time.Time // injectable for tests; production uses time.Now

	mu    sync.RWMutex
	store map[authCacheKey]*authCacheEntry

	sf     singleflight.Group
	logger *slog.Logger
}

// NewAuthCache constructs an AuthCache backed by the given AuthRefreshFn.
// refreshFn must not be nil. Pass a nil logger to use the default slog logger.
// Pass a nil clock to use time.Now (production). The clock parameter is
// exposed for testing (fake clock injection).
func NewAuthCache(refreshFn AuthRefreshFn, logger *slog.Logger, clock func() time.Time) *AuthCache {
	if refreshFn == nil {
		panic("auth cache: refreshFn must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if clock == nil {
		clock = time.Now
	}
	return &AuthCache{
		refreshFn: refreshFn,
		clock:     clock,
		store:     make(map[authCacheKey]*authCacheEntry),
		logger:    logger.With("component", "secrets_auth_cache"),
	}
}

// GetOrRefresh returns a valid auth token for the given (tenant, provider)
// pair. If a cached, non-expired token exists it is returned immediately
// (cache hit). Otherwise a refresh is triggered via AuthRefreshFn, with
// singleflight ensuring that only one refresh call is in-flight per
// (tenant, provider) at a time (concurrent callers wait and share the result).
//
// GetOrRefresh returns an error only when the refresh function itself returns
// an error.
func (c *AuthCache) GetOrRefresh(ctx context.Context, tenant, provider string) (string, error) {
	key := authCacheKey{tenant: tenant, provider: provider}
	now := c.clock()

	// Fast path: check for a valid cached entry under a read lock.
	c.mu.RLock()
	entry, ok := c.store[key]
	c.mu.RUnlock()

	if ok && entry.isValid(now) {
		authCacheHitTotal.WithLabelValues(tenant, provider).Inc()
		return entry.token, nil
	}

	// Slow path: cache miss — refresh via singleflight.
	authCacheMissTotal.WithLabelValues(tenant, provider).Inc()

	sfKey := fmt.Sprintf("%s:%s", tenant, provider)
	result, err, _ := c.sf.Do(sfKey, func() (interface{}, error) {
		return c.refresh(ctx, tenant, provider)
	})
	if err != nil {
		return "", err
	}
	return result.(string), nil
}

// refresh calls the AuthRefreshFn, stores the result, and returns the token.
// It is called from within singleflight.Do so only one concurrent refresh
// per (tenant, provider) key is ever in-flight.
func (c *AuthCache) refresh(ctx context.Context, tenant, provider string) (string, error) {
	start := c.clock()

	token, ttl, err := c.refreshFn(ctx, tenant, provider)

	elapsed := time.Since(start)
	authCacheRefreshDuration.WithLabelValues(tenant, provider).Observe(elapsed.Seconds())

	if err != nil {
		c.logger.Warn("auth token refresh failed",
			"tenant", tenant,
			"provider", provider,
			"err", err,
		)
		return "", fmt.Errorf("auth cache: refresh for tenant=%s provider=%s: %w", tenant, provider, err)
	}

	// Clamp the effective TTL to 80 % of the issued TTL.
	effectiveTTL := time.Duration(float64(ttl) * authCacheTTLFraction)
	if effectiveTTL <= 0 {
		// If the provider returns a zero or negative TTL (e.g. static tokens),
		// use a safe default of 5 minutes so the cache still provides
		// thundering-herd protection without caching forever.
		effectiveTTL = 5 * time.Minute
	}

	expiresAt := c.clock().Add(effectiveTTL)
	c.mu.Lock()
	c.store[authCacheKey{tenant: tenant, provider: provider}] = &authCacheEntry{
		token:     token,
		expiresAt: expiresAt,
	}
	c.mu.Unlock()

	c.logger.Debug("auth token refreshed",
		"tenant", tenant,
		"provider", provider,
		"effective_ttl_seconds", effectiveTTL.Seconds(),
		"expires_at", expiresAt,
	)

	return token, nil
}

// Invalidate evicts the cached token for a single (tenant, provider) pair.
// The next call to GetOrRefresh for that pair will trigger a fresh auth.
// This method is typically called when a provider signals that its current
// token has been revoked.
func (c *AuthCache) Invalidate(tenant, provider string) {
	key := authCacheKey{tenant: tenant, provider: provider}
	c.mu.Lock()
	delete(c.store, key)
	c.mu.Unlock()
	c.logger.Debug("auth token invalidated", "tenant", tenant, "provider", provider)
}

// InvalidateAll evicts all cached tokens for the given tenant across every
// provider. This is called on Reload events (e.g. broker configuration change)
// so the affected tenant's next request fetches a fresh token from the new
// provider configuration.
func (c *AuthCache) InvalidateAll(tenant string) {
	c.mu.Lock()
	for k := range c.store {
		if k.tenant == tenant {
			delete(c.store, k)
		}
	}
	c.mu.Unlock()
	c.logger.Debug("all auth tokens invalidated for tenant", "tenant", tenant)
}
