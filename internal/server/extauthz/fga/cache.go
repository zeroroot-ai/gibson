// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fga

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/headers"
)

// CachedChecker wraps a Checker with an in-memory TTL cache keyed on
// (subject, derived tenant, relation, object). A decision is reused until
// its entry expires; there is no other eviction path.
//
// THE TTL IS THE BOUND. This cache lives inside the ext-authz process, and
// the tuple writes that change a decision happen in the daemon (the
// tenantrole syncer, session revocation stamps). Nothing can reach into this
// process to evict an entry, so three invalidation methods that nothing
// called, and a comment that promised a push-invalidation slice, were
// removed (ADR-0027). What the platform promises, "a demoted or removed user
// is refused within seconds", is therefore exactly defaultCacheTTL after the
// tuple lands, and the identity exit test measures against that bound. An
// operator may set EXT_AUTHZ_FGA_CACHE_TTL; longer is looser.
//
// The cache is bounded (maxSize) with random eviction when full, and every
// hit and miss is counted (cacheHitsTotal, cacheMissesTotal) so the FGA load
// the TTL buys can be read off the metrics.
// defaultCacheTTL is how long a decision may lag the tuple that changed it.
// Five seconds keeps FGA load to one check per (subject, tenant, relation,
// object) per five seconds, and keeps the refusal promise measurable.
const defaultCacheTTL = 5 * time.Second

type CachedChecker struct {
	inner   *Checker
	ttl     time.Duration
	maxSize int

	mu      sync.Mutex
	entries map[cacheKey]cacheValue
}

type cacheKey struct {
	subject       string
	tenant        string
	relation      string
	object        string
	identityClass IdentityClass
}

type cacheValue struct {
	allowed  bool
	deadline time.Time
}

var (
	cacheHitsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "extauthz_fga_cache_hits_total",
		Help: "FGA decision cache hits.",
	}, []string{"decision"})

	cacheMissesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_fga_cache_misses_total",
		Help: "FGA decision cache misses.",
	})

	cacheEvictionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "extauthz_fga_cache_evictions_total",
		Help: "FGA decision cache evictions by reason.",
	}, []string{"reason"})

	cacheSizeGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "extauthz_fga_cache_size",
		Help: "Current size of the FGA decision cache.",
	})
)

// NewCachedChecker wraps inner with a cache of the given TTL and max
// size. If maxSize is 0 the cache is unbounded — only TTL eviction
// applies. Production deployments SHOULD set a reasonable bound
// (e.g. 100k entries) to prevent unbounded memory growth under
// hostile traffic.
func NewCachedChecker(inner *Checker, ttl time.Duration, maxSize int) *CachedChecker {
	if inner == nil {
		panic("fga.NewCachedChecker: inner Checker must not be nil")
	}
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	return &CachedChecker{
		inner:   inner,
		ttl:     ttl,
		maxSize: maxSize,
		entries: make(map[cacheKey]cacheValue),
	}
}

// Check returns the cached decision when present and within TTL,
// otherwise consults the underlying Checker and stores the result.
//
// Cache key composition: (identity.Subject, derived-tenant, relation,
// derived-object, identityClass). FGA "allowed" results are cached; FGA
// infrastructure errors are NOT cached (returned directly to the caller).
//
// AllowedIdentities is checked ahead of the cache lookup so a caller of
// the wrong identity class never retrieves a cached allow decision that
// was made for a different class (Req 2.1, 2.3, 2.4).
func (c *CachedChecker) Check(ctx context.Context, method string, identity headers.Identity, requestMetadata map[string]string) (bool, error) {
	entry, ok := c.inner.reg.Lookup(method)
	if !ok {
		// Default-deny: no registry entry means the underlying
		// Checker.Check would also deny; skip the cache to avoid
		// poisoning hot keys with deny-on-missing-method.
		return c.inner.Check(ctx, method, identity, requestMetadata)
	}
	if entry.Unauthenticated {
		slog.Debug("authz decision",
			"method", method,
			"entry_mode", entryMode(entry),
			"result", "allow",
		)
		return true, nil
	}

	// Self-mode branch runs BEFORE the cache lookup. Self-mode results are
	// purely a function of request shape (identity.Subject + identity class
	// vs AllowedIdentities) — no tuple state involved. Caching is
	// unnecessary and would waste memory on essentially-constant decisions.
	// Spec: self-mode-authz Req 3.3.
	if entry.Self {
		if identity.Subject == "" {
			slog.Info("authz decision",
				"method", method,
				"entry_mode", entryMode(entry),
				"result", "deny",
				"reason", "empty subject",
			)
			selfModeDecisionsTotal.WithLabelValues("deny").Inc()
			return false, nil
		}
		callerCls := callerClass(identity)
		if err := c.inner.checkIdentityClass(method, callerCls, entry.AllowedIdentities); err != nil {
			slog.Info("authz decision",
				"method", method,
				"entry_mode", entryMode(entry),
				"result", "deny",
				"reason", "identity-class not in allowed_identities",
				"caller_class", callerCls.String(),
				"allowed", entry.AllowedIdentities.String(),
			)
			identityClassDeniedCounter.WithLabelValues(method).Inc()
			selfModeDecisionsTotal.WithLabelValues("deny").Inc()
			return false, nil
		}
		slog.Debug("authz decision",
			"method", method,
			"entry_mode", entryMode(entry),
			"result", "allow",
		)
		selfModeDecisionsTotal.WithLabelValues("allow").Inc()
		return true, nil
	}

	// AllowedIdentities bitfield check runs before the cache lookup.
	// This prevents a SERVICE-class caller from hitting a cache entry
	// that was populated by a USER-class caller for the same subject.
	callerCls := callerClass(identity)
	if err := c.inner.checkIdentityClass(method, callerCls, entry.AllowedIdentities); err != nil {
		slog.Info("authz decision",
			"method", method,
			"entry_mode", entryMode(entry),
			"result", "deny",
			"reason", "identity-class not in allowed_identities",
		)
		identityClassDeniedCounter.WithLabelValues(method).Inc()
		return false, nil
	}

	// Handler-enforced rules pass through before object resolution and are never
	// cached: the decision is a constant allow at the gateway (the daemon
	// handler makes the per-resource decision), and there is no derivable object
	// to key a cache entry on. Mirrors Checker.Check; placed AFTER the
	// identity-class check so a mis-classed caller is still denied (gibson#1245).
	if handlerEnforced(entry) {
		handlerEnforcedPassthroughCounter.WithLabelValues(method).Inc()
		slog.Info("authz decision",
			"method", method,
			"entry_mode", entryMode(entry),
			"result", "allow",
			"reason", "handler-enforced (field-derived object); daemon handler decides",
			"deriver", entry.ObjectDeriver,
		)
		return true, nil
	}

	// We need the resolved object string for the cache key. Compute
	// it once and pass it on miss to avoid re-resolving inside the
	// inner Checker.
	object, err := resolveObject(entry, identity, requestMetadata)
	if err != nil {
		if errors.Is(err, ErrObjectUnresolvable) {
			// An unresolvable object is a POLICY deny, not an outage — the
			// same classification the uncached Checker.Check applies. Without
			// this branch the error reached the server as an FGA-unavailable
			// condition and the caller got 503 instead of 403: still a refused
			// request, but it counted as infrastructure failure, skipped the
			// deny log line and the object-unresolvable counter, and told the
			// client to retry something that will never succeed.
			objectUnresolvableCounter.WithLabelValues(method).Inc()
			slog.Info("authz decision",
				"method", method,
				"entry_mode", entryMode(entry),
				"result", "deny",
				"reason", "object unresolvable",
				"deriver", entry.ObjectDeriver,
				"err", err.Error(),
			)
			return false, nil
		}
		return false, err
	}
	tenant := requestMetadata["tenant"]
	if tenant == "" {
		tenant = identity.Tenant
	}
	key := cacheKey{
		subject:       identity.Subject,
		tenant:        tenant,
		relation:      entry.Relation,
		object:        object,
		identityClass: callerCls,
	}

	c.mu.Lock()
	if v, ok := c.entries[key]; ok {
		if time.Now().Before(v.deadline) {
			c.mu.Unlock()
			recordCacheHit(v.allowed)
			recordCacheHitOTel(ctx, v.allowed)
			return v.allowed, nil
		}
		// Expired — evict opportunistically.
		delete(c.entries, key)
		cacheEvictionsTotal.WithLabelValues("ttl").Inc()
	}
	c.mu.Unlock()

	cacheMissesTotal.Inc()
	recordCacheMissOTel(ctx)

	allowed, err := c.inner.Check(ctx, method, identity, requestMetadata)
	if err != nil {
		// Do not cache infrastructure errors.
		return false, err
	}

	c.mu.Lock()
	if c.maxSize > 0 && len(c.entries) >= c.maxSize {
		// Coarse eviction: drop a random entry. For low-cardinality
		// workloads this is fine; high-cardinality production
		// deployments should size maxSize generously to make eviction
		// rare.
		for k := range c.entries {
			delete(c.entries, k)
			cacheEvictionsTotal.WithLabelValues("size").Inc()
			break
		}
	}
	c.entries[key] = cacheValue{
		allowed:  allowed,
		deadline: time.Now().Add(c.ttl),
	}
	cacheSizeGauge.Set(float64(len(c.entries)))
	c.mu.Unlock()

	return allowed, nil
}

// LookupEntry returns the registry entry for the given gRPC FullMethod
// and a boolean indicating whether the entry exists. This is the early-
// dispatch hook the Envoy ext-authz server uses to decide whether to run
// the tenant cross-check at all: rule-mode entries need a derived tenant
// (so the check runs); self-mode and unauthenticated entries do not (so
// the check is skipped — they have no tenant context by design).
//
// Spec: self-mode-authz Req 3 (post-hotfix re-ordering of tenant cross-
// check vs. registry lookup).
func (c *CachedChecker) LookupEntry(method string) (Entry, bool) {
	return c.inner.reg.Lookup(method)
}

// Len returns the number of currently-cached entries (for tests and
// admin diagnostics).
func (c *CachedChecker) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func recordCacheHit(allowed bool) {
	if allowed {
		cacheHitsTotal.WithLabelValues("allow").Inc()
	} else {
		cacheHitsTotal.WithLabelValues("deny").Inc()
	}
}
