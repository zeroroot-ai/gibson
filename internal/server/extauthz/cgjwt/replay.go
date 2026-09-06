// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package cgjwt

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// DefaultReplayCacheMaxEntries bounds the component-token replay cache.
//
// An entry is retained only until the token it records expires, and a
// component token lives at most ComponentVerifier.maxLifetime (5 minutes by
// default). So the working set is roughly (component RPCs per second) ×
// (max token lifetime): 100k entries covers ~330 component RPCs/second
// sustained for a full 5 minutes on one pod, which is far above any observed
// component load. Each entry is a short string plus a deadline — on the order
// of 10 MB at the bound.
const DefaultReplayCacheMaxEntries = 100_000

// replayCache remembers the (kid, jti) pairs of component tokens that have
// already been accepted, so the same token cannot be presented twice.
//
// Scope of the guarantee — read this before trusting it:
//
//   - The cache is IN-PROCESS. ext-authz runs ≥2 replicas, so a token
//     replayed against a different pod than the one that first accepted it
//     is NOT caught. This narrows the replay window from "the token's whole
//     ~55s lifetime, unlimited uses" to "at most once per ext-authz pod",
//     which is a real reduction but not closure. Closing it needs either
//     shared state (which ext-authz deliberately has none of today — every
//     cache in this binary is per-pod) or a request binding minted by the
//     SDK (a method + body-digest claim, gibson#1246), which is the actual
//     fix and is cross-repo.
//   - An entry is only written AFTER the signature, descriptor and lifetime
//     checks pass. An unauthenticated caller therefore cannot consume cache
//     capacity, and cannot burn another component's jti to deny it service:
//     inserting under a kid requires a valid signature from that kid's key.
//
// replayCache is safe for concurrent use.
type replayCache struct {
	maxEntries int

	mu      sync.Mutex
	entries map[replayKey]time.Time // key -> deadline (the token's exp)
}

// replayKey namespaces the jti by the key that signed it. Two components
// choosing the same jti string must not collide, and — more importantly —
// no caller can pre-burn a jti it cannot sign for.
type replayKey struct {
	kid string
	jti string
}

func newReplayCache(maxEntries int) *replayCache {
	if maxEntries <= 0 {
		maxEntries = DefaultReplayCacheMaxEntries
	}
	return &replayCache{
		maxEntries: maxEntries,
		entries:    map[replayKey]time.Time{},
	}
}

// admit records (kid, jti) as seen and reports whether this is its first
// presentation. It returns false when the pair is already recorded — that is,
// when the token is a replay.
//
// deadline is the token's exp: past it the ordinary expiry check rejects the
// token anyway, so the entry carries no value and is dropped.
func (c *replayCache) admit(kid, jti string, deadline time.Time, now time.Time) bool {
	key := replayKey{kid: kid, jti: jti}

	c.mu.Lock()
	defer c.mu.Unlock()

	if seen, ok := c.entries[key]; ok && now.Before(seen) {
		return false
	}

	if len(c.entries) >= c.maxEntries {
		c.evictLocked(now)
	}

	c.entries[key] = deadline
	replayCacheSize.Set(float64(len(c.entries)))
	return true
}

// evictLocked frees room. It first drops every entry whose token has already
// expired (those are pure garbage). If that is not enough it drops the entry
// closest to expiring, which is the one whose remaining replay value is
// smallest.
//
// Capacity eviction weakens the guarantee for the evicted entry — a token
// whose jti was dropped early can be replayed once more on this pod. It is
// counted separately so a deployment can tell "the bound is too low" apart
// from ordinary expiry churn; sustained capacity evictions mean
// EXT_AUTHZ_CGJWT_REPLAY_CACHE_MAX_ENTRIES needs raising.
func (c *replayCache) evictLocked(now time.Time) {
	var (
		oldestKey      replayKey
		oldestDeadline time.Time
		haveOldest     bool
	)
	for k, deadline := range c.entries {
		if !now.Before(deadline) {
			delete(c.entries, k)
			replayCacheEvictions.WithLabelValues("expired").Inc()
			continue
		}
		if !haveOldest || deadline.Before(oldestDeadline) {
			oldestKey, oldestDeadline, haveOldest = k, deadline, true
		}
	}
	if len(c.entries) < c.maxEntries {
		return
	}
	if haveOldest {
		delete(c.entries, oldestKey)
		replayCacheEvictions.WithLabelValues("capacity").Inc()
	}
}

var (
	componentReplayedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_component_replay_rejected_total",
		Help: "Component CG-JWTs rejected because their (kid, jti) was already seen on this pod.",
	})
	replayCacheSize = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "extauthz_cgjwt_component_replay_cache_size",
		Help: "Entries currently held in the component-token replay cache (per pod).",
	})
	replayCacheEvictions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "extauthz_cgjwt_component_replay_cache_evictions_total",
		Help: "Component replay-cache evictions by reason. Sustained reason=capacity means the bound is too low and replay protection is degrading.",
	}, []string{"reason"})
)
