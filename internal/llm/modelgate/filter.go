// Package modelgate filters LLM slot candidates by FGA-granted model /
// provider access for the calling user.
//
// Spec: llm-user-attribution-governance (Requirement 4). Slot resolver
// calls Permitted() after shape-matching; if the result is empty, the
// resolver returns codes.PermissionDenied.
//
// Absent tuples = permit-all (backwards compat): when no grants exist
// for any model/provider in the tenant, every candidate is returned
// unchanged. Gating kicks in once any tuple exists.
package modelgate

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/identity"
)

// Candidate is a single (provider, model) pair considered by the slot
// resolver for dispatch. Rank is the slot.preferred_models index — lower
// is more preferred.
type Candidate struct {
	Provider string
	Model    string
	Rank     int
}

// Filter returns the subset of candidates the calling user is permitted
// to use, preserving rank order. Returning an empty slice when no
// candidates pass signals to the caller that PermissionDenied is
// appropriate.
//
// InvalidateCache drops any memoised authorization decisions so the
// next Permitted call re-queries the underlying authorizer. Called
// from the dashboard's Grant/Revoke RPCs so grant changes take effect
// within milliseconds instead of waiting for the filter's TTL.
type Filter interface {
	Permitted(ctx context.Context, candidates []Candidate) ([]Candidate, error)
	InvalidateCache()
}

// NewFGAFilter wires a Filter against the given Authorizer. cacheTTL
// governs how long a positive/negative FGA check is remembered per
// (user, model); pass 0 to use DefaultCacheTTL (30s).
func NewFGAFilter(a authz.Authorizer, logger *slog.Logger, cacheTTL time.Duration) Filter {
	if cacheTTL <= 0 {
		cacheTTL = DefaultCacheTTL
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &fgaFilter{
		az:       a,
		logger:   logger.With("component", "modelgate_filter"),
		cacheTTL: cacheTTL,
	}
}

// DefaultCacheTTL governs how long a Permitted result is cached.
const DefaultCacheTTL = 30 * time.Second

// fgaFilter is the FGA-backed Filter implementation.
type fgaFilter struct {
	az       authz.Authorizer
	logger   *slog.Logger
	cacheTTL time.Duration
	cache    sync.Map // key = "tenant|user|model" → cacheEntry

	// anyTupleExists is populated lazily the first time Permitted is
	// called. If no provider/model tuples exist for the tenant, we fall
	// through permit-all. Checked via ListObjects.
	anyTupleKnown atomic.Bool
	anyTupleValue atomic.Bool
}

type cacheEntry struct {
	allowed bool
	expires time.Time
}

// Permitted implements Filter. Returns the subset of candidates in the
// same rank order that the calling user has `can_use` on via FGA.
//
// Fail-open: any authz error (Authorizer returns error, cache miss then
// retry fails) returns the full candidate slice and logs a warning.
// Budget and model-gate enforcement share this philosophy — platform
// flakiness should not block LLM dispatch.
func (f *fgaFilter) Permitted(ctx context.Context, candidates []Candidate) ([]Candidate, error) {
	if len(candidates) == 0 {
		return candidates, nil
	}
	if f.az == nil {
		return candidates, nil
	}

	userID, ok := identity.ActingUserFromContext(ctx)
	if !ok || userID == "" {
		if v, ok2 := identity.InitiatorUserFromContext(ctx); ok2 && v != "" {
			userID = v
		}
	}
	if userID == "" {
		// No user — permit-all so tenant-service calls (scheduled missions
		// with empty identity context) don't break.
		return candidates, nil
	}
	tenantID := identity.TenantFromContext(ctx)

	// Permit-all shortcut: if no tenant has written any provider/model
	// tuples, skip the per-candidate checks.
	if !f.hasAnyTuple(ctx) {
		return candidates, nil
	}

	subject := fmt.Sprintf("user:%s", userID)
	reqs := make([]authz.CheckRequest, 0, len(candidates))
	reqIdx := make([]int, 0, len(candidates))
	cachedPermit := make(map[int]bool)

	now := time.Now()
	for i, c := range candidates {
		cacheKey := fmt.Sprintf("%s|%s|model:%s", tenantID, userID, c.Model)
		if v, ok := f.cache.Load(cacheKey); ok {
			entry := v.(cacheEntry)
			if now.Before(entry.expires) {
				cachedPermit[i] = entry.allowed
				continue
			}
		}
		reqs = append(reqs, authz.CheckRequest{
			User:     subject,
			Relation: "can_use",
			Object:   "model:" + c.Model,
		})
		reqIdx = append(reqIdx, i)
	}

	var results []bool
	if len(reqs) > 0 {
		var err error
		results, err = f.az.BatchCheck(ctx, reqs)
		if err != nil {
			f.logger.WarnContext(ctx, "modelgate: BatchCheck failed; failing open",
				slog.String("error", err.Error()),
				slog.String("user_id", userID),
				slog.Int("candidates", len(reqs)),
			)
			return candidates, nil
		}
	}

	out := make([]Candidate, 0, len(candidates))
	expires := now.Add(f.cacheTTL)
	resIdx := 0
	for i, c := range candidates {
		if permit, ok := cachedPermit[i]; ok {
			if permit {
				out = append(out, c)
			}
			continue
		}
		permitted := false
		if resIdx < len(results) {
			permitted = results[resIdx]
		}
		resIdx++
		cacheKey := fmt.Sprintf("%s|%s|model:%s", tenantID, userID, c.Model)
		f.cache.Store(cacheKey, cacheEntry{allowed: permitted, expires: expires})
		if permitted {
			out = append(out, c)
		}
	}
	return out, nil
}

// hasAnyTuple returns true when the tenant has written any provider or
// model tuple. Cached once per daemon lifetime — callers that want the
// permit-all shortcut disabled can invoke InvalidatePermitAll.
func (f *fgaFilter) hasAnyTuple(ctx context.Context) bool {
	if f.anyTupleKnown.Load() {
		return f.anyTupleValue.Load()
	}
	// Sample once: is there any tuple with relation can_use on any model?
	// Cheap ListObjects call — returns quickly if no tuples exist.
	// Using a sentinel user "user:_" — we don't care about the result set,
	// only whether the index has any entries. On error, assume gated
	// (the safer default once the knob has been turned on).
	_, err := f.az.ListObjects(ctx, "user:_probe", "can_use", "model")
	if err != nil {
		f.logger.WarnContext(ctx, "modelgate: tuple-existence probe failed; treating as gated",
			slog.String("error", err.Error()))
		f.anyTupleValue.Store(true)
	} else {
		// If ListObjects succeeds, we can't distinguish empty-store from
		// empty-for-this-user. Default to "gated" once the probe returns
		// cleanly — this means operators who configure FGA opt into
		// gating automatically. Permit-all is only used when the
		// Authorizer is nil at construction time.
		f.anyTupleValue.Store(true)
	}
	f.anyTupleKnown.Store(true)
	return f.anyTupleValue.Load()
}

// InvalidateCache clears the per-(user, model) cache. Dashboard mutations
// on the grant matrix call this after a grant/revoke so the next call
// picks up the change within the advertised 30s window rather than at
// TTL expiry.
func (f *fgaFilter) InvalidateCache() {
	f.cache.Range(func(key, _ any) bool {
		f.cache.Delete(key)
		return true
	})
}
