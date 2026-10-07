// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package modelgate decides which LLM providers and models a caller may use.
//
// Spec: llm-user-attribution-governance (Requirement 4). The daemon's slot
// manager calls Permitted after it picks a (provider, model). An empty result
// makes the resolver return a model_access_denied error.
//
// # The rule (hosted#358, owner decision 2026-10-05)
//
// A member of a tenant may use each provider of that tenant by default. An
// administrator turns that off explicitly.
//
//   - Default allow. When a tenant gets a provider, EnsureDefaultGrant writes
//     tenant:<id>#member can_use provider:<name>. Every member, human or
//     component, then passes the check for that provider and its models.
//   - Explicit off. An administrator revokes that tenant-wide grant
//     (ModelAccessService.RevokeAccess) and grants the provider, or single
//     models, to the users and teams that keep access. EnsureDefaultGrant
//     never writes the grant a second time: the tenant:<id> owner
//     provider:<name> tuple records that the default was written once.
//   - A candidate passes when the subject has can_use on the model OR on the
//     provider.
//
// # The subject
//
// Permitted asks FGA about one subject, the first of these that the request
// carries:
//
//  1. The acting user (a platform service acts for a signed-in person).
//  2. The mission initiator (the person who created the mission; the harness
//     factory puts it on the context for every slot resolution of the run).
//  3. The calling identity: a person, or a component's typed principal.
//  4. The tenant's members as a set (tenant:<id>#member), for work that no
//     person and no component started, such as a mission that a service
//     scheduled. That subject passes only while the tenant-wide grant stands.
//
// # Fail closed
//
// A request with no subject and no tenant is denied. An error from FGA is
// returned to the caller, and the slot manager denies on it. A filter built
// with no Authorizer denies every candidate. There is no permit-all branch.
package modelgate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/sdk/auth"
)

// Candidate is a single (provider, model) pair considered by the slot
// resolver for dispatch. Rank is the slot.preferred_models index — lower
// is more preferred.
type Candidate struct {
	Provider string
	Model    string
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
	cache    sync.Map // key = cacheKey(tenant, subject, candidate) → cacheEntry
}

type cacheEntry struct {
	allowed bool
	expires time.Time
}

// Permitted implements Filter. It returns, in rank order, the candidates the
// request's subject may use: those where the subject has can_use on the model
// or on the provider. See the package doc for the subject and for the
// fail-closed cases.
func (f *fgaFilter) Permitted(ctx context.Context, candidates []Candidate) ([]Candidate, error) {
	if len(candidates) == 0 {
		return candidates, nil
	}
	if f.az == nil {
		return nil, errors.New("modelgate: no authorizer is configured, so no model can be permitted")
	}

	// The tenant names the objects: a provider and a model are checked as
	// that tenant's own (authz.ProviderObject). A request with no tenant has
	// no object to check, so it is denied.
	tenantID := auth.TenantStringFromContext(ctx)
	subject := Subject(ctx)
	if tenantID == "" || subject == "" {
		f.logger.WarnContext(ctx, "modelgate: the request names no tenant, or no user, component or tenant member set; denying",
			slog.Int("candidates", len(candidates)))
		return nil, nil
	}

	// One decision per candidate, cached per (tenant, subject, provider,
	// model). Each uncached candidate costs two checks: the model, then the
	// provider.
	decided := make([]bool, len(candidates))
	known := make([]bool, len(candidates))
	reqs := make([]authz.CheckRequest, 0, 2*len(candidates))
	reqIdx := make([]int, 0, len(candidates))

	now := time.Now()
	for i, c := range candidates {
		if v, ok := f.cache.Load(cacheKey(tenantID, subject, c)); ok {
			if entry := v.(cacheEntry); now.Before(entry.expires) {
				decided[i], known[i] = entry.allowed, true
				continue
			}
		}
		model, merr := authz.ModelObject(tenantID, c.Model)
		provider, perr := authz.ProviderObject(tenantID, c.Provider)
		if merr != nil || perr != nil {
			// A name that cannot form an object cannot hold a grant.
			f.logger.WarnContext(ctx, "modelgate: the candidate cannot be named in FGA; denying",
				slog.String("provider", c.Provider), slog.String("model", c.Model))
			known[i] = true
			continue
		}
		reqs = append(reqs,
			authz.CheckRequest{User: subject, Relation: relationCanUse, Object: model},
			authz.CheckRequest{User: subject, Relation: relationCanUse, Object: provider},
		)
		reqIdx = append(reqIdx, i)
	}

	if len(reqs) > 0 {
		results, err := f.az.BatchCheck(ctx, reqs)
		if err != nil {
			return nil, fmt.Errorf("modelgate: authorization check failed: %w", err)
		}
		if len(results) != len(reqs) {
			return nil, fmt.Errorf("modelgate: authorizer answered %d of %d checks", len(results), len(reqs))
		}
		expires := now.Add(f.cacheTTL)
		for n, i := range reqIdx {
			allowed := results[2*n] || results[2*n+1]
			decided[i], known[i] = allowed, true
			f.cache.Store(cacheKey(tenantID, subject, candidates[i]), cacheEntry{allowed: allowed, expires: expires})
		}
	}

	out := make([]Candidate, 0, len(candidates))
	for i, c := range candidates {
		if known[i] && decided[i] {
			out = append(out, c)
		}
	}
	return out, nil
}

func cacheKey(tenantID, subject string, c Candidate) string {
	return tenantID + "|" + subject + "|" + c.Provider + "|" + c.Model
}

// InvalidateCache clears the decision cache. Dashboard mutations
// on the grant matrix call this after a grant/revoke so the next call
// picks up the change within the advertised 30s window rather than at
// TTL expiry.
func (f *fgaFilter) InvalidateCache() {
	f.cache.Range(func(key, _ any) bool {
		f.cache.Delete(key)
		return true
	})
}
