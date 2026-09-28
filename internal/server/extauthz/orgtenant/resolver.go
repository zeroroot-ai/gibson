// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package orgtenant resolves a verified Zitadel org id to a tenant id
// (ADR-0093 decision 4, hosted#195). ext-authz asks the daemon's
// /identity/v1/org-tenant/{orgID} route, over the same SVID-pinned mTLS
// transport it already uses for the authz registry and the
// Capability-Grant keys, and caches the answer.
//
// Fail closed: any error (transport, non-200, bad JSON) is returned as an
// error and is never cached, so the caller must deny rather than treat it
// as "no tenant." Only a genuinely unmapped org — the daemon answers 200
// with an empty tenant_id — is ErrNoTenant, and that IS cached (briefly),
// because it is a real, verified answer.
package orgtenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// ErrNoTenant is returned when the org maps to no tenant (the Platform
// owner, a service account's org, or a tenant that has not yet finished
// provisioning). Callers that require a tenant deny; callers that permit a
// tenant-less identity (self/unauthenticated registry entries) treat this
// as "no tenant" rather than an infrastructure failure.
var ErrNoTenant = errors.New("orgtenant: org maps to no tenant")

// Defaults for Config, chosen so a mapped org's steady-state traffic never
// reaches the daemon (positive TTL) while a newly-provisioned tenant
// resolves soon and a flood of unknown orgs is bounded (negative TTL).
const (
	DefaultPositiveTTL  = 5 * time.Minute
	DefaultNegativeTTL  = 10 * time.Second
	DefaultMaxSize      = 10000
	defaultFetchTimeout = 5 * time.Second
)

// Config configures New.
type Config struct {
	// Client is the SVID-pinned HTTP client (daemonMTLSClient in
	// cmd/ext-authz/main.go). Required.
	Client *http.Client
	// BaseURL is the daemon's org-tenant route, e.g.
	// "https://gibson:8086/identity/v1/org-tenant/". Required, must be
	// https (enforced by the caller, main.go, at startup).
	BaseURL string
	// PositiveTTL is how long a mapped org is cached. Default
	// DefaultPositiveTTL.
	PositiveTTL time.Duration
	// NegativeTTL is how long an unmapped org is cached. Default
	// DefaultNegativeTTL.
	NegativeTTL time.Duration
	// MaxSize bounds the cache; at this size the map is cleared rather
	// than evicted with an LRU. Default DefaultMaxSize.
	MaxSize int
	// Now is injectable for tests. Default time.Now.
	Now func() time.Time
}

type cacheEntry struct {
	tenant  string // "" means "cached unmapped" (ErrNoTenant)
	expires time.Time
}

// Resolver implements the OrgTenantResolver interface server.Config wants.
type Resolver struct {
	client  *http.Client
	baseURL string
	posTTL  time.Duration
	negTTL  time.Duration
	maxSize int
	now     func() time.Time

	mu      sync.Mutex
	entries map[string]cacheEntry

	sf singleflight.Group
}

// New builds a Resolver. Returns an error when Client or BaseURL is unset.
func New(cfg Config) (*Resolver, error) {
	if cfg.Client == nil {
		return nil, errors.New("orgtenant: Client required")
	}
	baseURL := strings.TrimSpace(cfg.BaseURL)
	if baseURL == "" {
		return nil, errors.New("orgtenant: BaseURL required")
	}
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	posTTL := cfg.PositiveTTL
	if posTTL <= 0 {
		posTTL = DefaultPositiveTTL
	}
	negTTL := cfg.NegativeTTL
	if negTTL <= 0 {
		negTTL = DefaultNegativeTTL
	}
	maxSize := cfg.MaxSize
	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Resolver{
		client:  cfg.Client,
		baseURL: baseURL,
		posTTL:  posTTL,
		negTTL:  negTTL,
		maxSize: maxSize,
		now:     now,
		entries: make(map[string]cacheEntry),
	}, nil
}

// TenantForOrg returns the tenant mapped to orgID, or ErrNoTenant when the
// org maps to no tenant. Any other error means the daemon could not be
// asked (transport, non-200, malformed JSON): the caller must deny (503),
// never treat it as "no tenant."
func (r *Resolver) TenantForOrg(ctx context.Context, orgID string) (string, error) {
	if !isValidOrgID(orgID) {
		// Not a shape a real Zitadel org id ever takes. No fetch: refuse
		// locally rather than send a malformed path to the daemon.
		return "", ErrNoTenant
	}

	if tenant, hit := r.cached(orgID); hit {
		if tenant == "" {
			return "", ErrNoTenant
		}
		return tenant, nil
	}

	v, err, _ := r.sf.Do(orgID, func() (any, error) {
		tenant, ferr := r.fetch(ctx, orgID)
		if ferr != nil {
			return "", ferr
		}
		r.store(orgID, tenant)
		return tenant, nil
	})
	if err != nil {
		// The wrapped func above returns only errors fetch() already wraps
		// with its own "orgtenant: ..." context; singleflight.Do itself adds
		// nothing to wrap here.
		return "", err //nolint:wrapcheck // see comment
	}
	tenant, _ := v.(string)
	if tenant == "" {
		return "", ErrNoTenant
	}
	return tenant, nil
}

// cached returns the cached tenant (possibly "" for a cached-unmapped
// entry) and whether the cache had a live entry at all.
func (r *Resolver) cached(orgID string) (tenant string, hit bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[orgID]
	if !ok {
		return "", false
	}
	if !r.now().Before(e.expires) {
		delete(r.entries, orgID)
		return "", false
	}
	return e.tenant, true
}

// store records a fetched result. At maxSize the map is cleared — simple
// and bounded, no LRU bookkeeping needed for a cache this size.
func (r *Resolver) store(orgID, tenant string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) >= r.maxSize {
		r.entries = make(map[string]cacheEntry)
	}
	ttl := r.negTTL
	if tenant != "" {
		ttl = r.posTTL
	}
	r.entries[orgID] = cacheEntry{tenant: tenant, expires: r.now().Add(ttl)}
}

// fetch performs the single daemon round trip. A non-200 (including 404 —
// an old daemon without the route) is an error, never "unmapped."
func (r *Resolver) fetch(ctx context.Context, orgID string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, defaultFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, r.baseURL+orgID, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("orgtenant: build request: %w", err)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("orgtenant: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("orgtenant: unexpected status %d from %s", resp.StatusCode, r.baseURL)
	}
	var doc struct {
		TenantID string `json:"tenant_id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&doc); err != nil {
		return "", fmt.Errorf("orgtenant: decode response: %w", err)
	}
	return doc.TenantID, nil
}

// isValidOrgID mirrors the daemon route's own validation: non-empty, max 64
// chars, [0-9A-Za-z_-] only. Zitadel org ids are numeric strings; anything
// else is refused here with no fetch.
func isValidOrgID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c == '_' || c == '-':
		default:
			return false
		}
	}
	return true
}
