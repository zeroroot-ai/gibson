package auth

import (
	"context"
	"sync"
	"time"
)

// TenantValidator validates that a tenant exists and is in an allowed state.
// This interface is used to avoid circular dependencies with the component package.
type TenantValidator interface {
	// ValidateTenantStatus checks if a tenant exists and returns its status.
	// Returns the tenant status ("active", "provisioning", "suspended", "deleted") or error if not found.
	ValidateTenantStatus(ctx context.Context, tenantID string) (string, error)
}

// cachedTenantEntry holds a cached tenant validation result.
type cachedTenantEntry struct {
	status    string
	err       error
	expiresAt time.Time
}

// CachedTenantValidator wraps a TenantValidator with an in-process cache.
//
// Cache entries are keyed by tenant ID. Both successful lookups and errors
// are cached to prevent thundering-herd problems when tenants are missing
// or the backing store is temporarily unavailable.
//
// CachedTenantValidator is safe for concurrent use.
type CachedTenantValidator struct {
	delegate TenantValidator
	cache    sync.Map // map[string]*cachedTenantEntry
	ttl      time.Duration
}

// NewCachedTenantValidator creates a new cached tenant validator.
//
// If ttl is zero it defaults to 60 seconds.
func NewCachedTenantValidator(delegate TenantValidator, ttl time.Duration) *CachedTenantValidator {
	if ttl == 0 {
		ttl = 60 * time.Second
	}
	return &CachedTenantValidator{
		delegate: delegate,
		ttl:      ttl,
	}
}

// ValidateTenantStatus checks the cache first, then delegates to the underlying validator.
//
// The result — including errors — is cached for the configured TTL so that
// repeated lookups for the same tenant ID do not hit Redis on every request.
func (v *CachedTenantValidator) ValidateTenantStatus(ctx context.Context, tenantID string) (string, error) {
	// Check cache first.
	if raw, ok := v.cache.Load(tenantID); ok {
		entry := raw.(*cachedTenantEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.status, entry.err
		}
		// Entry expired — evict and fall through to the delegate.
		v.cache.Delete(tenantID)
	}

	// Cache miss — delegate to the underlying validator.
	tenantStatus, err := v.delegate.ValidateTenantStatus(ctx, tenantID)

	// Cache both successes and errors to prevent thundering herd on
	// repeated lookups for unknown or temporarily unavailable tenants.
	v.cache.Store(tenantID, &cachedTenantEntry{
		status:    tenantStatus,
		err:       err,
		expiresAt: time.Now().Add(v.ttl),
	})

	return tenantStatus, err
}

// InvalidateCache removes a tenant from the cache.
//
// Call this when a tenant's status changes (e.g., after provisioning completes
// or when a tenant is suspended) so the next request fetches fresh data.
func (v *CachedTenantValidator) InvalidateCache(tenantID string) {
	v.cache.Delete(tenantID)
}

// IsTenantAccessible reports whether the given tenant status permits request processing.
//
// Status semantics:
//   - "active": fully operational — allow all requests.
//   - "provisioning": tenant is being set up — allow requests so provisioning
//     agents can operate; per-operation restrictions are handled downstream.
//   - "suspended": tenant account is suspended — read-only access is permitted;
//     write rejection is handled by downstream handlers, not the interceptor.
//   - "deleted" and any unknown value: deny all access.
func IsTenantAccessible(status string) bool {
	switch status {
	case "active", "provisioning":
		return true
	case "suspended":
		// Suspended tenants may still issue read requests; write-rejection
		// is enforced downstream, not at the auth-interceptor level.
		return true
	default:
		return false
	}
}
