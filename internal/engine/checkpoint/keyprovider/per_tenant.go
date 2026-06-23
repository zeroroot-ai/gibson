// Package keyprovider — per_tenant.go
//
// PerTenantKeyProvider is a thin facade around per-tenant KMS lookups. The
// daemon's mission-checkpointing pipeline encrypts checkpoint payloads with a
// key derived from the owning tenant, never a globally-shared key. This file
// implements:
//
//   - PerTenantKeyResolver: a small interface the daemon's KMS abstraction
//     fulfils (e.g. AWS KMS, Vault, in-cluster Kubernetes secret).
//   - PerTenantKeyProvider: a KeyProvider that resolves the live tenant from
//     a context-bound tenant ID and caches keys with a bounded LRU.
//   - InMemoryTenantKeyResolver: a test/dev resolver that returns deterministic
//     32-byte keys (NOT for production).
//
// Spec: mission-checkpointing R11.1 (per-tenant KMS), R11.4 (bounded cache).
package keyprovider

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

// TenantContextKey is the context key the daemon uses to thread the active
// tenant through to the encryption pipeline. Mirrors auth.TenantStringFromContext
// but exposed here to avoid cyclic imports between checkpoint/keyprovider and
// the auth package.
type tenantCtxKey struct{}

// ContextWithTenant attaches the supplied tenant ID to the context.
func ContextWithTenant(ctx context.Context, tenant string) context.Context {
	if tenant == "" {
		return ctx
	}
	return context.WithValue(ctx, tenantCtxKey{}, tenant)
}

// TenantFromContext extracts the tenant ID, returning an empty string if none
// is set.
func TenantFromContext(ctx context.Context) string {
	if v := ctx.Value(tenantCtxKey{}); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// PerTenantKeyResolver is implemented by the daemon's KMS abstraction. It
// returns a 32-byte AES-256 key derived from the tenant's KMS key material.
//
// Implementations MUST:
//   - Return a 32-byte key (AES-256 requirement).
//   - Return a stable, descriptive keyID per tenant (e.g. arn-or-vault-path).
//   - Never log key material.
//   - Return a typed error on KMS-unavailable so the caller can fail closed.
type PerTenantKeyResolver interface {
	// ResolveKey returns the current encryption key for the tenant.
	ResolveKey(ctx context.Context, tenantID string) (key []byte, keyID string, err error)

	// ResolveKeyByID returns a historical key by ID for decrypt-on-restore
	// when the active key has rotated.
	ResolveKeyByID(ctx context.Context, keyID string) (key []byte, err error)
}

// ErrTenantKeyUnavailable is returned by PerTenantKeyProvider when the
// resolver cannot supply a key (KMS unreachable, tenant unknown, etc.).
// The threaded checkpointer translates this into a fail-closed error.
var ErrTenantKeyUnavailable = errors.New("keyprovider: tenant key unavailable")

// ErrNoTenantInContext is returned when the encryption pipeline is invoked
// without a tenant on the context. The daemon's mission lifecycle MUST always
// thread the tenant; absence is a bug, not a fallback condition.
var ErrNoTenantInContext = errors.New("keyprovider: no tenant in context")

// PerTenantKeyProvider implements KeyProvider by resolving keys from a
// PerTenantKeyResolver, scoped by the tenant on the context. Resolved keys
// are cached with a bounded LRU and TTL to avoid hammering KMS on every
// checkpoint write.
type PerTenantKeyProvider struct {
	resolver PerTenantKeyResolver

	// cache state
	mu       sync.Mutex
	cap      int
	ttl      time.Duration
	entries  map[string]*tenantCacheEntry // keyed by tenantID for current keys
	byKeyID  map[string][]byte            // keyed by keyID for historical lookups
	lruOrder []string                     // tenant IDs in LRU order (front=oldest)
}

type tenantCacheEntry struct {
	key       []byte
	keyID     string
	expiresAt time.Time
}

// PerTenantKeyProviderOption configures PerTenantKeyProvider behaviour.
type PerTenantKeyProviderOption func(*PerTenantKeyProvider)

// WithTTL sets the cache entry TTL (how long a resolved key is reused before
// re-resolution). Default: 5 minutes.
func WithTTL(ttl time.Duration) PerTenantKeyProviderOption {
	return func(p *PerTenantKeyProvider) {
		if ttl > 0 {
			p.ttl = ttl
		}
	}
}

// NewPerTenantKeyProvider constructs a per-tenant KeyProvider. The resolver
// must be non-nil; passing nil is a programmer error.
func NewPerTenantKeyProvider(resolver PerTenantKeyResolver, opts ...PerTenantKeyProviderOption) *PerTenantKeyProvider {
	p := &PerTenantKeyProvider{
		resolver: resolver,
		cap:      256,
		ttl:      5 * time.Minute,
		entries:  make(map[string]*tenantCacheEntry),
		byKeyID:  make(map[string][]byte),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// GetKey returns the current encryption key for the tenant on the context.
// Spec: mission-checkpointing R11.1.
func (p *PerTenantKeyProvider) GetKey(ctx context.Context) ([]byte, error) {
	tenantID := TenantFromContext(ctx)
	if tenantID == "" {
		return nil, ErrNoTenantInContext
	}

	if cached := p.getCached(tenantID); cached != nil {
		return cached.key, nil
	}

	key, keyID, err := p.resolver.ResolveKey(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTenantKeyUnavailable, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("keyprovider: tenant %s returned %d-byte key, expected 32", tenantID, len(key))
	}

	p.put(tenantID, key, keyID)
	return key, nil
}

// GetKeyByID returns a historical key by ID for decrypt-on-restore.
// Spec: mission-checkpointing R11.1 (key rotation graceful path).
func (p *PerTenantKeyProvider) GetKeyByID(ctx context.Context, keyID string) ([]byte, error) {
	if keyID == "" {
		return nil, fmt.Errorf("keyprovider: empty keyID")
	}

	if k := p.getByKeyID(keyID); k != nil {
		return k, nil
	}

	key, err := p.resolver.ResolveKeyByID(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTenantKeyUnavailable, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("keyprovider: keyID %s returned %d-byte key, expected 32", keyID, len(key))
	}

	p.mu.Lock()
	p.byKeyID[keyID] = key
	p.mu.Unlock()
	return key, nil
}

// CurrentKeyID returns the latest resolved keyID for the most-recently-touched
// tenant. The threaded checkpointer uses this to stamp the EncryptedPayload.
// In a per-tenant scheme this is approximate — the keyID is also returned by
// GetKey, but the checkpointer doesn't currently surface that. The Encrypt
// path resolves via GetKey then reads CurrentKeyID; this works as long as
// concurrent writes for different tenants don't race; for safety, the daemon
// should serialise per-tenant or carry the keyID alongside the key in a
// future refactor.
func (p *PerTenantKeyProvider) CurrentKeyID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.lruOrder) == 0 {
		return ""
	}
	last := p.lruOrder[len(p.lruOrder)-1]
	if e, ok := p.entries[last]; ok {
		return e.keyID
	}
	return ""
}

func (p *PerTenantKeyProvider) getCached(tenantID string) *tenantCacheEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[tenantID]
	if !ok {
		return nil
	}
	if time.Now().After(e.expiresAt) {
		// expired
		delete(p.entries, tenantID)
		p.removeFromLRU(tenantID)
		return nil
	}
	p.touchLRU(tenantID)
	return e
}

func (p *PerTenantKeyProvider) put(tenantID string, key []byte, keyID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.entries[tenantID] = &tenantCacheEntry{
		key:       key,
		keyID:     keyID,
		expiresAt: time.Now().Add(p.ttl),
	}
	if keyID != "" {
		p.byKeyID[keyID] = key
	}
	p.touchLRU(tenantID)

	for len(p.lruOrder) > p.cap {
		evict := p.lruOrder[0]
		p.lruOrder = p.lruOrder[1:]
		delete(p.entries, evict)
	}
}

func (p *PerTenantKeyProvider) touchLRU(tenantID string) {
	p.removeFromLRU(tenantID)
	p.lruOrder = append(p.lruOrder, tenantID)
}

func (p *PerTenantKeyProvider) removeFromLRU(tenantID string) {
	for i, id := range p.lruOrder {
		if id == tenantID {
			p.lruOrder = append(p.lruOrder[:i], p.lruOrder[i+1:]...)
			return
		}
	}
}

func (p *PerTenantKeyProvider) getByKeyID(keyID string) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.byKeyID[keyID]
}

// InMemoryTenantKeyResolver is a development / test resolver that derives a
// deterministic 32-byte key from a master seed and the tenantID via SHA-256.
// NEVER use in production — it is suitable only for the chaos test harness
// and unit tests where the chart-managed KMS provisioning is not available.
type InMemoryTenantKeyResolver struct {
	seed []byte
}

// NewInMemoryTenantKeyResolver constructs an in-memory resolver. If seed is
// empty a fixed test seed is used.
func NewInMemoryTenantKeyResolver(seed []byte) *InMemoryTenantKeyResolver {
	if len(seed) == 0 {
		seed = []byte("gibson-mission-checkpointing-test-seed-do-not-use-in-prod")
	}
	return &InMemoryTenantKeyResolver{seed: seed}
}

// ResolveKey derives a per-tenant key by hashing seed||tenantID.
func (r *InMemoryTenantKeyResolver) ResolveKey(_ context.Context, tenantID string) ([]byte, string, error) {
	if tenantID == "" {
		return nil, "", fmt.Errorf("in-memory resolver: empty tenantID")
	}
	h := sha256.New()
	h.Write(r.seed)
	h.Write([]byte("|"))
	h.Write([]byte(tenantID))
	sum := h.Sum(nil)
	keyID := fmt.Sprintf("inmem:%s:v1", tenantID)
	return sum, keyID, nil
}

// ResolveKeyByID parses the deterministic keyID produced by ResolveKey and
// re-derives the same 32-byte key. Only the `inmem:<tenant>:v1` shape is
// supported.
func (r *InMemoryTenantKeyResolver) ResolveKeyByID(ctx context.Context, keyID string) ([]byte, error) {
	if len(keyID) < 7 || keyID[:6] != "inmem:" {
		return nil, fmt.Errorf("in-memory resolver: unsupported keyID %q", keyID)
	}
	rest := keyID[6:]
	// trim ":v1" suffix
	if n := len(rest) - 3; n > 0 && rest[n:] == ":v1" {
		rest = rest[:n]
	}
	key, _, err := r.ResolveKey(ctx, rest)
	return key, err
}
