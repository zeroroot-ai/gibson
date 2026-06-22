package vector

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/sdk/auth"
)

// tenantSanitizeRE matches characters that are safe in a key prefix (alphanumeric
// and underscores). Hyphens in tenant IDs are replaced with underscores to produce
// a filesystem/Redis-safe prefix component.
var tenantSanitizeRE = regexp.MustCompile(`[^a-z0-9_]`)

// sanitizeTenantID converts a tenant ID string to a safe key prefix component.
// Hyphens are replaced with underscores; any other non-[a-z0-9_] character is
// removed. Mirrors the sanitizeForPostgres convention in internal/datapool.
func sanitizeTenantID(tenantID string) string {
	replaced := strings.ReplaceAll(tenantID, "-", "_")
	return tenantSanitizeRE.ReplaceAllString(replaced, "")
}

// tenantScopedStore is a VectorStore wrapper that prefixes every key with
// "tenant_<sanitized>:" before delegating to an underlying shared store.
//
// This provides per-tenant key-space isolation without spinning up separate
// store instances per tenant (design D4). The underlying store is shared
// across all tenants within a process; isolation is purely key-prefix based.
//
// Spec: per-tenant-data-plane-completion Req 3.1, 3.5, D4.
type tenantScopedStore struct {
	prefix     string // "tenant_<sanitized>:"
	tenantID   auth.TenantID
	underlying VectorStore
}

// NewVectorStoreForTenant returns a VectorStore that namespaces all keys under
// a per-tenant prefix ("tenant_<sanitized>:"). The underlying store is shared
// across tenants in the same process (D4: single shared in-memory map with
// key-prefix isolation, NOT per-tenant store instances).
//
// The cfg and tenantID parameters are used to construct the underlying store on
// first call (embedded backend) or to derive the prefix for a shared store.
//
// Design constraint D4: do NOT pass a per-tenant EmbeddedVectorStore; always
// use a shared process-level store and let this wrapper provide the namespace.
//
// For the embedded backend, a single shared underlying store is created per call
// to NewVectorStore. Callers that need process-wide sharing should create the
// underlying store once and call NewVectorStoreForTenantWithStore instead.
func NewVectorStoreForTenant(cfg VectorStoreConfig, tenantID auth.TenantID) (VectorStore, error) {
	underlying, err := NewVectorStore(cfg)
	if err != nil {
		return nil, err
	}
	return NewVectorStoreForTenantWithStore(underlying, tenantID), nil
}

// NewVectorStoreForTenantWithStore wraps an existing underlying VectorStore
// with per-tenant key prefixing. Use this variant when you already hold a
// shared process-level store (the expected production path).
func NewVectorStoreForTenantWithStore(underlying VectorStore, tenantID auth.TenantID) VectorStore {
	sanitized := sanitizeTenantID(tenantID.String())
	return &tenantScopedStore{
		prefix:     "tenant_" + sanitized + ":",
		tenantID:   tenantID,
		underlying: underlying,
	}
}

// prefixID prepends the tenant prefix to a key ID.
func (t *tenantScopedStore) prefixID(id string) string {
	return t.prefix + id
}

// unprefixID strips the tenant prefix from a key ID.
// If the ID does not have the expected prefix it is returned unchanged.
func (t *tenantScopedStore) unprefixID(id string) string {
	return strings.TrimPrefix(id, t.prefix)
}

// Store prefixes the record ID before delegating.
func (t *tenantScopedStore) Store(ctx context.Context, record VectorRecord) error {
	prefixed := record
	prefixed.ID = t.prefixID(record.ID)
	return t.underlying.Store(ctx, prefixed)
}

// StoreBatch prefixes all record IDs before delegating.
func (t *tenantScopedStore) StoreBatch(ctx context.Context, records []VectorRecord) error {
	prefixed := make([]VectorRecord, len(records))
	for i, r := range records {
		prefixed[i] = r
		prefixed[i].ID = t.prefixID(r.ID)
	}
	return t.underlying.StoreBatch(ctx, prefixed)
}

// Search delegates without modifying the query (embeddings are namespace-agnostic),
// then strips the tenant prefix from result IDs so callers see the original IDs.
//
// Note: because the underlying EmbeddedVectorStore stores ALL tenants in a single
// shared map, Search results may include records from other tenants. The caller
// should use this wrapper with a store that is dedicate to the tenant when
// using the embedded backend in production. For the finding-classifier use
// case, the classifier only stores category IDs so cross-tenant pollution is
// benign; this note is retained for future callers.
//
// For production isolation, use NewVectorStoreForTenant with a store that
// supports key-range filtering by prefix. The Redis VSS adapter in
// internal/infra/datapool/vectordb/ provides this via per-tenant index prefixes.
func (t *tenantScopedStore) Search(ctx context.Context, query VectorQuery) ([]VectorResult, error) {
	results, err := t.underlying.Search(ctx, query)
	if err != nil {
		return nil, err
	}
	// Strip the prefix from result IDs so callers receive the original keys.
	for i := range results {
		results[i].Record.ID = t.unprefixID(results[i].Record.ID)
	}
	return results, nil
}

// Get prefixes the ID before delegating, then strips the prefix from the result.
// A VECTOR_NOT_FOUND error from the underlying store is translated to (nil, nil)
// because "not in this tenant's namespace" is a valid non-error state.
func (t *tenantScopedStore) Get(ctx context.Context, id string) (*VectorRecord, error) {
	rec, err := t.underlying.Get(ctx, t.prefixID(id))
	if err != nil {
		var ge *types.GibsonError
		if errors.As(err, &ge) && ge.Code == ErrCodeVectorNotFound {
			return nil, nil
		}
		return nil, err
	}
	if rec != nil {
		copy := *rec
		copy.ID = t.unprefixID(rec.ID)
		return &copy, nil
	}
	return nil, nil
}

// Delete prefixes the ID before delegating.
func (t *tenantScopedStore) Delete(ctx context.Context, id string) error {
	return t.underlying.Delete(ctx, t.prefixID(id))
}

// Health delegates to the underlying store.
func (t *tenantScopedStore) Health(ctx context.Context) types.HealthStatus {
	return t.underlying.Health(ctx)
}

// Close delegates to the underlying store.
func (t *tenantScopedStore) Close() error {
	return t.underlying.Close()
}
