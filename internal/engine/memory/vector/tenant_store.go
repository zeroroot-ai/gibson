// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package vector

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/sdk/auth"
)

// tenantKeyPrefix renders a tenant id as the key prefix its records live
// under. Lower-case letters and digits pass through; every other byte becomes
// `_` and its two hex digits. The mapping is injective, so two distinct
// tenant ids can never share a prefix — the earlier sanitizer stripped
// characters, which collapsed "a-b", "a_b" and "ab" onto one namespace.
func tenantKeyPrefix(tenantID string) string {
	var b strings.Builder
	b.WriteString("tenant_")
	for i := 0; i < len(tenantID); i++ {
		c := tenantID[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "_%02x", c)
	}
	b.WriteByte(':')
	return b.String()
}

// tenantScopedStore is a VectorStore wrapper that prefixes every key with
// "tenant_<sanitized>:" before delegating to an underlying shared store.
//
// Every operation, Search included, sees only this tenant's records; the
// shared store is one map, and the prefix is the whole boundary (design D4). The underlying store is shared
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
	return &tenantScopedStore{
		prefix:     tenantKeyPrefix(tenantID.String()),
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

// Search runs the query against the shared store and keeps only the results
// that live under this tenant's prefix, with the prefix stripped. The
// underlying store ranks every tenant's records together, so a result set is
// filtered here rather than trusted: before this filter, a tenant's Search
// returned other tenants' records with their prefixes still attached.
//
// TopK bounds what the shared store returns before the filter, so a tenant
// can receive fewer than TopK hits when other tenants' records outrank its
// own. That is a completeness limit of the shared-map design, never a leak.
func (t *tenantScopedStore) Search(ctx context.Context, query VectorQuery) ([]VectorResult, error) {
	results, err := t.underlying.Search(ctx, query)
	if err != nil {
		return nil, err
	}
	kept := results[:0]
	for _, r := range results {
		if !strings.HasPrefix(r.Record.ID, t.prefix) {
			continue
		}
		r.Record.ID = t.unprefixID(r.Record.ID)
		kept = append(kept, r)
	}
	return kept, nil
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
