// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package vector

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/sdk/auth"
)

const testDims = 3

// makeEmbedding creates a dummy embedding of the given dimension with the
// first element set to val so different records produce different embeddings.
func makeEmbedding(val float64) []float64 {
	emb := make([]float64, testDims)
	emb[0] = val
	return emb
}

// TestNewVectorStoreForTenant_KeyIsolation verifies that writes under tenant A
// are not visible to tenant B for the same logical key "x".
// Spec: per-tenant-data-plane-completion Req 3.1, 3.5, D4.
func TestNewVectorStoreForTenant_KeyIsolation(t *testing.T) {
	// Single shared underlying store (D4: one store, two tenant views).
	shared := NewEmbeddedVectorStore(testDims)
	defer shared.Close()

	tenantA := auth.MustNewTenantID("tenant-a")
	tenantB := auth.MustNewTenantID("tenant-b")

	storeA := NewVectorStoreForTenantWithStore(shared, tenantA)
	storeB := NewVectorStoreForTenantWithStore(shared, tenantB)

	ctx := context.Background()

	// Store "x" under tenant A.
	recA := VectorRecord{
		ID:        "x",
		Content:   "tenant A secret",
		Embedding: makeEmbedding(1.0),
	}
	require.NoError(t, storeA.Store(ctx, recA))

	// Tenant B should NOT find "x".
	got, err := storeB.Get(ctx, "x")
	require.NoError(t, err)
	assert.Nil(t, got, "tenant B must not see tenant A's key 'x'")

	// Tenant A should find "x" with original (un-prefixed) ID.
	gotA, err := storeA.Get(ctx, "x")
	require.NoError(t, err)
	require.NotNil(t, gotA)
	assert.Equal(t, "x", gotA.ID, "tenant A must get back the original ID without prefix")
	assert.Equal(t, "tenant A secret", gotA.Content)
}

// TestNewVectorStoreForTenant_TwoTenantsSameKey verifies that two tenants can
// each store a record under the same logical ID without colliding.
func TestNewVectorStoreForTenant_TwoTenantsSameKey(t *testing.T) {
	shared := NewEmbeddedVectorStore(testDims)
	defer shared.Close()

	tenantA := auth.MustNewTenantID("alpha")
	tenantB := auth.MustNewTenantID("beta")

	storeA := NewVectorStoreForTenantWithStore(shared, tenantA)
	storeB := NewVectorStoreForTenantWithStore(shared, tenantB)

	ctx := context.Background()

	recA := VectorRecord{ID: "shared-key", Content: "data-a", Embedding: makeEmbedding(0.9)}
	recB := VectorRecord{ID: "shared-key", Content: "data-b", Embedding: makeEmbedding(0.1)}

	require.NoError(t, storeA.Store(ctx, recA))
	require.NoError(t, storeB.Store(ctx, recB))

	gotA, err := storeA.Get(ctx, "shared-key")
	require.NoError(t, err)
	require.NotNil(t, gotA)
	assert.Equal(t, "data-a", gotA.Content, "tenant A gets its own record")

	gotB, err := storeB.Get(ctx, "shared-key")
	require.NoError(t, err)
	require.NotNil(t, gotB)
	assert.Equal(t, "data-b", gotB.Content, "tenant B gets its own record")
}

// TestNewVectorStoreForTenant_Delete verifies that Delete only removes the
// prefixed key from the tenant's namespace, not from other tenants.
func TestNewVectorStoreForTenant_Delete(t *testing.T) {
	shared := NewEmbeddedVectorStore(testDims)
	defer shared.Close()

	tenantA := auth.MustNewTenantID("aaa")
	tenantB := auth.MustNewTenantID("bbb")
	storeA := NewVectorStoreForTenantWithStore(shared, tenantA)
	storeB := NewVectorStoreForTenantWithStore(shared, tenantB)

	ctx := context.Background()

	rec := VectorRecord{ID: "item", Content: "value", Embedding: makeEmbedding(0.5)}
	require.NoError(t, storeA.Store(ctx, rec))
	require.NoError(t, storeB.Store(ctx, rec))

	// Delete from A.
	require.NoError(t, storeA.Delete(ctx, "item"))

	// A no longer has it.
	gotA, _ := storeA.Get(ctx, "item")
	assert.Nil(t, gotA, "deleted key must not be found under tenant A")

	// B still has it.
	gotB, err := storeB.Get(ctx, "item")
	require.NoError(t, err)
	assert.NotNil(t, gotB, "tenant B's record must survive tenant A's delete")
}

// TestSanitizeTenantID verifies the sanitize helper produces safe prefixes.
func TestTenantKeyPrefix_IsInjective(t *testing.T) {
	// Ids that differ only in characters the old sanitizer stripped must
	// not share a namespace.
	ids := []string{"acme", "acme-corp", "acme_corp", "acmecorp", "acme.corp", "ACME"}
	seen := map[string]string{}
	for _, id := range ids {
		p := tenantKeyPrefix(id)
		if prior, dup := seen[p]; dup {
			t.Fatalf("%q and %q share prefix %q", prior, id, p)
		}
		seen[p] = id
		assert.True(t, strings.HasPrefix(p, "tenant_") && strings.HasSuffix(p, ":"), p)
	}
	assert.Equal(t, "tenant_acme_2dcorp:", tenantKeyPrefix("acme-corp"))
}

// THE FIXTURE THIS EXISTS FOR: the wrapper's Search used to return other
// tenants' records (with their prefixes still on), because the shared store
// ranks everything together and nothing filtered the answer.
func TestTenantScopedStore_SearchSeesOnlyItsOwnTenant(t *testing.T) {
	shared := NewEmbeddedVectorStore(testDims)
	t.Cleanup(func() { _ = shared.Close() })
	storeA := NewVectorStoreForTenantWithStore(shared, auth.MustNewTenantID("tenant-a"))
	storeB := NewVectorStoreForTenantWithStore(shared, auth.MustNewTenantID("tenant-b"))
	ctx := context.Background()

	require.NoError(t, storeA.Store(ctx, VectorRecord{ID: "a1", Content: "a one", Embedding: makeEmbedding(1.0)}))
	require.NoError(t, storeA.Store(ctx, VectorRecord{ID: "a2", Content: "a two", Embedding: makeEmbedding(0.9)}))
	require.NoError(t, storeB.Store(ctx, VectorRecord{ID: "b1", Content: "b one", Embedding: makeEmbedding(1.0)}))
	require.NoError(t, storeB.Store(ctx, VectorRecord{ID: "b2", Content: "b two", Embedding: makeEmbedding(0.9)}))

	q := VectorQuery{Embedding: makeEmbedding(1.0), TopK: 10}
	resA, err := storeA.Search(ctx, q)
	require.NoError(t, err)
	resB, err := storeB.Search(ctx, q)
	require.NoError(t, err)

	idsOf := func(rs []VectorResult) []string {
		out := make([]string, 0, len(rs))
		for _, r := range rs {
			out = append(out, r.Record.ID)
		}
		return out
	}
	assert.ElementsMatch(t, []string{"a1", "a2"}, idsOf(resA), "tenant A sees only its own records, unprefixed")
	assert.ElementsMatch(t, []string{"b1", "b2"}, idsOf(resB), "tenant B sees only its own records, unprefixed")
	for _, r := range append(resA, resB...) {
		assert.False(t, strings.HasPrefix(r.Record.ID, "tenant_"), "no prefixed id may leak out: %s", r.Record.ID)
	}
}

// Two ids the old sanitizer collapsed are two namespaces now.
func TestTenantScopedStore_SimilarIdsDoNotShareANamespace(t *testing.T) {
	shared := NewEmbeddedVectorStore(testDims)
	t.Cleanup(func() { _ = shared.Close() })
	hyphen := NewVectorStoreForTenantWithStore(shared, auth.MustNewTenantID("acme-corp"))
	under := NewVectorStoreForTenantWithStore(shared, auth.MustNewTenantID("acme_corp"))
	ctx := context.Background()
	require.NoError(t, hyphen.Store(ctx, VectorRecord{ID: "k", Content: "hyphen", Embedding: makeEmbedding(1.0)}))
	got, err := under.Get(ctx, "k")
	require.NoError(t, err)
	assert.Nil(t, got, "acme_corp must not read acme-corp's record")
}

// TestNewVectorStoreForTenant_FactoryFunction verifies the factory-level
// constructor (creates its own underlying store) produces a working wrapper.
func TestNewVectorStoreForTenant_FactoryFunction(t *testing.T) {
	tenantA := auth.MustNewTenantID("factory-tenant")
	store, err := NewVectorStoreForTenant(VectorStoreConfig{Backend: "embedded", Dimensions: testDims}, tenantA)
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close()

	ctx := context.Background()
	rec := VectorRecord{ID: "test", Content: "content", Embedding: makeEmbedding(0.7)}
	require.NoError(t, store.Store(ctx, rec))
	got, err := store.Get(ctx, "test")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "test", got.ID)
}
