package vector

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/auth"
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
func TestSanitizeTenantID(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"acme", "acme"},
		{"acme-corp", "acme_corp"},
		{"tenant-123", "tenant_123"},
		{"my_tenant", "my_tenant"},
	}
	for _, c := range cases {
		assert.Equal(t, c.expected, sanitizeTenantID(c.input), "input: %s", c.input)
	}
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
