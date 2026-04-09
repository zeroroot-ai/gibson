package orchestrator

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingEmbeddingProvider counts Embed invocations and returns fixed vectors.
type countingEmbeddingProvider struct {
	calls int
	err   error
}

func (p *countingEmbeddingProvider) Embed(_ context.Context, texts []string) ([][]float64, error) {
	if p.err != nil {
		return nil, p.err
	}
	p.calls++
	result := make([][]float64, len(texts))
	for i := range texts {
		result[i] = []float64{1.0, 2.0, 3.0}
	}
	return result, nil
}
func (p *countingEmbeddingProvider) SupportsEmbeddings() bool { return true }

func newTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })
	return mr, client
}

func TestCachedEmbeddingProvider_CacheMissCallsProvider(t *testing.T) {
	_, client := newTestRedis(t)
	inner := &countingEmbeddingProvider{}
	cached := NewCachedEmbeddingProvider(inner, client, nil)

	vecs, err := cached.Embed(context.Background(), []string{"hello"})
	require.NoError(t, err)
	require.Len(t, vecs, 1)
	assert.Equal(t, []float64{1.0, 2.0, 3.0}, vecs[0])
	assert.Equal(t, 1, inner.calls)
}

func TestCachedEmbeddingProvider_CacheHitAvoidsDuplicateCall(t *testing.T) {
	_, client := newTestRedis(t)
	inner := &countingEmbeddingProvider{}
	cached := NewCachedEmbeddingProvider(inner, client, nil)

	// First call: miss -> provider
	_, err := cached.Embed(context.Background(), []string{"hello"})
	require.NoError(t, err)
	assert.Equal(t, 1, inner.calls)

	// Second call: hit -> no provider call
	vecs, err := cached.Embed(context.Background(), []string{"hello"})
	require.NoError(t, err)
	assert.Equal(t, 1, inner.calls) // still 1
	assert.Equal(t, []float64{1.0, 2.0, 3.0}, vecs[0])
}

func TestCachedEmbeddingProvider_RedisErrorFallsThrough(t *testing.T) {
	mr, client := newTestRedis(t)
	inner := &countingEmbeddingProvider{}
	cached := NewCachedEmbeddingProvider(inner, client, nil)

	// Make Redis unreachable by closing the server.
	mr.Close()

	vecs, err := cached.Embed(context.Background(), []string{"hello"})
	require.NoError(t, err) // Should not propagate the Redis error
	assert.Equal(t, []float64{1.0, 2.0, 3.0}, vecs[0])
	assert.Equal(t, 1, inner.calls)
}

func TestCachedEmbeddingProvider_SupportsEmbeddings(t *testing.T) {
	_, client := newTestRedis(t)
	inner := &countingEmbeddingProvider{}
	cached := NewCachedEmbeddingProvider(inner, client, nil)
	assert.True(t, cached.SupportsEmbeddings())
}

func TestCachedEmbeddingProvider_MultipleMixedHitsMisses(t *testing.T) {
	_, client := newTestRedis(t)
	inner := &countingEmbeddingProvider{}
	cached := NewCachedEmbeddingProvider(inner, client, nil)

	// Prime cache with "hello"
	_, err := cached.Embed(context.Background(), []string{"hello"})
	require.NoError(t, err)
	assert.Equal(t, 1, inner.calls)

	// Now call with both a cached and an uncached text
	vecs, err := cached.Embed(context.Background(), []string{"hello", "world"})
	require.NoError(t, err)
	require.Len(t, vecs, 2)
	// inner should have been called exactly once more for "world"
	assert.Equal(t, 2, inner.calls)
	assert.Equal(t, []float64{1.0, 2.0, 3.0}, vecs[0])
	assert.Equal(t, []float64{1.0, 2.0, 3.0}, vecs[1])
}
