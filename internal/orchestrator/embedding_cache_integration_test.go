//go:build integration

package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// intCountingProvider is a counting embedding provider for integration tests.
// It returns deterministic vectors for each call so equality assertions are reliable.
type intCountingProvider struct {
	calls int
}

func (p *intCountingProvider) Embed(_ context.Context, texts []string) ([][]float64, error) {
	p.calls++
	result := make([][]float64, len(texts))
	for i := range texts {
		result[i] = []float64{0.1, 0.2, 0.3, 0.4, 0.5}
	}
	return result, nil
}

func (p *intCountingProvider) SupportsEmbeddings() bool { return true }

// newIntegrationRedis starts an in-process Redis server and returns the
// miniredis handle and a connected go-redis client. The client is closed
// when the test finishes.
func newIntegrationRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })
	return mr, client
}

// TestCachedEmbeddingProvider_Integration_CacheRoundTrip verifies the full
// read-write-read cycle of the embedding cache using an in-process Redis:
//
//  1. First Embed call: inner provider invoked, result cached.
//  2. Second Embed call with same text: inner provider NOT invoked, cached value returned.
//  3. Both return values are identical float64 slices.
func TestCachedEmbeddingProvider_Integration_CacheRoundTrip(t *testing.T) {
	_, client := newIntegrationRedis(t)
	inner := &intCountingProvider{}
	cached := NewCachedEmbeddingProvider(inner, client, nil)

	ctx := context.Background()
	const text = "integration test embedding"

	// First call: miss → calls inner provider.
	first, err := cached.Embed(ctx, []string{text})
	require.NoError(t, err)
	require.Len(t, first, 1)
	assert.Equal(t, 1, inner.calls, "inner should be called exactly once on first request")

	// Second call: hit → inner provider not called again.
	second, err := cached.Embed(ctx, []string{text})
	require.NoError(t, err)
	require.Len(t, second, 1)
	assert.Equal(t, 1, inner.calls, "inner should still be called only once after cache hit")

	// Both return values must be identical.
	assert.Equal(t, first[0], second[0], "cached value must equal original value")
}

// TestCachedEmbeddingProvider_Integration_TTLExpiry verifies that after the
// cache TTL elapses (simulated by advancing the miniredis clock), a subsequent
// call re-invokes the inner provider.
func TestCachedEmbeddingProvider_Integration_TTLExpiry(t *testing.T) {
	mr, client := newIntegrationRedis(t)
	inner := &intCountingProvider{}
	cached := NewCachedEmbeddingProvider(inner, client, nil)

	ctx := context.Background()
	const text = "ttl expiry test"

	// Prime the cache.
	_, err := cached.Embed(ctx, []string{text})
	require.NoError(t, err)
	assert.Equal(t, 1, inner.calls)

	// Confirm cache hit before expiry.
	_, err = cached.Embed(ctx, []string{text})
	require.NoError(t, err)
	assert.Equal(t, 1, inner.calls, "should still be 1 call before TTL expires")

	// Advance time past the 5-minute TTL.
	mr.FastForward(6 * time.Minute)

	// Cache entry should have expired; inner provider must be called again.
	_, err = cached.Embed(ctx, []string{text})
	require.NoError(t, err)
	assert.Equal(t, 2, inner.calls, "inner should be called again after TTL expiry")
}
