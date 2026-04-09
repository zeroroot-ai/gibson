package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	embeddingCacheTTL    = 5 * time.Minute
	embeddingCachePrefix = "emb:"
)

// EmbeddingProvider is the package-local interface for generating vector
// embeddings. It mirrors the shape of llm.EmbeddingProvider and is declared
// here to keep the orchestrator package decoupled from the llm package.
type EmbeddingProvider interface {
	// Embed generates vector embeddings for a batch of texts.
	Embed(ctx context.Context, texts []string) ([][]float64, error)

	// SupportsEmbeddings reports whether this provider can generate embeddings.
	SupportsEmbeddings() bool
}

// CachedEmbeddingProvider wraps an EmbeddingProvider with a Redis-backed cache.
// Cache keys are "emb:{sha256(text)}" with a 5-minute TTL. Vectors are stored
// as JSON-encoded []float64 values.
//
// On Redis errors the provider falls through to the inner provider without
// failing the call, emitting a WARN log to slog.
type CachedEmbeddingProvider struct {
	inner  EmbeddingProvider
	client *redis.Client
	logger *slog.Logger
}

// NewCachedEmbeddingProvider creates a new CachedEmbeddingProvider.
// A nil logger falls back to slog.Default().
func NewCachedEmbeddingProvider(inner EmbeddingProvider, client *redis.Client, logger *slog.Logger) *CachedEmbeddingProvider {
	if logger == nil {
		logger = slog.Default()
	}
	return &CachedEmbeddingProvider{
		inner:  inner,
		client: client,
		logger: logger,
	}
}

// SupportsEmbeddings delegates to the inner provider.
func (c *CachedEmbeddingProvider) SupportsEmbeddings() bool {
	return c.inner.SupportsEmbeddings()
}

// Embed returns embeddings for the given texts, consulting the Redis cache
// before calling the inner provider.
//
// Cache semantics per text:
//   - HIT: return the cached []float64 slice directly.
//   - MISS: call inner provider, cache the result, return it.
//   - REDIS ERROR: log WARN, call inner provider directly (no-fail).
func (c *CachedEmbeddingProvider) Embed(ctx context.Context, texts []string) ([][]float64, error) {
	results := make([][]float64, len(texts))
	missIndices := make([]int, 0, len(texts))
	missTexts := make([]string, 0, len(texts))

	// Phase 1: try to load all vectors from cache.
	for i, text := range texts {
		key := embeddingKey(text)
		cached, err := c.client.Get(ctx, key).Bytes()
		if err == nil {
			var vec []float64
			if jsonErr := json.Unmarshal(cached, &vec); jsonErr == nil {
				results[i] = vec
				continue
			}
		} else if err != redis.Nil {
			c.logger.WarnContext(ctx, "embedding cache GET failed, falling through to provider",
				slog.String("key", key),
				slog.String("error", err.Error()),
			)
		}
		// Cache miss (or unmarshal error): mark for provider call.
		missIndices = append(missIndices, i)
		missTexts = append(missTexts, text)
	}

	if len(missTexts) == 0 {
		return results, nil
	}

	// Phase 2: fetch from inner provider for all misses.
	fetched, err := c.inner.Embed(ctx, missTexts)
	if err != nil {
		return nil, err
	}

	// Phase 3: populate results and write to cache.
	for j, idx := range missIndices {
		results[idx] = fetched[j]
		c.store(ctx, texts[idx], fetched[j])
	}

	return results, nil
}

// store persists a single embedding vector to Redis.
// Errors are logged at WARN level and swallowed; the calling path has already
// retrieved the vector so a cache write failure is non-fatal.
func (c *CachedEmbeddingProvider) store(ctx context.Context, text string, vec []float64) {
	data, err := json.Marshal(vec)
	if err != nil {
		c.logger.WarnContext(ctx, "failed to marshal embedding for cache",
			slog.String("error", err.Error()),
		)
		return
	}
	key := embeddingKey(text)
	if err := c.client.Set(ctx, key, data, embeddingCacheTTL).Err(); err != nil {
		c.logger.WarnContext(ctx, "embedding cache SET failed",
			slog.String("key", key),
			slog.String("error", err.Error()),
		)
	}
}

// embeddingKey derives the Redis cache key for a given text.
func embeddingKey(text string) string {
	h := sha256.Sum256([]byte(text))
	return fmt.Sprintf("%s%s", embeddingCachePrefix, hex.EncodeToString(h[:]))
}
