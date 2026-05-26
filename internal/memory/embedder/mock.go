package embedder

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// MockEmbedder is a mock implementation of the Embedder interface for testing.
// It generates deterministic embeddings based on the hash of the input text.
type MockEmbedder struct {
	dimensions   int
	healthStatus types.HealthStatus
	calls        []string
	mu           sync.RWMutex
}

// NewMockEmbedder creates a new mock embedder with 384 dimensions (same as all-MiniLM-L6-v2).
func NewMockEmbedder() *MockEmbedder {
	return &MockEmbedder{
		dimensions:   384,
		healthStatus: types.NewHealthStatus(types.HealthStateHealthy, "mock embedder always healthy"),
		calls:        []string{},
	}
}

// Embed generates a deterministic mock embedding for the given text.
// The embedding is based on the SHA-256 hash of the input text.
func (m *MockEmbedder) Embed(ctx context.Context, text string) ([]float64, error) {
	m.mu.Lock()
	m.calls = append(m.calls, "Embed:"+text)
	m.mu.Unlock()

	// Check if context is canceled
	if err := ctx.Err(); err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingFailed, "context canceled", err)
	}

	// Generate a deterministic hash of the text
	hash := sha256.Sum256([]byte(text))

	// Convert hash bytes to float64 values
	embedding := make([]float64, m.dimensions)
	for i := 0; i < m.dimensions; i++ {
		// Use portions of the hash to generate values
		byteIndex := (i * 8) % len(hash)
		value := binary.BigEndian.Uint64(hash[byteIndex:])
		// Normalize to [-1, 1] range
		embedding[i] = (float64(value)/float64(math.MaxUint64))*2.0 - 1.0
	}

	// Normalize the vector to unit length (L2 normalization)
	var norm float64
	for _, v := range embedding {
		norm += v * v
	}
	norm = math.Sqrt(norm)

	if norm > 0 {
		for i := range embedding {
			embedding[i] /= norm
		}
	}

	return embedding, nil
}

// EmbedBatch generates mock embeddings for multiple texts.
func (m *MockEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	m.mu.Lock()
	for _, text := range texts {
		m.calls = append(m.calls, "EmbedBatch:"+text)
	}
	m.mu.Unlock()

	// Check if context is canceled
	if err := ctx.Err(); err != nil {
		return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, "context canceled", err)
	}

	if len(texts) == 0 {
		return [][]float64{}, nil
	}

	embeddings := make([][]float64, len(texts))
	for i, text := range texts {
		// Check context between iterations
		if err := ctx.Err(); err != nil {
			return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, "context canceled", err)
		}

		embedding, err := m.Embed(ctx, text)
		if err != nil {
			return nil, types.WrapError(ErrCodeEmbeddingBatchFailed, "failed to embed text", err)
		}

		embeddings[i] = embedding
	}

	return embeddings, nil
}

// Dimensions returns the dimensionality of the mock embeddings.
func (m *MockEmbedder) Dimensions() int {
	return m.dimensions
}

// Model returns the mock model name.
func (m *MockEmbedder) Model() string {
	return "mock-embedder"
}

// Health returns the configured health status for the mock embedder.
func (m *MockEmbedder) Health(ctx context.Context) types.HealthStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.healthStatus
}

// SetHealthStatus sets the health status for the mock embedder (for testing).
func (m *MockEmbedder) SetHealthStatus(status types.HealthStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthStatus = status
}

// GetCalls returns the list of method calls made to the mock embedder (for testing).
func (m *MockEmbedder) GetCalls() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	calls := make([]string, len(m.calls))
	copy(calls, m.calls)
	return calls
}

// ClearCalls clears the call history (for testing).
func (m *MockEmbedder) ClearCalls() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = []string{}
}
