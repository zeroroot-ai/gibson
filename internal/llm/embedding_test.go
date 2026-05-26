package llm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// mockNonEmbeddingProvider implements LLMProvider but not EmbeddingProvider.
type mockNonEmbeddingProvider struct{}

func (m *mockNonEmbeddingProvider) Name() string { return "mock-no-embed" }
func (m *mockNonEmbeddingProvider) Models(_ context.Context) ([]ModelInfo, error) {
	return nil, nil
}
func (m *mockNonEmbeddingProvider) Complete(_ context.Context, _ CompletionRequest) (*CompletionResponse, error) {
	return nil, nil
}
func (m *mockNonEmbeddingProvider) CompleteWithTools(_ context.Context, _ CompletionRequest, _ []ToolDef) (*CompletionResponse, error) {
	return nil, nil
}
func (m *mockNonEmbeddingProvider) Stream(_ context.Context, _ CompletionRequest) (<-chan StreamChunk, error) {
	return nil, nil
}
func (m *mockNonEmbeddingProvider) Health(_ context.Context) types.HealthStatus {
	return types.Healthy("ok")
}

// mockEmbeddingProvider implements both LLMProvider and EmbeddingProvider.
type mockEmbeddingProvider struct {
	name      string
	supported bool
}

func (m *mockEmbeddingProvider) Name() string { return m.name }
func (m *mockEmbeddingProvider) Models(_ context.Context) ([]ModelInfo, error) {
	return nil, nil
}
func (m *mockEmbeddingProvider) Complete(_ context.Context, _ CompletionRequest) (*CompletionResponse, error) {
	return nil, nil
}
func (m *mockEmbeddingProvider) CompleteWithTools(_ context.Context, _ CompletionRequest, _ []ToolDef) (*CompletionResponse, error) {
	return nil, nil
}
func (m *mockEmbeddingProvider) Stream(_ context.Context, _ CompletionRequest) (<-chan StreamChunk, error) {
	return nil, nil
}
func (m *mockEmbeddingProvider) Health(_ context.Context) types.HealthStatus {
	return types.Healthy("ok")
}
func (m *mockEmbeddingProvider) Embed(_ context.Context, texts []string) ([][]float64, error) {
	result := make([][]float64, len(texts))
	for i := range texts {
		result[i] = []float64{0.1, 0.2, 0.3}
	}
	return result, nil
}
func (m *mockEmbeddingProvider) SupportsEmbeddings() bool { return m.supported }

func TestGetEmbeddingProvider_NoProviders(t *testing.T) {
	reg := NewLLMRegistry()
	_, err := reg.GetEmbeddingProvider()
	assert.ErrorIs(t, err, ErrEmbeddingsNotSupported)
}

func TestGetEmbeddingProvider_OnlyNonEmbeddingProvider(t *testing.T) {
	reg := NewLLMRegistry()
	require.NoError(t, reg.RegisterProvider(&mockNonEmbeddingProvider{}))

	_, err := reg.GetEmbeddingProvider()
	assert.ErrorIs(t, err, ErrEmbeddingsNotSupported)
}

func TestGetEmbeddingProvider_EmbeddingProviderNotSupported(t *testing.T) {
	reg := NewLLMRegistry()
	require.NoError(t, reg.RegisterProvider(&mockEmbeddingProvider{name: "mock-disabled", supported: false}))

	_, err := reg.GetEmbeddingProvider()
	assert.ErrorIs(t, err, ErrEmbeddingsNotSupported)
}

func TestGetEmbeddingProvider_EmbeddingProviderSupported(t *testing.T) {
	reg := NewLLMRegistry()
	require.NoError(t, reg.RegisterProvider(&mockEmbeddingProvider{name: "mock-embed", supported: true}))

	ep, err := reg.GetEmbeddingProvider()
	require.NoError(t, err)
	assert.NotNil(t, ep)
	assert.True(t, ep.SupportsEmbeddings())

	vecs, err := ep.Embed(context.Background(), []string{"hello"})
	require.NoError(t, err)
	require.Len(t, vecs, 1)
	assert.Equal(t, []float64{0.1, 0.2, 0.3}, vecs[0])
}

func TestGetEmbeddingProvider_MixedProviders(t *testing.T) {
	reg := NewLLMRegistry()
	require.NoError(t, reg.RegisterProvider(&mockNonEmbeddingProvider{}))
	require.NoError(t, reg.RegisterProvider(&mockEmbeddingProvider{name: "mock-embed", supported: true}))

	ep, err := reg.GetEmbeddingProvider()
	require.NoError(t, err)
	assert.NotNil(t, ep)
}
