package llm

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// mockProvider implements LLMProvider for testing.
type mockRateLimitProvider struct {
	callCount int
	usage     CompletionTokenUsage
}

func (m *mockRateLimitProvider) Name() string { return "mock" }
func (m *mockRateLimitProvider) Models(_ context.Context) ([]ModelInfo, error) {
	return nil, nil
}
func (m *mockRateLimitProvider) Health(_ context.Context) types.HealthStatus {
	return types.Healthy("ok")
}
func (m *mockRateLimitProvider) Complete(_ context.Context, _ CompletionRequest) (*CompletionResponse, error) {
	m.callCount++
	return &CompletionResponse{Usage: m.usage}, nil
}
func (m *mockRateLimitProvider) CompleteWithTools(_ context.Context, _ CompletionRequest, _ []ToolDef) (*CompletionResponse, error) {
	m.callCount++
	return &CompletionResponse{Usage: m.usage}, nil
}
func (m *mockRateLimitProvider) Stream(_ context.Context, _ CompletionRequest) (<-chan StreamChunk, error) {
	m.callCount++
	ch := make(chan StreamChunk)
	close(ch)
	return ch, nil
}

func TestRateLimitConfig_IsEnabled(t *testing.T) {
	assert.False(t, RateLimitConfig{}.IsEnabled())
	assert.True(t, RateLimitConfig{RequestsPerMinute: 60}.IsEnabled())
	assert.True(t, RateLimitConfig{TokensPerMinute: 1000}.IsEnabled())
	assert.True(t, RateLimitConfig{RequestsPerMinute: 60, TokensPerMinute: 1000}.IsEnabled())
}

func TestNewRateLimitedProvider_ZeroConfig_ReturnsUnwrapped(t *testing.T) {
	inner := &mockRateLimitProvider{}
	provider := NewRateLimitedProvider(inner, RateLimitConfig{})
	// Should return the inner provider directly, not wrapped
	assert.Equal(t, inner, provider)
}

func TestNewRateLimitedProvider_WithConfig_ReturnsWrapped(t *testing.T) {
	inner := &mockRateLimitProvider{}
	provider := NewRateLimitedProvider(inner, RateLimitConfig{RequestsPerMinute: 60})
	// Should return a wrapped provider
	_, isWrapped := provider.(*RateLimitedProvider)
	assert.True(t, isWrapped)
}

func TestRateLimitedProvider_DelegatesNameAndHealth(t *testing.T) {
	inner := &mockRateLimitProvider{}
	provider := NewRateLimitedProvider(inner, RateLimitConfig{RequestsPerMinute: 60})

	assert.Equal(t, "mock", provider.Name())
	assert.True(t, provider.Health(context.Background()).IsHealthy())
}

func TestRateLimitedProvider_Complete_PassesThrough(t *testing.T) {
	inner := &mockRateLimitProvider{usage: CompletionTokenUsage{TotalTokens: 100}}
	provider := NewRateLimitedProvider(inner, RateLimitConfig{RequestsPerMinute: 600})

	resp, err := provider.Complete(context.Background(), CompletionRequest{})
	require.NoError(t, err)
	assert.Equal(t, 100, resp.Usage.TotalTokens)
	assert.Equal(t, 1, inner.callCount)
}

func TestRateLimitedProvider_CompleteWithTools_PassesThrough(t *testing.T) {
	inner := &mockRateLimitProvider{usage: CompletionTokenUsage{TotalTokens: 200}}
	provider := NewRateLimitedProvider(inner, RateLimitConfig{RequestsPerMinute: 600})

	resp, err := provider.CompleteWithTools(context.Background(), CompletionRequest{}, nil)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.Usage.TotalTokens)
	assert.Equal(t, 1, inner.callCount)
}

func TestRateLimitedProvider_Stream_PassesThrough(t *testing.T) {
	inner := &mockRateLimitProvider{}
	provider := NewRateLimitedProvider(inner, RateLimitConfig{RequestsPerMinute: 600})

	ch, err := provider.Stream(context.Background(), CompletionRequest{})
	require.NoError(t, err)
	require.NotNil(t, ch)
	assert.Equal(t, 1, inner.callCount)
}

func TestRateLimitedProvider_ContextCancellation(t *testing.T) {
	inner := &mockRateLimitProvider{}
	// Very low rate limit: 1 request per minute, burst of 1
	provider := NewRateLimitedProvider(inner, RateLimitConfig{RequestsPerMinute: 1})

	// First call should succeed (uses the burst token)
	_, err := provider.Complete(context.Background(), CompletionRequest{})
	require.NoError(t, err)

	// Second call with cancelled context should fail
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err = provider.Complete(ctx, CompletionRequest{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rate limit exceeded")
}
