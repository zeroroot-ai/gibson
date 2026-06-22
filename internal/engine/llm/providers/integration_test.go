package providers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

func TestMockProvider_Integration(t *testing.T) {
	// Test mock provider creation and basic operations
	provider := NewMockProvider([]string{"Hello, world!"})

	assert.Equal(t, "mock", provider.Name())

	ctx := context.Background()

	// Test Models
	models, err := provider.Models(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, models)

	// Test Complete
	req := llm.CompletionRequest{
		Model: "mock-model",
		Messages: []llm.Message{
			llm.NewUserMessage("test"),
		},
		MaxTokens: 100,
	}

	resp, err := provider.Complete(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "Hello, world!", resp.Message.Content)
	assert.Equal(t, llm.RoleAssistant, resp.Message.Role)

	// Test Stream
	chunkChan, err := provider.Stream(ctx, req)
	require.NoError(t, err)

	var chunks []llm.StreamChunk
	for chunk := range chunkChan {
		chunks = append(chunks, chunk)
	}

	assert.NotEmpty(t, chunks)

	// Test Health
	health := provider.Health(ctx)
	assert.Equal(t, "healthy", health.State.String())

	// Test GetCalls
	calls := provider.GetCalls()
	assert.Len(t, calls, 2) // Complete and Stream (Health doesn't call Complete for mock)
}

func TestProviderFactory(t *testing.T) {
	tests := []struct {
		name         string
		cfg          llm.ProviderConfig
		wantProvider string
		wantErr      bool
	}{
		{
			name: "mock provider",
			cfg: llm.ProviderConfig{
				Type:         "mock",
				DefaultModel: "mock-model",
			},
			wantProvider: "mock",
			wantErr:      false,
		},
		{
			name: "ollama provider",
			cfg: llm.ProviderConfig{
				Type:         "ollama",
				DefaultModel: "llama2",
				BaseURL:      "http://localhost:11434",
			},
			wantProvider: "ollama",
			wantErr:      false,
		},
		{
			name: "unknown provider",
			cfg: llm.ProviderConfig{
				Type:         "unknown",
				DefaultModel: "test",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(tt.cfg)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, provider)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, provider)
				assert.Equal(t, tt.wantProvider, provider.Name())
			}
		})
	}
}
