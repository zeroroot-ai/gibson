package daemon

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/memory"
	"github.com/zeroroot-ai/gibson/internal/state"
)

// setupTestStateClient creates a miniredis-backed StateClient for testing.
func setupTestStateClient(t *testing.T) *state.StateClient {
	t.Helper()

	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()

	client, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	t.Cleanup(func() { client.Close() })
	return client
}

// TestNewMemoryManagerFactory verifies factory initialization.
func TestNewMemoryManagerFactory(t *testing.T) {
	t.Run("success with default config", func(t *testing.T) {
		sc := setupTestStateClient(t)

		factory, err := NewMemoryManagerFactory(sc, nil)
		require.NoError(t, err)
		require.NotNil(t, factory)
		assert.NotNil(t, factory.Config())
		assert.Equal(t, sc, factory.StateClient())
	})

	t.Run("success with custom config", func(t *testing.T) {
		sc := setupTestStateClient(t)

		config := &memory.MemoryConfig{
			Working: memory.WorkingMemoryConfig{
				MaxTokens:      50000,
				EvictionPolicy: "lru",
			},
			Mission: memory.MissionMemoryConfig{
				CacheSize: 500,
				EnableFTS: true,
			},
			LongTerm: memory.LongTermMemoryConfig{
				Backend: "embedded",
				Embedder: memory.EmbedderConfig{
					Provider: "native",
				},
			},
		}

		factory, err := NewMemoryManagerFactory(sc, config)
		require.NoError(t, err)
		require.NotNil(t, factory)
		assert.Equal(t, 50000, factory.Config().Working.MaxTokens)
		assert.Equal(t, 500, factory.Config().Mission.CacheSize)
	})

	t.Run("error when state client is nil", func(t *testing.T) {
		factory, err := NewMemoryManagerFactory(nil, nil)
		assert.Error(t, err)
		assert.Nil(t, factory)
		assert.Contains(t, err.Error(), "state client cannot be nil")
	})

	t.Run("error with invalid config", func(t *testing.T) {
		sc := setupTestStateClient(t)

		config := &memory.MemoryConfig{
			Working: memory.WorkingMemoryConfig{
				MaxTokens:      -1, // Invalid
				EvictionPolicy: "lru",
			},
		}

		factory, err := NewMemoryManagerFactory(sc, config)
		assert.Error(t, err)
		assert.Nil(t, factory)
		assert.Contains(t, err.Error(), "validation failed")
	})
}

// TestMemoryManagerFactory_ConfigPropagation verifies config is applied.
func TestMemoryManagerFactory_ConfigPropagation(t *testing.T) {
	t.Run("custom config is applied to factory", func(t *testing.T) {
		sc := setupTestStateClient(t)

		config := &memory.MemoryConfig{
			Working: memory.WorkingMemoryConfig{
				MaxTokens:      25000,
				EvictionPolicy: "lru",
			},
			Mission: memory.MissionMemoryConfig{
				CacheSize: 250,
				EnableFTS: true,
			},
			LongTerm: memory.LongTermMemoryConfig{
				Backend: "embedded",
				Embedder: memory.EmbedderConfig{
					Provider: "native",
				},
			},
		}

		factory, err := NewMemoryManagerFactory(sc, config)
		require.NoError(t, err)

		assert.Equal(t, 25000, factory.Config().Working.MaxTokens)
		assert.Equal(t, 250, factory.Config().Mission.CacheSize)
		assert.Equal(t, "embedded", factory.Config().LongTerm.Backend)
	})
}
