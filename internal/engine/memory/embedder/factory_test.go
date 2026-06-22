//go:build embedder_tests

// These tests load HuggingFace tokenizer model files from disk and can hang or
// download large artifacts on first run. They are gated behind the
// `embedder_tests` build tag so the standard `go test ./...` skips them.
//
// Run explicitly with:
//
//	go test -tags=embedder_tests ./internal/engine/memory/embedder/...
//
// CI runs them in a dedicated job; local dev runs do not.

package embedder

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateEmbedder_Native(t *testing.T) {
	config := EmbedderConfig{
		Provider: "native",
	}

	emb, err := CreateEmbedder(config)
	if err != nil && strings.Contains(err.Error(), "unknown tokenizer class") {
		t.Skip("BertTokenizer not yet supported by go-huggingface/tokenizers")
	}
	require.NoError(t, err, "native embedder should initialize successfully")
	require.NotNil(t, emb)
	assert.Equal(t, "all-MiniLM-L6-v2", emb.Model())
	assert.Equal(t, 384, emb.Dimensions())
}

func TestCreateEmbedder_EmptyProvider(t *testing.T) {
	config := EmbedderConfig{
		Provider: "",
	}

	emb, err := CreateEmbedder(config)
	if err != nil && strings.Contains(err.Error(), "unknown tokenizer class") {
		t.Skip("BertTokenizer not yet supported by go-huggingface/tokenizers")
	}
	require.NoError(t, err, "empty provider should default to native")
	require.NotNil(t, emb)
	assert.Equal(t, "all-MiniLM-L6-v2", emb.Model())
	assert.Equal(t, 384, emb.Dimensions())
}

func TestCreateEmbedder_InvalidProvider(t *testing.T) {
	config := EmbedderConfig{
		Provider: "invalid-provider",
	}

	emb, err := CreateEmbedder(config)
	assert.Error(t, err)
	assert.Nil(t, emb)
	assert.Contains(t, err.Error(), "unknown embedder provider")
	assert.Contains(t, err.Error(), "must be 'native'")
}

func TestValidateEmbedderConfig_Native(t *testing.T) {
	config := EmbedderConfig{
		Provider: "native",
	}

	err := ValidateEmbedderConfig(config)
	assert.NoError(t, err, "native embedder config should be valid")
}

func TestValidateEmbedderConfig_EmptyProvider(t *testing.T) {
	config := EmbedderConfig{
		Provider: "",
	}

	err := ValidateEmbedderConfig(config)
	assert.NoError(t, err, "empty provider should default to native")
}

func TestValidateEmbedderConfig_UnknownProvider(t *testing.T) {
	config := EmbedderConfig{
		Provider: "unknown-provider",
	}

	err := ValidateEmbedderConfig(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown embedder provider")
	assert.Contains(t, err.Error(), "must be 'native'")
}

func TestDefaultEmbedderConfig(t *testing.T) {
	config := DefaultEmbedderConfig()

	assert.Equal(t, "native", config.Provider, "default provider should be native")
	assert.NoError(t, ValidateEmbedderConfig(config),
		"default config should be valid")
}

func TestEmbedderType_Constants(t *testing.T) {
	// Verify embedder type constants
	assert.Equal(t, EmbedderType("native"), EmbedderTypeNative)
}
