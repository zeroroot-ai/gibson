package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

func TestLlamafileProvider_Name(t *testing.T) {
	p := &LlamafileProvider{}
	assert.Equal(t, "llamafile", p.Name())
}

func TestNewLlamafileProvider_NoCredentialsRequired(t *testing.T) {
	p, err := NewLlamafileProvider(llm.ProviderConfig{
		Type:         llm.ProviderLlamafile,
		DefaultModel: "llama-3.1-8b-instruct",
	})
	require.NoError(t, err)
	require.NotNil(t, p.model)
}

func TestLlamafileProvider_Models_SyntheticEntry(t *testing.T) {
	p := &LlamafileProvider{config: llm.ProviderConfig{DefaultModel: "my-model"}}
	models, err := p.Models(nil)
	require.NoError(t, err)
	require.Len(t, models, 1)
	assert.Equal(t, "my-model", models[0].Name)
}

func TestLlamafileProvider_Models_DefaultName(t *testing.T) {
	p := &LlamafileProvider{config: llm.ProviderConfig{}}
	models, err := p.Models(nil)
	require.NoError(t, err)
	require.Len(t, models, 1)
	assert.Equal(t, "llamafile-local", models[0].Name)
}

func TestLlamafileCredentialSchema(t *testing.T) {
	// Llamafile is creds-free; schema is intentionally empty.
	assert.Empty(t, LlamafileCredentialSchema())
}
