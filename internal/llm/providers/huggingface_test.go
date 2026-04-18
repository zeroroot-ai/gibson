package providers

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/llm"
)

func TestHuggingFaceProvider_Name(t *testing.T) {
	p := &HuggingFaceProvider{}
	assert.Equal(t, "huggingface", p.Name())
}

func TestNewHuggingFaceProvider_MissingToken(t *testing.T) {
	t.Setenv("HUGGINGFACE_API_TOKEN", "")
	_, err := NewHuggingFaceProvider(llm.ProviderConfig{
		Type:         llm.ProviderHuggingFace,
		DefaultModel: "meta-llama/Llama-3.1-8B-Instruct",
	})
	require.Error(t, err)
}

func TestNewHuggingFaceProvider_EnvFallback(t *testing.T) {
	t.Setenv("HUGGINGFACE_API_TOKEN", "hf-env")
	p, err := NewHuggingFaceProvider(llm.ProviderConfig{
		Type:         llm.ProviderHuggingFace,
		DefaultModel: "meta-llama/Llama-3.1-8B-Instruct",
	})
	require.NoError(t, err)
	require.NotNil(t, p.client)
}

func TestHuggingFaceProvider_Models(t *testing.T) {
	p := &HuggingFaceProvider{}
	models, err := p.Models(nil)
	require.NoError(t, err)
	assert.NotEmpty(t, models)
}

func TestHuggingFaceCredentialSchema(t *testing.T) {
	schema := HuggingFaceCredentialSchema()
	found := false
	for _, f := range schema {
		if f.Key == "api_key" {
			found = true
			assert.True(t, f.Required)
			assert.True(t, f.Secret)
		}
	}
	assert.True(t, found)
}

func TestTranslateHuggingFaceError(t *testing.T) {
	assert.Contains(t, strings.ToLower(translateHuggingFaceError(errors.New("429 too many")).Error()), "rate limit")
	assert.Contains(t, strings.ToLower(translateHuggingFaceError(errors.New("401 no auth")).Error()), "auth")
	assert.Nil(t, translateHuggingFaceError(nil))
}
