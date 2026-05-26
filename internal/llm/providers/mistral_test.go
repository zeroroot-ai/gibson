package providers

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/llm"
)

func TestMistralProvider_Name(t *testing.T) {
	p := &MistralProvider{}
	assert.Equal(t, "mistral", p.Name())
}

func TestNewMistralProvider_MissingAPIKey(t *testing.T) {
	t.Setenv("MISTRAL_API_KEY", "")
	_, err := NewMistralProvider(llm.ProviderConfig{
		Type:         llm.ProviderMistral,
		DefaultModel: "mistral-large-latest",
	})
	require.Error(t, err)
}

func TestNewMistralProvider_EnvFallback(t *testing.T) {
	// GIBSON_DEV_ENV_FALLBACK must be true to allow env-var credential fallback.
	t.Setenv("GIBSON_DEV_ENV_FALLBACK", "true")
	t.Setenv("MISTRAL_API_KEY", "env-key")
	p, err := NewMistralProvider(llm.ProviderConfig{
		Type:         llm.ProviderMistral,
		DefaultModel: "mistral-large-latest",
	})
	require.NoError(t, err)
	require.NotNil(t, p.client)
}

func TestMistralProvider_Models_ToolCapability(t *testing.T) {
	p := &MistralProvider{}
	models, err := p.Models(nil)
	require.NoError(t, err)
	foundLargeWithTools := false
	for _, m := range models {
		if m.Name != "mistral-large-latest" {
			continue
		}
		for _, f := range m.Features {
			if f == "tools" {
				foundLargeWithTools = true
			}
		}
	}
	assert.True(t, foundLargeWithTools, "mistral-large-latest should advertise tool_use")
}

func TestMistralCredentialSchema(t *testing.T) {
	schema := MistralCredentialSchema()
	require.NotEmpty(t, schema)
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

func TestTranslateMistralError(t *testing.T) {
	assert.Contains(t, strings.ToLower(translateMistralError(errors.New("429 rate limit")).Error()), "rate limit")
	assert.Contains(t, strings.ToLower(translateMistralError(errors.New("401 unauthorized")).Error()), "auth")
	assert.Contains(t, strings.ToLower(translateMistralError(errors.New("400 invalid model")).Error()), "invalid")
	assert.Nil(t, translateMistralError(nil))
}
