package providers

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/llm"
)

func TestCohereProvider_Name(t *testing.T) {
	p := &CohereProvider{}
	assert.Equal(t, "cohere", p.Name())
}

func TestNewCohereProvider_MissingToken(t *testing.T) {
	t.Setenv("COHERE_API_KEY", "")
	_, err := NewCohereProvider(llm.ProviderConfig{
		Type:         llm.ProviderCohere,
		DefaultModel: "command-r",
	})
	require.Error(t, err)
}

func TestNewCohereProvider_EnvFallback(t *testing.T) {
	// GIBSON_DEV_ENV_FALLBACK must be true to allow env-var credential fallback.
	t.Setenv("GIBSON_DEV_ENV_FALLBACK", "true")
	t.Setenv("COHERE_API_KEY", "env-key")
	p, err := NewCohereProvider(llm.ProviderConfig{
		Type:         llm.ProviderCohere,
		DefaultModel: "command-r",
	})
	require.NoError(t, err)
	require.NotNil(t, p.client)
}

func TestCohereProvider_Models(t *testing.T) {
	p := &CohereProvider{}
	models, err := p.Models(nil)
	require.NoError(t, err)
	names := make([]string, 0, len(models))
	for _, m := range models {
		names = append(names, m.Name)
	}
	assert.Contains(t, names, "command-r-plus")
	assert.Contains(t, names, "command-r")
}

func TestCohereCredentialSchema(t *testing.T) {
	schema := CohereCredentialSchema()
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

func TestTranslateCohereError(t *testing.T) {
	assert.Contains(t, strings.ToLower(translateCohereError(errors.New("429 rate limit")).Error()), "rate limit")
	assert.Contains(t, strings.ToLower(translateCohereError(errors.New("401 unauthorized")).Error()), "auth")
	assert.Contains(t, strings.ToLower(translateCohereError(errors.New("400 bad request")).Error()), "invalid")
	assert.Nil(t, translateCohereError(nil))
}
