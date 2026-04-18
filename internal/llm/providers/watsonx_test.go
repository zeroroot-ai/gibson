package providers

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/llm"
)

func TestWatsonXProvider_Name(t *testing.T) {
	p := &WatsonXProvider{}
	assert.Equal(t, "watsonx", p.Name())
}

func TestNewWatsonXProvider_MissingAPIKey(t *testing.T) {
	t.Setenv("WATSONX_API_KEY", "")
	t.Setenv("WATSONX_PROJECT_ID", "proj-123")
	_, err := NewWatsonXProvider(llm.ProviderConfig{
		Type:         llm.ProviderWatsonX,
		DefaultModel: "ibm/granite-13b-chat-v2",
	})
	require.Error(t, err)
}

func TestNewWatsonXProvider_MissingProjectID(t *testing.T) {
	t.Setenv("WATSONX_API_KEY", "key")
	t.Setenv("WATSONX_PROJECT_ID", "")
	_, err := NewWatsonXProvider(llm.ProviderConfig{
		Type:         llm.ProviderWatsonX,
		APIKey:       "key",
		DefaultModel: "ibm/granite-13b-chat-v2",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "watsonx_project_id")
}

func TestNewWatsonXProvider_HappyPath(t *testing.T) {
	p, err := NewWatsonXProvider(llm.ProviderConfig{
		Type:         llm.ProviderWatsonX,
		APIKey:       "key",
		DefaultModel: "ibm/granite-13b-chat-v2",
		Extra:        map[string]string{"watsonx_project_id": "proj-abc"},
	})
	require.NoError(t, err)
	require.NotNil(t, p.client)
}

func TestWatsonXCredentialSchema(t *testing.T) {
	schema := WatsonXCredentialSchema()
	keys := map[string]llm.CredentialField{}
	for _, f := range schema {
		keys[f.Key] = f
	}
	require.Contains(t, keys, "api_key")
	require.Contains(t, keys, "watsonx_project_id")
	assert.True(t, keys["api_key"].Required)
	assert.True(t, keys["watsonx_project_id"].Required)
}

func TestTranslateWatsonXError(t *testing.T) {
	assert.Contains(t, strings.ToLower(translateWatsonXError(errors.New("429 rate")).Error()), "rate limit")
	assert.Contains(t, strings.ToLower(translateWatsonXError(errors.New("401 unauth")).Error()), "auth")
	assert.Nil(t, translateWatsonXError(nil))
}
