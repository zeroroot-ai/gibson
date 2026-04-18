package providers

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/llm"
)

func TestErnieProvider_Name(t *testing.T) {
	p := &ErnieProvider{}
	assert.Equal(t, "ernie", p.Name())
}

func TestNewErnieProvider_MissingAPIKey(t *testing.T) {
	t.Setenv("ERNIE_API_KEY", "")
	t.Setenv("ERNIE_SECRET_KEY", "")
	_, err := NewErnieProvider(llm.ProviderConfig{
		Type:         llm.ProviderErnie,
		DefaultModel: "ernie-bot-4",
		Extra:        map[string]string{"ernie_secret_key": "sec"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ernie_access_key")
}

func TestNewErnieProvider_MissingSecretKey(t *testing.T) {
	t.Setenv("ERNIE_API_KEY", "")
	t.Setenv("ERNIE_SECRET_KEY", "")
	_, err := NewErnieProvider(llm.ProviderConfig{
		Type:         llm.ProviderErnie,
		DefaultModel: "ernie-bot-4",
		Extra:        map[string]string{"ernie_access_key": "ak"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ernie_secret_key")
}

// TestNewErnieProvider_CredentialsAccepted verifies both credentials are
// resolved and passed to langchaingo without failing on the missing-credential
// path. ERNIE performs a live access_token request at construction time, so a
// successful construction requires real Baidu credentials — that path is
// covered by the integration test. Here we only assert the failure we see is
// *not* a missing-credential error from our own resolver.
func TestNewErnieProvider_CredentialsAccepted(t *testing.T) {
	_, err := NewErnieProvider(llm.ProviderConfig{
		Type:         llm.ProviderErnie,
		DefaultModel: "ernie-bot-4",
		Extra: map[string]string{
			"ernie_access_key": "ak",
			"ernie_secret_key": "sk",
		},
	})
	if err != nil {
		assert.NotContains(t, err.Error(), "missing credential",
			"resolver should have accepted both credentials; got local-cred error: %v", err)
	}
}

func TestErnieCredentialSchema(t *testing.T) {
	schema := ErnieCredentialSchema()
	keys := map[string]llm.CredentialField{}
	for _, f := range schema {
		keys[f.Key] = f
	}
	require.Contains(t, keys, "ernie_access_key")
	require.Contains(t, keys, "ernie_secret_key")
	assert.True(t, keys["ernie_access_key"].Required)
	assert.True(t, keys["ernie_secret_key"].Required)
}

func TestTranslateErnieError(t *testing.T) {
	assert.Contains(t, strings.ToLower(translateErnieError(errors.New("429 rate")).Error()), "rate limit")
	assert.Nil(t, translateErnieError(nil))
}
