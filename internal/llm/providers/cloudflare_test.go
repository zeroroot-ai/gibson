package providers

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/llm"
)

func TestCloudflareProvider_Name(t *testing.T) {
	p := &CloudflareProvider{}
	assert.Equal(t, "cloudflare", p.Name())
}

func TestNewCloudflareProvider_MissingAccountID(t *testing.T) {
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "")
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	_, err := NewCloudflareProvider(llm.ProviderConfig{
		Type:         llm.ProviderCloudflare,
		APIKey:       "token-only",
		DefaultModel: "@cf/meta/llama-3.1-8b-instruct",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cloudflare_account_id")
}

func TestNewCloudflareProvider_MissingToken(t *testing.T) {
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "")
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	_, err := NewCloudflareProvider(llm.ProviderConfig{
		Type:         llm.ProviderCloudflare,
		DefaultModel: "@cf/meta/llama-3.1-8b-instruct",
		Extra:        map[string]string{"cloudflare_account_id": "acct-123"},
	})
	require.Error(t, err)
}

func TestNewCloudflareProvider_HappyPath(t *testing.T) {
	p, err := NewCloudflareProvider(llm.ProviderConfig{
		Type:         llm.ProviderCloudflare,
		APIKey:       "cf-token",
		DefaultModel: "@cf/meta/llama-3.1-8b-instruct",
		Extra:        map[string]string{"cloudflare_account_id": "acct-123"},
	})
	require.NoError(t, err)
	require.NotNil(t, p.client)
}

func TestCloudflareProvider_Models(t *testing.T) {
	p := &CloudflareProvider{}
	models, err := p.Models(nil)
	require.NoError(t, err)
	assert.NotEmpty(t, models)
	names := make([]string, 0, len(models))
	for _, m := range models {
		names = append(names, m.Name)
	}
	// Spot-check: the Workers AI catalogue uses the @cf/ prefix.
	for _, n := range names {
		assert.True(t, strings.HasPrefix(n, "@cf/"), "cloudflare model name %q should start with @cf/", n)
	}
}

func TestCloudflareCredentialSchema(t *testing.T) {
	schema := CloudflareCredentialSchema()
	keys := make(map[string]llm.CredentialField, len(schema))
	for _, f := range schema {
		keys[f.Key] = f
	}
	require.Contains(t, keys, "cloudflare_account_id")
	require.Contains(t, keys, "api_key")
	assert.True(t, keys["cloudflare_account_id"].Required)
	assert.True(t, keys["api_key"].Required)
	assert.True(t, keys["api_key"].Secret)
}

func TestTranslateCloudflareError(t *testing.T) {
	cases := map[string]struct{ in, wantSub string }{
		"rate":    {"429 Too Many Requests", "rate limit"},
		"auth":    {"401 unauthorized", "auth"},
		"invalid": {"400 Bad Request: invalid model", "invalid"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out := translateCloudflareError(errors.New(tc.in))
			require.NotNil(t, out)
			assert.Contains(t, strings.ToLower(out.Error()), tc.wantSub)
		})
	}
	assert.Nil(t, translateCloudflareError(nil))
}
