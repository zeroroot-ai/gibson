package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetSupportedProviders_IncludesEveryKnownProvider asserts the admin RPC
// returns a descriptor for every provider Gibson can construct. If a new
// provider is added to the factory without extending the descriptor
// registry, this test fails.
func TestGetSupportedProviders_IncludesEveryKnownProvider(t *testing.T) {
	s := &DaemonServer{}
	resp, err := s.GetSupportedProviders(context.Background(), &GetSupportedProvidersRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)

	byType := make(map[string]*ProviderDescriptor, len(resp.Providers))
	for _, d := range resp.Providers {
		byType[d.Type] = d
	}

	// Spot-check the core providers. ProviderCustom is intentionally
	// excluded from the descriptor set (custom is operator-defined).
	required := []string{
		"anthropic", "openai", "google", "ollama",
		"bedrock", "cloudflare", "cohere", "ernie",
		"huggingface", "llamafile", "local", "maritaca",
		"mistral", "watsonx",
	}
	for _, typ := range required {
		assert.Contains(t, byType, typ, "descriptor missing for provider %q", typ)
	}
	assert.NotContains(t, byType, "custom", "ProviderCustom should not appear in descriptors")
}

// TestGetSupportedProviders_BedrockHasAWSCredentialSchema asserts the
// credential-field mapping from the Go descriptor to the proto message
// preserves every field the dashboard needs.
func TestGetSupportedProviders_BedrockHasAWSCredentialSchema(t *testing.T) {
	s := &DaemonServer{}
	resp, err := s.GetSupportedProviders(context.Background(), &GetSupportedProvidersRequest{})
	require.NoError(t, err)

	var bedrock *ProviderDescriptor
	for _, d := range resp.Providers {
		if d.Type == "bedrock" {
			bedrock = d
			break
		}
	}
	require.NotNil(t, bedrock, "bedrock descriptor missing")

	keys := make(map[string]*CredentialField, len(bedrock.Credentials))
	for _, f := range bedrock.Credentials {
		keys[f.Key] = f
	}
	assert.Contains(t, keys, "aws_access_key_id")
	assert.Contains(t, keys, "aws_secret_access_key")
	assert.Contains(t, keys, "aws_session_token")
	assert.Contains(t, keys, "aws_region")
	assert.True(t, keys["aws_access_key_id"].Secret, "aws_access_key_id must be marked Secret")
	assert.True(t, keys["aws_secret_access_key"].Secret, "aws_secret_access_key must be marked Secret")
	assert.False(t, keys["aws_region"].Secret, "aws_region is not a secret")

	// Bedrock's descriptor must include the curated model catalogue so the
	// dashboard can render a model picker without instantiating the client.
	assert.NotEmpty(t, bedrock.DefaultModels, "bedrock descriptor must carry default models")
	assert.NotEmpty(t, bedrock.DocsUrl, "bedrock descriptor must carry docs URL")
}

// TestGetSupportedProviders_SelfHostedFlag checks the self_hosted flag
// matches reality for every provider — the dashboard uses it to hide the
// "Test connection" button and cost-tracking warnings.
func TestGetSupportedProviders_SelfHostedFlag(t *testing.T) {
	s := &DaemonServer{}
	resp, err := s.GetSupportedProviders(context.Background(), &GetSupportedProvidersRequest{})
	require.NoError(t, err)

	byType := make(map[string]*ProviderDescriptor, len(resp.Providers))
	for _, d := range resp.Providers {
		byType[d.Type] = d
	}

	for _, typ := range []string{"ollama", "llamafile", "local"} {
		if d := byType[typ]; d != nil {
			assert.True(t, d.SelfHosted, "%s must be flagged self_hosted", typ)
		}
	}
	for _, typ := range []string{"anthropic", "openai", "bedrock", "mistral", "cohere"} {
		if d := byType[typ]; d != nil {
			assert.False(t, d.SelfHosted, "%s must NOT be flagged self_hosted", typ)
		}
	}
}
