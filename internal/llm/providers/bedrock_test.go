package providers

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/llm"
)

func TestBedrockProvider_Name(t *testing.T) {
	p := &BedrockProvider{region: "us-east-1", modelID: "anthropic.claude-3-sonnet-20240229-v1:0"}
	assert.Equal(t, "bedrock", p.Name())
}

func TestNewBedrockProvider_MismatchedCredentials(t *testing.T) {
	// Only access key set, no secret key → must fail loudly.
	cfg := llm.ProviderConfig{
		Type:         llm.ProviderBedrock,
		DefaultModel: "anthropic.claude-3-sonnet-20240229-v1:0",
		Extra: map[string]string{
			"aws_access_key_id": "AKIAEXAMPLE",
			"aws_region":        "us-east-1",
		},
	}
	_, err := NewBedrockProvider(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws_access_key_id")
	assert.Contains(t, err.Error(), "aws_secret_access_key")
}

func TestNewBedrockProvider_FullStaticCredentialsConstruct(t *testing.T) {
	// Both halves of the static credential pair present — constructor should
	// succeed without any network call. The AWS SDK lazily validates creds
	// on first API request, so construction is cheap.
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	cfg := llm.ProviderConfig{
		Type:         llm.ProviderBedrock,
		DefaultModel: "anthropic.claude-3-sonnet-20240229-v1:0",
		Extra: map[string]string{
			"aws_access_key_id":     "AKIAEXAMPLE",
			"aws_secret_access_key": "example",
			"aws_region":            "us-west-2",
		},
	}
	p, err := NewBedrockProvider(cfg)
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "us-west-2", p.region)
	assert.Equal(t, cfg.DefaultModel, p.modelID)
}

func TestNewBedrockProvider_DefaultsToUSEast1(t *testing.T) {
	t.Setenv("AWS_REGION", "")
	cfg := llm.ProviderConfig{
		Type:         llm.ProviderBedrock,
		DefaultModel: "anthropic.claude-3-sonnet-20240229-v1:0",
	}
	p, err := NewBedrockProvider(cfg)
	require.NoError(t, err)
	assert.Equal(t, "us-east-1", p.region)
}

func TestBedrockProvider_Models_NonEmpty(t *testing.T) {
	p := &BedrockProvider{}
	models, err := p.Models(nil)
	require.NoError(t, err)
	require.NotEmpty(t, models)

	// Spot-check feature flags for Claude (must carry tool_use) vs Titan (chat only).
	foundClaudeWithTools := false
	foundTitanWithoutTools := false
	for _, m := range models {
		if strings.HasPrefix(m.Name, "anthropic.claude-3") {
			for _, f := range m.Features {
				if f == "tools" {
					foundClaudeWithTools = true
				}
			}
		}
		if strings.HasPrefix(m.Name, "amazon.titan-text") {
			hasTools := false
			for _, f := range m.Features {
				if f == "tools" {
					hasTools = true
				}
			}
			if !hasTools {
				foundTitanWithoutTools = true
			}
		}
	}
	assert.True(t, foundClaudeWithTools, "expected at least one Claude model with tool_use feature")
	assert.True(t, foundTitanWithoutTools, "expected Titan entries to NOT declare tool_use")
}

func TestBedrockCredentialSchema(t *testing.T) {
	schema := BedrockCredentialSchema()
	keys := make(map[string]llm.CredentialField, len(schema))
	for _, f := range schema {
		keys[f.Key] = f
	}
	require.Contains(t, keys, "aws_region")
	require.Contains(t, keys, "use_irsa")
	require.Contains(t, keys, "aws_access_key_id")
	require.Contains(t, keys, "aws_secret_access_key")
	require.Contains(t, keys, "aws_session_token")

	// Access key & secret must be Secret=true; region and use_irsa are not secrets.
	assert.True(t, keys["aws_access_key_id"].Secret)
	assert.True(t, keys["aws_secret_access_key"].Secret)
	assert.True(t, keys["aws_session_token"].Secret)
	assert.False(t, keys["aws_region"].Secret)
	assert.False(t, keys["use_irsa"].Secret)
}

func TestBedrockProvider_IRSA_SkipsStaticKeyValidation(t *testing.T) {
	// With use_irsa=true, the constructor must NOT reject a config that has no
	// static credentials — the IRSA / default credential chain provides them at
	// runtime. We clear env vars so no ambient credentials can influence the
	// mismatch guard either.
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	cfg := llm.ProviderConfig{
		Type:         llm.ProviderBedrock,
		DefaultModel: "anthropic.claude-3-sonnet-20240229-v1:0",
		Extra: map[string]string{
			"use_irsa":   "true",
			"aws_region": "us-east-1",
		},
	}
	_, err := NewBedrockProvider(cfg)
	// Construction itself should not fail due to missing static credentials.
	// Any error here must NOT be the "must both be set or both empty" mismatch guard.
	if err != nil && strings.Contains(err.Error(), "must both be set") {
		t.Fatalf("IRSA path should not require static credentials: %v", err)
	}
}

func TestBedrockProvider_IRSA_False_StillEnforcesMismatch(t *testing.T) {
	// Explicit use_irsa=false must still trigger the mismatch guard when only
	// one of the key pair is provided.
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	cfg := llm.ProviderConfig{
		Type:         llm.ProviderBedrock,
		DefaultModel: "anthropic.claude-3-sonnet-20240229-v1:0",
		Extra: map[string]string{
			"use_irsa":          "false",
			"aws_access_key_id": "AKIAEXAMPLE",
			// aws_secret_access_key intentionally absent
		},
	}
	_, err := NewBedrockProvider(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws_access_key_id")
	assert.Contains(t, err.Error(), "aws_secret_access_key")
}

func TestTranslateBedrockError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantMsg string // substring in the translated error
	}{
		{"throttling", errors.New("ThrottlingException: rate exceeded"), "rate limit"},
		{"accessDenied", errors.New("AccessDeniedException: user not authorised"), "auth"},
		{"validation", errors.New("ValidationException: invalid model id"), "invalid"},
		{"unknown", errors.New("weird internal error"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := translateBedrockError(tt.err)
			require.NotNil(t, out)
			if tt.wantMsg != "" {
				assert.Contains(t, strings.ToLower(out.Error()), tt.wantMsg)
			}
		})
	}
	// nil → nil
	assert.Nil(t, translateBedrockError(nil))
}

func TestFirstNonEmpty(t *testing.T) {
	assert.Equal(t, "a", firstNonEmpty("a", "b"))
	assert.Equal(t, "b", firstNonEmpty("", "b"))
	assert.Equal(t, "c", firstNonEmpty("", "", "c"))
	assert.Equal(t, "", firstNonEmpty("", "", ""))
	assert.Equal(t, "", firstNonEmpty())
}
