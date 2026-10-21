// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
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
		Extra:        map[string]string{"aws_access_key_id": "AKIAEXAMPLE", "aws_secret_access_key": "secret"},
	}
	p, err := NewBedrockProvider(cfg)
	require.NoError(t, err)
	assert.Equal(t, "us-east-1", p.region)
}

func TestBedrockCredentialSchema(t *testing.T) {
	schema := BedrockCredentialSchema()
	keys := make(map[string]llm.CredentialField, len(schema))
	for _, f := range schema {
		keys[f.Key] = f
	}
	require.Contains(t, keys, "aws_region")
	assert.NotContains(t, keys, "use_irsa", "the daemon's own AWS credentials are never a tenant credential")
	require.Contains(t, keys, "aws_access_key_id")
	require.Contains(t, keys, "aws_secret_access_key")
	require.Contains(t, keys, "aws_session_token")

	// Access key & secret must be Secret=true; region is not a secret.
	assert.True(t, keys["aws_access_key_id"].Secret)
	assert.True(t, keys["aws_secret_access_key"].Secret)
	assert.True(t, keys["aws_session_token"].Secret)
	assert.False(t, keys["aws_region"].Secret)
}

// A config that asks for the credential chain of the daemon, or that names no
// key pair, is refused. The chain of the daemon (an IRSA role, an instance
// profile, the environment) is never a credential of a tenant.
func TestBedrockProvider_NeverUsesTheAmbientCredentialChain(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIADAEMON")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "daemon-secret")
	for name, extra := range map[string]map[string]string{
		"use_irsa":     {"use_irsa": "true", "aws_region": "us-east-1"},
		"no key pair":  {"aws_region": "us-east-1"},
		"only the key": {"aws_access_key_id": "AKIAEXAMPLE"},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := NewBedrockProvider(llm.ProviderConfig{
				Type: llm.ProviderBedrock, DefaultModel: "anthropic.claude-3-sonnet-20240229-v1:0", Extra: extra,
			})
			require.Error(t, err)
			assert.Nil(t, p)
		})
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
