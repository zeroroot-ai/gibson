// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

func TestResolveCredential_Precedence(t *testing.T) {
	t.Setenv("TESTPROV_KEY", "from-env")

	tests := []struct {
		name     string
		cfg      llm.ProviderConfig
		extraKey string
		required bool
		wantVal  string
		wantErr  bool
	}{
		{
			name: "extra map wins over api_key",
			cfg: llm.ProviderConfig{
				APIKey: "from-apikey",
				Extra:  map[string]string{"my_token": "from-extra"},
			},
			extraKey: "my_token",
			required: true,
			wantVal:  "from-extra",
		},
		{
			name:     "api_key used when extraKey is empty",
			cfg:      llm.ProviderConfig{APIKey: "from-apikey"},
			extraKey: "",
			required: true,
			wantVal:  "from-apikey",
		},
		{
			name:     "the daemon environment is never a source: empty config + required = error",
			cfg:      llm.ProviderConfig{},
			extraKey: "",
			required: true,
			wantErr:  true,
		},
		{
			name:     "extra key miss + required = error, never the environment",
			cfg:      llm.ProviderConfig{Extra: map[string]string{"other_key": "x"}},
			extraKey: "my_token",
			required: true,
			wantErr:  true,
		},
		{
			name:     "missing + not-required returns empty string, no error",
			cfg:      llm.ProviderConfig{},
			extraKey: "my_token",
			required: false,
			wantVal:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveCredential(tt.cfg, "testprov", tt.extraKey, tt.required)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, strings.ToLower(err.Error()), "missing credential")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantVal, got)
		})
	}
}

// TestResolveCredential_ErrorMessage_MentionsHint ensures operators get a
// pointer to the Extra key or the APIKey field of the tenant's provider
// configuration, and never to an environment variable.
func TestResolveCredential_ErrorMessage_MentionsHint(t *testing.T) {
	_, err := resolveCredential(llm.ProviderConfig{}, "bedrock", "aws_access_key_id", true)
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "aws_access_key_id")
	assert.Contains(t, msg, "tenant's provider configuration")
	assert.NotContains(t, msg, "env ")
}

func TestRedactCredentialKeys_IncludesEveryProviderSecret(t *testing.T) {
	keys := redactCredentialKeys()
	set := make(map[string]bool, len(keys))
	for _, k := range keys {
		set[k] = true
	}
	// Spot-check the keys every provider relies on. If a new provider is
	// added without updating this list, the observability redaction
	// allowlist will leak credentials.
	required := []string{
		"api_key",
		"aws_access_key_id", "aws_secret_access_key", "aws_session_token",
		"cloudflare_account_id", "cloudflare_api_token",
		"huggingface_api_token",
		"mistral_api_key", "cohere_api_key",
	}
	for _, k := range required {
		assert.True(t, set[k], "redactCredentialKeys() missing %q", k)
	}
}

// keylessProviderCase builds a provider from a config that carries no
// credential of its own.
type keylessProviderCase struct {
	name   string
	envVar string
	build  func() error
}

func keylessProviderCases() []keylessProviderCase {
	return []keylessProviderCase{
		{
			name:   "openai",
			envVar: "OPENAI_API_KEY",
			build: func() error {
				_, err := NewOpenAIProvider(llm.ProviderConfig{Type: llm.ProviderOpenAI, DefaultModel: "gpt-4"})
				return err
			},
		},
		{
			name:   "anthropic",
			envVar: "ANTHROPIC_API_KEY",
			build: func() error {
				_, err := NewAnthropicProvider(llm.ProviderConfig{Type: llm.ProviderAnthropic, DefaultModel: "claude-sonnet-4-5-20250929"})
				return err
			},
		},
		{
			name:   "google",
			envVar: "GOOGLE_API_KEY",
			build: func() error {
				_, err := NewGoogleProvider(llm.ProviderConfig{Type: llm.ProviderGoogle, DefaultModel: "gemini-1.5-flash"})
				return err
			},
		},
	}
}

// TestKeylessConfig_DoesNotConstructOnDaemonEnv asserts that a config with an
// empty APIKey is REJECTED even though a key of the same name is present in
// the daemon's environment. There is no gate that would turn this on: the
// platform holds no LLM credential, and a tenant provider row that carries no
// credential of its own must never construct on the pod's ambient key and
// register as if the credential were the tenant's.
func TestKeylessConfig_DoesNotConstructOnDaemonEnv(t *testing.T) {
	for _, tc := range keylessProviderCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.envVar, "daemon-operator-key")

			err := tc.build()
			require.Error(t, err, "a config with no credential must not construct on the daemon's ambient key")
			assert.Contains(t, strings.ToLower(err.Error()), "auth")
		})
	}
}

// TestBedrock_KeylessConfig_DoesNotReadDaemonEnv observes the same property
// through Bedrock's paired-credential guard: a lone AWS_ACCESS_KEY_ID in the
// daemon's environment used to be adopted as the caller's own and tripped the
// "both or neither" check. The env is not read at all, so no half-populated
// static credential pair is ever assembled and the SDK default chain applies.
func TestBedrock_KeylessConfig_DoesNotReadDaemonEnv(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIADAEMONOPERATOR")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_REGION", "us-east-1")

	_, err := NewBedrockProvider(llm.ProviderConfig{Type: llm.ProviderBedrock})
	require.NoError(t, err, "the daemon's ambient access key must not be adopted as the caller's credential")
}
