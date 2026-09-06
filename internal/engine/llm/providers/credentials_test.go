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

// ---------------------------------------------------------------------------
// Original resolveCredential tests (without broker) — behavior preserved.
// ---------------------------------------------------------------------------

func TestResolveCredential_Precedence(t *testing.T) {
	t.Setenv("TESTPROV_KEY", "from-env")
	t.Setenv("GIBSON_DEV_ENV_FALLBACK", "true")

	tests := []struct {
		name     string
		cfg      llm.ProviderConfig
		extraKey string
		envVar   string
		required bool
		wantVal  string
		wantErr  bool
	}{
		{
			name: "extra map wins over api_key and env",
			cfg: llm.ProviderConfig{
				APIKey: "from-apikey",
				Extra:  map[string]string{"my_token": "from-extra"},
			},
			extraKey: "my_token",
			envVar:   "TESTPROV_KEY",
			required: true,
			wantVal:  "from-extra",
		},
		{
			name: "api_key used when extraKey is empty",
			cfg: llm.ProviderConfig{
				APIKey: "from-apikey",
			},
			extraKey: "",
			envVar:   "TESTPROV_KEY",
			required: true,
			wantVal:  "from-apikey",
		},
		{
			name:     "env falls through when extra and api_key both empty (dev fallback enabled)",
			cfg:      llm.ProviderConfig{},
			extraKey: "",
			envVar:   "TESTPROV_KEY",
			required: true,
			wantVal:  "from-env",
		},
		{
			name:     "extra key miss falls through to env",
			cfg:      llm.ProviderConfig{Extra: map[string]string{"other_key": "x"}},
			extraKey: "my_token",
			envVar:   "TESTPROV_KEY",
			required: true,
			wantVal:  "from-env",
		},
		{
			name:     "missing + required returns AuthError naming both sources",
			cfg:      llm.ProviderConfig{},
			extraKey: "my_token",
			envVar:   "ABSENT_VAR_XYZ",
			required: true,
			wantErr:  true,
		},
		{
			name:     "missing + not-required returns empty string, no error",
			cfg:      llm.ProviderConfig{},
			extraKey: "my_token",
			envVar:   "ABSENT_VAR_XYZ",
			required: false,
			wantVal:  "",
		},
		{
			name:     "extraKey empty + api_key empty + env empty + required = error",
			cfg:      llm.ProviderConfig{},
			extraKey: "",
			envVar:   "ABSENT_VAR_XYZ",
			required: true,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveCredential(tt.cfg, "testprov", tt.extraKey, tt.envVar, tt.required)
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
// pointer to either the Extra key, the APIKey field, or the env var.
func TestResolveCredential_ErrorMessage_MentionsHint(t *testing.T) {
	_, err := resolveCredential(llm.ProviderConfig{}, "bedrock", "aws_access_key_id", "AWS_ACCESS_KEY_ID", true)
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "aws_access_key_id")
	assert.Contains(t, msg, "AWS_ACCESS_KEY_ID")
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

// TestResolveCredential_EnvFallbackDisabledByDefault verifies that env-var
// fallback is off unless GIBSON_DEV_ENV_FALLBACK=true.
func TestResolveCredential_EnvFallbackDisabledByDefault(t *testing.T) {
	t.Setenv("MY_SECRET_KEY", "from-env")
	// GIBSON_DEV_ENV_FALLBACK is NOT set → env fallback disabled.
	t.Setenv("GIBSON_DEV_ENV_FALLBACK", "false")

	_, err := resolveCredential(llm.ProviderConfig{}, "testprov", "", "MY_SECRET_KEY", true)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "missing credential")
}

// ---------------------------------------------------------------------------
// devEnvCredential gate — the single sanctioned door to the daemon's own
// environment.
//
// Every provider constructor must go through it. A provider config that
// carries no credential of its own must NOT construct on the daemon's ambient
// key and then register as if the credential belonged to the caller: that
// substitution is silent, so the only way to observe it is that construction
// succeeds when it should have failed.
// ---------------------------------------------------------------------------

func TestDevEnvCredential_GateOff_ReturnsEmpty(t *testing.T) {
	t.Setenv("GATED_TEST_KEY", "from-daemon-env")
	t.Setenv("GIBSON_DEV_ENV_FALLBACK", "")

	assert.Empty(t, devEnvCredential("GATED_TEST_KEY"))
}

func TestDevEnvCredential_GateOn_ReturnsValue(t *testing.T) {
	t.Setenv("GATED_TEST_KEY", "from-daemon-env")
	t.Setenv("GIBSON_DEV_ENV_FALLBACK", "true")

	assert.Equal(t, "from-daemon-env", devEnvCredential("GATED_TEST_KEY"))
}

func TestDevEnvCredential_EmptyVarName_ReturnsEmpty(t *testing.T) {
	t.Setenv("GIBSON_DEV_ENV_FALLBACK", "true")

	assert.Empty(t, devEnvCredential(""))
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

// TestKeylessConfig_DoesNotConstructOnDaemonEnv_GateOff asserts that with the
// dev gate off, a config with an empty APIKey is REJECTED even though the
// daemon's own key is present in the environment.
func TestKeylessConfig_DoesNotConstructOnDaemonEnv_GateOff(t *testing.T) {
	for _, tc := range keylessProviderCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GIBSON_DEV_ENV_FALLBACK", "")
			t.Setenv(tc.envVar, "daemon-operator-key")

			err := tc.build()
			require.Error(t, err, "a config with no credential must not construct on the daemon's ambient key")
			assert.Contains(t, strings.ToLower(err.Error()), "auth")
		})
	}
}

// TestKeylessConfig_UsesEnv_GateOn is the positive control for the test above:
// the env var IS still honoured in dev overlays, so the assertion there is
// about the gate and not about construction always failing.
func TestKeylessConfig_UsesEnv_GateOn(t *testing.T) {
	for _, tc := range keylessProviderCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GIBSON_DEV_ENV_FALLBACK", "true")
			t.Setenv(tc.envVar, "dev-overlay-key")

			require.NoError(t, tc.build())
		})
	}
}

// TestBedrock_KeylessConfig_DoesNotReadDaemonEnv_GateOff observes the gate
// through Bedrock's paired-credential guard: a lone AWS_ACCESS_KEY_ID in the
// daemon's environment used to be adopted as the caller's own and tripped the
// "both or neither" check. With the gate off the env is not read at all, so no
// half-populated static credential pair is ever assembled.
func TestBedrock_KeylessConfig_DoesNotReadDaemonEnv_GateOff(t *testing.T) {
	t.Setenv("GIBSON_DEV_ENV_FALLBACK", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIADAEMONOPERATOR")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_REGION", "us-east-1")

	_, err := NewBedrockProvider(llm.ProviderConfig{Type: llm.ProviderBedrock})
	require.NoError(t, err, "the daemon's ambient access key must not be adopted as the caller's credential")
}

// TestBedrock_KeylessConfig_ReadsEnv_GateOn is the positive control: with the
// dev gate on the env IS read, so the lone access key is adopted and the
// paired-credential guard fires.
func TestBedrock_KeylessConfig_ReadsEnv_GateOn(t *testing.T) {
	t.Setenv("GIBSON_DEV_ENV_FALLBACK", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIADEVOVERLAY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_REGION", "us-east-1")

	_, err := NewBedrockProvider(llm.ProviderConfig{Type: llm.ProviderBedrock})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must both be set or both empty")
}
