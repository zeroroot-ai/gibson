package providers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/llm"
)

func TestResolveCredential_Precedence(t *testing.T) {
	t.Setenv("TESTPROV_KEY", "from-env")

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
			name:     "env falls through when extra and api_key both empty",
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
// pointer to either the Extra key, the APIKey field, or the env var so the
// misconfig is diagnosable without firing a network call.
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
