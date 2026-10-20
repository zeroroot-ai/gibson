// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// poisonAnthropicAmbient sets every ambient Anthropic default to a value that a
// tenant request must never use.
func poisonAnthropicAmbient(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "configs"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "configs", "default.json"), []byte("not json"), 0o600))
	t.Setenv("ANTHROPIC_CONFIG_DIR", dir)
	t.Setenv("ANTHROPIC_API_KEY", "platform-key")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "platform-token")
	t.Setenv("ANTHROPIC_BASE_URL", "http://platform.invalid")
	t.Setenv("ANTHROPIC_PROFILE", "poisoned")
}

const anthropicReply = `{"id":"msg_1","type":"message","role":"assistant","model":"m",` +
	`"content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","stop_sequence":null,` +
	`"usage":{"input_tokens":1,"output_tokens":1}}`

// The direct Anthropic provider sends the tenant key to the configured URL, with
// the ambient defaults of the daemon set to values that would break the call or
// leak the platform key.
func TestAnthropicProvider_UsesOnlyTheTenantKeyAndURL(t *testing.T) {
	poisonAnthropicAmbient(t)
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, anthropicReply) })
	p, err := NewAnthropicProvider(llm.ProviderConfig{
		APIKey: "tenant-key", BaseURL: fake.URL, AllowPrivateEndpoint: true, DefaultModel: "claude-x",
	})
	require.NoError(t, err)

	_, err = p.Complete(context.Background(), llm.CompletionRequest{
		Model: "claude-x", Messages: []llm.Message{{Role: llm.RoleUser, Content: "hi"}}, MaxTokens: 16,
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, fake.requests.Load(), "the call must reach the URL of the config")
	h := fake.lastHeader.Load()
	require.NotNil(t, h)
	assert.Equal(t, "tenant-key", h.Get("X-Api-Key"))
	assert.NotContains(t, strings.Join(h.Values("Authorization"), " "), "platform-token")
}

// With no explicit base URL, ANTHROPIC_BASE_URL does not decide where the tenant
// key goes.
func TestAnthropicProvider_AmbientBaseURLIsIgnored(t *testing.T) {
	poisonAnthropicAmbient(t)
	p, err := NewAnthropicProvider(llm.ProviderConfig{APIKey: "tenant-key", DefaultModel: "claude-x"})
	require.NoError(t, err, "a poisoned profile or base URL must not stop construction")
	require.NotNil(t, p)
	_, set := os.LookupEnv("ANTHROPIC_BASE_URL")
	assert.False(t, set, "the ambient base URL must be removed before the client is built")
}

// A Vertex chat client builds with the ambient Anthropic defaults poisoned, and
// removes them.
func TestVertex_ChatClientIgnoresTheAmbientAnthropicDefaults(t *testing.T) {
	poisonAnthropicAmbient(t)
	poisonedADC(t)
	tokenSrv := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, `{}`) })
	p, err := NewVertexProvider(context.Background(), llm.ProviderConfig{
		DefaultModel: "claude-x", AllowPrivateEndpoint: true,
		Extra: map[string]string{
			"vertex_project_id": "p", "vertex_region": "us-east5",
			"google_application_credentials_json": fakeServiceAccountJSON(t, tokenSrv.URL),
		},
	})
	require.NoError(t, err)
	require.NotNil(t, p)
	for _, name := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_PROFILE"} {
		_, set := os.LookupEnv(name)
		assert.False(t, set, "%s must be removed", name)
	}
	assert.NotContains(t, os.Getenv("ANTHROPIC_CONFIG_DIR"), "poison", "the profile directory must be empty")
}

// A Vertex request never carries an API key header, even when an ambient
// default put one on it.
func TestVertex_TransportStripsTheAPIKeyHeader(t *testing.T) {
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, `{}`) })
	client := withoutAmbientAuth(fake.Client())
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, fake.URL, http.NoBody)
	require.NoError(t, err)
	req.Header.Set("X-Api-Key", "platform-key")
	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	h := fake.lastHeader.Load()
	require.NotNil(t, h)
	assert.Empty(t, h.Get("X-Api-Key"))
}

// Only a service_account credential builds a Vertex chat client. Any other type
// makes the daemon read a file or call a URL of the tenant's choosing, so it is
// refused before it reaches the client library, with a saved model set.
func TestVertex_ChatClientRefusesAnyOtherCredentialType(t *testing.T) {
	poisonedADC(t)
	called := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, `{}`) })
	secret := filepath.Join(t.TempDir(), "tenant-chosen-file")
	require.NoError(t, os.WriteFile(secret, []byte("token"), 0o000))

	docs := map[string]string{
		"external_account": `{"type":"external_account","audience":"x","subject_token_type":"urn:ietf:params:oauth:token-type:jwt",` +
			`"token_url":"` + called.URL + `/token","credential_source":{"file":"` + secret + `"}}`,
		"authorized_user": `{"type":"authorized_user","client_id":"a","client_secret":"b","refresh_token":"c"}`,
		"impersonated_service_account": `{"type":"impersonated_service_account",` +
			`"service_account_impersonation_url":"` + called.URL + `/impersonate","source_credentials":{"type":"authorized_user",` +
			`"client_id":"a","client_secret":"b","refresh_token":"c"}}`,
	}
	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			_, err := NewVertexProvider(context.Background(), llm.ProviderConfig{
				DefaultModel: "claude-x", AllowPrivateEndpoint: true,
				Extra: map[string]string{
					"vertex_project_id": "p", "vertex_region": "us-east5", "google_application_credentials_json": doc,
				},
			})
			require.Error(t, err)
			assert.NotContains(t, err.Error(), secret, "the daemon must not try to read a file of the tenant's choosing")
			assert.Zero(t, called.requests.Load(), "the daemon must not call a URL of the tenant's choosing")
		})
	}
}
