// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

const anthropicReply = `{"id":"msg_1","type":"message","role":"assistant","model":"m",` +
	`"content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","stop_sequence":null,` +
	`"usage":{"input_tokens":1,"output_tokens":1}}`

// The direct Anthropic provider sends the tenant key to the configured URL, with
// the ambient defaults of the process set to values that would leak the platform
// key or move the call.
func TestAnthropicProvider_UsesOnlyTheTenantKeyAndURL(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "platform-key")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "platform-token")
	t.Setenv("ANTHROPIC_BASE_URL", "http://platform.invalid")
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

// The daemon refuses to start with any ANTHROPIC_ variable set, other than the
// profile directory variable, and gives the SDK an empty profile directory.
func TestSecureAnthropicEnvironment(t *testing.T) {
	for _, name := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "ANTHROPIC_PROFILE", "ANTHROPIC_SOMETHING_NEW"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "x")
			err := SecureAnthropicEnvironment()
			require.Error(t, err)
			assert.Contains(t, err.Error(), name)
		})
	}

	t.Run("clean environment", func(t *testing.T) {
		t.Setenv("ANTHROPIC_CONFIG_DIR", "")
		require.NoError(t, SecureAnthropicEnvironment())
		dir := os.Getenv("ANTHROPIC_CONFIG_DIR")
		require.NotEmpty(t, dir)
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Empty(t, entries, "the profile directory must be empty")
	})
}

// A full Vertex completion on a daemon that passed the startup check. Every connection goes to a fake TLS server, except the token
// call. The request carries only the Bearer token that the tenant service
// account minted, and no API key.
func TestVertex_CompleteCarriesOnlyTheTenantToken(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "platform-key")
	t.Setenv("ANTHROPIC_BASE_URL", "http://platform.invalid")
	require.Error(t, SecureAnthropicEnvironment(), "the startup check must refuse this environment")
	// The daemon never runs past that check with these set. The Vertex client of
	// the eino library puts an ambient API key on the request and ignores the
	// HTTP client of the config, so the check is the guard. Emulate a daemon that
	// passed it.
	require.NoError(t, os.Unsetenv("ANTHROPIC_API_KEY"))
	require.NoError(t, os.Unsetenv("ANTHROPIC_BASE_URL"))
	t.Setenv("ANTHROPIC_CONFIG_DIR", t.TempDir()) // what the daemon sets, after the check
	poisonedADC(t)

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reply(w, 200, `{"access_token":"tenant-token","token_type":"Bearer","expires_in":3600}`)
	}))
	t.Cleanup(tokenSrv.Close)

	var seen atomic.Pointer[http.Header]
	var seenPath atomic.Pointer[string]
	vertex := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Clone()
		seen.Store(&h)
		pth := r.URL.Path
		seenPath.Store(&pth)
		reply(w, 200, anthropicReply)
	}))
	t.Cleanup(vertex.Close)

	tokenHost := strings.TrimPrefix(tokenSrv.URL, "http://")
	transport := http.DefaultTransport.(*http.Transport).Clone()      //nolint:forcetypeassert // the default transport is an *http.Transport
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // a test server with a throwaway certificate
	dialer := &net.Dialer{}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == tokenHost {
			return dialer.DialContext(ctx, network, addr)
		}
		return dialer.DialContext(ctx, network, vertex.Listener.Addr().String())
	}
	client := &http.Client{Transport: transport}
	// The Vertex client of the eino library takes no HTTP client, so it uses the
	// default transport of the process. Point that at the fake for this test.
	oldDefault := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = oldDefault })

	p, err := newVertexProviderWithClient(context.Background(), llm.ProviderConfig{
		DefaultModel: "claude-x",
		Extra: map[string]string{
			"vertex_project_id": "proj", "vertex_region": "us-east5",
			"google_application_credentials_json": fakeServiceAccountJSON(t, tokenSrv.URL),
		},
	}, serviceAccountToken, client)
	require.NoError(t, err)

	_, err = p.Complete(context.Background(), llm.CompletionRequest{
		Model: "claude-x", Messages: []llm.Message{{Role: llm.RoleUser, Content: "hi"}}, MaxTokens: 16,
	})
	require.NoError(t, err)
	h := seen.Load()
	require.NotNil(t, h, "the completion must reach the fake Vertex endpoint")
	assert.Equal(t, "Bearer tenant-token", h.Get("Authorization"))
	assert.Empty(t, h.Get("X-Api-Key"), "the platform API key must not reach a Vertex request")
	require.NotNil(t, seenPath.Load())
	assert.Contains(t, *seenPath.Load(), "publishers/anthropic/models/claude-x")
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

// A project or a region that is not a plain name could move the Vertex request
// to another host, so it is refused.
func TestVertex_RefusesAProjectOrRegionThatIsNotAPlainName(t *testing.T) {
	for name, extra := range map[string]map[string]string{
		"region with a host":  {"vertex_project_id": "p", "vertex_region": "x.evil.com/"},
		"region with an at":   {"vertex_project_id": "p", "vertex_region": "x@evil.com"},
		"project with a path": {"vertex_project_id": "p/../x", "vertex_region": "us-east5"},
	} {
		t.Run(name, func(t *testing.T) {
			extra["google_application_credentials_json"] = "{}"
			_, err := NewVertexProvider(context.Background(), llm.ProviderConfig{Extra: extra})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "letters, digits and hyphens")
		})
	}
}
