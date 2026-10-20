// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

const anthropicMessageReply = `{"id":"msg_1","type":"message","role":"assistant","model":"m","content":[{"type":"text","text":"pong"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`

// messagesFake answers POST /v1/messages (and the Foundry path) and records
// the model of each request.
func messagesFake(t *testing.T) (*fakeProviderAPI, *atomic.Value) {
	t.Helper()
	var lastModel atomic.Value
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(body, &req)
		lastModel.Store(req.Model)
		reply(w, 200, anthropicMessageReply)
	})
	return fake, &lastModel
}

func TestAnthropic_CompletesWithTheRequestModelWhenNoDefaultIsSaved(t *testing.T) {
	fake, lastModel := messagesFake(t)
	p, err := NewAnthropicProvider(llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL, AllowPrivateEndpoint: true})
	require.NoError(t, err)

	resp, err := p.Complete(context.Background(), llm.CompletionRequest{
		Model: "claude-req", Messages: []llm.Message{llm.NewUserMessage("hi")}, MaxTokens: 5,
	})
	require.NoError(t, err)
	assert.Equal(t, "pong", resp.Message.Content)
	assert.Equal(t, "claude-req", lastModel.Load())
	assert.Zero(t, listHits(fake), "a completion never lists models")
}

func listHits(f *fakeProviderAPI) int32 { return f.requests.Load() - f.nonListHits.Load() }

func TestAnthropic_RequestModelWinsThenSavedDefault(t *testing.T) {
	fake, lastModel := messagesFake(t)
	p, err := NewAnthropicProvider(llm.ProviderConfig{APIKey: "k", DefaultModel: "claude-saved", BaseURL: fake.URL, AllowPrivateEndpoint: true})
	require.NoError(t, err)
	assert.Equal(t, "claude-saved", llm.SavedModel(p))

	_, err = p.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.NewUserMessage("hi")}, MaxTokens: 5})
	require.NoError(t, err)
	assert.Equal(t, "claude-saved", lastModel.Load(), "the saved default model serves a request that names none")

	_, err = p.Complete(context.Background(), llm.CompletionRequest{Model: "claude-req", Messages: []llm.Message{llm.NewUserMessage("hi")}, MaxTokens: 5})
	require.NoError(t, err)
	assert.Equal(t, "claude-req", lastModel.Load(), "the request model wins")
}

func TestAnthropic_NoRequestModelAndNoSavedModelFailsClearly(t *testing.T) {
	p, err := NewAnthropicProvider(llm.ProviderConfig{APIKey: "k"})
	require.NoError(t, err)
	_, err = p.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.NewUserMessage("hi")}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no model")
	assert.Contains(t, err.Error(), "default model")
}

func TestFoundry_HasNoListAndProbesTheTypedModel(t *testing.T) {
	fake, lastModel := messagesFake(t)
	p, err := NewFoundryProvider(context.Background(), llm.ProviderConfig{
		APIKey: "k", BaseURL: fake.URL + "/anthropic", AllowPrivateEndpoint: true,
	})
	require.NoError(t, err)

	_, err = p.Models(context.Background())
	require.ErrorIs(t, err, llm.ErrModelListUnsupported)
	assert.Zero(t, fake.requests.Load(), "Foundry has no Models API, so no list call is sent")

	require.NoError(t, p.ProbeModel(context.Background(), "my-deployment"))
	assert.Equal(t, "my-deployment", lastModel.Load())
	var _ llm.ModelProber = p
}

func TestCircuitWrapperForwardsTheSavedModelAndTheProbe(t *testing.T) {
	fake, lastModel := messagesFake(t)
	inner, err := NewFoundryProvider(context.Background(), llm.ProviderConfig{
		APIKey: "k", DefaultModel: "dep", BaseURL: fake.URL + "/anthropic", AllowPrivateEndpoint: true,
	})
	require.NoError(t, err)
	wrapped := newCircuitLLMProvider(inner, "foundry-circuit-test")
	assert.Equal(t, "dep", llm.SavedModel(wrapped))
	require.NoError(t, wrapped.ProbeModel(context.Background(), "dep2"))
	assert.Equal(t, "dep2", lastModel.Load())

	plain := newCircuitLLMProvider(NewMockProvider([]string{"x"}), "mock-circuit-test")
	assert.Equal(t, "mock-model", llm.SavedModel(plain))
	require.ErrorIs(t, plain.ProbeModel(context.Background(), "m"), llm.ErrModelListUnsupported)
}

func TestSavedModel_OfEveryProvider(t *testing.T) {
	cfg := func(m string) llm.ProviderConfig {
		return llm.ProviderConfig{APIKey: "k", DefaultModel: m, BaseURL: "http://127.0.0.1:1/v1", AllowPrivateEndpoint: true}
	}
	oa, err := NewOpenAIProvider(cfg("gpt-saved"))
	require.NoError(t, err)
	assert.Equal(t, "gpt-saved", llm.SavedModel(oa))
	g, err := NewGoogleProvider(cfg("gemini-saved"))
	require.NoError(t, err)
	assert.Equal(t, "gemini-saved", llm.SavedModel(g))
	o, err := NewOllamaProvider(cfg("llama-saved"))
	require.NoError(t, err)
	assert.Equal(t, "llama-saved", llm.SavedModel(o))
	m, err := newMistralProviderWithContext(context.Background(), cfg("mistral-saved"))
	require.NoError(t, err)
	assert.Equal(t, "mistral-saved", llm.SavedModel(m))
	c, err := newCohereProviderWithContext(context.Background(), cfg("cmd-saved"))
	require.NoError(t, err)
	assert.Equal(t, "cmd-saved", llm.SavedModel(c))
	h, err := newHuggingFaceProviderWithContext(context.Background(), cfg("hf-saved"))
	require.NoError(t, err)
	assert.Equal(t, "hf-saved", llm.SavedModel(h))
	l, err := NewLlamafileProvider(cfg("gguf-saved"))
	require.NoError(t, err)
	assert.Equal(t, "gguf-saved", llm.SavedModel(l))
	cf := cfg("cf-saved")
	cf.Extra = map[string]string{"cloudflare_account_id": "a"}
	cl, err := newCloudflareProviderWithContext(context.Background(), cf)
	require.NoError(t, err)
	assert.Equal(t, "cf-saved", llm.SavedModel(cl))
	assert.Equal(t, "br-saved", llm.SavedModel(&BedrockProvider{modelID: "br-saved"}))
}

func TestUnreportedFieldsAreMarkedOnEveryList(t *testing.T) {
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		reply(w, 200, `{"data":[{"id":"windowed","max_input_tokens":200000},{"id":"bare"}]}`)
	})
	p, err := NewAnthropicProvider(llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL, AllowPrivateEndpoint: true})
	require.NoError(t, err)
	models, err := p.Models(context.Background())
	require.NoError(t, err)
	require.Len(t, models, 2)
	assert.False(t, models[0].ContextWindowUnreported)
	assert.True(t, models[1].ContextWindowUnreported, "a window the API did not report is unknown, not zero")
	assert.True(t, models[0].ContextWindowAtLeast(100000))
	assert.False(t, models[0].ContextWindowAtLeast(300000), "a reported window below the minimum fails")
	assert.True(t, models[1].ContextWindowAtLeast(300000))
}

func TestModelCache_ServesTheLastGoodListWhenARefreshFails(t *testing.T) {
	var fail atomic.Bool
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			reply(w, 500, `{"error":"down"}`)
			return
		}
		reply(w, 200, `{"data":[{"id":"m1"}]}`)
	})
	p, err := NewOpenAIProvider(llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL + "/v1", AllowPrivateEndpoint: true})
	require.NoError(t, err)

	models, err := p.Models(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"m1"}, names(models))

	// Expire the list, then take the endpoint down.
	p.lister.cache.mu.Lock()
	p.lister.cache.loaded = time.Now().Add(-2 * modelListCacheTTL)
	p.lister.cache.mu.Unlock()
	fail.Store(true)

	models, err = p.Models(context.Background())
	require.NoError(t, err, "a failed refresh serves the last good list")
	assert.Equal(t, []string{"m1"}, names(models))
	assert.EqualValues(t, 2, fake.requests.Load())
}

func TestModelCache_OneRefreshServesAllCallersWithoutHoldingTheLock(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 8)
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		started <- struct{}{}
		<-release
		reply(w, 200, `{"data":[{"id":"m1"}]}`)
	})
	p, err := NewOpenAIProvider(llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL + "/v1", AllowPrivateEndpoint: true})
	require.NoError(t, err)

	const callers = 5
	var wg sync.WaitGroup
	results := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.Models(context.Background())
			results <- err
		}()
	}
	<-started
	// The fetch is in flight. The cache lock must be free, so a reader can
	// take it at once.
	locked := make(chan struct{})
	go func() {
		p.lister.cache.mu.Lock()
		defer p.lister.cache.mu.Unlock()
		close(locked)
	}()
	select {
	case <-locked:
	case <-time.After(2 * time.Second):
		t.Fatal("the cache lock is held across the network call")
	}
	close(release)
	wg.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	assert.EqualValues(t, 1, fake.requests.Load(), "concurrent callers share one list call")
}

func TestGetJSON_RefusesARedirectToAnotherHost(t *testing.T) {
	other := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, `{"data":[{"id":"stolen"}]}`) })
	first := newFakeProviderAPI(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/v1/models", http.StatusFound)
	})
	p, err := NewAnthropicProvider(llm.ProviderConfig{APIKey: "sk-secret", BaseURL: first.URL, AllowPrivateEndpoint: true})
	require.NoError(t, err)

	_, err = p.Models(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "302")
	assert.Zero(t, other.requests.Load(), "the key header must not reach another host")
	assert.NotContains(t, err.Error(), "sk-secret")
}

func TestGetJSON_FollowsASameHostRedirect(t *testing.T) {
	var fake *fakeProviderAPI
	fake = newFakeProviderAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/moved" {
			reply(w, 200, `{"data":[{"id":"m1"}]}`)
			return
		}
		http.Redirect(w, r, fake.URL+"/v1/moved", http.StatusFound)
	})
	p, err := NewOpenAIProvider(llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL + "/v1", AllowPrivateEndpoint: true})
	require.NoError(t, err)
	_, err = p.Models(context.Background())
	require.NoError(t, err)
}

// fakeServiceAccountJSON returns a service-account key whose token endpoint is
// tokenURL, so the Google library mints a token from the fake and not from
// Google.
func fakeServiceAccountJSON(t *testing.T, tokenURL string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	doc, err := json.Marshal(map[string]string{ //nolint:gosec // a generated throwaway key for a test
		"type":           "service_account",
		"project_id":     "proj",
		"private_key_id": "k1",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   "sa@proj.iam.gserviceaccount.com",
		"client_id":      "1",
		"token_uri":      tokenURL,
	})
	require.NoError(t, err)
	return string(doc)
}

// poisonedADC points the Application Default Credentials at a file that a read
// would fail on and records nothing else: a test that passes with it proves the
// daemon credential was not used.
func poisonedADC(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "adc.json")
	require.NoError(t, os.WriteFile(path, []byte("not json: the daemon credential must never be read"), 0o600))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
}

func vertexCfg(base, saJSON string) llm.ProviderConfig {
	return llm.ProviderConfig{
		BaseURL: base, AllowPrivateEndpoint: true,
		Extra: map[string]string{
			"vertex_project_id": "proj", "vertex_region": "us-east5",
			"google_application_credentials_json": saJSON,
		},
	}
}

func TestVertex_ListsWithATokenMintedFromTheTenantJSON(t *testing.T) {
	poisonedADC(t)
	var mints atomic.Int32
	tokenSrv := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		mints.Add(1)
		reply(w, 200, `{"access_token":"tenant-token","token_type":"Bearer","expires_in":3600}`)
	})
	var gotAuth, gotProject, gotPath atomic.Value
	api := newFakeProviderAPI(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		gotProject.Store(r.Header.Get("x-goog-user-project"))
		gotPath.Store(r.URL.Path)
		if r.URL.Query().Get("pageToken") == "" {
			reply(w, 200, `{"publisherModels":[{"name":"publishers/anthropic/models/claude-a","versionId":"20250929"}],"nextPageToken":"p2"}`)
			return
		}
		reply(w, 200, `{"publisherModels":[{"name":"publishers/anthropic/models/claude-b"}]}`)
	})

	p, err := NewVertexProvider(context.Background(), vertexCfg(api.URL, fakeServiceAccountJSON(t, tokenSrv.URL)))
	require.NoError(t, err, "a Vertex test names no model and builds without a Google credential")

	models, err := p.Models(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"claude-a@20250929", "claude-b"}, names(models), "a versioned model is listed as model@version")
	assert.EqualValues(t, 1, mints.Load(), "the token comes from the tenant JSON")
	assert.Equal(t, "Bearer tenant-token", gotAuth.Load())
	assert.Equal(t, "proj", gotProject.Load(), "the call is scoped to the tenant project")
	assert.Equal(t, "/v1beta1/publishers/anthropic/models", gotPath.Load())
}

func TestVertex_BadTenantJSONFailsAndTheDaemonCredentialIsNeverRead(t *testing.T) {
	poisonedADC(t)
	api := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, `{"publisherModels":[]}`) })

	for name, js := range map[string]string{
		"not json":        "{{{",
		"empty":           "",
		"wrong type":      `{"type":"external_account","audience":"x","credential_source":{"url":"http://169.254.169.254/"}}`,
		"authorized user": `{"type":"authorized_user","client_id":"a","client_secret":"b","refresh_token":"c"}`,
	} {
		t.Run(name, func(t *testing.T) {
			p, err := NewVertexProvider(context.Background(), vertexCfg(api.URL, js))
			require.NoError(t, err)
			_, err = p.Models(context.Background())
			require.Error(t, err)
			assert.Equal(t, llm.ErrProviderUnauthorized, gibsonCode(t, err))
			assert.NotContains(t, err.Error(), "adc.json", "the daemon credential must not be consulted")
			assert.Zero(t, api.requests.Load(), "no API call is made without a minted token")
		})
	}
}

func TestVertex_TokenEndpointRefusalIsACredentialError(t *testing.T) {
	poisonedADC(t)
	tokenSrv := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		reply(w, 400, `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`)
	})
	p, err := NewVertexProvider(context.Background(), vertexCfg("http://127.0.0.1:1", fakeServiceAccountJSON(t, tokenSrv.URL)))
	require.NoError(t, err)
	_, err = p.Models(context.Background())
	require.Error(t, err)
	assert.Equal(t, llm.ErrProviderUnauthorized, gibsonCode(t, err))
	assert.Contains(t, err.Error(), "Invalid JWT Signature")
}

func TestVertex_HostFollowsTheRegion(t *testing.T) {
	assert.Equal(t, "https://us-east5-aiplatform.googleapis.com", vertexListBase("", "us-east5"))
	assert.Equal(t, "https://aiplatform.googleapis.com", vertexListBase("", "global"))
	assert.Equal(t, "https://aiplatform.googleapis.com", vertexListBase("", ""))
	assert.Equal(t, "http://x:1", vertexListBase("http://x:1/", "us-east5"))
}

func TestVertexModelID_MapsToTheDocumentedForm(t *testing.T) {
	// Google documents Claude on Vertex as model@version.
	assert.Equal(t, "claude-sonnet-4-5@20250929", vertexModelID("publishers/anthropic/models/claude-sonnet-4-5", "20250929"))
	assert.Equal(t, "claude-opus-4-1", vertexModelID("publishers/anthropic/models/claude-opus-4-1", ""))
	assert.Equal(t, "claude-x", vertexModelID("publishers/anthropic/models/claude-x", "default"))
	assert.Equal(t, "claude-y@1", vertexModelID("publishers/anthropic/models/claude-y@1", "2"), "an ID that has a version keeps it")
	assert.Empty(t, vertexModelID("", "1"))
}

func TestVertex_ConstructWithoutAGoogleCredentialRefusesOnlyWithASavedModel(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent/creds.json")
	cfg := llm.ProviderConfig{Extra: map[string]string{"vertex_project_id": "p", "vertex_region": "us-east5"}}
	_, err := NewVertexProvider(context.Background(), cfg)
	require.NoError(t, err, "no saved model builds nothing, so no credential is read")

	cfg.DefaultModel = "claude-x"
	_, err = NewVertexProvider(context.Background(), cfg)
	require.Error(t, err, "a saved model builds the client at once, as before")
}

func TestCohere_FollowsNextPageToken(t *testing.T) {
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "chat", r.URL.Query().Get("endpoint"))
		if r.URL.Query().Get("page_token") == "" {
			reply(w, 200, `{"models":[{"name":"a"}],"next_page_token":"t2"}`)
			return
		}
		reply(w, 200, `{"models":[{"name":"b","context_length":128000}]}`)
	})
	p, err := newCohereProviderWithContext(context.Background(), llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL + "/compatibility/v1", AllowPrivateEndpoint: true})
	require.NoError(t, err)
	models, err := p.Models(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, names(models))
	assert.Equal(t, 128000, models[1].ContextWindow)
	assert.True(t, models[0].ContextWindowUnreported)
}

func TestCloudflare_FollowsResultPages(t *testing.T) {
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Text Generation", r.URL.Query().Get("task"))
		if r.URL.Query().Get("page") == "1" {
			reply(w, 200, `{"result":[{"name":"@cf/a"}],"result_info":{"total_count":150}}`)
			return
		}
		reply(w, 200, `{"result":[{"name":"@cf/b"}],"result_info":{"total_count":150}}`)
	})
	c := llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL + "/ai/v1", AllowPrivateEndpoint: true,
		Extra: map[string]string{"cloudflare_account_id": "a"}}
	p, err := newCloudflareProviderWithContext(context.Background(), c)
	require.NoError(t, err)
	models, err := p.Models(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"@cf/a", "@cf/b"}, names(models))
}

func TestListURLs(t *testing.T) {
	assert.Equal(t, "https://api.cohere.com/v1/models", cohereModelsURL("https://api.cohere.com/compatibility/v1"))
	assert.Equal(t, "x/v1/models", cohereModelsURL("x"))
	assert.Equal(t, "https://api.cloudflare.com/client/v4/accounts/a/ai/models/search",
		cloudflareModelsURL("https://api.cloudflare.com/client/v4/accounts/a/ai/v1"))
	assert.Equal(t, "https://router.huggingface.co/v1", huggingFaceRouterURL)
	assert.Equal(t, "https://h/v1/models", openAIModelsURL("https://h/v1/"))
}

// A caller that passed the cache check before an earlier flight stored its list
// reaches the flight after that flight ended. It must take the stored list and
// not fetch again. This was the cause of two list requests where one was
// expected (gibson#1260).
func TestModelCache_ALateCallerTakesTheListThatTheEarlierFlightStored(t *testing.T) {
	c := &modelCache{}
	c.models = []llm.ModelInfo{{Name: "m1"}}
	c.loaded = time.Now()

	fetched := 0
	got, err := c.refresh(context.Background(), func(context.Context) ([]llm.ModelInfo, error) {
		fetched++
		return []llm.ModelInfo{{Name: "m2"}}, nil
	})
	require.NoError(t, err)
	assert.Zero(t, fetched, "a fresh stored list must not be fetched again")
	assert.Equal(t, []llm.ModelInfo{{Name: "m1"}}, got)

	c.loaded = time.Now().Add(-2 * modelListCacheTTL)
	_, err = c.refresh(context.Background(), func(context.Context) ([]llm.ModelInfo, error) {
		fetched++
		return []llm.ModelInfo{{Name: "m2"}}, nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, fetched, "a stale list is fetched once")
}
