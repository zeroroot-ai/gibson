// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
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
	assert.True(t, models[0].FeaturesUnreported)
	assert.True(t, models[1].FeaturesUnreported)
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

func TestVertex_ListsPublisherModelsWithAMintedToken(t *testing.T) {
	var gotAuth atomic.Value
	var gotPath atomic.Value
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		gotPath.Store(r.URL.Path)
		if r.URL.Query().Get("pageToken") == "" {
			reply(w, 200, `{"publisherModels":[{"name":"publishers/anthropic/models/claude-a"}],"nextPageToken":"p2"}`)
			return
		}
		reply(w, 200, `{"publisherModels":[{"name":"publishers/anthropic/models/claude-b"}]}`)
	})
	mint := func(context.Context, *http.Client) (string, error) { return "tok-123", nil }
	p, err := newVertexProvider(context.Background(), llm.ProviderConfig{
		BaseURL: fake.URL, AllowPrivateEndpoint: true,
		Extra: map[string]string{"vertex_project_id": "proj", "vertex_region": "us-east5"},
	}, mint)
	require.NoError(t, err, "a Vertex test names no model and needs no Google credential to build")

	models, err := p.Models(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"claude-a", "claude-b"}, names(models))
	assert.Equal(t, "Bearer tok-123", gotAuth.Load())
	assert.Equal(t, "/v1beta1/publishers/anthropic/models", gotPath.Load())
	assert.EqualValues(t, 2, fake.requests.Load())
}

func TestVertex_TokenFailureIsACredentialError(t *testing.T) {
	mint := func(context.Context, *http.Client) (string, error) { return "", assert.AnError }
	p, err := newVertexProvider(context.Background(), llm.ProviderConfig{
		Extra: map[string]string{"vertex_project_id": "proj", "vertex_region": "global"},
	}, mint)
	require.NoError(t, err)
	_, err = p.Models(context.Background())
	require.Error(t, err)
	assert.Equal(t, llm.ErrProviderUnauthorized, gibsonCode(t, err))
}

func TestVertex_HostFollowsTheRegion(t *testing.T) {
	assert.Equal(t, "https://us-east5-aiplatform.googleapis.com", vertexListBase("", "us-east5"))
	assert.Equal(t, "https://aiplatform.googleapis.com", vertexListBase("", "global"))
	assert.Equal(t, "https://aiplatform.googleapis.com", vertexListBase("", ""))
	assert.Equal(t, "http://x:1", vertexListBase("http://x:1/", "us-east5"))
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

func TestGoogleAccessToken_NoCredentialIsAnError(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent/creds.json")
	_, err := googleAccessToken(context.Background(), http.DefaultClient)
	require.Error(t, err)
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
