// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	bedrockcontrol "github.com/aws/aws-sdk-go-v2/service/bedrock"
	controltypes "github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// fakeProviderAPI is an httptest server that answers the model list call of a
// provider. It counts every request and records the ones that are not a GET of
// a list path, so a test can prove that no completion request arrived.
type fakeProviderAPI struct {
	*httptest.Server
	requests    atomic.Int32
	nonListHits atomic.Int32
	lastHeader  atomic.Pointer[http.Header]
	lastQuery   atomic.Pointer[string]
}

func newFakeProviderAPI(t *testing.T, handler http.HandlerFunc) *fakeProviderAPI {
	t.Helper()
	f := &fakeProviderAPI{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		h := r.Header.Clone()
		f.lastHeader.Store(&h)
		q := r.URL.RawQuery
		f.lastQuery.Store(&q)
		if r.Method != http.MethodGet {
			f.nonListHits.Add(1)
		}
		handler(w, r)
	}))
	t.Cleanup(f.Close)
	return f
}

func reply(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func gibsonCode(t *testing.T, err error) types.ErrorCode {
	t.Helper()
	var ge *types.GibsonError
	require.ErrorAs(t, err, &ge)
	return ge.Code
}

func names(models []llm.ModelInfo) []string {
	out := make([]string, 0, len(models))
	for _, m := range models {
		out = append(out, m.Name)
	}
	return out
}

// listCase describes one provider under test: how to build it against a fake
// server, the fake list response, and the 401 body in the shape of the provider.
type listCase struct {
	name        string
	build       func(t *testing.T, base string) llm.LLMProvider
	listPath    string
	okBody      string
	wantNames   []string
	authBody    string
	authMessage string
}

func listCases() []listCase {
	openAIOK := `{"object":"list","data":[{"id":"m-one"},{"id":"m-two"},{"id":""}]}`
	openAIAuth := `{"error":{"message":"Incorrect API key provided: sk-bad","type":"invalid_request_error"}}`
	cfg := func(base string) llm.ProviderConfig {
		return llm.ProviderConfig{APIKey: "key-123", BaseURL: base, AllowPrivateEndpoint: true}
	}
	return []listCase{
		{
			name: "openai",
			build: func(t *testing.T, base string) llm.LLMProvider {
				t.Helper()
				p, err := NewOpenAIProvider(cfg(base + "/v1"))
				require.NoError(t, err)
				return p
			},
			listPath: "/v1/models", okBody: openAIOK, wantNames: []string{"m-one", "m-two"},
			authBody: openAIAuth, authMessage: "Incorrect API key provided: sk-bad",
		},
		{
			name: "mistral",
			build: func(t *testing.T, base string) llm.LLMProvider {
				t.Helper()
				p, err := newMistralProviderWithContext(context.Background(), cfg(base+"/v1"))
				require.NoError(t, err)
				return p
			},
			listPath:  "/v1/models",
			okBody:    `{"data":[{"id":"mistral-large-latest","max_context_length":131072,"capabilities":{"completion_chat":true,"function_calling":true,"vision":false}},{"id":"mistral-embed","capabilities":{"completion_chat":false}}]}`,
			wantNames: []string{"mistral-large-latest", "mistral-embed"},
			authBody:  `{"message":"Unauthorized","request_id":"r1"}`, authMessage: "Unauthorized",
		},
		{
			name: "cohere",
			build: func(t *testing.T, base string) llm.LLMProvider {
				t.Helper()
				p, err := newCohereProviderWithContext(context.Background(), cfg(base+"/compatibility/v1"))
				require.NoError(t, err)
				return p
			},
			// Cohere lists on its native route: https://docs.cohere.com/reference/list-models
			listPath:  "/v1/models",
			okBody:    `{"models":[{"name":"command-a","context_length":256000,"endpoints":["chat"]},{"name":"command-r"}]}`,
			wantNames: []string{"command-a", "command-r"},
			authBody:  `{"message":"invalid api token"}`, authMessage: "invalid api token",
		},
		{
			name: "huggingface",
			build: func(t *testing.T, base string) llm.LLMProvider {
				t.Helper()
				p, err := newHuggingFaceProviderWithContext(context.Background(), cfg(base+"/v1"))
				require.NoError(t, err)
				return p
			},
			listPath: "/v1/models", okBody: openAIOK, wantNames: []string{"m-one", "m-two"},
			authBody: `{"error":"Invalid credentials in Authorization header"}`, authMessage: "Invalid credentials in Authorization header",
		},
		{
			name: "cloudflare",
			build: func(t *testing.T, base string) llm.LLMProvider {
				t.Helper()
				c := cfg(base + "/client/v4/accounts/acct-1/ai/v1")
				c.Extra = map[string]string{"cloudflare_account_id": "acct-1"}
				p, err := newCloudflareProviderWithContext(context.Background(), c)
				require.NoError(t, err)
				return p
			},
			// Cloudflare lists on the model search route:
			// https://developers.cloudflare.com/api/resources/ai/subresources/models/
			listPath:  "/client/v4/accounts/acct-1/ai/models/search",
			okBody:    `{"success":true,"result":[{"name":"@cf/meta/llama-3.1-8b-instruct","task":{"name":"Text Generation"}},{"name":"@cf/x/y"}],"result_info":{"page":1,"per_page":100,"total_count":2}}`,
			wantNames: []string{"@cf/meta/llama-3.1-8b-instruct", "@cf/x/y"},
			authBody:  `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`, authMessage: "Authentication error",
		},
		{
			name: "llamafile",
			build: func(t *testing.T, base string) llm.LLMProvider {
				t.Helper()
				p, err := NewLlamafileProvider(llm.ProviderConfig{BaseURL: base, AllowPrivateEndpoint: true})
				require.NoError(t, err)
				return p
			},
			listPath: "/v1/models", okBody: `{"data":[{"id":"my-local.gguf"}]}`, wantNames: []string{"my-local.gguf"},
			authBody: `{"error":{"message":"Invalid API Key"}}`, authMessage: "Invalid API Key",
		},
		{
			name: "anthropic",
			build: func(t *testing.T, base string) llm.LLMProvider {
				t.Helper()
				p, err := NewAnthropicProvider(cfg(base))
				require.NoError(t, err)
				return p
			},
			listPath:  "/v1/models",
			okBody:    `{"data":[{"id":"claude-a","type":"model","max_input_tokens":200000,"max_tokens":64000,"capabilities":{"image_input":{"supported":true}}},{"id":"claude-b","type":"model"}],"has_more":false,"last_id":"claude-b"}`,
			wantNames: []string{"claude-a", "claude-b"},
			authBody:  `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`, authMessage: "invalid x-api-key",
		},
		{
			name: "google",
			build: func(t *testing.T, base string) llm.LLMProvider {
				t.Helper()
				p, err := NewGoogleProvider(cfg(base))
				require.NoError(t, err)
				return p
			},
			listPath:  "/v1beta/models",
			okBody:    `{"models":[{"name":"models/gemini-x","inputTokenLimit":1048576,"outputTokenLimit":65536,"supportedGenerationMethods":["generateContent","countTokens"]},{"name":"models/text-embedding-y","supportedGenerationMethods":["embedContent"]}]}`,
			wantNames: []string{"gemini-x"},
			authBody:  `{"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT"}}`, authMessage: "API key not valid. Please pass a valid API key.",
		},
		{
			name: "ollama",
			build: func(t *testing.T, base string) llm.LLMProvider {
				t.Helper()
				p, err := NewOllamaProvider(llm.ProviderConfig{BaseURL: base, AllowPrivateEndpoint: true})
				require.NoError(t, err)
				return p
			},
			listPath: "/api/tags", okBody: `{"models":[{"name":"llama3:latest","size":1},{"name":"qwen:7b"}]}`, wantNames: []string{"llama3:latest", "qwen:7b"},
			authBody: `{"error":"unauthorized"}`, authMessage: "unauthorized",
		},
	}
}

func caseNamed(t *testing.T, name string) listCase {
	t.Helper()
	for _, c := range listCases() {
		if c.name == name {
			return c
		}
	}
	t.Fatalf("no list case %q", name)
	return listCase{}
}

func TestModels_ListsWhatTheProviderReports(t *testing.T) {
	for _, tc := range listCases() {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeProviderAPI(t, func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tc.listPath, r.URL.Path)
				reply(w, http.StatusOK, tc.okBody)
			})
			p := tc.build(t, fake.URL)
			models, err := p.Models(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tc.wantNames, names(models))
			assert.EqualValues(t, 1, fake.requests.Load())
			assert.Zero(t, fake.nonListHits.Load(), "only a GET list call may reach the provider")
		})
	}
}

func TestModels_BadCredentialSurfacesTheProviderMessage(t *testing.T) {
	for _, tc := range listCases() {
		t.Run(tc.name, func(t *testing.T) {
			for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
				fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) {
					reply(w, status, tc.authBody)
				})
				p := tc.build(t, fake.URL)
				_, err := p.Models(context.Background())
				require.Error(t, err)
				assert.Equal(t, llm.ErrProviderUnauthorized, gibsonCode(t, err))
				assert.Contains(t, err.Error(), tc.authMessage)
				assert.NotContains(t, err.Error(), "key-123", "the key must never appear in an error")
			}
		})
	}
}

func TestModels_NotFoundIsAnEndpointError(t *testing.T) {
	for _, tc := range listCases() {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) {
				reply(w, http.StatusNotFound, `{"error":{"message":"no such route"}}`)
			})
			p := tc.build(t, fake.URL)
			_, err := p.Models(context.Background())
			require.Error(t, err)
			assert.Equal(t, llm.ErrProviderUnavailable, gibsonCode(t, err))
			assert.Contains(t, err.Error(), "endpoint")
			assert.Contains(t, err.Error(), "404")
			assert.NotContains(t, err.Error(), "key-123")
		})
	}
}

func TestModels_TimeoutIsATimeoutError(t *testing.T) {
	release := make(chan struct{})
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		reply(w, http.StatusOK, `{"data":[]}`)
	})
	defer close(release)
	p, err := NewOpenAIProvider(llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL + "/v1", AllowPrivateEndpoint: true})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = p.Models(ctx)
	require.Error(t, err)
	assert.Equal(t, llm.ErrTimeoutExceeded, gibsonCode(t, err))
	assert.NotContains(t, err.Error(), fake.URL)
}

func TestModels_UnreachableEndpointIsANetworkError(t *testing.T) {
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, `{}`) })
	base := fake.URL
	fake.Close()
	p, err := NewOpenAIProvider(llm.ProviderConfig{APIKey: "k", BaseURL: base + "/v1", AllowPrivateEndpoint: true})
	require.NoError(t, err)
	_, err = p.Models(context.Background())
	require.Error(t, err)
	assert.Equal(t, llm.ErrNetworkFailed, gibsonCode(t, err))
}

func TestModels_OtherStatusesAndBadBodies(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		code   types.ErrorCode
		text   string
	}{
		{"rate limit", http.StatusTooManyRequests, `{"error":{"message":"slow down"}}`, llm.ErrProviderRateLimited, ""},
		{"server error", http.StatusBadGateway, `upstream exploded`, llm.ErrProviderUnavailable, "upstream exploded"},
		{"empty error body", http.StatusInternalServerError, ``, llm.ErrProviderUnavailable, "no error text"},
		{"long error body", http.StatusInternalServerError, strings.Repeat("x", 500), llm.ErrProviderUnavailable, "..."},
		{"not json", http.StatusOK, `<html>`, llm.ErrProviderUnavailable, "not valid JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, tc.status, tc.body) })
			p, err := NewOpenAIProvider(llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL + "/v1", AllowPrivateEndpoint: true})
			require.NoError(t, err)
			_, err = p.Models(context.Background())
			require.Error(t, err)
			assert.Equal(t, tc.code, gibsonCode(t, err))
			assert.Contains(t, err.Error(), tc.text)
		})
	}
}

func TestModels_SendsTheCredentialTheProviderExpects(t *testing.T) {
	t.Run("openai bearer", func(t *testing.T) {
		fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, `{"data":[]}`) })
		p, err := NewOpenAIProvider(llm.ProviderConfig{APIKey: "sk-live", BaseURL: fake.URL + "/v1", AllowPrivateEndpoint: true})
		require.NoError(t, err)
		_, err = p.Models(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "Bearer sk-live", fake.lastHeader.Load().Get("Authorization"))
	})
	t.Run("anthropic headers", func(t *testing.T) {
		fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, `{"data":[]}`) })
		p, err := NewAnthropicProvider(llm.ProviderConfig{APIKey: "sk-ant", BaseURL: fake.URL, AllowPrivateEndpoint: true})
		require.NoError(t, err)
		_, err = p.Models(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "sk-ant", fake.lastHeader.Load().Get("x-api-key"))
		assert.Equal(t, "2023-06-01", fake.lastHeader.Load().Get("anthropic-version"))
	})
	t.Run("google header not url", func(t *testing.T) {
		fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, `{"models":[]}`) })
		p, err := NewGoogleProvider(llm.ProviderConfig{APIKey: "g-key", BaseURL: fake.URL, AllowPrivateEndpoint: true})
		require.NoError(t, err)
		_, err = p.Models(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "g-key", fake.lastHeader.Load().Get("x-goog-api-key"))
		assert.NotContains(t, *fake.lastQuery.Load(), "g-key")
	})
	t.Run("ollama with a proxy key", func(t *testing.T) {
		fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, `{"models":[]}`) })
		p, err := NewOllamaProvider(llm.ProviderConfig{APIKey: "proxy", BaseURL: fake.URL, AllowPrivateEndpoint: true})
		require.NoError(t, err)
		_, err = p.Models(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "Bearer proxy", fake.lastHeader.Load().Get("Authorization"))
	})
}

func TestModels_ReportsSizeOnlyWhenTheAPIDoes(t *testing.T) {
	t.Run("anthropic", func(t *testing.T) {
		tc := caseNamed(t, "anthropic")
		fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, tc.okBody) })
		models, err := tc.build(t, fake.URL).Models(context.Background())
		require.NoError(t, err)
		require.Len(t, models, 2)
		assert.Equal(t, 200000, models[0].ContextWindow)
		assert.Equal(t, 64000, models[0].MaxOutput)
		assert.Contains(t, models[0].Features, "vision")
		assert.Zero(t, models[1].ContextWindow, "an unreported size stays zero")
		assert.Zero(t, models[1].MaxOutput)
		assert.NotContains(t, models[1].Features, "vision")
	})
	t.Run("google", func(t *testing.T) {
		tc := caseNamed(t, "google")
		fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, tc.okBody) })
		models, err := tc.build(t, fake.URL).Models(context.Background())
		require.NoError(t, err)
		require.Len(t, models, 1)
		assert.Equal(t, 1048576, models[0].ContextWindow)
		assert.Equal(t, 65536, models[0].MaxOutput)
	})
	t.Run("mistral", func(t *testing.T) {
		tc := caseNamed(t, "mistral")
		fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, tc.okBody) })
		models, err := tc.build(t, fake.URL).Models(context.Background())
		require.NoError(t, err)
		require.Len(t, models, 2)
		assert.Equal(t, 131072, models[0].ContextWindow)
		assert.Equal(t, []string{"chat", "tools"}, models[0].Features)
		assert.Empty(t, models[1].Features)
		assert.Zero(t, models[1].ContextWindow)
	})
	t.Run("openai reports none", func(t *testing.T) {
		tc := caseNamed(t, "openai")
		fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, tc.okBody) })
		models, err := tc.build(t, fake.URL).Models(context.Background())
		require.NoError(t, err)
		for _, m := range models {
			assert.Zero(t, m.ContextWindow)
			assert.Zero(t, m.MaxOutput)
		}
	})
}

func TestAnthropicModels_FollowsPagination(t *testing.T) {
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("after_id") {
		case "":
			reply(w, 200, `{"data":[{"id":"a"},{"id":"b"}],"has_more":true,"last_id":"b"}`)
		case "b":
			reply(w, 200, `{"data":[{"id":"c"}],"has_more":false,"last_id":"c"}`)
		default:
			reply(w, 400, `{"error":{"message":"bad cursor"}}`)
		}
	})
	p, err := NewAnthropicProvider(llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL, AllowPrivateEndpoint: true})
	require.NoError(t, err)
	models, err := p.Models(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, names(models))
	assert.EqualValues(t, 2, fake.requests.Load())
}

func TestAnthropicModels_StopsOnARepeatedCursor(t *testing.T) {
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		reply(w, 200, `{"data":[{"id":"a"}],"has_more":true,"last_id":"a"}`)
	})
	p, err := NewAnthropicProvider(llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL, AllowPrivateEndpoint: true})
	require.NoError(t, err)
	models, err := p.Models(context.Background())
	require.NoError(t, err)
	assert.Len(t, models, 2)
	assert.EqualValues(t, 2, fake.requests.Load())
}

func TestAnthropicModels_StopsAtThePageLimit(t *testing.T) {
	var n atomic.Int32
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		id := string(rune('a' + n.Add(1)))
		reply(w, 200, `{"data":[{"id":"`+id+`"}],"has_more":true,"last_id":"`+id+`"}`)
	})
	p, err := NewAnthropicProvider(llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL, AllowPrivateEndpoint: true})
	require.NoError(t, err)
	models, err := p.Models(context.Background())
	require.NoError(t, err)
	assert.Len(t, models, maxModelListPages)
}

func TestAnthropicModels_VertexHasNoListCall(t *testing.T) {
	p := &AnthropicProvider{name: string(llm.ProviderVertex)}
	_, err := p.Models(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no model list call")
}

func TestGoogleModels_FollowsPagination(t *testing.T) {
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("pageToken") {
		case "":
			reply(w, 200, `{"models":[{"name":"models/g1","supportedGenerationMethods":["generateContent"]}],"nextPageToken":"t2"}`)
		case "t2":
			reply(w, 200, `{"models":[{"name":"models/g2","supportedGenerationMethods":["generateContent"]},{"name":"models/emb","supportedGenerationMethods":["embedContent"]}]}`)
		default:
			reply(w, 400, `{"error":{"message":"bad token"}}`)
		}
	})
	p, err := NewGoogleProvider(llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL, AllowPrivateEndpoint: true})
	require.NoError(t, err)
	models, err := p.Models(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"g1", "g2"}, names(models))
	assert.EqualValues(t, 2, fake.requests.Load())
}

func TestGoogleModels_StopsOnARepeatedTokenAndAtThePageLimit(t *testing.T) {
	t.Run("repeated token", func(t *testing.T) {
		fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, `{"models":[{"name":"models/g","supportedGenerationMethods":["generateContent"]}],"nextPageToken":"same"}`)
		})
		p, err := NewGoogleProvider(llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL, AllowPrivateEndpoint: true})
		require.NoError(t, err)
		models, err := p.Models(context.Background())
		require.NoError(t, err)
		assert.Len(t, models, 2)
	})
	t.Run("page limit", func(t *testing.T) {
		var n atomic.Int32
		fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) {
			reply(w, 200, `{"models":[{"name":"models/g","supportedGenerationMethods":["generateContent"]}],"nextPageToken":"t`+string(rune('a'+n.Add(1)))+`"}`)
		})
		p, err := NewGoogleProvider(llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL, AllowPrivateEndpoint: true})
		require.NoError(t, err)
		models, err := p.Models(context.Background())
		require.NoError(t, err)
		assert.Len(t, models, maxModelListPages)
	})
}

func TestModels_CachesASuccessNotAFailure(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			reply(w, 500, `{"error":"down"}`)
			return
		}
		reply(w, 200, `{"data":[{"id":"m"}]}`)
	})
	p, err := NewOpenAIProvider(llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL + "/v1", AllowPrivateEndpoint: true})
	require.NoError(t, err)

	_, err = p.Models(context.Background())
	require.Error(t, err)
	_, err = p.Models(context.Background())
	require.Error(t, err)
	assert.EqualValues(t, 2, fake.requests.Load(), "a failure is never cached")

	fail.Store(false)
	for range 3 {
		models, err := p.Models(context.Background())
		require.NoError(t, err)
		assert.Equal(t, []string{"m"}, names(models))
	}
	assert.EqualValues(t, 3, fake.requests.Load(), "one call fills the cache and later calls reuse it")
}

func TestModels_EmptyListIsASuccess(t *testing.T) {
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, `{"models":[]}`) })
	p, err := NewOllamaProvider(llm.ProviderConfig{BaseURL: fake.URL, AllowPrivateEndpoint: true})
	require.NoError(t, err)
	models, err := p.Models(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, models)
	assert.Empty(t, models)
	_, err = p.Models(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, 1, fake.requests.Load(), "an empty list is cached too")
}

func TestModels_PrivateEndpointIsRefusedWithoutTheOverride(t *testing.T) {
	fake := newFakeProviderAPI(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, `{"models":[]}`) })
	_, err := NewOllamaProvider(llm.ProviderConfig{BaseURL: fake.URL})
	require.Error(t, err)
	assert.Zero(t, fake.requests.Load())

	_, err = NewAnthropicProvider(llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL})
	require.Error(t, err)
	_, err = NewGoogleProvider(llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL})
	require.Error(t, err)
	assert.Zero(t, fake.requests.Load())
}

func TestProviderMessage_Shapes(t *testing.T) {
	cases := map[string]string{
		`{"error":{"message":"nested"}}`:        "nested",
		`{"error":"flat"}`:                      "flat",
		`{"message":"top"}`:                     "top",
		`{"detail":"fastapi"}`:                  "fastapi",
		`{"errors":[{"message":"cloudflare"}]}`: "cloudflare",
		`plain text`:                            "plain text",
		`{"error":{}}`:                          `{"error":{}}`,
	}
	for body, want := range cases {
		assert.Equal(t, want, providerMessage([]byte(body)), body)
	}
}

func TestStripQuery(t *testing.T) {
	assert.Equal(t, "https://h.example/v1/models", stripQuery("https://user:pw@h.example/v1/models?key=SECRET#frag"))
	assert.Equal(t, "(unparsable URL)", stripQuery("http://[::1"))
}

// fakeBedrockLister is a bedrockModelLister that returns a fixed answer.
type fakeBedrockLister struct {
	out   *bedrockcontrol.ListFoundationModelsOutput
	err   error
	calls atomic.Int32
}

func (f *fakeBedrockLister) ListFoundationModels(_ context.Context, _ *bedrockcontrol.ListFoundationModelsInput, _ ...func(*bedrockcontrol.Options)) (*bedrockcontrol.ListFoundationModelsOutput, error) {
	f.calls.Add(1)
	return f.out, f.err
}

func TestBedrockModels_ListFoundationModels(t *testing.T) {
	fake := &fakeBedrockLister{out: &bedrockcontrol.ListFoundationModelsOutput{
		ModelSummaries: []controltypes.FoundationModelSummary{
			{
				ModelId:                    aws.String("anthropic.claude-x"),
				OutputModalities:           []controltypes.ModelModality{controltypes.ModelModalityText},
				InputModalities:            []controltypes.ModelModality{controltypes.ModelModalityText, controltypes.ModelModalityImage},
				ResponseStreamingSupported: aws.Bool(true),
			},
			{
				ModelId:          aws.String("amazon.titan-embed-x"),
				OutputModalities: []controltypes.ModelModality{controltypes.ModelModalityEmbedding},
			},
			{
				ModelId:          aws.String("stability.image-x"),
				OutputModalities: []controltypes.ModelModality{controltypes.ModelModalityImage},
			},
			{OutputModalities: []controltypes.ModelModality{controltypes.ModelModalityText}},
		},
	}}
	p := &BedrockProvider{controlClient: fake}
	models, err := p.Models(context.Background())
	require.NoError(t, err)
	require.Len(t, models, 2)
	assert.Equal(t, "anthropic.claude-x", models[0].Name)
	assert.Equal(t, []string{"chat", "streaming", "vision"}, models[0].Features)
	assert.Zero(t, models[0].ContextWindow, "Bedrock reports no context window")
	assert.Equal(t, "amazon.titan-embed-x", models[1].Name)
	assert.Equal(t, []string{"embedding"}, models[1].Features)

	_, err = p.Models(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, 1, fake.calls.Load(), "the second call reuses the cache")
}

func TestBedrockModels_Errors(t *testing.T) {
	t.Run("access denied is a credential error", func(t *testing.T) {
		p := &BedrockProvider{controlClient: &fakeBedrockLister{err: errors.New("AccessDeniedException: not allowed to call ListFoundationModels")}}
		_, err := p.Models(context.Background())
		require.Error(t, err)
		assert.Equal(t, llm.ErrProviderUnauthorized, gibsonCode(t, err))
		assert.Contains(t, err.Error(), "not allowed to call ListFoundationModels")
	})
	t.Run("no client", func(t *testing.T) {
		p := &BedrockProvider{}
		_, err := p.Models(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not initialised")
	})
}

func TestAnthropicProvider_BuildsWithNoModelAndRefusesToComplete(t *testing.T) {
	p, err := NewAnthropicProvider(llm.ProviderConfig{APIKey: "k"})
	require.NoError(t, err, "the credential test names no model")
	req := llm.CompletionRequest{Messages: []llm.Message{llm.NewUserMessage("hi")}}

	_, err = p.Complete(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no model")
	_, err = p.CompleteWithTools(context.Background(), req, nil)
	require.Error(t, err)
	_, err = p.Stream(context.Background(), req)
	require.Error(t, err)
	_, err = p.CompleteStructured(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, types.HealthStateUnhealthy, p.Health(context.Background()).State)

	f, err := NewFoundryProvider(context.Background(), llm.ProviderConfig{APIKey: "k", Extra: map[string]string{"foundry_resource": "r"}})
	require.NoError(t, err)
	_, err = f.Complete(context.Background(), req)
	require.Error(t, err)
}
