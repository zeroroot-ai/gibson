// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// The model lists in this package come from the provider. No provider keeps a
// fixed list of model IDs. Each Models method calls the list endpoint of the
// provider with the configured credentials and base URL, then returns what the
// provider reports. A field that the provider does not report stays zero.

const (
	// maxModelListBody bounds one list response so a hostile endpoint cannot
	// fill the memory of the daemon.
	maxModelListBody = 4 << 20

	// maxModelListPages bounds the pages that one list call follows.
	maxModelListPages = 20

	// modelListCacheTTL is how long a successful list stays valid for one
	// provider instance. Slot resolution calls Models on a request path.
	modelListCacheTTL = 5 * time.Minute
)

// modelCache keeps the last successful model list of one provider instance.
// Only a success is cached. A failure always reaches the provider again.
type modelCache struct {
	mu     sync.Mutex
	loaded time.Time
	models []llm.ModelInfo
}

// get returns the cached list while it is fresh and calls fetch otherwise.
func (c *modelCache) get(fetch func() ([]llm.ModelInfo, error)) ([]llm.ModelInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.models != nil && time.Since(c.loaded) < modelListCacheTTL {
		return slices.Clone(c.models), nil
	}
	models, err := fetch()
	if err != nil {
		return nil, err
	}
	if models == nil {
		models = []llm.ModelInfo{}
	}
	c.models = models
	c.loaded = time.Now()
	return slices.Clone(models), nil
}

// getJSON sends one GET request through the guarded client and decodes a 2xx
// JSON body into out. It maps each failure to an error that names the
// provider:
//   - 401 and 403 give an authentication error that carries the message of the
//     provider.
//   - 404 gives an endpoint error that names the URL without its query.
//   - 429 gives a rate limit error.
//   - A timeout gives a timeout error.
//
//nolint:wrapcheck // the typed llm errors are the contract that callers read by code
func getJSON(ctx context.Context, client *http.Client, provider, rawURL string, header http.Header, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return llm.NewProviderError(provider, fmt.Errorf("build the model list request: %w", err))
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return modelListTransportError(provider, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxModelListBody))
	if err != nil {
		return modelListTransportError(provider, err)
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if err := json.Unmarshal(body, out); err != nil {
			return llm.NewProviderError(provider, fmt.Errorf("the model list response is not valid JSON: %w", err))
		}
		return nil
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return llm.NewAuthError(provider, fmt.Errorf("%s (HTTP %d)", providerMessage(body), resp.StatusCode))
	case resp.StatusCode == http.StatusNotFound:
		return llm.NewProviderError(provider, fmt.Errorf("the model list endpoint %s was not found (HTTP 404): %s",
			stripQuery(rawURL), providerMessage(body)))
	case resp.StatusCode == http.StatusTooManyRequests:
		return llm.NewRateLimitError(provider)
	default:
		return llm.NewProviderError(provider, fmt.Errorf("the model list call failed (HTTP %d): %s",
			resp.StatusCode, providerMessage(body)))
	}
}

// modelListTransportError maps a transport failure to a timeout or a network
// error. It drops the request URL from the text of the error.
func modelListTransportError(provider string, err error) error {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return llm.NewTimeoutError(fmt.Sprintf("the model list call to provider %s timed out", provider))
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	return llm.NewNetworkError(fmt.Sprintf("the model list call to provider %s failed: %v", provider, err), err)
}

// stripQuery returns the URL without its query string and fragment.
func stripQuery(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "(unparsable URL)"
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.User = nil
	return u.String()
}

// providerMessage pulls the error text out of a provider error body. The
// shapes cover Anthropic and OpenAI ({"error":{"message":..}}), Google, Mistral
// ({"message":..}), Cloudflare ({"errors":[{"message":..}]}) and Ollama and
// HuggingFace ({"error":".."}). An unknown shape gives the trimmed body.
func providerMessage(body []byte) string {
	var shape struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
		Detail  string          `json:"detail"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &shape); err == nil {
		if len(shape.Error) > 0 {
			var nested struct {
				Message string `json:"message"`
			}
			if json.Unmarshal(shape.Error, &nested) == nil && nested.Message != "" {
				return nested.Message
			}
			var text string
			if json.Unmarshal(shape.Error, &text) == nil && text != "" {
				return text
			}
		}
		if shape.Message != "" {
			return shape.Message
		}
		if shape.Detail != "" {
			return shape.Detail
		}
		if len(shape.Errors) > 0 && shape.Errors[0].Message != "" {
			return shape.Errors[0].Message
		}
	}
	text := strings.TrimSpace(string(body))
	if text == "" {
		return "the provider sent no error text"
	}
	if len(text) > 300 {
		text = text[:300] + "..."
	}
	return text
}

// openAIListEndpoint lists models from an OpenAI-compatible GET {base}/models
// call with bearer auth. OpenAI, Mistral, Cohere, HuggingFace, Cloudflare and
// Llamafile all use it.
type openAIListEndpoint struct {
	client   *http.Client
	provider string
	baseURL  string
	token    string
	cache    modelCache
}

// Models returns the models that the endpoint reports.
func (e *openAIListEndpoint) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	return e.cache.get(func() ([]llm.ModelInfo, error) {
		header := http.Header{}
		if e.token != "" {
			header.Set("Authorization", "Bearer "+e.token)
		}
		var page struct {
			Data []struct {
				ID string `json:"id"`
				// Optional size fields. Providers that report one use one of
				// these names.
				ContextWindow    int `json:"context_window"`
				ContextLength    int `json:"context_length"`
				MaxContextLength int `json:"max_context_length"`
				// Optional capability flags (Mistral).
				Capabilities *struct {
					CompletionChat  bool `json:"completion_chat"`
					FunctionCalling bool `json:"function_calling"`
					Vision          bool `json:"vision"`
				} `json:"capabilities"`
			} `json:"data"`
		}
		if err := getJSON(ctx, e.client, e.provider, strings.TrimRight(e.baseURL, "/")+"/models", header, &page); err != nil {
			return nil, err
		}
		models := make([]llm.ModelInfo, 0, len(page.Data))
		for _, m := range page.Data {
			if m.ID == "" {
				continue
			}
			info := llm.ModelInfo{Name: m.ID, ContextWindow: firstPositive(m.ContextWindow, m.ContextLength, m.MaxContextLength)}
			if c := m.Capabilities; c != nil {
				if c.CompletionChat {
					info.Features = append(info.Features, "chat")
				}
				if c.FunctionCalling {
					info.Features = append(info.Features, "tools")
				}
				if c.Vision {
					info.Features = append(info.Features, "vision")
				}
			}
			models = append(models, info)
		}
		return models, nil
	})
}

// firstPositive returns the first value above zero, or zero.
func firstPositive(vs ...int) int {
	for _, v := range vs {
		if v > 0 {
			return v
		}
	}
	return 0
}
