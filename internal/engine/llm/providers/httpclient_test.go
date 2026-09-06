// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/netguard"
)

func TestGuardedHTTPClient_RefusesBlockedAddressAtDialTime(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := guardedHTTPClient(llm.ProviderConfig{})
	resp, err := client.Get(srv.URL) //nolint:bodyclose // no response on the error path
	require.Error(t, err)
	require.Nil(t, resp)

	var blocked *netguard.BlockedAddressError
	require.ErrorAs(t, err, &blocked, "want *BlockedAddressError, got %v", err)
	assert.Equal(t, "loopback", blocked.Class)
	assert.Zero(t, hits.Load(), "the blocked endpoint must never be reached")
}

func TestGuardedHTTPClient_HonoursAllowPrivateEscapeHatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := guardedHTTPClient(llm.ProviderConfig{AllowPrivateEndpoint: true})
	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestGuardedHTTPClient_Timeout(t *testing.T) {
	assert.Equal(t, defaultProviderHTTPTimeout, guardedHTTPClient(llm.ProviderConfig{}).Timeout)
	assert.Equal(t, 7*time.Second,
		guardedHTTPClient(llm.ProviderConfig{HTTPTimeout: 7 * time.Second}).Timeout)
}

// TestProviderConstructors_RejectBlockedBaseURL covers the fail-fast layer: a
// tenant pointing a provider at the metadata service is rejected at config
// time, with a clear message rather than an opaque dial error.
func TestProviderConstructors_RejectBlockedBaseURL(t *testing.T) {
	const imds = "http://169.254.169.254/latest/meta-data"

	cases := []struct {
		name string
		ctor func(llm.ProviderConfig) error
	}{
		{"openai", func(c llm.ProviderConfig) error { _, err := NewOpenAIProvider(c); return err }},
		{"ollama", func(c llm.ProviderConfig) error { _, err := NewOllamaProvider(c); return err }},
		{"llamafile", func(c llm.ProviderConfig) error { _, err := NewLlamafileProvider(c); return err }},
		{"mistral", func(c llm.ProviderConfig) error { _, err := NewMistralProvider(c); return err }},
		{"cohere", func(c llm.ProviderConfig) error { _, err := NewCohereProvider(c); return err }},
		{"huggingface", func(c llm.ProviderConfig) error { _, err := NewHuggingFaceProvider(c); return err }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ctor(llm.ProviderConfig{
				Type:         llm.ProviderType(tc.name),
				APIKey:       "test-key",
				BaseURL:      imds,
				DefaultModel: "test-model",
			})
			require.Error(t, err, "%s must refuse a metadata-service base URL", tc.name)
			assert.Contains(t, strings.ToLower(err.Error()), "blocked",
				"error should name the blocked address class")
		})
	}
}

func TestValidateLLMEndpoint_RejectsNonHTTPSchemes(t *testing.T) {
	for _, raw := range []string{
		"file:///etc/passwd",
		"gopher://example.com:70/_test",
		"ftp://example.com/",
	} {
		assert.Error(t, validateLLMEndpoint(raw, false), "scheme in %q must be refused", raw)
	}
}

// TestNoProviderBuildsItsOwnHTTPClient is the anti-regression audit the fix
// depends on: the SSRF guard lives on the shared client, so a provider that
// hand-rolls an http.Client or reaches for http.DefaultClient reopens the hole.
// guardedHTTPClient (httpclient.go) is the single permitted construction site.
func TestNoProviderBuildsItsOwnHTTPClient(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	require.NotEmpty(t, files)

	banned := []string{"&http.Client{", "http.DefaultClient", "http.DefaultTransport", "&http.Transport{"}

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "httpclient.go" {
			continue
		}
		src, readErr := os.ReadFile(f) //nolint:gosec // fixed glob over this package's own sources
		require.NoError(t, readErr)
		for _, b := range banned {
			assert.NotContains(t, string(src), b,
				"%s must not build its own HTTP client (%q) — route through guardedHTTPClient so the SSRF dial guard applies", f, b)
		}
	}
}
