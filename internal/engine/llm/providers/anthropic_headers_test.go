// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

func TestParseCustomHeaders(t *testing.T) {
	h, err := parseCustomHeaders("anthropic-workspace-id: wrkspc_1\n\n X-Other :v:w \n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := h.Get("anthropic-workspace-id"); got != "wrkspc_1" {
		t.Errorf("workspace header = %q", got)
	}
	if got := h.Get("X-Other"); got != "v:w" {
		t.Errorf("X-Other = %q", got)
	}
	for _, bad := range []string{"no colon here", ": value", "X-Api-Key: other", "Authorization: Bearer x"} {
		if _, err := parseCustomHeaders(bad); err == nil {
			t.Errorf("want an error for %q", bad)
		}
	}
}

func TestWithCustomHeaders_SendsTheHeaderAndKeepsTheClient(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("anthropic-workspace-id")
	}))
	t.Cleanup(srv.Close)

	base := srv.Client()
	baseTransport := base.Transport
	client, err := withCustomHeaders(base, "anthropic-workspace-id: wrkspc_1")
	if err != nil {
		t.Fatalf("withCustomHeaders: %v", err)
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	if got != "wrkspc_1" {
		t.Fatalf("server saw header %q", got)
	}
	if base.Transport != baseTransport {
		t.Error("the base client must not change")
	}
	same, err := withCustomHeaders(base, "  ")
	if err != nil || same != base {
		t.Errorf("an empty value must return the client unchanged, got %v %v", same, err)
	}
}

func TestNewAnthropicProvider_RefusesBadCustomHeaders(t *testing.T) {
	_, err := NewAnthropicProvider(llm.ProviderConfig{
		Type: llm.ProviderAnthropic, APIKey: "k",
		Extra: map[string]string{customHeadersKey: "not a header line"},
	})
	if err == nil {
		t.Fatal("want an error for a malformed custom_headers value")
	}
}
