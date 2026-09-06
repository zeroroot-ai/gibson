// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package providers implements the per-vendor LLM provider clients (OpenAI,
// Anthropic, Bedrock, Cohere, and the rest) behind the llm.Provider interface,
// plus the SSRF egress controls (guardedHTTPClient, validateLLMEndpoint) that
// every provider constructor must route tenant-supplied endpoints through.
package providers

import (
	"net/http"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/netguard"
)

// defaultProviderHTTPTimeout bounds a single upstream LLM request when
// ProviderConfig.HTTPTimeout is unset.
const defaultProviderHTTPTimeout = 120 * time.Second

// guardedHTTPClient is the ONLY HTTP client an LLM provider may use.
//
// Every provider in this package reaches an endpoint that a tenant can set
// (ProviderConfig.BaseURL). The client returned here carries a net.Dialer
// Control hook that rejects loopback, link-local (169.254.169.254 metadata),
// RFC1918, CGNAT, IPv6 ULA and the other non-public classes at connect time —
// so the check survives DNS rebinding and HTTP redirects, which a one-shot URL
// validation does not.
//
// Do not construct an http.Client for an LLM provider anywhere else: a client
// built elsewhere has no guard and reopens the SSRF hole. providers_httpclient_test
// asserts that no provider constructor bypasses this helper.
func guardedHTTPClient(cfg llm.ProviderConfig) *http.Client {
	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = defaultProviderHTTPTimeout
	}
	return netguard.HTTPClient(timeout, cfg.AllowPrivateEndpoint)
}
