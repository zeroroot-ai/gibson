// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/netguard"
)

// validateLLMEndpoint is the URL-shape and fail-fast check on a tenant-supplied
// LLM endpoint. It is NOT the load-bearing SSRF control — the connect-time
// net.Dialer guard installed by guardedHTTPClient is (see httpclient.go and
// internal/infra/netguard). A URL check alone cannot survive DNS rebinding or a
// redirect to an internal address; it runs here only so an obviously wrong
// endpoint is rejected at configuration time with a clear message instead of
// failing later as an opaque dial error.
//
// When allowPrivate is true the check is skipped — the daemon sets that from
// security.allow_private_llm_endpoints for dev-mode operators running local
// llamafile/vLLM/ollama servers on the same host as the daemon.
//
// Rejected: non-http(s) schemes, missing host, well-known cloud metadata
// hostnames, and hosts whose current DNS answer is in a blocked address class
// (see netguard.BlockedClass).
//
// Returns nil for unresolvable hostnames: the upstream call will fail anyway,
// blocking here would make DNS-based load balancers unreachable, and the dialer
// guard catches whatever the name later resolves to.
func validateLLMEndpoint(rawURL string, allowPrivate bool) error {
	if allowPrivate {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return llm.NewInvalidInputError("endpoint", fmt.Sprintf("invalid URL: %v", err))
	}
	host := u.Hostname()
	if host == "" {
		return llm.NewInvalidInputError("endpoint", "URL has no host")
	}
	// Only http(s) may reach the network. file://, gopher:// and friends are an
	// SSRF primitive in their own right.
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("validate llm endpoint: %w", llm.NewInvalidInputError("endpoint",
			fmt.Sprintf("scheme %q is not permitted; use http or https", u.Scheme)))
	}

	// Block well-known metadata hostnames outright.
	switch strings.ToLower(host) {
	case "metadata.google.internal", "metadata", "instance-data":
		return llm.NewInvalidInputError("endpoint",
			fmt.Sprintf("host %q is a cloud metadata service endpoint", host))
	}

	// Try DNS resolution; if it fails, let the dialer guard decide at connect time.
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		return nil
	}

	for _, ip := range addrs {
		if class := netguard.BlockedClass(ip); class != "" {
			return llm.NewInvalidInputError("endpoint",
				fmt.Sprintf("host %q resolves to blocked address class %s (%s); set security.allow_private_llm_endpoints=true to override", host, class, ip))
		}
	}
	return nil
}
