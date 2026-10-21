// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// headerTransport sets fixed headers on each request.
type headerTransport struct {
	next    http.RoundTripper
	headers http.Header
}

func (t headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	for name, values := range t.headers {
		req.Header.Del(name)
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("round trip with custom headers: %w", err)
	}
	return resp, nil
}

// withCustomHeaders makes the client send the headers of raw on each request.
// With an empty raw it returns the client unchanged. The client keeps its
// dialer guard, because only the transport that wraps the guarded one changes.
func withCustomHeaders(client *http.Client, raw string) (*http.Client, error) {
	if strings.TrimSpace(raw) == "" {
		return client, nil
	}
	headers, err := llm.ParseCustomHeaders(raw)
	if err != nil {
		return nil, err
	}
	next := client.Transport
	if next == nil {
		return nil, errors.New("the client has no transport to wrap")
	}
	wrapped := *client
	wrapped.Transport = headerTransport{next: next, headers: headers}
	return &wrapped, nil
}
