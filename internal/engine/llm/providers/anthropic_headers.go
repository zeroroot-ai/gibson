// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// customHeadersKey is the credential field of an Anthropic provider that
// carries extra request headers. The format is the one of the variable
// ANTHROPIC_CUSTOM_HEADERS of Claude Code: one "Name: Value" pair on each line.
// The launcher injects the same field into the sandbox, so the daemon and the
// claude binary read one value in one format.
//
// An organization user key needs it: that key works only with the header
// "anthropic-workspace-id: <id>".
const customHeadersKey = "custom_headers"

// parseCustomHeaders reads the "Name: Value" lines. It refuses a line with no
// colon and a header that would replace the credential of the request.
func parseCustomHeaders(raw string) (http.Header, error) {
	h := http.Header{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, fmt.Errorf("%s: each line must be \"Name: Value\"", customHeadersKey)
		}
		switch strings.ToLower(name) {
		case "x-api-key", "authorization", "host", "content-length":
			return nil, fmt.Errorf("%s: the header %q is not allowed", customHeadersKey, name)
		}
		h.Add(name, strings.TrimSpace(value))
	}
	return h, nil
}

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
	return t.next.RoundTrip(req)
}

// withCustomHeaders makes the client send the headers of raw on each request.
// With an empty raw it returns the client unchanged. The client keeps its
// dialer guard, because only the transport that wraps the guarded one changes.
func withCustomHeaders(client *http.Client, raw string) (*http.Client, error) {
	if strings.TrimSpace(raw) == "" {
		return client, nil
	}
	headers, err := parseCustomHeaders(raw)
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
