// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// contentValue returns the content list as plain JSON values.
func TestContentValue_ReturnsPlainJSON(t *testing.T) {
	got, err := contentValue([]mcp.Content{&mcp.TextContent{Text: "hello"}})
	if err != nil {
		t.Fatalf("contentValue: %v", err)
	}
	list, ok := got.([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("value = %#v; want a list of one part", got)
	}
	part, ok := list[0].(map[string]any)
	if !ok || part["text"] != "hello" {
		t.Fatalf("part = %#v; want the text hello", list[0])
	}
}

// contentText joins the text parts and skips each other part.
func TestContentText_JoinsTheTextParts(t *testing.T) {
	got := contentText([]mcp.Content{
		&mcp.TextContent{Text: "a"},
		&mcp.ImageContent{MIMEType: "image/png"},
		&mcp.TextContent{Text: "b"},
	})
	if got != "a\nb" {
		t.Fatalf("contentText = %q; want %q", got, "a\nb")
	}
}

// A token error fails the request. The request does not go out with no
// identity.
func TestBearerTransport_TokenErrorFailsTheRequest(t *testing.T) {
	sent := false
	transport := &bearerTransport{
		base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			sent = true
			return nil, errors.New("must not be reached")
		}),
		token: func(context.Context) (string, error) { return "", errors.New("no svid") },
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://proxy.invalid/mcp", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := transport.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || sent {
		t.Fatalf("err = %v, sent = %v; want an error and no request", err, sent)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
