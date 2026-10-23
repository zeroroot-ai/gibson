// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// vertexAnthropicVersion is the anthropic_version field that Vertex requires
// in the body of each request.
const vertexAnthropicVersion = "vertex-2023-10-16"

// vertexChatBase returns the host of the Vertex chat API for the region. It is
// a fixed Google host. The tenant never sets it.
func vertexChatBase(region string) string {
	switch region {
	case "global":
		return "https://aiplatform.googleapis.com/"
	case "us":
		return "https://aiplatform.us.rep.googleapis.com/"
	case "eu":
		return "https://aiplatform.eu.rep.googleapis.com/"
	default:
		return "https://" + region + "-aiplatform.googleapis.com/"
	}
}

// vertexTransport turns a request of the Anthropic client into a Vertex
// request. The Anthropic client posts to /v1/messages with the model in the
// body. Vertex wants the model in the path, the anthropic_version in the body
// and a Google token in the header. The inner transport adds the token and
// sends the request, so it is the guarded transport.
//
// The Vertex branch of the eino library does this rewrite itself, but it
// builds its own HTTP client. This type does the same rewrite on the client
// that gibson passes in, so the request meets the egress guard (gibson#1273).
type vertexTransport struct {
	project string
	region  string
	inner   http.RoundTripper
}

func (t vertexTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if req.Body != nil && req.Body != http.NoBody {
		raw, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read the vertex request body: %w", err)
		}
		body, err := t.rewrite(req, raw)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		req.ContentLength = int64(len(body))
	}
	return t.inner.RoundTrip(req) //nolint:wrapcheck // the transport error is the answer
}

// rewrite sets the anthropic_version, and for a message call moves the model
// from the body to the path.
func (t vertexTransport) rewrite(req *http.Request, raw []byte) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("read the vertex request body: %w", err)
	}
	if _, ok := fields["anthropic_version"]; !ok {
		fields["anthropic_version"] = json.RawMessage(`"` + vertexAnthropicVersion + `"`)
	}
	post := req.Method == http.MethodPost
	switch {
	case post && req.URL.Path == "/v1/messages":
		var model string
		if err := json.Unmarshal(fields["model"], &model); err != nil || model == "" {
			return nil, errors.New("the vertex request names no model")
		}
		// The model is one path segment. Anything else could move the request.
		if strings.ContainsAny(model, "/?#\\") || strings.Contains(model, "..") {
			return nil, errors.New("the vertex model name is not a plain name")
		}
		delete(fields, "model")
		method := "rawPredict"
		var stream bool
		if json.Unmarshal(fields["stream"], &stream) == nil && stream {
			method = "streamRawPredict"
		}
		req.URL.Path = fmt.Sprintf("/v1/projects/%s/locations/%s/publishers/anthropic/models/%s:%s",
			t.project, t.region, model, method)
		req.URL.RawPath = ""
	case post && req.URL.Path == "/v1/messages/count_tokens":
		req.URL.Path = fmt.Sprintf("/v1/projects/%s/locations/%s/publishers/anthropic/models/count-tokens:rawPredict",
			t.project, t.region)
		req.URL.RawPath = ""
	}
	return json.Marshal(fields) //nolint:wrapcheck // a map of valid raw JSON always marshals
}
