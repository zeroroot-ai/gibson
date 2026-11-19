// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package modelclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

func TestModels_ReadsTheListShapes(t *testing.T) {
	cases := map[string]struct {
		body string
		want []ModelEntry
	}{
		"openai":    {`{"data":[{"id":"gpt-a"},{"id":"gpt-b"}]}`, []ModelEntry{{ID: "gpt-a"}, {ID: "gpt-b"}}},
		"anthropic": {`{"data":[{"id":"claude-a","max_input_tokens":200000}],"has_more":false}`, []ModelEntry{{ID: "claude-a", ContextWindow: 200000}}},
		"gemini":    {`{"models":[{"name":"models/gemini-x","inputTokenLimit":1048576}]}`, []ModelEntry{{ID: "gemini-x", ContextWindow: 1048576}}},
		"bedrock":   {`{"modelSummaries":[{"modelId":"anthropic.claude-v2"}]}`, []ModelEntry{{ID: "anthropic.claude-v2"}}},
		"empty":     {`{}`, nil},
	}
	for name, tc := range cases {
		var method, path string
		c, _ := gateway(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
			method, path = r.Method, r.URL.Path
			_, _ = io.WriteString(w, tc.body)
		})
		got, err := c.Models(context.Background(), Caller{Tenant: "acme", Purpose: modelcall.PurposeModelList},
			Target{Tenant: "acme", Provider: "p"})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if method != http.MethodGet || path != modelcall.RouteModels {
			t.Errorf("%s: %s %s", name, method, path)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("%s: got %v, want %v", name, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: got %v, want %v", name, got, tc.want)
			}
		}
	}
}

func TestModels_ReportsTheGatewayRefusal(t *testing.T) {
	c, _ := gateway(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) { w.WriteHeader(http.StatusForbidden) })
	_, err := c.Models(context.Background(), Caller{Tenant: "acme", Purpose: "model_list"}, Target{Tenant: "acme", Provider: "p"})
	var ae *APIError
	if !errors.As(err, &ae) || !ae.Refused() {
		t.Fatalf("err = %v", err)
	}
}
